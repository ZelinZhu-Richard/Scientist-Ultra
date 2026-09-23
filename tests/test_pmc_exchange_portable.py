"""Portable supplied-connection PMC lifecycle controls."""

import io
import socket
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

from scientist_one import external as subject

def prepared(**changes):
    value = subject.PreparedEgressRequest(
        request_id="a" * 64, method="GET", url="https://pmc.ncbi.nlm.nih.gov/fixture",
        host="pmc.ncbi.nlm.nih.gov", target="/fixture", headers=(), body=b"",
        timeout_seconds=2.0, maximum_response_bytes=64, _deadline_monotonic=100.0,
    )
    return replace(value, **changes)

class Connection:
    def __init__(self, owned):
        self.sock = owned
        self.timeout = None
        self.calls = []
        self.closes = 0
        self.request_hook = self.close_hook = None

    def request(self, method, target, *, body, headers):
        self.calls.append((method, target, body, headers, self.timeout, self.sock.gettimeout()))
        if self.request_hook is not None:
            self.request_hook()

    def close(self):
        self.closes += 1
        if self.close_hook is not None:
            self.close_hook()
        else:
            owned, self.sock = self.sock, None
            if owned is not None:
                owned.close()

@contextmanager
def fixture(wire=b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"):
    sender, receiver = socket.socketpair()
    connection = Connection(receiver)
    try:
        sender.sendall(wire)
        sender.shutdown(socket.SHUT_WR)
        yield connection, receiver
    finally:
        receiver.close()
        sender.close()

def throwing(error):
    def fail(*args, **kwargs):
        raise error
    return fail

class PmcExchangeCandidateTests(unittest.TestCase):
    def lifecycle(self, connection, *, request=None, headers=(), remaining=None):
        return subject._PmcExchangeLifecycle(
            connection=connection, prepared=prepared() if request is None else request,
            headers=headers, deadline_remaining=remaining or (lambda request: 1.0),
        )

    def denied(self, owner, count=0):
        with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
            owner.run()
        self.assertEqual(caught.exception.response_body_bytes, count)
        self.assertEqual(owner.response_body_bytes, count)
        self.assertTrue(caught.exception.policy_denial)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertFalse(hasattr(caught.exception, "partial"))
        return caught.exception

    def test_real_native_fixed_chunked_and_zero_body_cleanup(self):
        wires = (
            (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", b"abc", 64),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", b"abc", 64),
            (b"HTTP/1.1 204 OK\r\n\r\n", b"", 0),
        )
        for wire, body, cap in wires:
            with self.subTest(body=body), fixture(wire) as (connection, receiver):
                owner = self.lifecycle(connection, request=prepared(maximum_response_bytes=cap))
                self.assertEqual(owner.run()[2], body)
                self.assertTrue(owner.network_started)
                self.assertTrue(owner.ownership_complete)
                self.assertTrue(owner.framing_complete)
                self.assertTrue(owner.local_cleanup_complete)
                self.assertEqual(owner.response_body_bytes, len(body))
                self.assertEqual(receiver.fileno(), -1)
                self.assertEqual(receiver._io_refs, 0)
                self.assertEqual(connection.closes, 1)

    def test_request_minimum_timeout_headers_and_none_body(self):
        for limit, remaining in ((0.125, 1.0), (2.0, 0.25)):
            with self.subTest(limit=limit), fixture() as (connection, _):
                owner = self.lifecycle(connection, request=prepared(timeout_seconds=limit),
                                       remaining=lambda request: remaining,
                                       headers=(("Accept", "application/xml"),))
                owner.run()
                self.assertEqual(connection.calls, [("GET", "/fixture", None,
                                 {"Accept": "application/xml"}, min(limit, remaining), min(limit, remaining))])

    def test_fresh_connection_attaches_socket_only_during_inert_request(self):
        with fixture() as (_, receiver):
            class FreshConnection(Connection):
                def request(self, method, target, *, body, headers):
                    self.sock = receiver
                    self.sock.settimeout(self.timeout)
                    super().request(method, target, body=body, headers=headers)
            connection = FreshConnection(None)
            owner = self.lifecycle(connection, remaining=lambda request: 0.25)
            self.assertEqual(owner.run()[2], b"abc")
            self.assertEqual(connection.calls[0][-2:], (0.25, 0.25))
            self.assertTrue(owner.ownership_complete)
            self.assertTrue(owner.local_cleanup_complete)
            self.assertEqual(connection.closes, 1)

    def test_invalid_exact_request_fields_never_send(self):
        invalid = [prepared(method="POST"), prepared(body=b"x"), prepared(body=bytearray()),
                   prepared(credential_header="Authorization"), prepared(maximum_response_bytes=True),
                   prepared(maximum_response_bytes=-1)]
        invalid += [prepared(timeout_seconds=value) for value in
                    (True, 0, -1, float("inf"), float("nan"), "1")]
        for request in invalid:
            with self.subTest(request=request), fixture() as (connection, _):
                owner = self.lifecycle(connection, request=request)
                self.denied(owner)
                self.assertEqual(connection.calls, [])
                self.assertFalse(owner.network_started)
                self.assertFalse(owner.ownership_complete)
                self.assertFalse(owner.local_cleanup_complete)
                self.assertEqual(connection.closes, 1)

    def test_header_exact_shape_duplicates_and_controls(self):
        for headers in ([], (["Accept", "x"],), (("Accept", b"x"),),
                        (("Accept", "x"), ("accept", "y")), (("X-Test", "bad\r\nvalue"),)):
            with self.subTest(headers=headers), fixture() as (connection, _):
                owner = self.lifecycle(connection, headers=headers)
                self.denied(owner)
                self.assertFalse(connection.calls)

    def test_bad_remaining_values_never_send(self):
        for value in (True, 0, -1.0, float("inf"), float("nan"), "1"):
            with self.subTest(value=value), fixture() as (connection, _):
                owner = self.lifecycle(connection, remaining=lambda request: value)
                self.denied(owner)
                self.assertFalse(connection.calls)

    def test_readonly_observations_and_single_use(self):
        with fixture() as (connection, _):
            owner = self.lifecycle(connection)
            owner.run()
            for name in ("network_started", "ownership_complete", "framing_complete",
                         "local_cleanup_complete", "response_body_bytes"):
                with self.assertRaises(AttributeError):
                    setattr(owner, name, False)
            self.denied(owner, 3)
            self.assertEqual(connection.closes, 1)
            self.assertEqual(len(connection.calls), 1)

    def test_request_failure_and_cancellation_remain_unknown_ownership(self):
        for primary in (OSError("private fixture"), KeyboardInterrupt()):
            with self.subTest(primary=type(primary)), fixture() as (connection, _):
                connection.request_hook = throwing(primary)
                owner = self.lifecycle(connection)
                if isinstance(primary, Exception):
                    self.denied(owner)
                else:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        owner.run()
                    self.assertIs(caught.exception, primary)
                self.assertTrue(owner.network_started)
                self.assertFalse(owner.ownership_complete)
                self.assertFalse(owner.local_cleanup_complete)
                self.assertEqual(connection.closes, 1)

    def test_deadline_expires_after_request_but_before_parse(self):
        with fixture() as (connection, receiver):
            owner = self.lifecycle(connection, remaining=lambda request: 0 if connection.calls else 1)
            self.denied(owner)
            self.assertTrue(owner.ownership_complete)
            self.assertFalse(owner.framing_complete)
            self.assertTrue(owner.local_cleanup_complete)
            self.assertEqual(receiver.fileno(), -1)

    def test_deadline_identity_and_final_expiry_keep_completion(self):
        observed, holder = [], []
        def remaining(request):
            observed.append(request._deadline_monotonic)
            return 0 if holder[0].local_cleanup_complete else 1
        with fixture() as (connection, _):
            owner = self.lifecycle(connection, remaining=remaining)
            holder.append(owner)
            self.denied(owner, 3)
            self.assertEqual(set(observed), {100.0})
            self.assertTrue(owner.framing_complete)
            self.assertTrue(owner.local_cleanup_complete)

    def test_existing_wrapper_prevents_request(self):
        with fixture() as (connection, receiver):
            raw = receiver.makefile("rb", buffering=0)
            try:
                owner = self.lifecycle(connection)
                self.denied(owner)
                self.assertFalse(connection.calls)
                self.assertFalse(owner.local_cleanup_complete)
            finally:
                raw.close()

    def test_makefile_failure_before_return_never_claims_complete(self):
        original = socket.socket.makefile
        retained = []
        for after_effect in (False, True):
            with self.subTest(after_effect=after_effect), fixture() as (connection, receiver):
                def failing(owned, *args, **kwargs):
                    if after_effect:
                        retained.append(original(owned, *args, **kwargs))
                    raise OSError("inert stage failure")
                owner = self.lifecycle(connection)
                try:
                    with patch.object(socket.socket, "makefile", failing):
                        self.denied(owner)
                    self.assertFalse(owner.ownership_complete)
                    self.assertFalse(owner.local_cleanup_complete)
                    self.assertEqual(connection.closes, 1)
                finally:
                    for raw in retained:
                        raw.close()
                    retained.clear()

    def test_buffer_constructor_failure_closes_returned_raw_once(self):
        original = socket.socket.makefile
        raws, closes = [], []
        with fixture() as (connection, _):
            def makefile(owned, *args, **kwargs):
                raw = original(owned, *args, **kwargs)
                raws.append(raw)
                native_close = raw.close
                def close():
                    closes.append(1)
                    if len(closes) > 1:
                        raise AssertionError("duplicate raw close intercepted")
                    native_close()
                raw.close = close
                return raw
            owner = self.lifecycle(connection)
            with patch.object(socket.socket, "makefile", makefile), \
                    patch.object(io, "BufferedReader", throwing(OSError("constructor"))):
                self.denied(owner)
            self.assertEqual(closes, [1])
            self.assertTrue(raws[0].closed)
            self.assertFalse(owner.ownership_complete)
            self.assertFalse(owner.local_cleanup_complete)
            self.assertEqual(connection.closes, 1)

    def test_parser_refusal_retains_partial_count_with_complete_cleanup(self):
        with fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc") as (connection, _):
            owner = self.lifecycle(connection)
            self.denied(owner, 3)
            self.assertFalse(owner.framing_complete)
            self.assertTrue(owner.local_cleanup_complete)

    def test_wrong_returned_raw_never_grants_ownership_or_closes_foreign_stream(self):
        foreign = io.BytesIO(b"unowned")
        try:
            with fixture() as (connection, _):
                owner = self.lifecycle(connection)
                with patch.object(socket.socket, "makefile", lambda *args, **kwargs: foreign):
                    self.denied(owner)
                self.assertFalse(foreign.closed)
                self.assertFalse(owner.ownership_complete)
                self.assertFalse(owner.local_cleanup_complete)
                self.assertEqual(connection.closes, 1)
        finally:
            foreign.close()

    def test_raw_binding_and_buffer_return_validation(self):
        original = socket.socket.makefile
        for stage in ("raw-mode", "buffer-type"):
            with self.subTest(stage=stage), fixture() as (connection, _):
                owner = self.lifecycle(connection)
                if stage == "raw-mode":
                    def makefile(owned, *args, **kwargs):
                        return original(owned, "wb", buffering=0)
                    with patch.object(socket.socket, "makefile", makefile):
                        self.denied(owner)
                else:
                    foreign = io.BytesIO()
                    try:
                        with patch.object(io, "BufferedReader", lambda raw: foreign):
                            self.denied(owner)
                        self.assertFalse(foreign.closed)
                        # Returned raw remains fixture-retained through owner;
                        # the subject cannot safely close the invalid buffer.
                        owner._raw.close()
                    finally:
                        foreign.close()
                self.assertFalse(owner.ownership_complete)
                self.assertFalse(owner.local_cleanup_complete)
                self.assertEqual(connection.closes, 1)

    def test_request_socket_replacement_never_closes_replacement(self):
        replacement, peer = socket.socketpair()
        try:
            with fixture() as (connection, receiver):
                def substitute():
                    connection.sock = replacement
                connection.request_hook = substitute
                owner = self.lifecycle(connection)
                self.denied(owner)
                self.assertEqual(connection.closes, 0)
                self.assertEqual(receiver.fileno(), -1)
                self.assertGreaterEqual(replacement.fileno(), 0)
                self.assertFalse(owner.ownership_complete)
        finally:
            replacement.close()
            peer.close()

    def test_parser_cancellation_is_primary_over_secondary_close_failure(self):
        original = subject._PmcFramedResponseReader.read
        primary = KeyboardInterrupt()
        with fixture() as (connection, _):
            def cancel(reader):
                original(reader)
                raise primary
            connection.close_hook = throwing(OSError("secondary"))
            owner = self.lifecycle(connection)
            with patch.object(subject._PmcFramedResponseReader, "read", cancel):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    owner.run()
            self.assertIs(caught.exception, primary)
            self.assertEqual(owner.response_body_bytes, 3)
            self.assertFalse(owner.local_cleanup_complete)
            self.assertIn("PMC_EXCHANGE_SECONDARY_CLEANUP_FAILURE", primary.__notes__)

    def test_first_cleanup_cancellation_is_primary(self):
        with fixture() as (connection, _):
            primary = KeyboardInterrupt()
            connection.close_hook = throwing(primary)
            owner = self.lifecycle(connection)
            with self.assertRaises(KeyboardInterrupt) as caught:
                owner.run()
            self.assertIs(caught.exception, primary)
            self.assertEqual(owner.response_body_bytes, 3)
            self.assertTrue(owner.framing_complete)
            self.assertFalse(owner.local_cleanup_complete)

    def test_invalid_primary_notes_cannot_mask_cancellation_or_skip_connection(self):
        original_read = subject._PmcFramedResponseReader.read
        original_makefile = socket.socket.makefile
        primary = KeyboardInterrupt()
        primary.__notes__ = ()  # add_note rejects non-list notes on supported runtimes.
        with fixture() as (connection, _):
            def makefile(owned, *args, **kwargs):
                raw = original_makefile(owned, *args, **kwargs)
                native_close = raw.close
                def close():
                    native_close()
                    raise OSError("secondary close")
                raw.close = close
                return raw
            def cancel(reader):
                original_read(reader)
                raise primary
            owner = self.lifecycle(connection)
            with patch.object(socket.socket, "makefile", makefile), \
                    patch.object(subject._PmcFramedResponseReader, "read", cancel):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    owner.run()
            self.assertIs(caught.exception, primary)
            self.assertEqual(owner.response_body_bytes, 3)
            self.assertEqual(connection.closes, 1)
            self.assertFalse(owner.local_cleanup_complete)

    def test_connection_close_before_after_effect_never_retries_socket(self):
        original = socket.socket.close
        for after_effect in (False, True):
            with self.subTest(after_effect=after_effect), fixture() as (connection, receiver):
                calls = []
                def intercepted(owned):
                    if owned is receiver:
                        calls.append(1)
                        if len(calls) > 1:
                            raise AssertionError("second close intercepted")
                    return original(owned)
                def close():
                    if after_effect:
                        owned, connection.sock = connection.sock, None
                        owned.close()
                    raise OSError("close outcome")
                connection.close_hook = close
                owner = self.lifecycle(connection)
                with patch.object(socket.socket, "close", intercepted):
                    self.denied(owner, 3)
                self.assertEqual(calls, [1] if after_effect else [])
                self.assertEqual(connection.closes, 1)
                self.assertFalse(owner.local_cleanup_complete)

    def test_raw_close_failure_before_after_effect_never_retried(self):
        original = socket.socket.makefile
        for after_effect in (False, True):
            with self.subTest(after_effect=after_effect), fixture() as (connection, _):
                retained, calls = [], []
                def makefile(owned, *args, **kwargs):
                    raw = original(owned, *args, **kwargs)
                    native_close = raw.close
                    retained.append((raw, native_close))
                    def close():
                        calls.append(1)
                        if len(calls) > 1:
                            raise AssertionError("second alias close intercepted")
                        if after_effect:
                            native_close()
                        raise OSError("raw close outcome")
                    raw.close = close
                    return raw
                owner = self.lifecycle(connection)
                try:
                    with patch.object(socket.socket, "makefile", makefile):
                        self.denied(owner, 3)
                        self.assertEqual(calls, [1])
                        self.assertEqual(connection.closes, 1)
                        self.assertFalse(owner.local_cleanup_complete)
                finally:
                    for raw, native_close in retained:
                        raw.close = native_close
                        native_close()  # Fixture owns deferred resource teardown, not subject retry.

    def test_connection_binding_observation_failure_uses_retained_socket_only(self):
        class ObservedConnection(Connection):
            fail_observation = False
            @property
            def sock(self):
                if self.fail_observation:
                    raise OSError("observation")
                return self._sock
            @sock.setter
            def sock(self, value):
                self._sock = value
        original = subject._PmcFramedResponseReader.read
        with fixture() as (_, receiver):
            connection = ObservedConnection(receiver)
            def parsed(reader):
                result = original(reader)
                connection.fail_observation = True
                return result
            owner = self.lifecycle(connection)
            with patch.object(subject._PmcFramedResponseReader, "read", parsed):
                self.denied(owner, 3)
            self.assertEqual(connection.closes, 0)
            self.assertEqual(receiver.fileno(), -1)
            self.assertFalse(owner.local_cleanup_complete)

    def test_unexpected_fstat_outcomes_never_prove_cleanup(self):
        for outcome in (lambda fd: object(), throwing(OSError(5, "fixture")), throwing(KeyboardInterrupt())):
            with self.subTest(outcome=outcome), fixture() as (connection, _):
                owner = self.lifecycle(connection)
                with patch.object(subject.os, "fstat", outcome):
                    try:
                        self.denied(owner, 3)
                    except KeyboardInterrupt:
                        self.assertEqual(owner.response_body_bytes, 3)
                self.assertFalse(owner.local_cleanup_complete)
                self.assertEqual(connection.closes, 1)

    def test_reentry_poison_preserves_parser_count_and_single_cleanup(self):
        original = subject._PmcFramedResponseReader.read
        with fixture() as (connection, _):
            owner = self.lifecycle(connection)
            def reenter(reader):
                result = original(reader)
                self.denied(owner, 3)
                return result
            with patch.object(subject._PmcFramedResponseReader, "read", reenter):
                self.denied(owner, 3)
            self.assertEqual(connection.closes, 1)
            self.assertEqual(len(connection.calls), 1)
