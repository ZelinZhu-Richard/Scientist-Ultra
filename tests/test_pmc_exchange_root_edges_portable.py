"""Portable supplied-connection PMC exchange root edges."""

from contextlib import contextmanager
import socket
import unittest
from unittest.mock import patch

from scientist_one import external as subject

def prepared(*, cap=64, timeout=5.0, body=b""):
    return subject.PreparedEgressRequest(
        request_id="a" * 64, method="GET", url="https://pmc.ncbi.nlm.nih.gov/fixture",
        host="pmc.ncbi.nlm.nih.gov", target="/fixture", headers=(), body=body,
        timeout_seconds=timeout, maximum_response_bytes=cap, _deadline_monotonic=100.0,
    )

class SuppliedConnection:
    """Retains a real disposable socket, but request is an inert observation."""
    def __init__(self, owned_socket):
        self.sock = owned_socket
        self.timeout = 999.0
        self.requests = []
        self.close_calls = 0
        self.close_failure = None

    def request(self, method, target, *, body, headers):
        self.requests.append((method, target, body, headers, self.timeout, self.sock.gettimeout()))

    def close(self):
        self.close_calls += 1
        owned, self.sock = self.sock, None
        if owned is not None:
            owned.close()
        if self.close_failure is not None:
            raise self.close_failure

@contextmanager
def fixture(*, content=b"abc", declared=3):
    sender, receiver = socket.socketpair()
    connection = SuppliedConnection(receiver)
    try:
        sender.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(declared).encode()
                       + b"\r\n\r\n" + content)
        sender.shutdown(socket.SHUT_WR)
        yield connection, receiver
    finally:
        # Test-owned object cleanup only, never a bare numeric descriptor close.
        receiver.close()
        sender.close()

class ExchangeRootEdges(unittest.TestCase):
    def lifecycle(self, connection, *, request=None, deadline=None):
        return subject._PmcExchangeLifecycle(
            connection=connection, prepared=prepared() if request is None else request,
            headers=(("Accept", "application/xml"), ("Accept-Encoding", "gzip, deflate")),
            deadline_remaining=deadline or (lambda request: 0.25),
        )

    def denied(self, instance, count):
        with self.assertRaises(subject._PartialResponseTransportFailure) as caught:
            instance.run()
        self.assertTrue(caught.exception.policy_denial)
        self.assertEqual(caught.exception.response_body_bytes, count)
        self.assertEqual(instance.response_body_bytes, count)
        return caught.exception

    def test_request_timeout_and_empty_get_are_exact_before_local_cleanup(self):
        for timeout, remaining, expected in ((5.0, 0.25, 0.25), (0.125, 1.0, 0.125)):
            with self.subTest(timeout=timeout), fixture() as (connection, receiver):
                instance = self.lifecycle(connection, request=prepared(timeout=timeout),
                                          deadline=lambda request: remaining)
                result = instance.run()
                self.assertEqual(result, (200, (("Content-Length", "3"),), b"abc"))
                self.assertEqual(connection.requests, [
                    ("GET", "/fixture", None,
                     {"Accept": "application/xml", "Accept-Encoding": "gzip, deflate"},
                     expected, expected),
                ])
                self.assertTrue(instance.network_started)
                self.assertTrue(instance.ownership_complete)
                self.assertTrue(instance.framing_complete)
                self.assertTrue(instance.local_cleanup_complete)
                self.assertEqual(connection.close_calls, 1)
                self.assertEqual(receiver.fileno(), -1)
                self.denied(instance, 3)
                self.assertEqual(len(connection.requests), 1)
                self.assertEqual(connection.close_calls, 1)

    def test_invalid_budget_or_get_body_never_invokes_request(self):
        for request in (prepared(cap=-1), prepared(cap=True), prepared(timeout=float("inf")),
                        prepared(timeout=True), prepared(body=b"forbidden")):
            with self.subTest(request=request), fixture() as (connection, _):
                instance = self.lifecycle(connection, request=request)
                self.denied(instance, 0)
                self.assertFalse(instance.network_started)
                self.assertFalse(instance.ownership_complete)
                self.assertFalse(instance.local_cleanup_complete)
                self.assertEqual(connection.requests, [])

    def test_short_content_is_aborted_but_known_local_handles_close(self):
        with fixture(declared=5) as (connection, receiver):
            instance = self.lifecycle(connection)
            self.denied(instance, 3)
            self.assertTrue(instance.network_started)
            self.assertTrue(instance.ownership_complete)
            self.assertFalse(instance.framing_complete)
            self.assertTrue(instance.local_cleanup_complete)
            self.assertEqual(receiver.fileno(), -1)

    def test_parser_cancellation_survives_cleanup_with_original_count(self):
        original_read = subject._PmcFramedResponseReader.read
        primary = KeyboardInterrupt()

        def cancel_after_framing(parser):
            original_read(parser)
            raise primary

        with fixture() as (connection, _):
            instance = self.lifecycle(connection)
            with patch.object(subject._PmcFramedResponseReader, "read", cancel_after_framing):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    instance.run()
            self.assertIs(caught.exception, primary)
            self.assertEqual(instance.response_body_bytes, 3)
            self.assertTrue(instance.local_cleanup_complete)
            self.assertFalse(instance.framing_complete)

    def test_after_effect_connection_failure_never_retries_socket_alias(self):
        original_close = socket.socket.close
        with fixture(declared=5) as (connection, receiver):
            connection.close_failure = OSError("fixture after effect")
            calls = []

            def intercepted_close(owned):
                if owned is receiver:
                    calls.append(1)
                    if len(calls) > 1:
                        raise AssertionError("intercepted duplicate; no native second close")
                return original_close(owned)

            instance = self.lifecycle(connection)
            with patch.object(socket.socket, "close", intercepted_close):
                self.denied(instance, 3)
            self.assertEqual(calls, [1])
            self.assertEqual(connection.close_calls, 1)
            self.assertFalse(instance.local_cleanup_complete)
            self.assertEqual(receiver.fileno(), -1)

    def test_buffer_to_raw_after_effect_failure_is_not_retried(self):
        original_makefile = socket.socket.makefile
        raw_calls = []
        with fixture() as (connection, receiver):
            def makefile(owned, *args, **kwargs):
                raw = original_makefile(owned, *args, **kwargs)
                if owned is receiver:
                    original_close = raw.close

                    def close_raw():
                        raw_calls.append(1)
                        if len(raw_calls) > 1:
                            raise AssertionError("intercepted duplicate raw close")
                        original_close()
                        raise OSError("fixture after raw close effect")

                    raw.close = close_raw
                return raw

            instance = self.lifecycle(connection)
            with patch.object(socket.socket, "makefile", makefile):
                self.denied(instance, 3)
            self.assertEqual(raw_calls, [1])
            self.assertEqual(connection.close_calls, 1)
            self.assertTrue(instance.framing_complete)
            self.assertFalse(instance.local_cleanup_complete)
            self.assertEqual(receiver.fileno(), -1)

    def test_changed_connection_binding_never_closes_substituted_socket(self):
        foreign, peer = socket.socketpair()
        try:
            with fixture() as (connection, receiver):
                original_read = subject._PmcFramedResponseReader.read

                def replace_after_framing(parser):
                    value = original_read(parser)
                    connection.sock = foreign
                    return value

                instance = self.lifecycle(connection)
                with patch.object(subject._PmcFramedResponseReader, "read", replace_after_framing):
                    self.denied(instance, 3)
                self.assertEqual(connection.close_calls, 0)
                self.assertGreaterEqual(foreign.fileno(), 0)
                self.assertEqual(receiver.fileno(), -1)
                self.assertFalse(instance.local_cleanup_complete)
        finally:
            # These are independent test-owned handles, not descriptor-reuse controls.
            foreign.close()
            peer.close()

    def test_deadline_after_cleanup_cancels_without_erasing_completion_facts(self):
        holder = []
        observed_deadlines = []
        primary = KeyboardInterrupt()

        def deadline(request):
            observed_deadlines.append(request._deadline_monotonic)
            if holder and holder[0].local_cleanup_complete:
                raise primary
            return 1.0

        with fixture() as (connection, _):
            instance = self.lifecycle(connection, deadline=deadline)
            holder.append(instance)
            with self.assertRaises(KeyboardInterrupt) as caught:
                instance.run()
            self.assertIs(caught.exception, primary)
            self.assertEqual(instance.response_body_bytes, 3)
            self.assertTrue(instance.framing_complete)
            self.assertTrue(instance.local_cleanup_complete)
            self.assertEqual(set(observed_deadlines), {100.0})
            self.assertEqual(connection.close_calls, 1)
