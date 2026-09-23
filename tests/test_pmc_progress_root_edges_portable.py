"""Portable supplied-stream PMC progress root edges."""

from contextlib import contextmanager
from dataclasses import replace
import socket
import sys
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.literature import PMCAdapter, ScholarlyIdentifier, IdentifierKind
from scientist_one.scholarly_gateway import _encode_pmc_request, pmc_content_scholarly_egress_policy
from tests.test_scholarly_gateway import pmc_xml

class InertConnection:
    def __init__(self, owned):
        self.sock = owned
        self.timeout = None
        self.requests = 0

    def request(self, method, target, *, body, headers):
        self.requests += 1

    def close(self):
        owned, self.sock = self.sock, None
        if owned is not None:
            owned.close()

class LocalFixtureTransport:
    network_used = False
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = "UNTESTED"

    def __init__(self, *, payload=b"abc", declared=None):
        self.payload, self.declared = payload, declared
        self.prepared = []
        self.owners = []
        self.before = self.after = None
        self.completed = False

    def send(self, prepared, *, credential):
        if credential is not None:
            raise AssertionError("fixture must not receive a credential")
        subject._consume_prepared_request(prepared, self)
        self.prepared.append(prepared)
        sender, receiver = socket.socketpair()
        connection = InertConnection(receiver)
        try:
            declared = len(self.payload) if self.declared is None else self.declared
            sender.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n"
                           b"Content-Length: " + str(declared).encode() + b"\r\n\r\n"
                           + self.payload)
            sender.shutdown(socket.SHUT_WR)
            owner = subject._PmcExchangeLifecycle(
                connection=connection, prepared=prepared, headers=prepared.headers,
                deadline_remaining=lambda request: request._deadline_monotonic - time.monotonic(),
            )
            self.owners.append(owner)
            subject._register_pmc_exchange_progress(prepared, self, owner)
            if self.before is not None:
                self.before(owner)
            status, headers, body = owner.run()
            response = subject.TransportResponse(status, headers, body, prepared.url)
            self.completed = True
            return response if self.after is None else self.after(owner, response)
        finally:
            # Test-owned objects only. These closes do not certify subject cleanup.
            receiver.close()
            sender.close()

@contextmanager
def observed_counts(gateway):
    """Read integer locals during this execute only; never retain/mutate frames."""
    if sys.gettrace() is not None:
        raise AssertionError("unexpected pre-existing tracer")
    counts = []
    filename = subject.__file__

    def observer(frame, event, arg):
        if (frame.f_code.co_filename != filename or frame.f_code.co_name != "execute"
                or frame.f_locals.get("self") is not gateway):
            return None
        count = frame.f_locals.get("response_bytes_used")
        if type(count) is int:
            counts.append(count)
        return observer

    sys.settrace(observer)
    try:
        yield counts
    finally:
        sys.settrace(None)

class ProgressRootEdges(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.registry = ArtifactRegistry(Path(temporary.name))

    def gateway(self, transport, **options):
        policy = pmc_content_scholarly_egress_policy(maximum_attempts=2, **options)
        gateway = subject.EgressGateway(policy, transport, registry=self.registry)
        request = PMCAdapter().build_request(ScholarlyIdentifier(IdentifierKind.PMCID, "PMC1234567"))
        return gateway, replace(_encode_pmc_request(request), adapter_id=policy.adapter_id)

    def no_response_publication(self):
        self.assertFalse(any(record.logical_type in {
            "external_response_raw", "external_response_denial_receipt",
            "external_budget_denial_receipt", "external_response_receipt",
        } for record in self.registry.list_records()))

    def finalized(self, transport):
        for prepared in transport.prepared:
            with self.assertRaises(subject.EgressDeniedError):
                subject._consume_prepared_request(prepared, transport)

    def exact_charge(self, counts, amount):
        self.assertTrue(counts)
        self.assertEqual(counts[-1], amount)
        self.assertTrue(set(counts).issubset({0, amount}), counts)

    def test_both_primary_cancellations_charge_retained_parser_count_once(self):
        read = subject._PmcFramedResponseReader.read
        for primary in (KeyboardInterrupt("root cancellation"), SystemExit(42)):
            with self.subTest(primary=type(primary).__name__):
                transport = LocalFixtureTransport()
                gateway, request = self.gateway(transport)

                def cancel_after_read(reader):
                    read(reader)
                    raise primary

                with patch.object(subject._PmcFramedResponseReader, "read", cancel_after_read):
                    with observed_counts(gateway) as counts:
                        with self.assertRaises(type(primary)) as caught:
                            gateway.execute(request)
                self.assertIs(caught.exception, primary)
                self.exact_charge(counts, 3)
                self.assertEqual(len(transport.prepared), 1)
                self.assertEqual(gateway._request_count, 1)
                self.assertEqual(transport.owners[0]._count, 0)
                self.assertEqual(transport.owners[0]._reader._count, 3)
                self.finalized(transport)
                self.no_response_publication()

    def test_unknown_parser_count_never_fabricates_attempt_and_preserves_primary(self):
        for primary in (None, KeyboardInterrupt("unknown count"), SystemExit(43)):
            with self.subTest(primary=type(primary).__name__):
                transport = LocalFixtureTransport()
                gateway, request = self.gateway(transport)

                def corrupt_then_exit(owner, response):
                    owner._reader._count = True  # Explicit fixture corruption, not measured bytes.
                    if primary is not None:
                        raise primary
                    return response

                transport.after = corrupt_then_exit
                expected = subject.EgressDeniedError if primary is None else type(primary)
                with self.assertRaises(expected) as caught:
                    gateway.execute(request)
                if primary is None:
                    self.assertEqual(caught.exception.attempts, ())
                else:
                    self.assertIs(caught.exception, primary)
                self.assertEqual(len(transport.prepared), 1)
                self.finalized(transport)
                self.no_response_publication()

    def test_settlement_bypasses_public_count_properties_after_run(self):
        payload = pmc_xml()
        transport = LocalFixtureTransport(payload=payload)
        gateway, request = self.gateway(transport)
        patches = []

        def forbidden(owner):
            raise AssertionError("settlement dispatched a replaceable property")

        def replace_properties(owner, response):
            for kind in (subject._PmcExchangeLifecycle, subject._PmcFramedResponseReader):
                replacement = patch.object(kind, "response_body_bytes", property(forbidden))
                replacement.start()
                patches.append(replacement)
            return response

        transport.after = replace_properties
        try:
            with observed_counts(gateway) as counts:
                result = gateway.execute(request)
        finally:
            for replacement in reversed(patches):
                replacement.stop()
        self.exact_charge(counts, len(payload))
        self.assertEqual(result.total_bytes_used, len(payload))
        self.assertEqual(result.decoded_body, payload)
        self.assertIsNone(result.transport_execution_authority_artifact)
        self.finalized(transport)

    def test_normal_body_mismatch_uses_known_count_without_retry_or_raw_capture(self):
        for returned in (b"", b"ab", b"abcd"):
            with self.subTest(returned_size=len(returned)):
                transport = LocalFixtureTransport()
                gateway, request = self.gateway(transport)
                transport.after = lambda owner, response: subject.TransportResponse(
                    503, (("Content-Type", "application/xml"),), returned, response.effective_url)
                with observed_counts(gateway) as counts:
                    with self.assertRaises(subject.EgressDeniedError) as caught:
                        gateway.execute(request)
                self.exact_charge(counts, 3)
                self.assertEqual(len(transport.prepared), 1)
                self.assertEqual(len(caught.exception.attempts), 1)
                self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], 3)
                self.assertEqual(caught.exception.attempts[0]["cumulative_bytes"], 3)
                self.assertFalse(any(record.logical_type == "external_response_raw"
                                     for record in caught.exception.artifacts))
                self.finalized(transport)

    def test_post_send_authority_cancellation_cannot_precede_known_charge(self):
        transport = LocalFixtureTransport()
        gateway, request = self.gateway(transport)
        primary = KeyboardInterrupt("after send")
        classify = subject._classify_transport_authority

        def after_send(candidate):
            if candidate is transport and transport.completed:
                raise primary
            return classify(candidate)

        with patch.object(subject, "_classify_transport_authority", after_send):
            with observed_counts(gateway) as counts:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    gateway.execute(request)
        self.assertIs(caught.exception, primary)
        self.exact_charge(counts, 3)
        self.assertEqual(len(transport.prepared), 1)
        self.finalized(transport)
        self.no_response_publication()

    def test_same_content_distinct_attempt_owners_have_local_counts_and_no_quota_refund(self):
        transport = LocalFixtureTransport(declared=5)
        gateway, request = self.gateway(transport, maximum_requests=2)
        for _ in range(2):
            with observed_counts(gateway) as counts:
                with self.assertRaises(subject.EgressDeniedError) as caught:
                    gateway.execute(request)
            self.exact_charge(counts, 3)
            self.assertEqual(len(caught.exception.attempts), 1)
            self.assertEqual(caught.exception.attempts[0]["cumulative_bytes"], 3)
        self.assertEqual(len(transport.prepared), 2)
        self.assertEqual(transport.prepared[0].request_id, transport.prepared[1].request_id)
        self.assertIsNot(transport.prepared[0]._capability, transport.prepared[1]._capability)
        self.assertEqual(gateway._request_count, 2)
        with self.assertRaises(subject.EgressDeniedError):
            gateway.execute(request)
        self.assertEqual(len(transport.prepared), 2)
        self.finalized(transport)

    def test_success_at_exact_representation_cap_is_not_charged_twice(self):
        payload = pmc_xml()
        transport = LocalFixtureTransport(payload=payload)
        gateway, request = self.gateway(transport, maximum_response_bytes=len(payload),
                                        maximum_total_bytes=len(payload))
        with observed_counts(gateway) as counts:
            result = gateway.execute(request)
        self.exact_charge(counts, len(payload))
        self.assertEqual(transport.prepared[0].maximum_response_bytes, len(payload))
        self.assertEqual(result.total_bytes_used, len(payload))
        self.assertEqual(result.attempts[0]["response_body_bytes"], len(payload))
        self.assertEqual(result.decoded_body, payload)
        self.assertIsNone(result.transport_execution_authority_artifact)
        self.finalized(transport)

    def test_registered_proved_zero_ordinary_failure_is_terminal(self):
        transport = LocalFixtureTransport()
        gateway, request = self.gateway(transport)

        def before_read(owner):
            raise OSError("fixture failed before lifecycle run")

        transport.before = before_read
        with observed_counts(gateway) as counts:
            with self.assertRaises(subject.EgressDeniedError) as caught:
                gateway.execute(request)
        self.exact_charge(counts, 0)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(len(caught.exception.attempts), 1)
        self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], 0)
        self.assertFalse(transport.owners[0].network_started)
        self.finalized(transport)

    def test_ambient_handled_exception_cannot_hide_actual_revoke_failure(self):
        # Synthetic private callbacks isolate finalization precedence. The scalar
        # is injected, not evidence from a genuine capability or native reader.
        raw_execute = next(cell.cell_contents for cell in subject.EgressGateway.execute.__closure__
                           if callable(cell.cell_contents)
                           and getattr(cell.cell_contents, "__name__", None) == "execute")

        class ReturnTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"

            def send(self, prepared, *, credential):
                return subject.TransportResponse(200, (("Content-Type", "application/xml"),),
                                                 b"<x/>", prepared.url)

        gateway, request = self.gateway(ReturnTransport())
        failure = OSError("fixture revoke failed")
        revocations = []

        def issue(prepared):
            object.__setattr__(prepared, "_capability", object())

        def revoke(capability):
            revocations.append(capability)
            raise failure

        start = time.monotonic()
        try:
            raise ValueError("ambient handled caller exception, not an execute outcome")
        except ValueError:
            with self.assertRaises(OSError) as caught:
                raw_execute(
                    gateway, request, _issue_prepared=issue,
                    _capability_consumed=lambda capability: True,
                    _revoke_capability=revoke,
                    _issue_execution_authority=lambda *args, **kwargs: None,
                    _native_timing=(start, start + 30, time.monotonic, time.sleep),
                    _settle_pmc_progress=lambda capability: 4,
                )
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(revocations), 1)
        self.no_response_publication()
