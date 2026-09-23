"""Portable supplied-stream PMC progress controls."""

import socket
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.scholarly_gateway import pmc_content_scholarly_egress_policy

URL = "https://pmc.ncbi.nlm.nih.gov/api/oai/v1/mh/?verb=GetRecord&identifier=oai%3Apubmedcentral.nih.gov%3A123&metadataPrefix=pmc"
def request():
    return subject.EgressRequest(
        adapter_id=subject.PMC_CONTENT_ADAPTER_ID, method="GET", url=URL,
        headers=(("Accept", "application/xml, text/xml;q=0.9"),
                 ("User-Agent", "Scientist-One-vNext-Scholarly/2")),
        body=b"", content_type="application/xml",
    )

class Connection:
    def __init__(self, sock):
        self.sock = sock

    def request(self, *args, **kwargs):
        pass  # Supplied local fixture, no HTTP endpoint or TLS.

    def close(self):
        owned, self.sock = self.sock, None
        if owned is not None:
            owned.close()

class ProgressTransport:
    network_used = False
    inherits_proxy_environment = False
    scientific_evidence = False
    external_validation = "UNTESTED"

    def __init__(self, *, body=b"<x/>", before=None, after=None, consume=True):
        self.body, self.before, self.after, self.consume = body, before, after, consume
        self.prepared = []
        self.owners = []
        self.completed = False

    def send(self, prepared, *, credential):
        self.prepared.append(prepared)
        if self.consume:
            subject._consume_prepared_request(prepared, self)
        sender, receiver = socket.socketpair()
        try:
            sender.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: "
                           + str(len(self.body)).encode() + b"\r\n\r\n" + self.body)
            sender.shutdown(socket.SHUT_WR)
            owner = subject._PmcExchangeLifecycle(
                connection=Connection(receiver), prepared=prepared, headers=prepared.headers,
                deadline_remaining=lambda req: req._deadline_monotonic - time.monotonic(),
            )
            self.owners.append(owner)
            if self.before is not None:
                self.before(self, prepared, owner)
            else:
                subject._register_pmc_exchange_progress(prepared, self, owner)
            status, headers, body = owner.run()
            result = subject.TransportResponse(status, headers, body, prepared.url)
            self.completed = True
            if self.after is not None:
                return self.after(self, prepared, owner, result)
            return result
        finally:
            receiver.close()
            sender.close()

@contextmanager
def counters():
    """Read scalar snapshots only; restore caller trace immediately on exit."""
    snapshots = []
    old = sys.gettrace()
    def observe(frame, event, arg):
        if frame.f_code.co_name == "execute" and frame.f_code.co_filename == subject.__file__:
            if "response_bytes_used" in frame.f_locals:
                snapshots.append((event, frame.f_locals["response_bytes_used"]))
        return observe
    sys.settrace(observe)
    try:
        yield snapshots
    finally:
        sys.settrace(old)

def throwing(error):
    def fail(*args, **kwargs):
        raise error
    return fail

class PmcProgressCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.registry = ArtifactRegistry(Path(temporary.name))

    def gateway(self, transport, **changes):
        policy = pmc_content_scholarly_egress_policy(maximum_attempts=2, **changes)
        return subject.EgressGateway(policy, transport, registry=self.registry)

    def settled_denial(self, transport, count):
        gateway = self.gateway(transport)
        with counters() as trace:
            with self.assertRaises(subject.EgressDeniedError) as caught:
                gateway.execute(request())
        self.assertEqual(trace[-1][1], count)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(gateway._request_count, 1)
        self.assertEqual(len(caught.exception.attempts), 1)
        self.assertEqual(caught.exception.attempts[0]["response_body_bytes"], count)
        self.assertEqual(caught.exception.attempts[0]["cumulative_bytes"], count)
        self.assertIsNone(caught.exception.attempts[0]["retry_delay_seconds"])
        return caught.exception

    def unknown(self, transport):
        gateway = self.gateway(transport)
        with self.assertRaises(subject._PmcProgressAccountingError) as caught:
            gateway.execute(request())
        self.assertEqual(caught.exception.attempts, ())
        self.assertEqual(caught.exception.artifacts, ())
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(gateway._request_count, 1)
        self.assertEqual(str(caught.exception), "PMC_PROGRESS_UNKNOWN")
        return gateway

    def test_actual_gateway_success_charges_once_and_finalizes_registration(self):
        transport = ProgressTransport()
        with counters() as trace:
            result = self.gateway(transport).execute(request())
        self.assertEqual(result.total_bytes_used, 4)
        self.assertEqual(trace[-1][1], 4)
        self.assertEqual(result.attempts[0]["response_body_bytes"], 4)
        self.assertFalse(result.scientific_evidence)
        self.assertIsNone(result.transport_execution_authority_artifact)
        with self.assertRaises(subject._PmcProgressAccountingError):
            subject._register_pmc_exchange_progress(transport.prepared[0], transport, transport.owners[0])
        with self.assertRaises(subject.EgressDeniedError):
            subject._consume_prepared_request(transport.prepared[0], transport)

    def test_registered_ordinary_error_is_terminal_counted_denial(self):
        self.settled_denial(ProgressTransport(after=throwing(RuntimeError("fixture private text"))), 4)

    def test_registered_partial_agreement_and_mismatch_never_retry(self):
        for claimed in (4, 1):
            with self.subTest(claimed=claimed):
                error = subject._PartialResponseTransportFailure("fixture", response_body_bytes=claimed,
                                                                policy_denial=False)
                denial = self.settled_denial(ProgressTransport(after=throwing(error)), 4)
                self.assertEqual(denial.attempts[0]["status"], "TRANSPORT_FAILURE")

    def test_untyped_post_send_result_keeps_settled_count(self):
        self.settled_denial(ProgressTransport(after=lambda *args: object()), 4)

    def test_post_send_authority_exception_keeps_count_and_does_not_retry(self):
        transport = ProgressTransport()
        original = subject._classify_transport_authority
        calls = []
        def classifier(value):
            if transport.completed and not calls:
                calls.append(1)
                raise ValueError("post-send classifier")
            return original(value)
        with patch.object(subject, "_classify_transport_authority", classifier):
            self.settled_denial(transport, 4)
        self.assertEqual(calls, [1])

    def test_callback_policy_failure_keeps_count(self):
        self.settled_denial(ProgressTransport(after=throwing(subject.EgressPolicyError("fixture"))), 4)

    def test_duplicate_registration_remains_required_unknown_even_if_caught(self):
        def before(transport, prepared, owner):
            subject._register_pmc_exchange_progress(prepared, transport, owner)
            with self.assertRaises(subject._PmcProgressAccountingError):
                subject._register_pmc_exchange_progress(prepared, transport, owner)
        self.unknown(ProgressTransport(before=before))

    def test_registration_requires_consumed_correct_transport_and_prepared_owner(self):
        cases = ("not-consumed", "wrong-transport", "wrong-prepared", "subclass")
        for case in cases:
            with self.subTest(case=case):
                def before(transport, prepared, owner):
                    selected = owner
                    if case == "wrong-prepared":
                        owner._prepared = replace(prepared)
                    if case == "subclass":
                        class Derived(subject._PmcExchangeLifecycle):
                            pass
                        selected = Derived(connection=owner._connection, prepared=prepared,
                                           headers=(), deadline_remaining=lambda req: 1)
                    subject._register_pmc_exchange_progress(
                        prepared, object() if case == "wrong-transport" else transport, selected)
                self.unknown(ProgressTransport(before=before, consume=case != "not-consumed"))

    def test_registration_after_run_is_not_retroactive(self):
        def before(transport, prepared, owner):
            owner.run()
            subject._register_pmc_exchange_progress(prepared, transport, owner)
        self.unknown(ProgressTransport(before=before))

    def test_frozen_pmc_profile_is_not_recomputed_from_prepared(self):
        def before(transport, prepared, owner):
            with patch.object(subject, "_pmc_content_profile", throwing(AssertionError("not during registration"))):
                subject._register_pmc_exchange_progress(prepared, transport, owner)
        self.assertEqual(self.gateway(ProgressTransport(before=before)).execute(request()).total_bytes_used, 4)

    def test_non_pmc_invocation_cannot_register(self):
        transport = ProgressTransport()
        policy = replace(pmc_content_scholarly_egress_policy(), adapter_id="fixture-generic")
        gateway = subject.EgressGateway(policy, transport, registry=self.registry)
        with self.assertRaises(subject._PmcProgressAccountingError):
            gateway.execute(replace(request(), adapter_id="fixture-generic"))

    def test_lost_parser_after_network_start_is_unknown_not_zero(self):
        def after(transport, prepared, owner, result):
            owner._reader = None
            owner._count = 0
            owner._framing = False
            return result
        self.unknown(ProgressTransport(after=after))

    def test_pre_request_cancellation_proved_zero_and_registration_removed(self):
        primary = SystemExit(17)
        def before(transport, prepared, owner):
            subject._register_pmc_exchange_progress(prepared, transport, owner)
            raise primary
        transport = ProgressTransport(before=before)
        gateway = self.gateway(transport)
        with counters() as trace:
            with self.assertRaises(SystemExit) as caught:
                gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(trace[-1][1], 0)
        self.assertFalse(transport.owners[0].network_started)
        with self.assertRaises(subject._PmcProgressAccountingError):
            subject._register_pmc_exchange_progress(transport.prepared[0], transport, transport.owners[0])

    def test_parser_cancellation_reads_advancing_slot_not_lifecycle_copy(self):
        primary = KeyboardInterrupt()
        original = subject._PmcFramedResponseReader.read
        def cancel(parser):
            original(parser)
            raise primary
        transport = ProgressTransport()
        gateway = self.gateway(transport)
        with patch.object(subject._PmcFramedResponseReader, "read", cancel), counters() as trace:
            with self.assertRaises(KeyboardInterrupt) as caught:
                gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(transport.owners[0]._count, 0)
        self.assertEqual(trace[-1][1], 4)
        self.assertEqual(gateway._request_count, 1)

    def test_missing_parser_slot_with_cancellation_preserves_primary(self):
        primary = KeyboardInterrupt()
        def after(transport, prepared, owner, result):
            del owner._reader
            raise primary
        gateway = self.gateway(ProgressTransport(after=after))
        with self.assertRaises(KeyboardInterrupt) as caught:
            gateway.execute(request())
        self.assertIs(caught.exception, primary)

    def test_changed_prepared_binding_after_registration_is_unknown(self):
        def after(transport, prepared, owner, result):
            object.__setattr__(prepared, "target", "/changed")
            return result
        self.unknown(ProgressTransport(after=after))

    def test_generic_optional_absence_preserves_existing_accounting(self):
        response = subject.TransportResponse(200, (("Content-Type", "application/xml"),), b"<x/>", URL)
        transport = subject.FixtureTransport((response,))
        result = self.gateway(transport).execute(request())
        self.assertEqual(result.total_bytes_used, 4)
        self.assertEqual(result.attempts[0]["response_body_bytes"], 4)

    def test_hidden_gateway_settlement_and_revoke_failures_preserve_primary(self):
        # Explicit inert callback fixture over the actual execute function.
        # No production caller receives these callbacks, and no frame is mutated.
        raw_execute = next(cell.cell_contents for cell in subject.EgressGateway.execute.__closure__
                           if callable(cell.cell_contents)
                           and getattr(cell.cell_contents, "__name__", None) == "execute")
        for settle_fails in (False, True):
            primary = KeyboardInterrupt()
            class InertTransport:
                network_used = False
                inherits_proxy_environment = False
                scientific_evidence = False
                external_validation = "UNTESTED"
                def send(self, prepared, *, credential):
                    raise primary
            gateway = self.gateway(InertTransport())
            revoked = []
            def issue(prepared):
                object.__setattr__(prepared, "_capability", object())
            def revoke(capability):
                revoked.append(capability)
                raise SystemExit(29)
            def settle(capability):
                if settle_fails:
                    raise ValueError("settlement failure")
                return 4
            start = time.monotonic()
            with counters() as trace:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    raw_execute(gateway, request(), _issue_prepared=issue,
                                _capability_consumed=lambda capability: True,
                                _revoke_capability=revoke, _issue_execution_authority=lambda *args, **kwargs: None,
                                _native_timing=(start, start + 30, time.monotonic, time.sleep),
                                _settle_pmc_progress=settle)
            self.assertIs(caught.exception, primary)
            self.assertEqual(trace[-1][1], 0 if settle_fails else 4)
            self.assertEqual(len(revoked), 1)

    def raw_outcome(self, send, revoke, *, settlement=4, maximum_attempts=2):
        """Synthetic callbacks isolate finalization, not real row/count authority."""
        raw_execute = next(cell.cell_contents for cell in subject.EgressGateway.execute.__closure__
                           if callable(cell.cell_contents)
                           and getattr(cell.cell_contents, "__name__", None) == "execute")
        class InertTransport:
            network_used = False
            inherits_proxy_environment = False
            scientific_evidence = False
            external_validation = "UNTESTED"
            def send(self, prepared, *, credential):
                return send(prepared)
        gateway = subject.EgressGateway(
            pmc_content_scholarly_egress_policy(maximum_attempts=maximum_attempts),
            InertTransport(), registry=self.registry,
        )
        def issue(prepared):
            object.__setattr__(prepared, "_capability", object())
        elapsed = [0.0]
        def sleep(delay):
            elapsed[0] += delay
        return raw_execute(
            gateway, request(), _issue_prepared=issue, _capability_consumed=lambda capability: True,
            _revoke_capability=revoke, _issue_execution_authority=lambda *args, **kwargs: None,
            _native_timing=(0.0, 30.0, lambda: elapsed[0], sleep),
            _settle_pmc_progress=lambda capability: settlement,
        )

    def test_normal_outcome_finalizer_failure_propagates_with_or_without_ambient_exception(self):
        for ambient in (False, True):
            for failure in (OSError("revoke failure"), SystemExit(41)):
                with self.subTest(ambient=ambient, failure=type(failure)):
                    revocations = []
                    def send(prepared):
                        return subject.TransportResponse(200, (("Content-Type", "application/xml"),),
                                                         b"<x/>", prepared.url)
                    def revoke(capability):
                        revocations.append(capability)
                        raise failure
                    def invoke():
                        with self.assertRaises(type(failure)) as caught:
                            self.raw_outcome(send, revoke)
                        self.assertIs(caught.exception, failure)
                    if ambient:
                        try:
                            raise ValueError("caller-handled ambient exception")
                        except ValueError:
                            invoke()
                    else:
                        invoke()
                    self.assertEqual(len(revocations), 1)

    def test_actual_primary_not_ambient_survives_finalizer_failure(self):
        for primary in (KeyboardInterrupt(), SystemExit(13)):
            with self.subTest(primary=type(primary)):
                revocations = []
                def revoke(capability):
                    revocations.append(capability)
                    raise OSError("secondary revoke")
                try:
                    raise ValueError("ambient")
                except ValueError:
                    with self.assertRaises(type(primary)) as caught:
                        self.raw_outcome(throwing(primary), revoke)
                self.assertIs(caught.exception, primary)
                self.assertEqual(len(revocations), 1)

    def test_exception_raised_inside_outcome_handler_is_primary_for_finalization(self):
        primary = KeyboardInterrupt()
        after_send, revocations = [], []
        original = subject._classify_transport_authority
        def send(prepared):
            after_send.append(True)
            raise RuntimeError("registered ordinary failure")
        def classify(transport):
            if after_send:
                raise primary
            return original(transport)
        def revoke(capability):
            revocations.append(capability)
            raise SystemExit(99)
        with patch.object(subject, "_classify_transport_authority", classify), counters() as trace:
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.raw_outcome(send, revoke)
        self.assertIs(caught.exception, primary)
        self.assertEqual(trace[-1][1], 4)
        self.assertEqual(len(revocations), 1)

    def test_break_and_continue_do_not_treat_ambient_exception_as_primary(self):
        for maximum in (1, 2):
            with self.subTest(maximum=maximum):
                sends, revocations = [], []
                failure = OSError("revoke must stop break or retry")
                def send(prepared):
                    sends.append(prepared)
                    raise RuntimeError("generic optional transport failure")
                def revoke(capability):
                    revocations.append(capability)
                    raise failure
                try:
                    raise ValueError("caller-handled ambient")
                except ValueError:
                    with self.assertRaises(OSError) as caught:
                        self.raw_outcome(send, revoke, settlement=None, maximum_attempts=maximum)
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(sends), 1)
                self.assertEqual(len(revocations), 1)
