"""Portable synthetic PMC-attempt behavior controls."""

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one import pmc_coordination as coordination
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.scholarly_gateway import pmc_content_scholarly_egress_policy
from tests import pmc_wire_fixtures as _fixtures

FixtureEnvironment = _fixtures.FixtureEnvironment
ComposedTransport = _fixtures.ComposedTransport
observed_counts = _fixtures.observed_counts
request = _fixtures.request

class PmcAttemptCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="pmc-composition-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "artifacts").mkdir()
        self.registry = ArtifactRegistry(root / "artifacts")
        self.env = FixtureEnvironment(root / "store")
        self.addCleanup(self.env.cleanup)

    def gateway(self, *, before=None):
        transport = ComposedTransport(self.env, before)
        return subject.EgressGateway(pmc_content_scholarly_egress_policy(maximum_attempts=2), transport,
                                     registry=self.registry), transport

    def denied(self, *, count=0):
        gateway, transport = self.gateway()
        with self.env.active(), observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError) as caught:
                gateway.execute(request())
        self.assertEqual(counts[-1], count)
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(gateway._request_count, 1)
        return caught.exception

    def test_complete_ordered_attempt_uses_real_store_and_lifecycle(self):
        gateway, transport = self.gateway()
        with self.env.active():
            result = gateway.execute(request())
        self.assertEqual(result.total_bytes_used, 4)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertEqual(self.env.state()["phase"], "QUIESCENT")
        events = [event[0] for event in self.env.events]
        self.assertLess(events.index("register"), events.index("acquire"))
        self.assertLess(events.index("confirm"), events.index("tls"))
        self.assertLess(events.index("connection-close"), events.index("terminal"))
        self.assertEqual(len(self.env.contexts), 4)  # Initial + preconstruction + BOTH pre-request checks.
        self.assertTrue(all(context.closed for context in self.env.contexts))
        self.assertEqual(self.env.connections[0].requests[0][2], None)
        self.assertEqual(self.env.connections[0].requests[0][3]["Accept-Encoding"], "identity")
        self.assertEqual(self.env.state()["pending"]["policy_claim_sha256"],
                         subject._safe_hash(subject.canonical_json_bytes(subject._egress_policy_claim(gateway.policy))))
        self.assertIsNone(result.transport_execution_authority_artifact)
        self.assertEqual(len(transport.prepared), 1)

    def test_acquisition_failure_happens_after_registration_and_cannot_retry(self):
        self.env.acquire_error = OSError("inert acquisition failure")
        self.denied()
        self.assertEqual(len(self.env.registered), 1)
        self.assertEqual(self.env.connections, [])
        self.assertEqual(self.env.state()["sequence"], 0)

    def test_original_deadline_comes_from_row_not_mutated_private_dto(self):
        original = []
        def mutate(prepared):
            original.append(prepared._deadline_monotonic)
            object.__setattr__(prepared, "_deadline_monotonic", float("inf"))
        gateway, _ = self.gateway(before=mutate)
        with self.env.active():
            self.assertEqual(gateway.execute(request()).total_bytes_used, 4)
        self.assertEqual(self.env.deadlines, original)
        self.assertEqual(float.fromhex(self.env.state()["pending"]["deadline_seconds"]), original[0])

    def test_fresh_namespace_identity_and_boot_mismatch_prevent_construction(self):
        self.env.changed[2] = {"_boot_session_uuid": b"34567890-3456-4456-8456-34567890abcd"}
        self.denied()
        self.assertEqual(self.env.connections, [])
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")

    def test_fresh_component_chain_mismatch_is_not_hidden_by_same_boot(self):
        self.env.changed[2] = {"_native_home": "/different-fixture-home"}
        self.denied()
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")
        self.assertEqual(self.env.connections, [])

    def test_preconstruction_schedule_refusal_preserves_cleanup_floor(self):
        self.env.blocked.add(2)
        self.denied()
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")
        self.assertIsNone(self.env.state()["last_cleanup_ns"])
        self.assertEqual(self.env.connections, [])

    def test_both_pre_request_callbacks_refresh_schedule(self):
        self.env.blocked.add(4)
        self.denied()
        self.assertEqual(len(self.env.contexts), 4)
        self.assertEqual(self.env.connections[0].requests, [])
        self.assertEqual(self.env.connections[0].closes, 1)
        self.assertEqual(self.env.state()["phase"], "PENDING")

    def test_post_request_callback_does_not_apply_mid_response_schedule_gate(self):
        self.env.blocked.update(range(5, 100))
        gateway, _ = self.gateway()
        with self.env.active():
            gateway.execute(request())
        self.assertEqual(len(self.env.contexts), 4)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")

    def test_constructor_delay_cannot_reuse_preconstruction_schedule(self):
        self.env.after_constructor = lambda: self.env.blocked.add(3)
        self.denied()
        self.assertEqual(self.env.connections[0].requests, [])
        self.assertEqual(self.env.state()["phase"], "PENDING")

    def test_unknown_constructor_retains_pending_without_no_send_inference(self):
        self.env.constructor_error = OSError("unreturned constructor fixture")
        self.denied()
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertIsNone(self.env.state()["terminal"])

    def test_short_frame_closes_and_commits_aborted_with_exact_gateway_count(self):
        self.env.wires = [b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc"]
        self.denied(count=3)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_ABORTED")

    def test_terminal_failure_retains_pending_and_cannot_return_content(self):
        self.env.terminal_error = OSError("inert terminal failure")
        self.denied(count=4)
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertEqual(self.env.connections[0].closes, 1)

    def test_terminal_readback_failure_refuses_even_if_quiescent_was_written(self):
        self.env.confirm_error = "LOCAL_CLOSED_COMPLETE"
        self.denied(count=4)
        self.assertEqual(self.env.state()["phase"], "QUIESCENT")

    def test_finalizer_failure_cannot_return_content_under_ambient_exception(self):
        self.env.native_close_error = OSError("inert close failure")
        try:
            raise ValueError("ambient caller exception")
        except ValueError:
            self.denied(count=4)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")

    def test_cancellation_retains_count_through_terminal_and_context_failures(self):
        primary = KeyboardInterrupt()
        self.env.terminal_error = OSError("secondary terminal")
        self.env.native_close_error = SystemExit(21)
        original = subject._PmcFramedResponseReader.read
        def cancel(reader):
            original(reader)
            raise primary
        gateway, _ = self.gateway()
        with self.env.active(), patch.object(subject._PmcFramedResponseReader, "read", cancel), observed_counts() as counts:
            with self.assertRaises(KeyboardInterrupt) as caught:
                gateway.execute(request())
        self.assertIs(caught.exception, primary)
        self.assertEqual(counts[-1], 4)
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertTrue(all(context.closed for context in self.env.contexts))

    def test_observation_close_failure_cannot_admit_construction(self):
        self.env.close_errors[2] = OSError("fresh observation close failure")
        self.denied()
        self.assertEqual(self.env.connections, [])
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")

    def test_pending_readback_failure_is_not_repaired_into_no_send(self):
        self.env.confirm_error = "PENDING"
        self.denied()
        self.assertEqual(self.env.state()["phase"], "PENDING")
        self.assertEqual(self.env.connections, [])

    def test_expiry_after_pending_commit_uses_guarded_no_send_without_snapshot(self):
        original = coordination._PmcCoordinationStore._commit
        def commit(store, payload):
            original(store, payload)
            if payload["phase"] == "PENDING":
                self.env.expired = True
        with patch.object(coordination._PmcCoordinationStore, "_commit", commit), \
                patch.object(coordination._PmcCoordinationStore, "read_snapshot", side_effect=AssertionError("forbidden recovery")):
            self.denied()
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")
        self.assertIsNone(self.env.state()["last_cleanup_ns"])
        self.assertEqual(self.env.connections, [])

    def test_expiry_before_pending_has_no_terminal_or_construction(self):
        self.env.expired = True
        self.denied()
        self.assertEqual(self.env.state()["sequence"], 0)
        self.assertIsNone(self.env.state()["terminal"])
        self.assertEqual(self.env.connections, [])

    def test_second_http_status_attempt_waits_after_cleanup_under_same_deadline(self):
        self.env.wires = [b"HTTP/1.1 500 Error\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\nfail",
                          b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\n<x/>"]
        gateway, transport = self.gateway()
        with self.env.active():
            result = gateway.execute(request())
        self.assertEqual(result.total_bytes_used, 8)
        self.assertEqual(len(transport.prepared), 2)
        self.assertEqual(self.env.deadlines[0], self.env.deadlines[1])
        state = self.env.state()
        self.assertEqual(state["sequence"], 2)
        self.assertGreaterEqual(state["pending"]["observed_ns"] - state["predecessor"]["cleanup_ns"], 333_333_334)

    def test_actual_strict_entry_rejects_consumed_fixture_without_native_acquisition(self):
        self.env.driver = subject._execute_pmc_coordinated_attempt
        gateway, transport = self.gateway()
        with self.assertRaises(subject.EgressDeniedError):
            gateway.execute(request())
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.events, [])
        self.assertEqual(self.env.state()["sequence"], 0)
