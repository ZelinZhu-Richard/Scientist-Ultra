"""Portable synthetic PMC-outcome behavior controls."""

from types import FunctionType
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scientist_one import external as subject
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.scholarly_gateway import pmc_content_scholarly_egress_policy
from tests import pmc_wire_fixtures as _fixtures

fixtures = _fixtures
FixtureEnvironment = _fixtures.FixtureEnvironment
ComposedTransport = _fixtures.ComposedTransport
observed_counts = _fixtures.observed_counts
request = _fixtures.request

def execute_with_hooks(gateway, request, *, outcome_hook=None, count_hook=None):
    """TEST ONLY: wrap hidden callbacks, preserving real wrapper/row/raw execute.

    This is deliberate source/closure reconstruction, not production admission.
    No module binding, function or gateway instance is changed.
    """
    wrapper = subject.EgressGateway.execute
    original = fixtures.captured_cell(wrapper, "method")
    def method(self, request, **kwargs):
        for name, hook in (("_settle_pmc_outcome", outcome_hook), ("_settle_pmc_progress", count_hook)):
            if hook is not None:
                callback = kwargs[name]
                def intercepted(capability, callback=callback, hook=hook):
                    return hook(callback, capability)
                kwargs[name] = intercepted
        return original(self, request, **kwargs)
    def cell(value):
        return (lambda: value).__closure__[0]
    closure = tuple(cell(method) if name == "method" else old
                    for name, old in zip(wrapper.__code__.co_freevars, wrapper.__closure__))
    reconstructed = FunctionType(wrapper.__code__, wrapper.__globals__, wrapper.__name__, wrapper.__defaults__, closure)
    reconstructed.__kwdefaults__ = wrapper.__kwdefaults__
    return reconstructed(gateway, request)

def live_row(capability):
    admission = fixtures.captured_cell(subject._execute_pmc_coordinated_attempt, "admission")
    return fixtures.captured_cell(admission, "issued")[id(capability)]

class PmcOutcomeCandidateTests(unittest.TestCase):
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

    def run_gateway(self, **hooks):
        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            result = execute_with_hooks(gateway, fixtures.request(), **hooks)
        return result, transport, counts

    def test_complete_pair_is_settled_after_count_and_retained_until_cleanup(self):
        captured = []
        def settle(original, capability):
            before = live_row(capability)
            self.assertEqual(before[9], "SETTLED")
            self.assertEqual(before[11], 4)
            result = original(capability)
            captured.append(live_row(capability)[15])
            self.assertTrue(result)
            return result
        result, transport, counts = self.run_gateway(outcome_hook=settle)
        self.assertEqual(result.total_bytes_used, 4)
        self.assertEqual(counts[-1], 4)
        phase, pending, terminal, finalized, settled = captured[0]
        self.assertEqual((phase, finalized, settled), ("REQUIRED", True, True))
        self.assertEqual(dict(pending)["kind"], "PENDING")
        self.assertEqual(dict(terminal)["kind"], "LOCAL_CLOSED_COMPLETE")
        with self.assertRaises(KeyError):
            live_row(transport.prepared[0]._capability)

    def test_gateway_rejects_equal_body_and_count_without_required_witness(self):
        self.env.writer_hooks.update(pending=lambda original, record: None,
                                     terminal=lambda original, record: None,
                                     finalized=lambda original: None)
        driver, returned = self.env.driver, []
        def record_return(prepared, transport):
            value = driver(prepared, transport)
            returned.append(value)
            return value
        self.env.driver = record_return
        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError) as caught:
                gateway.execute(fixtures.request())
        self.assertEqual(counts[-1], 4)
        self.assertEqual([value.body for value in returned], [b"<x/>"])
        self.assertEqual(caught.exception.attempts[0]["status"], "TRANSPORT_FAILURE")
        self.assertIsNone(caught.exception.attempts[0]["raw_response_record_sha256"])
        self.assertFalse({record.logical_type for record in self.registry.list_records()} &
                         {"external_response_raw", "external_response_decoding", "external_response_receipt"})
        self.assertEqual(len(transport.prepared), 1)
        self.assertEqual(self.env.state()["terminal"]["kind"], "LOCAL_CLOSED_COMPLETE")
        self.assertEqual(self.env.connections[0].closes, 1)

    def test_gateway_rejects_normal_response_with_aborted_or_unfinalized_pair(self):
        for mode in ("aborted", "unfinalized"):
            with self.subTest(mode=mode):
                self.env.wires.append(self.env.wires[0] if self.env.wires else
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\n<x/>")
                self.env.writer_hooks.clear()
                if mode == "aborted":
                    self.env.writer_hooks["terminal"] = lambda original, record: original(dict(record, kind="LOCAL_CLOSED_ABORTED"))
                else:
                    self.env.writer_hooks["finalized"] = lambda original: None
                self.denied(count=4)

    def test_record_mutation_after_event_cannot_change_retained_primitives(self):
        originals = []
        def mutate(original, record):
            originals.append(dict(record))
            original(record)
            record.clear()
            record["kind"] = "NOT_SENT"
        self.env.writer_hooks.update(pending=mutate, terminal=mutate)
        result, _, _ = self.run_gateway()
        self.assertEqual(result.total_bytes_used, 4)
        snapshot = self.env.outcome_snapshots[-1]
        self.assertEqual(dict(snapshot[1]), originals[0])
        self.assertEqual(dict(snapshot[2]), originals[1])
        self.assertIs(type(snapshot[1]), tuple)

    def test_duplicate_pending_poison_is_sticky_without_undoing_operational_terminal(self):
        def duplicate(original, record):
            original(record)
            with self.assertRaises(subject.EgressDeniedError):
                original(record)
        self.env.writer_hooks["pending"] = duplicate
        self.denied(count=4)  # Swallowed fixture misuse reaches normal response, never acceptance.
        self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")
        self.assertTrue(self.env.outcome_snapshots[-1][3])

    def test_pending_writer_failure_does_not_suppress_guarded_not_sent_or_close(self):
        def fail(original, record):
            raise OSError("fixture writer failure")
        self.env.writer_hooks["pending"] = fail
        self.denied()
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")
        self.assertEqual([e for e in self.env.events if e[0] == "terminal"], [("terminal", "NOT_SENT")])
        self.assertTrue(self.env.outcome_snapshots[-1][3])
        self.assertEqual(self.env.connections, [])

    def test_terminal_writer_failure_never_repeats_publication(self):
        def fail(original, record):
            raise OSError("fixture terminal writer failure")
        self.env.writer_hooks["terminal"] = fail
        self.denied(count=4)
        self.assertEqual([e for e in self.env.events if e[0] == "terminal"], [("terminal", "LOCAL_CLOSED_COMPLETE")])
        self.assertTrue(self.env.outcome_snapshots[-1][3])

    def test_finalization_only_prefix_is_known_but_not_complete(self):
        self.env.acquire_error = OSError("fixture acquisition")
        observed = []
        def settle(original, capability):
            result = original(capability)
            observed.append(live_row(capability)[15])
            return result
        with self.assertRaises(subject.EgressDeniedError):
            self.run_gateway(outcome_hook=settle)
        self.assertEqual(observed, [("REQUIRED", None, None, True, True)])

    def test_raising_close_cannot_record_finalization(self):
        self.env.native_close_error = OSError("fixture finalization")
        observed = []
        def settle(original, capability):
            value = original(capability)
            observed.append(live_row(capability)[15])
            return value
        with self.assertRaises(subject.EgressDeniedError):
            self.run_gateway(outcome_hook=settle)
        self.assertFalse(observed[0][3])
        self.assertIsNotNone(observed[0][2])

    def test_duplicate_finalization_and_later_writers_poison_eligibility(self):
        def duplicate(original):
            original()
            with self.assertRaises(subject.EgressDeniedError):
                original()
            with self.assertRaises(subject.EgressDeniedError):
                self.env.writer_bundles[-1][0]({})
        self.env.writer_hooks["finalized"] = duplicate
        self.denied(count=4)
        self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")
        self.assertTrue(self.env.outcome_snapshots[-1][3])

    def test_records_reject_exact_shape_scalar_and_temporal_errors(self):
        changes = ({"sequence": True}, {"attempt_number": 2}, {"request_id": "f" * 64},
                   {"policy_claim_sha256": "f" * 64}, {"prepared_claim_sha256": "f" * 64},
                   {"boot_uuid": "12345678-1234-4234-8234-123456789abc"},
                   {"observed_ns": (1 << 63)}, {"deadline_seconds": float("inf")},
                   {"unknown": 0})
        for change in changes:
            with self.subTest(change=change):
                self.setUp()  # A fresh actual row/store per malformed first event.
                def invalid(original, record):
                    with self.assertRaises(subject.EgressDeniedError):
                        original(dict(record, **change))
                    with self.assertRaises(subject.EgressDeniedError):
                        original(record)
                self.env.writer_hooks["pending"] = invalid
                self.denied(count=4)
                self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")

    def test_terminal_temporal_and_same_pending_bindings_are_enforced(self):
        for field in ("sequence", "boot_uuid", "observed_ns", "cleanup_ns"):
            with self.subTest(field=field):
                self.setUp()
                def invalid(original, record):
                    changed = dict(record)
                    changed[field] = (record[field] + 1 if field == "sequence" else
                                      b"34567890-3456-4456-8456-34567890abcd" if field == "boot_uuid" else 0)
                    original(changed)
                self.env.writer_hooks["terminal"] = invalid
                self.denied(count=4)
                self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")

    def test_stale_prior_attempt_terminal_cannot_complete_a_new_invocation(self):
        self.env.wires *= 2
        self.run_gateway()
        stale = dict(next(args[0] for name, args in self.env.writer_calls if name == "terminal"))
        def stale_terminal(original, record):
            original(stale)
        self.env.writer_hooks["terminal"] = stale_terminal
        self.denied(count=4)
        self.assertEqual(self.env.state()["sequence"], 2)
        self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")

    def test_duplicate_admission_poison_is_sticky_without_replacing_count_state(self):
        admission = fixtures.captured_cell(subject._execute_pmc_coordinated_attempt, "admission")
        gateway, transport = self.gateway()
        def duplicate(original, record):
            original(record)
            prepared = transport.prepared[-1]
            before_progress = live_row(prepared._capability)[9:12]
            with self.assertRaises(subject.EgressDeniedError):
                admission(prepared, transport)
            self.assertEqual(live_row(prepared._capability)[9:12], before_progress)
        self.env.writer_hooks["pending"] = duplicate
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                gateway.execute(fixtures.request())
        self.assertEqual(counts[-1], 4)
        self.assertEqual(self.env.outcome_snapshots[-1][0], "UNKNOWN")

    def test_equal_content_invocations_get_distinct_bound_sequences(self):
        self.env.wires *= 2
        one, t1, _ = self.run_gateway()
        two, t2, _ = self.run_gateway()
        self.assertEqual(one.request_id, two.request_id)
        self.assertEqual(t1.prepared[0].attempt_number, t2.prepared[0].attempt_number)
        pending = [args[0] for name, args in self.env.writer_calls if name == "pending"]
        self.assertEqual([p["sequence"] for p in pending], [1, 2])
        with self.assertRaises(subject.EgressDeniedError):
            self.env.writer_bundles[0][0](pending[1])

    def test_nonexact_containers_keys_and_scalars_are_not_coerced(self):
        class DictSubclass(dict):
            pass
        class StringSubclass(str):
            pass
        class Bomb:
            def __str__(self):
                raise AssertionError("supplied object coerced")
        for mode in ("dict", "key", "hash"):
            with self.subTest(mode=mode):
                self.setUp()
                def invalid(original, record):
                    changed = DictSubclass(record) if mode == "dict" else dict(record)
                    if mode == "key":
                        changed[Bomb()] = changed.pop("kind")
                    elif mode == "hash":
                        changed["request_id"] = StringSubclass(record["request_id"])
                    original(changed)
                self.env.writer_hooks["pending"] = invalid
                self.denied()
                self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")

    def test_post_pending_expiry_keeps_operational_not_sent_but_incomplete_handoff(self):
        coordination = fixtures.coordination
        original = coordination._PmcCoordinationStore._commit
        def commit(store, payload):
            original(store, payload)
            if payload["phase"] == "PENDING":
                self.env.expired = True
        seen = []
        def settle(original, capability):
            result = original(capability)
            seen.append(live_row(capability)[15])
            return result
        with patch.object(coordination._PmcCoordinationStore, "_commit", commit), \
                patch.object(coordination._PmcCoordinationStore, "read_snapshot", side_effect=AssertionError("expired recovery")):
            with self.assertRaises(subject.EgressDeniedError):
                self.run_gateway(outcome_hook=settle)
        self.assertEqual(self.env.state()["terminal"]["kind"], "NOT_SENT")
        self.assertIsNone(seen[0][1])
        self.assertIsNone(seen[0][2])
        self.assertTrue(seen[0][3])
        self.assertNotEqual(seen[0][0], "OPTIONAL")

    def test_status_retry_has_distinct_join_and_missing_second_witness_is_terminal(self):
        self.env.wires = [b"HTTP/1.1 500 Error\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\nfail",
                          b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4\r\n\r\n<x/>"]
        def terminal(original, record):
            if record["attempt_number"] == 1:
                original(record)
        self.env.writer_hooks["terminal"] = terminal
        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                gateway.execute(fixtures.request())
        self.assertEqual(counts[-1], 8)
        self.assertEqual(len(transport.prepared), 2)
        pending = [args[0] for name, args in self.env.writer_calls if name == "pending"]
        self.assertEqual([(p["sequence"], p["attempt_number"]) for p in pending], [(1, 1), (2, 2)])

    def test_required_outcome_cannot_fill_an_absent_count(self):
        gateway, _ = self.gateway()
        def drop_count(original, capability):
            self.assertEqual(original(capability), 4)
            return None
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject._PmcProgressAccountingError):
                execute_with_hooks(gateway, fixtures.request(), count_hook=drop_count)
        self.assertEqual(counts[-1], 0)  # Unknown bridge evidence is not reconstructed from body/outcome.

    def test_outcome_cancellation_cannot_mask_earlier_ordinary_transport_failure(self):
        self.env.terminal_error = OSError("earlier operational failure")
        def later(original, capability):
            original(capability)
            raise SystemExit(71)
        gateway, transport = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(subject.EgressDeniedError):
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=later)
        self.assertEqual(counts[-1], 4)
        self.assertEqual(len(transport.prepared), 1)

    def test_same_cancellation_survives_later_outcome_failure(self):
        primary = KeyboardInterrupt()
        self.env.terminal_error = primary
        def later(original, capability):
            original(capability)
            raise SystemExit(72)
        gateway, _ = self.gateway()
        with self.env.active(), fixtures.observed_counts() as counts:
            with self.assertRaises(KeyboardInterrupt) as caught:
                execute_with_hooks(gateway, fixtures.request(), outcome_hook=later)
        self.assertIs(caught.exception, primary)
        self.assertEqual(counts[-1], 4)

    def test_settlement_is_once_and_post_settlement_writers_cannot_change_facts(self):
        def settle(original, capability):
            self.assertTrue(original(capability))
            before = live_row(capability)[15]
            with self.assertRaises(subject.EgressDeniedError):
                original(capability)
            with self.assertRaises(subject.EgressDeniedError):
                self.env.writer_bundles[-1][2]()
            self.assertEqual(live_row(capability)[15], before)
            return True
        self.assertEqual(self.run_gateway(outcome_hook=settle)[0].total_bytes_used, 4)
