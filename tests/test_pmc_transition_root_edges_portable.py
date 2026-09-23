"""Portable supplied-data PMC trace root edges."""

import copy
import unittest

from scientist_one import pmc_coordination as subject

SPACING = 333_333_334
MAX_NS = (1 << 63) - 1
BOOT = b"12345678-1234-4234-8234-123456789abc"
COORDINATOR = b"abcdefab-cdef-4abc-8def-abcdefabcdef"

def anchor():
    return {
        "schema": "pmc-supplied-coordination-trace/v1",
        "coordinator_uuid": COORDINATOR, "boot_uuid": BOOT,
        "initialized_ns": 1000, "initial_sequence": 0,
    }

def pending(sequence=1, observed=1100, *, attempt=1, deadline=1.0):
    return {
        "kind": "PENDING", "coordinator_uuid": COORDINATOR, "boot_uuid": BOOT,
        "sequence": sequence, "request_id": "a" * 64,
        "prepared_claim_sha256": f"{sequence:064x}", "policy_claim_sha256": "b" * 64,
        "attempt_number": attempt, "observed_ns": observed,
        "deadline_seconds": deadline,
    }

def terminal(start, *, kind="LOCAL_CLOSED_COMPLETE", observed=1300, cleanup=1200):
    result = {key: value for key, value in start.items() if key != "deadline_seconds"}
    result.update(kind=kind, observed_ns=observed)
    if kind != "NOT_SENT":
        result["cleanup_ns"] = cleanup
    return result

class RootPmcTraceEdgeTests(unittest.TestCase):
    def project(self, records=(), **kwargs):
        initial = anchor()
        before = copy.deepcopy((initial, records, kwargs))
        try:
            return subject._project_pmc_coordination_trace(initial, records, **kwargs)
        finally:
            self.assertEqual((initial, records, kwargs), before)

    def reject(self, records, **kwargs):
        with self.assertRaises(subject._PmcTraceProjectionError):
            self.project(records, **kwargs)

    def test_too_early_pending_refuses_even_with_ample_remaining_deadline(self):
        first = pending()
        closed = terminal(first)
        too_early = pending(2, 1200 + SPACING - 1)
        self.reject((first, closed, too_early))
        exact = pending(2, 1200 + SPACING)
        result = self.project((first, closed, exact))
        self.assertEqual((result.committed_phase, result.pending_sequence), ("PENDING", 2))
        self.assertTrue(result.continuation_blocked)

    def test_same_content_can_start_at_attempt_one_in_a_new_execution(self):
        first = pending(attempt=1)
        second = pending(2, 1200 + SPACING, attempt=1)
        self.assertEqual(first["request_id"], second["request_id"])
        result = self.project((first, terminal(first), second))
        self.assertEqual(result.last_sequence, 2)
        self.assertEqual(result.pending_sequence, 2)

    def test_not_sent_chain_never_fabricates_a_cleanup(self):
        records = []
        for sequence in range(1, 4):
            start = pending(sequence, 1000 + sequence * 10)
            records.extend((start, terminal(start, kind="NOT_SENT", observed=start["observed_ns"])))
        result = self.project(tuple(records))
        self.assertEqual((result.committed_phase, result.last_sequence), ("QUIESCENT", 3))
        self.assertIsNone(result.last_cleanup_ns)
        self.assertFalse(result.continuation_blocked)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_COORDINATION_TRACE")

    def test_not_sent_chain_retains_last_real_cleanup_floor(self):
        first = pending()
        second = pending(2, 1200 + SPACING)
        third = pending(3, 1200 + SPACING)
        records = (first, terminal(first), second,
                   terminal(second, kind="NOT_SENT", observed=second["observed_ns"]), third,
                   terminal(third, kind="NOT_SENT", observed=third["observed_ns"]))
        result = self.project(records)
        self.assertEqual(result.last_cleanup_ns, 1200)
        self.assertEqual(result.last_sequence, 3)
        self.assertFalse(result.continuation_blocked)

    def test_late_aborted_cleanup_remains_an_operational_not_content_fact(self):
        first = pending(deadline=1.0)
        late = terminal(first, kind="LOCAL_CLOSED_ABORTED", cleanup=1_000_000_010,
                        observed=1_000_000_020)
        result = self.project((first, late))
        self.assertEqual(result.last_cleanup_ns, 1_000_000_010)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_COORDINATION_TRACE")
        next_start = pending(2, 1_000_000_010 + SPACING, deadline=2.0)
        self.assertEqual(self.project((first, late, next_start)).pending_sequence, 2)

    def test_missing_terminal_and_timeout_label_cannot_clear_pending(self):
        first = pending()
        result = self.project((first,))
        self.assertTrue(result.continuation_blocked)
        timeout = terminal(first, kind="TIMEOUT", observed=2_000_000_000)
        self.reject((first, timeout))

    def test_uncertain_commit_keeps_known_prefix_separate_and_blocks(self):
        quiet = self.project(uncertain_commit="PENDING")
        self.assertEqual(quiet.committed_phase, "QUIESCENT")
        self.assertEqual(quiet.last_sequence, 0)
        self.assertIsNone(quiet.pending_sequence)
        self.assertTrue(quiet.continuation_blocked)
        active = self.project((pending(),), uncertain_commit="TERMINAL")
        self.assertEqual(active.committed_phase, "PENDING")
        self.assertEqual(active.pending_sequence, 1)
        self.assertTrue(active.continuation_blocked)
        self.reject((), uncertain_commit="TERMINAL")
        self.reject((pending(),), uncertain_commit="PENDING")
        self.reject((), uncertain_commit=False)

    def test_old_terminal_replay_never_clears_a_later_pending(self):
        first = pending()
        closed = terminal(first)
        second = pending(2, 1200 + SPACING)
        self.reject((first, closed, copy.deepcopy(closed)))
        self.reject((first, closed, second, copy.deepcopy(closed)))

    def test_terminal_requires_all_exact_pending_bindings(self):
        first = pending()
        for field, value in (("sequence", 2), ("request_id", "c" * 64),
                             ("prepared_claim_sha256", "d" * 64),
                             ("policy_claim_sha256", "e" * 64), ("attempt_number", 2)):
            with self.subTest(field=field):
                changed = terminal(first)
                changed[field] = value
                self.reject((first, changed))

    def test_declared_pending_cannot_extend_float_deadline_by_rounding(self):
        self.reject((pending(observed=299_999_999, deadline=0.3),))
        result = self.project((pending(observed=299_999_998, deadline=0.3),))
        self.assertEqual(result.pending_sequence, 1)

    def test_no_pending_blocker_is_not_a_claim_of_feasible_future_timing(self):
        first = pending()
        last = terminal(first, cleanup=MAX_NS, observed=MAX_NS)
        result = self.project((first, last))
        self.assertFalse(result.continuation_blocked)
        self.assertEqual(result.last_cleanup_ns, MAX_NS)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_COORDINATION_TRACE")
        self.reject((first, last, pending(2, MAX_NS, deadline=9223372036.854774)))

    def test_mutation_and_unknown_success_fields_are_not_shortcuts(self):
        first = pending()
        claimed = terminal(first)
        claimed["cleanup_success"] = True
        self.reject((first, claimed))
        wrong_boot = terminal(first)
        wrong_boot["boot_uuid"] = COORDINATOR
        self.reject((first, wrong_boot))
