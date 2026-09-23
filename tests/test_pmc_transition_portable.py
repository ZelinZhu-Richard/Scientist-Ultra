"""Portable supplied-data PMC trace-projection controls."""

import copy
from dataclasses import FrozenInstanceError, fields
import unittest
from unittest.mock import patch

from scientist_one import pmc_coordination as subject

BOOT = b"12345678-1234-4234-8234-123456789abc"
COORDINATOR = b"23456789-2345-4345-8345-23456789abcd"
SPACING = 333_333_334
MAX_NS = (1 << 63) - 1

def anchor(**changes):
    value = {
        "schema": "pmc-supplied-coordination-trace/v1",
        "coordinator_uuid": COORDINATOR,
        "boot_uuid": BOOT,
        "initialized_ns": 0,
        "initial_sequence": 0,
    }
    value.update(changes)
    return value

def pending(sequence=1, observed_ns=0, **changes):
    value = {
        "kind": "PENDING", "coordinator_uuid": COORDINATOR, "boot_uuid": BOOT,
        "sequence": sequence, "request_id": "a" * 64,
        "prepared_claim_sha256": "b" * 64, "policy_claim_sha256": "c" * 64,
        "attempt_number": 1, "observed_ns": observed_ns, "deadline_seconds": 10.0,
    }
    value.update(changes)
    return value

def terminal(prior, kind="NOT_SENT", observed_ns=None, **changes):
    value = {key: item for key, item in prior.items() if key != "deadline_seconds"}
    value["kind"] = kind
    value["observed_ns"] = prior["observed_ns"] if observed_ns is None else observed_ns
    if kind in {"LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED"}:
        value["cleanup_ns"] = value["observed_ns"]
    value.update(changes)
    return value

class PmcTraceCandidateTests(unittest.TestCase):
    def project(self, records=(), *, initial=None, uncertain_commit=None):
        initial = anchor() if initial is None else initial
        original_anchor, original_records = copy.deepcopy(initial), copy.deepcopy(records)
        result = subject._project_pmc_coordination_trace(
            initial, records, uncertain_commit=uncertain_commit,
        )
        self.assertEqual(initial, original_anchor)
        self.assertEqual(records, original_records)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_COORDINATION_TRACE")
        return result

    def reject(self, records=(), *, initial=None, uncertain_commit=None):
        initial = anchor() if initial is None else initial
        with self.assertRaises(subject._PmcTraceProjectionError) as caught:
            subject._project_pmc_coordination_trace(
                initial, records, uncertain_commit=uncertain_commit,
            )
        self.assertRegex(str(caught.exception), r"^PMC_TRACE_[A-Z_]+$")

    def test_explicit_anchor_has_no_invented_cleanup_and_frozen_output(self):
        result = self.project(initial=anchor(initialized_ns=99))
        self.assertEqual(tuple(field.name for field in fields(result)), (
            "classification", "committed_phase", "last_sequence", "pending_sequence",
            "last_cleanup_ns", "last_observed_ns", "uncertain_commit", "continuation_blocked",
        ))
        self.assertEqual((result.committed_phase, result.last_sequence), ("QUIESCENT", 0))
        self.assertIsNone(result.pending_sequence)
        self.assertIsNone(result.last_cleanup_ns)
        self.assertEqual(result.last_observed_ns, 99)
        self.assertFalse(result.continuation_blocked)
        with self.assertRaises(FrozenInstanceError):
            result.continuation_blocked = True
        self.reject(initial={})

    def test_first_pending_does_not_fabricate_spacing_from_initialization(self):
        result = self.project((pending(observed_ns=100),), initial=anchor(initialized_ns=100))
        self.assertEqual(result.pending_sequence, 1)
        self.assertTrue(result.continuation_blocked)
        self.assertIsNone(result.last_cleanup_ns)
        self.reject((pending(observed_ns=99),), initial=anchor(initialized_ns=100))

    def test_not_sent_chain_retains_initial_condition(self):
        first, second, third = pending(1), pending(2, 1), pending(3, 2)
        result = self.project((first, terminal(first), second, terminal(second), third))
        self.assertEqual(result.last_sequence, 3)
        self.assertIsNone(result.last_cleanup_ns)
        self.assertEqual(result.last_observed_ns, 2)

    def test_complete_and_aborted_share_spacing_but_have_no_content_authority(self):
        for kind in ("LOCAL_CLOSED_COMPLETE", "LOCAL_CLOSED_ABORTED"):
            with self.subTest(kind=kind):
                first = pending()
                closed = terminal(first, kind, 10, cleanup_ns=7)
                result = self.project((first, closed))
                self.assertEqual((result.committed_phase, result.last_cleanup_ns), ("QUIESCENT", 7))
                self.assertEqual(result.last_observed_ns, 10)
                self.assertFalse(result.continuation_blocked)
                self.assertFalse(hasattr(result, "scientific_evidence"))
                self.project((first, closed, pending(2, 7 + SPACING)))
                self.reject((first, closed, pending(2, 7 + SPACING - 1)))

    def test_not_sent_after_cleanup_preserves_actual_cleanup_floor(self):
        first = pending()
        second = pending(2, SPACING + 10)
        records = (
            first, terminal(first, "LOCAL_CLOSED_ABORTED", 10),
            second, terminal(second, observed_ns=SPACING + 11),
        )
        result = self.project(records)
        self.assertEqual(result.last_cleanup_ns, 10)
        self.project((*records, pending(3, SPACING + 11)))

    def test_late_cleanup_is_recorded_without_deadline_extension(self):
        first = pending(deadline_seconds=1e-9)
        closed = terminal(first, "LOCAL_CLOSED_ABORTED", 900, cleanup_ns=800)
        result = self.project((first, closed))
        self.assertEqual(result.last_cleanup_ns, 800)
        self.project((first, closed, pending(2, 800 + SPACING)))
        self.assertEqual(first["deadline_seconds"], 1e-9)

    def test_pending_deadline_uses_exact_float_floor_and_strict_comparison(self):
        self.project((pending(observed_ns=299_999_998, deadline_seconds=0.3),))
        self.reject((pending(observed_ns=299_999_999, deadline_seconds=0.3),))
        self.reject((pending(deadline_seconds=0.0),))
        self.reject((pending(deadline_seconds=1),))

    def test_repeated_request_id_does_not_require_global_retry_number_increase(self):
        first = pending(attempt_number=7)
        second = pending(2, 1, attempt_number=1)
        result = self.project((first, terminal(first), second, terminal(second)))
        self.assertEqual(result.last_sequence, 2)
        self.assertFalse(result.continuation_blocked)
        self.assertEqual(first["request_id"], second["request_id"])

    def test_terminals_bind_every_current_pending_identity(self):
        first = pending()
        for key, value in (
            ("request_id", "d" * 64), ("prepared_claim_sha256", "d" * 64),
            ("policy_claim_sha256", "d" * 64), ("attempt_number", 2),
            ("sequence", 2), ("coordinator_uuid", BOOT), ("boot_uuid", COORDINATOR),
        ):
            with self.subTest(key=key):
                self.reject((first, terminal(first, **{key: value})))

    def test_sequence_gaps_duplicate_terminals_and_nested_pending_are_rejected(self):
        first, second = pending(), pending(2)
        closed = terminal(first)
        for records in (
            (pending(2),), (first, second), (closed,), (first, closed, closed),
            (first, closed, pending(3)), (first, closed, second, closed),
        ):
            with self.subTest(kinds=tuple(value["kind"] for value in records)):
                self.reject(records)

    def test_observation_and_cleanup_order_are_independent(self):
        first = pending(observed_ns=10)
        self.reject((first, terminal(first, observed_ns=9)))
        self.reject((first, terminal(first, "LOCAL_CLOSED_COMPLETE", 20, cleanup_ns=9)))
        self.reject((first, terminal(first, "LOCAL_CLOSED_COMPLETE", 20, cleanup_ns=21)))
        self.project((first, terminal(first, "LOCAL_CLOSED_COMPLETE", 20, cleanup_ns=10)))

    def test_late_int64_cleanup_cannot_wrap_into_new_allowance(self):
        first = pending()
        closed = terminal(first, "LOCAL_CLOSED_ABORTED", MAX_NS)
        self.assertEqual(self.project((first, closed)).last_cleanup_ns, MAX_NS)
        self.reject((first, closed, pending(2, MAX_NS, deadline_seconds=1.0)))

    def test_uncertain_suffix_is_not_a_committed_record_and_matches_phase(self):
        uncertain_pending = self.project(uncertain_commit="PENDING")
        self.assertEqual(uncertain_pending.committed_phase, "QUIESCENT")
        self.assertEqual(uncertain_pending.last_sequence, 0)
        self.assertTrue(uncertain_pending.continuation_blocked)
        first = pending()
        uncertain_terminal = self.project((first,), uncertain_commit="TERMINAL")
        self.assertEqual(uncertain_terminal.pending_sequence, 1)
        self.assertTrue(uncertain_terminal.continuation_blocked)
        self.assertTrue(self.project((first,)).continuation_blocked)
        self.reject(uncertain_commit="TERMINAL")
        self.reject((first,), uncertain_commit="PENDING")
        for value in (True, b"PENDING", "UNKNOWN", "x" * 100):
            self.reject(uncertain_commit=value)

    def test_exact_container_and_key_grammar_has_no_silent_extensions(self):
        first = pending()
        for value in ([], [first], (first,) * 257):
            self.reject(value)
        for record in (
            {**first, "extra": 1}, {key: value for key, value in first.items() if key != "request_id"},
            {**first, "kind": "UNKNOWN"}, {**terminal(first), "cleanup_ns": 0},
            {**terminal(first, "LOCAL_CLOSED_COMPLETE"), "deadline_seconds": 10.0},
        ):
            self.reject((record,))
        for change in ({"extra": 1}, {"initial_sequence": True}, {"initial_sequence": 1},
                       {"schema": "unknown"}, {"initialized_ns": -1}):
            self.reject(initial=anchor(**change))

    def test_exact_scalar_bounds_and_identity_syntax(self):
        class IntegerSubclass(int):
            pass

        for key in ("sequence", "attempt_number", "observed_ns"):
            for value in (True, 1.0, IntegerSubclass(1), -1, MAX_NS + 1):
                with self.subTest(key=key, value_type=type(value).__name__):
                    self.reject((pending(**{key: value}),))
        for key in ("request_id", "prepared_claim_sha256", "policy_claim_sha256"):
            for value in ("A" * 64, "a" * 63, b"a" * 64):
                self.reject((pending(**{key: value}),))
        for value in (BOOT.upper(), b"00000000-0000-0000-0000-000000000000", BOOT.decode()):
            self.reject(initial=anchor(boot_uuid=value))
        self.reject((pending(boot_uuid=COORDINATOR),))

    def test_record_limit_accepts_256_without_becoming_a_runtime_quota(self):
        records = []
        for sequence in range(1, 129):
            first = pending(sequence, sequence)
            records.extend((first, terminal(first)))
        result = self.project(tuple(records))
        self.assertEqual(result.last_sequence, 128)
        self.assertIsNone(result.last_cleanup_ns)
        self.reject((*records, pending(129, 129)))

    def test_bad_suffix_returns_no_prefix_and_leaves_inputs_unchanged(self):
        first = pending()
        records = (first, terminal(first), pending(3))
        initial = anchor()
        before = copy.deepcopy((initial, records))
        self.reject(records, initial=initial)
        self.assertEqual((initial, records), before)

    def test_untrusted_objects_and_container_subclasses_are_not_coerced(self):
        class Poison:
            __hash__ = object.__hash__

            def __eq__(self, other):
                raise AssertionError("unexpected equality")

            def __str__(self):
                raise AssertionError("unexpected string conversion")

            def __len__(self):
                raise AssertionError("unexpected length")

        class DictSubclass(dict):
            def __len__(self):
                raise AssertionError("unexpected container access")

        class TupleSubclass(tuple):
            def __len__(self):
                raise AssertionError("unexpected container access")

        self.reject(initial=DictSubclass(anchor()))
        self.reject(TupleSubclass())
        self.reject((DictSubclass(pending()),))
        value = Poison()
        for key in ("kind", "sequence", "request_id", "coordinator_uuid", "deadline_seconds"):
            self.reject((pending(**{key: value}),))
        self.reject(initial=anchor(schema=value))
        self.reject(uncertain_commit=value)
        bad_keys = pending()
        del bad_keys["request_id"]
        bad_keys[value] = "a" * 64
        self.reject((bad_keys,))

    def test_projection_uses_no_io_native_acquisition_or_clock(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected I/O")), \
             patch.object(subject.os, "open", side_effect=AssertionError("unexpected I/O")), \
             patch.object(subject.time, "monotonic", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject.time, "monotonic_ns", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject.time, "time_ns", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject, "acquire_native_pmc_context", side_effect=AssertionError("unexpected native")):
            first = pending()
            result = subject._project_pmc_coordination_trace(anchor(), (first, terminal(first)))
        self.assertFalse(result.continuation_blocked)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_COORDINATION_TRACE")
