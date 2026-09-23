"""Portable synthetic PMC deadline-projection controls."""

from dataclasses import FrozenInstanceError, fields
from fractions import Fraction
import inspect
import unittest
from unittest.mock import patch

from scientist_one import pmc_coordination as subject

MAX_NS = (1 << 63) - 1
SPACING_NS = 333_333_334
BOOT = b"12345678-1234-4234-8234-123456789abc"

class PmcDeadlineProjectionTests(unittest.TestCase):
    def test_exact_floor_does_not_use_rounded_float_multiplication(self):
        for value, expected in ((0.3, 299_999_999), (12345.678901234, 12_345_678_901_233)):
            with self.subTest(value=value):
                self.assertEqual(subject._pmc_floor_deadline_ns(value), expected)
                self.assertGreater(int(value * 10**9), expected)

    def test_result_is_the_exact_rational_floor_across_exponent_boundaries(self):
        values = (0.0, -0.0, 5e-324, 1e-12, 1e-9, 0.125, 0.3, 1.0,
                  1.000000003, 12345.678901234, 1e9, 9223372036.854774)
        for value in values:
            with self.subTest(value=value):
                result = subject._pmc_floor_deadline_ns(value)
                exact = Fraction(value) * 10**9
                self.assertIs(type(result), int)
                self.assertLessEqual(result, exact)
                self.assertLess(exact, result + 1)
                self.assertGreaterEqual(result, 0)
                self.assertLessEqual(result, MAX_NS)

    def test_malformed_and_overflowing_deadlines_are_static_refusals(self):
        class FloatSubclass(float):
            pass

        for value in (True, False, 0, 1, None, "0.3", FloatSubclass(0.3),
                      -1e-12, float("nan"), float("inf"), -float("inf"),
                      9223372036.854776, 1e300):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(subject._PmcSpacingProjectionError) as caught:
                    subject._pmc_floor_deadline_ns(value)
                self.assertEqual(str(caught.exception), "PMC_DEADLINE_SECONDS_INVALID")
                self.assertIsNone(caught.exception.__context__)

    def test_composed_spacing_keeps_strict_original_deadline_bound(self):
        deadline = 0.7
        exact_ns = Fraction(deadline) * 10**9
        floor = subject._pmc_floor_deadline_ns(deadline)
        for now, expected in ((floor - 1, True), (floor, False), (floor + 1, False)):
            with self.subTest(now=now):
                result = subject._project_pmc_post_cleanup_spacing(
                    now_ns=now, cleanup_completed_ns=0, deadline_ns=floor,
                    current_boot_uuid=BOOT, cleanup_boot_uuid=BOOT,
                )
                self.assertEqual(result.deadline_feasible, expected)
                self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_TIMING_PROJECTION")
                if result.deadline_feasible:
                    self.assertLess(result.earliest_ns, exact_ns)

    def test_bridge_has_no_io_clock_or_native_acquisition(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected I/O")), \
             patch.object(subject.os, "open", side_effect=AssertionError("unexpected I/O")), \
             patch.object(subject.time, "monotonic", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject.time, "monotonic_ns", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject, "acquire_native_pmc_context", side_effect=AssertionError("unexpected acquisition")):
            self.assertEqual(subject._pmc_floor_deadline_ns(0.3), 299_999_999)

class PmcSpacingCandidateTests(unittest.TestCase):
    def project(self, **updates):
        values = {
            "now_ns": 0,
            "cleanup_completed_ns": 0,
            "deadline_ns": 10**12,
            "current_boot_uuid": BOOT,
            "cleanup_boot_uuid": BOOT,
        }
        values.update(updates)
        return subject._project_pmc_post_cleanup_spacing(**values)

    def assert_error(self, code, **updates):
        with self.assertRaises(subject._PmcSpacingProjectionError) as caught:
            self.project(**updates)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(str(updates), str(caught.exception))

    def test_projection_is_frozen_and_explicitly_non_authorizing(self):
        result = self.project(deadline_ns=SPACING_NS + 1)
        self.assertEqual(
            tuple(field.name for field in fields(subject._PmcSpacingProjection)),
            ("earliest_ns", "wait_ns", "deadline_feasible", "classification"),
        )
        self.assertEqual(
            (result.earliest_ns, result.wait_ns, result.deadline_feasible),
            (SPACING_NS, SPACING_NS, True),
        )
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_TIMING_PROJECTION")
        with self.assertRaises(FrozenInstanceError):
            result.wait_ns = 0

    def test_spacing_boundary_before_at_and_after_required_interval(self):
        before = self.project(now_ns=SPACING_NS - 1)
        at = self.project(now_ns=SPACING_NS)
        after = self.project(now_ns=SPACING_NS + 1)
        self.assertEqual((before.earliest_ns, before.wait_ns), (SPACING_NS, 1))
        self.assertEqual((at.earliest_ns, at.wait_ns), (SPACING_NS, 0))
        self.assertEqual((after.earliest_ns, after.wait_ns), (SPACING_NS + 1, 0))

    def test_elapsed_cleanup_does_not_add_a_second_wait(self):
        result = self.project(now_ns=1_000_000_000, cleanup_completed_ns=1)
        self.assertEqual(result.earliest_ns, 1_000_000_000)
        self.assertEqual(result.wait_ns, 0)
        self.assertTrue(result.deadline_feasible)

    def test_deadline_equality_and_one_nanosecond_remaining_are_distinct(self):
        equal = self.project(deadline_ns=SPACING_NS)
        one_remaining = self.project(deadline_ns=SPACING_NS + 1)
        self.assertFalse(equal.deadline_feasible)
        self.assertTrue(one_remaining.deadline_feasible)

    def test_expired_deadline_is_valid_data_not_a_fresh_allowance(self):
        current = 1_000
        result = self.project(now_ns=current, deadline_ns=current)
        self.assertEqual(result.earliest_ns, SPACING_NS)
        self.assertEqual(result.wait_ns, SPACING_NS - current)
        self.assertFalse(result.deadline_feasible)
        expired = self.project(now_ns=current, deadline_ns=0)
        self.assertEqual(expired, result)

    def test_int64_max_boundary_is_exact(self):
        cleanup = MAX_NS - SPACING_NS
        result = self.project(
            now_ns=cleanup,
            cleanup_completed_ns=cleanup,
            deadline_ns=MAX_NS,
        )
        self.assertEqual(result.earliest_ns, MAX_NS)
        self.assertEqual(result.wait_ns, SPACING_NS)
        self.assertFalse(result.deadline_feasible)
        at_max = self.project(now_ns=MAX_NS, deadline_ns=MAX_NS)
        self.assertEqual((at_max.earliest_ns, at_max.wait_ns), (MAX_NS, 0))

    def test_cleanup_spacing_overflow_is_rejected_without_wrapping(self):
        self.assert_error(
            "PMC_CLEANUP_SPACING_OVERFLOW",
            now_ns=MAX_NS - SPACING_NS + 1,
            cleanup_completed_ns=MAX_NS - SPACING_NS + 1,
            deadline_ns=MAX_NS,
        )

    def test_regressed_current_time_is_rejected(self):
        self.assert_error(
            "PMC_TIME_ORDER_INVALID",
            now_ns=9,
            cleanup_completed_ns=10,
        )

    def test_nanoseconds_require_exact_bounded_ints_and_reject_booleans(self):
        class IntegerSubclass(int):
            pass

        for name in ("now_ns", "cleanup_completed_ns", "deadline_ns"):
            for value in (True, False, 1.0, IntegerSubclass(1), -1, MAX_NS + 1, None, "1"):
                with self.subTest(name=name, value_type=type(value).__name__):
                    self.assert_error("PMC_NANOSECONDS_INVALID", **{name: value})

    def test_boot_identity_is_lowercase_canonical_syntax_only(self):
        accepted = self.project(
            current_boot_uuid=b"abcdefab-cdef-4abc-8def-abcdefabcdef",
            cleanup_boot_uuid=b"abcdefab-cdef-4abc-8def-abcdefabcdef",
        )
        self.assertEqual(accepted.classification, "UNVERIFIED_SUPPLIED_TIMING_PROJECTION")

        class BytesSubclass(bytes):
            pass

        for value in (
            b"12345678-1234-4234-8234-123456789ABC",
            b"{12345678-1234-4234-8234-123456789abc}",
            b"12345678123442348234123456789abc",
            b"00000000-0000-0000-0000-000000000000",
            BytesSubclass(BOOT),
            "12345678-1234-4234-8234-123456789abc",
            None,
            123,
        ):
            with self.subTest(value_type=type(value).__name__):
                self.assert_error("PMC_BOOT_UUID_INVALID", current_boot_uuid=value)

    def test_boot_identity_mismatch_is_refused_without_echoing_supplied_data(self):
        self.assert_error(
            "PMC_BOOT_UUID_MISMATCH",
            current_boot_uuid=BOOT,
            cleanup_boot_uuid=b"abcdefab-cdef-4abc-8def-abcdefabcdef",
        )

    def test_completed_response_and_local_abort_use_same_unverified_arithmetic(self):
        cases = (
            ("completed-response-cleanup", 20, 10),
            ("locally-terminated-abort-cleanup", 30, 20),
        )
        for label, now, cleanup in cases:
            with self.subTest(label=label):
                result = self.project(now_ns=now, cleanup_completed_ns=cleanup, deadline_ns=40)
                self.assertEqual(result.earliest_ns, cleanup + SPACING_NS)
                self.assertEqual(result.wait_ns, cleanup + SPACING_NS - now)
                self.assertFalse(result.deadline_feasible)
                self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_TIMING_PROJECTION")

    def test_projection_has_no_io_clock_or_native_acquisition_side_effect(self):
        with patch.object(subject.os, "open", side_effect=AssertionError("unexpected file I/O")), \
             patch.object(subject.os, "stat", side_effect=AssertionError("unexpected file I/O")), \
             patch.object(subject.time, "monotonic_ns", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject.time, "time_ns", side_effect=AssertionError("unexpected clock")), \
             patch.object(subject.ctypes, "CDLL", side_effect=AssertionError("unexpected native load")), \
             patch.object(subject, "acquire_native_pmc_context", side_effect=AssertionError("unexpected acquisition")):
            result = self.project(now_ns=SPACING_NS + 1)
        self.assertEqual(result.classification, "UNVERIFIED_SUPPLIED_TIMING_PROJECTION")

    def test_interface_is_keyword_only_and_has_no_none_or_first_use_shortcut(self):
        signature = inspect.signature(subject._project_pmc_post_cleanup_spacing)
        self.assertTrue(all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in signature.parameters.values()))
        self.assertTrue(all(parameter.default is inspect.Parameter.empty for parameter in signature.parameters.values()))
        with self.assertRaises(TypeError):
            subject._project_pmc_post_cleanup_spacing(0, 0, 1, BOOT, BOOT)
        self.assert_error("PMC_NANOSECONDS_INVALID", cleanup_completed_ns=None)
        self.assert_error("PMC_BOOT_UUID_INVALID", cleanup_boot_uuid=None)
