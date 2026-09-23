"""Independent exact-arithmetic controls for represented-value permutation tails.

These are numerical tests, not evidence of exchangeability in any real study.
The oracle computes Fraction means directly, independently of the production
integer-score implementation. All observations here are synthetic test values.
"""

from fractions import Fraction
import itertools
import math
import random
import sys
import unittest

from scientist_one.statistics import (
    StatisticalValidationError,
    analyze_two_group,
    permutation_test_mean_difference,
)


def _difference(values, selected):
    left = [value for index, value in enumerate(values) if index in selected]
    right = [value for index, value in enumerate(values) if index not in selected]
    return sum(left, Fraction()) / len(left) - sum(right, Fraction()) / len(right)


def _extreme(value, observed, alternative):
    if alternative == "two-sided":
        return abs(value) >= abs(observed)
    if alternative == "greater":
        return value >= observed
    return value <= observed


def _oracle(treatment, control, alternative="two-sided"):
    values = tuple(Fraction.from_float(float(value)) for value in (*treatment, *control))
    count = len(treatment)
    observed = _difference(values, set(range(count)))
    outcomes = [
        _extreme(_difference(values, set(selected)), observed, alternative)
        for selected in itertools.combinations(range(len(values)), count)
    ]
    return Fraction(sum(outcomes), len(outcomes))


def _monte_carlo_oracle(treatment, control, alternative, resamples, seed):
    values = tuple(Fraction.from_float(float(value)) for value in (*treatment, *control))
    observed = _difference(values, set(range(len(treatment))))
    # Shuffle positions, not the production transformed values. The arithmetic
    # still uses separately computed rational group means for each allocation.
    positions = list(range(len(values)))
    generator = random.Random(seed)
    extreme = 0
    for _ in range(resamples):
        generator.shuffle(positions)
        extreme += _extreme(
            _difference(values, set(positions[:len(treatment)])), observed, alternative
        )
    return Fraction(extreme + 1, resamples + 1)


class PermutationPrecisionTests(unittest.TestCase):
    def assert_oracle(self, treatment, control):
        for alternative in ("greater", "less", "two-sided"):
            with self.subTest(alternative=alternative, treatment=treatment, control=control):
                self.assertEqual(
                    permutation_test_mean_difference(treatment, control, alternative=alternative),
                    float(_oracle(treatment, control, alternative)),
                )

    def test_reported_unscaled_example_has_two_extreme_assignments_of_seventy(self):
        self.assertEqual(_oracle([1, 2, 3, 4], [0, 0, 0, 0]), Fraction(1, 35))
        self.assertEqual(permutation_test_mean_difference([1, 2, 3, 4], [0, 0, 0, 0]), 1 / 35)

    def test_reported_small_scale_defect(self):
        treatment = [value * 1e-16 for value in (1, 2, 3, 4)]
        control = [0.0] * 4
        self.assertEqual(_oracle(treatment, control), Fraction(1, 35))
        self.assertEqual(permutation_test_mean_difference(treatment, control), 1 / 35)

    def test_power_of_two_rescaling_preserves_all_tails(self):
        treatment, control = [1.0, 2.0, 3.0, 4.0], [0.0] * 4
        for exponent in (-1000, -100, 0, 100, 1000):
            scaled = [math.ldexp(value, exponent) for value in treatment]
            self.assertEqual(_oracle(scaled, control), Fraction(1, 35))
            self.assert_oracle(scaled, control)

    def test_decimal_small_and_large_scales_match_represented_value_oracle(self):
        for scale in (1e-200, 1e-16, 1e16, 1e200):
            self.assert_oracle([value * scale for value in (1, 2, 3, 4)], [0.0] * 4)

    def test_duplicate_values_are_counted_by_assignment_not_unique_partition(self):
        self.assert_oracle([1.0, 1.0], [0.0, 1.0])

    def test_all_ties_and_signed_zeros(self):
        for treatment, control in (([2.0, 2.0], [2.0, 2.0]), ([0.0, -0.0], [-0.0, 0.0])):
            self.assert_oracle(treatment, control)
            for alternative in ("greater", "less", "two-sided"):
                self.assertEqual(permutation_test_mean_difference(treatment, control, alternative=alternative), 1.0)

    def test_zero_observed_statistic_with_nonzero_permutations(self):
        self.assert_oracle([-1.0, 1.0], [0.0, 0.0])
        self.assertEqual(permutation_test_mean_difference([-1.0, 1.0], [0.0, 0.0]), 1.0)

    def test_unequal_groups_and_reversal(self):
        treatment, control = [2.0], [0.0, 0.0]
        self.assertEqual(_oracle(treatment, control), Fraction(1, 3))
        self.assert_oracle(treatment, control)
        self.assert_oracle(control, treatment)
        self.assertEqual(
            permutation_test_mean_difference(treatment, control, alternative="greater"),
            permutation_test_mean_difference(control, treatment, alternative="less"),
        )
        self.assertEqual(permutation_test_mean_difference(treatment, control), permutation_test_mean_difference(control, treatment))

    def test_near_but_unequal_statistics_are_not_ties(self):
        self.assert_oracle([1.0, math.nextafter(1.0, math.inf)], [1.0, 1.0])

    def test_subnormal_values_preserve_exact_tails(self):
        smallest = math.ulp(0.0)
        self.assertEqual(_oracle([smallest, 2 * smallest], [0.0, 0.0]), Fraction(1, 3))
        self.assert_oracle([smallest, 2 * smallest], [0.0, 0.0])

    def test_large_finite_values_do_not_overflow_tail_comparison(self):
        largest = sys.float_info.max
        self.assertEqual(_oracle([largest, largest], [0.0, 0.0]), Fraction(1, 3))
        self.assert_oracle([largest, largest], [0.0, 0.0])

    def test_mixed_exponents_and_cancellation(self):
        largest, smallest = sys.float_info.max, math.ulp(0.0)
        self.assert_oracle([largest, smallest], [-largest, 0.0])
        self.assert_oracle([2.0**53, 1.0, -(2.0**53)], [0.0, 0.0, 0.0])

    def test_exact_enumeration_cutoff_and_seed_independence(self):
        for seed in (-9, 0, 19):
            self.assertEqual(permutation_test_mean_difference([1, 2, 3, 4], [0] * 4, seed=seed, exact_limit=70), 1 / 35)

    def test_seeded_monte_carlo_matches_independent_oracle_and_plus_one(self):
        for alternative in ("greater", "less", "two-sided"):
            for seed in (0, 7, -3):
                expected = float(_monte_carlo_oracle([1, 2, 3, 4], [0] * 4, alternative, 127, seed))
                kwargs = dict(alternative=alternative, resamples=127, seed=seed, exact_limit=1)
                first = permutation_test_mean_difference([1, 2, 3, 4], [0] * 4, **kwargs)
                self.assertEqual(first, expected)
                self.assertEqual(first, permutation_test_mean_difference([1, 2, 3, 4], [0] * 4, **kwargs))
                self.assertGreaterEqual(first, 1 / 128)

    def test_monte_carlo_safe_rescaling_and_ties(self):
        for alternative in ("greater", "less", "two-sided"):
            kwargs = dict(alternative=alternative, resamples=101, seed=11, exact_limit=1)
            reference = permutation_test_mean_difference([1, 2, 3, 4], [0] * 4, **kwargs)
            for scale in (2.0**-1000, 1e-16, 2.0**1000):
                self.assertEqual(permutation_test_mean_difference([x * scale for x in (1, 2, 3, 4)], [0] * 4, **kwargs), reference)
            self.assertEqual(permutation_test_mean_difference([2, 2], [2, 2], **kwargs), 1.0)

    def test_malformed_and_nonfinite_observations_still_reject(self):
        for values in ([], None, [True], ["bad"], [None], [math.nan], [math.inf], [-math.inf]):
            for reverse in (False, True):
                treatment, control = (values, [0]) if not reverse else ([0], values)
                with self.subTest(values=values, reverse=reverse):
                    with self.assertRaises(StatisticalValidationError):
                        permutation_test_mean_difference(treatment, control)

    def test_parameter_validation_is_preserved_even_for_exact_small_family(self):
        for kwargs in (
            {"alternative": "invalid"}, {"resamples": True}, {"resamples": 99},
            {"resamples": 100.0}, {"seed": True}, {"seed": 1.5},
            {"exact_limit": True}, {"exact_limit": 0}, {"exact_limit": 2.5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(StatisticalValidationError):
                    permutation_test_mean_difference([1], [0], **kwargs)

    def test_analysis_reports_new_comparison_semantics_without_claiming_exact_sampling(self):
        estimate = analyze_two_group([1, 2, 3, 4], [0] * 4, bootstrap_resamples=100, permutation_resamples=100, seed=4)
        self.assertEqual(estimate.p_value, 1 / 35)
        self.assertEqual(estimate.test_method, "exchangeable-unit label permutation; binary64-exact-comparison/v2")
