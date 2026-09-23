"""Non-evidentiary arithmetic controls; no scientific owner is simulated."""

from dataclasses import replace
import math
import unittest

from scientist_one.bounded_mean_inference import (
    BoundedMeanDecision,
    BoundedMeanInferencePlan,
    PairedRowCorrectnessCounts,
    analyze_fixed_complete_bounded_mean,
)
from scientist_one.errors import ValidationError
from scientist_one.scientific_design import (
    _recompute_bounded_mean_from_projection_grid,
)


class BoundedMeanProjectionGridTests(unittest.TestCase):
    def setUp(self):
        self.plan = BoundedMeanInferencePlan(
            alpha=0.05,
            benefit_margin=0.2,
            harm_margin=0.2,
            minimum_unit_count=2,
            unit_ids=("unit-a", "unit-b", "unit-c"),
            seed_order=(5, 17, 29),
        )
        self.inputs = {
            "seed_order": self.plan.seed_order,
            "unit_ids": self.plan.unit_ids,
            "candidate_seed_rows": ((1.0, 0.0, 1.0), (0, 1, 1), (1, 0, 0)),
            "baseline_seed_rows": ((0, 1, 1), (0, 0, 0), (0, 1, 0)),
        }

    def test_integer_counts_match_direct_numeric_engine_not_seed_pseudoreplicates(self):
        actual = _recompute_bounded_mean_from_projection_grid(self.plan, **self.inputs)
        expected = analyze_fixed_complete_bounded_mean(
            plan=self.plan,
            rows=(
                PairedRowCorrectnessCounts("unit-a", 3, 2, 0),
                PairedRowCorrectnessCounts("unit-b", 3, 1, 2),
                PairedRowCorrectnessCounts("unit-c", 3, 2, 1),
            ),
        )
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual.rows), 3)
        self.assertEqual(actual.row_effect_numerators, (2, -1, 1))
        self.assertEqual(actual.row_effect_denominator, 3)
        self.assertEqual((actual.mean_numerator, actual.mean_denominator), (2, 9))

    def test_grid_labels_cannot_be_omitted_added_or_reordered(self):
        for field in ("seed_order", "unit_ids"):
            original = self.inputs[field]
            for changed in (original[:-1], original[::-1], original + original[:1]):
                with self.subTest(field=field, changed=changed):
                    with self.assertRaises(ValidationError):
                        _recompute_bounded_mean_from_projection_grid(
                            self.plan, **{**self.inputs, field: changed}
                        )

    def test_each_condition_requires_every_seed_and_row(self):
        for field in ("candidate_seed_rows", "baseline_seed_rows"):
            original = self.inputs[field]
            for changed in (
                original[:-1],
                original + original[:1],
                (original[0][:-1], *original[1:]),
                (original[0] + (0,), *original[1:]),
                (),
            ):
                with self.subTest(field=field, changed=changed):
                    with self.assertRaises(ValidationError):
                        _recompute_bounded_mean_from_projection_grid(
                            self.plan, **{**self.inputs, field: changed}
                        )

    def test_nonbinary_rounded_nonfinite_and_boolean_values_are_rejected(self):
        for value in (
            True,
            False,
            0.5,
            math.nextafter(1.0, 0.0),
            math.nextafter(0.0, 1.0),
            -1,
            2,
            math.nan,
            math.inf,
            "1",
        ):
            with self.subTest(value=value):
                rows = ((value, 0, 1), *self.inputs["candidate_seed_rows"][1:])
                with self.assertRaises(ValidationError):
                    _recompute_bounded_mean_from_projection_grid(
                        self.plan, **{**self.inputs, "candidate_seed_rows": rows}
                    )

    def test_caller_subclass_comparisons_do_not_skip_grid_checks(self):
        class EqualInt(int):
            def __eq__(self, other):
                return True

        class EqualStr(str):
            def __eq__(self, other):
                return True

        class EqualTuple(tuple):
            def __ne__(self, other):
                return False

        for change in (
            {"seed_order": (EqualInt(999), 17, 29)},
            {"unit_ids": (EqualStr("wrong"), "unit-b", "unit-c")},
            {"unit_ids": EqualTuple(("wrong",))},
            {"candidate_seed_rows": EqualTuple(self.inputs["candidate_seed_rows"])},
            {"candidate_seed_rows": ((EqualInt(9), 0, 1), (0, 1, 1), (1, 0, 0))},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValidationError):
                    _recompute_bounded_mean_from_projection_grid(
                        self.plan, **{**self.inputs, **change}
                    )

    def test_missing_minimum_preserves_complete_grid_as_inconclusive(self):
        plan = replace(self.plan, minimum_unit_count=4)
        result = _recompute_bounded_mean_from_projection_grid(plan, **self.inputs)
        self.assertEqual(result.decision, BoundedMeanDecision.INCONCLUSIVE)
        self.assertEqual(len(result.rows), 3)

    def test_tampered_plan_is_revalidated_before_arithmetic(self):
        plan = replace(self.plan)
        object.__setattr__(plan, "alpha", float("nan"))
        with self.assertRaises(ValidationError):
            _recompute_bounded_mean_from_projection_grid(plan, **self.inputs)


if __name__ == "__main__":
    unittest.main()
