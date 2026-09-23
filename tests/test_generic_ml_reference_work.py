"""Pure arithmetic controls; no resource, execution or scientific authority."""

from dataclasses import FrozenInstanceError
import unittest

from scientist_one.generic_ml_projection import (
    GENERIC_ML_REFERENCE_WORK_SCHEMA,
    GENERIC_ML_REFERENCE_WORK_SCOPE,
    GenericMLProjectionError,
    GenericMLReferenceWork,
)


class GenericMLReferenceWorkTests(unittest.TestCase):
    def test_complete_grid_and_asymmetric_robustness_are_separate(self) -> None:
        value = GenericMLReferenceWork(7, 3, 4, 5).to_dict()
        expected = {
            "predictions": 21,
            "integer_multiplications": 420,
            "dot_reduction_additions": 336,
            "bias_additions": 84,
            "argmax_score_comparisons": 63,
        }
        self.assertEqual(value["candidate_primary_metric"], expected)
        self.assertEqual(value["baseline_primary_metric"], expected)
        self.assertEqual(
            value["candidate_robustness_overhead"],
            {name: 2 * count for name, count in expected.items()},
        )
        self.assertEqual(value["schema_version"], GENERIC_ML_REFERENCE_WORK_SCHEMA)
        self.assertEqual(value["scope"], GENERIC_ML_REFERENCE_WORK_SCOPE)
        self.assertNotIn("compute_budget_equivalent", value)
        self.assertNotIn("scientific_evidence", value)
        self.assertNotIn("passed", value)

    def test_one_feature_has_no_dot_reduction_addition(self) -> None:
        value = GenericMLReferenceWork(1, 1, 2, 1).to_dict()
        self.assertEqual(
            value["candidate_primary_metric"],
            {
                "predictions": 1,
                "integer_multiplications": 2,
                "dot_reduction_additions": 0,
                "bias_additions": 2,
                "argmax_score_comparisons": 1,
            },
        )

    def test_all_dimensions_require_exact_bounded_nonempty_integers(self) -> None:
        for index, invalid in enumerate(
            ((0, -1, 10001), (0, -1, 25), (0, 1, 1025), (0, -1, 1025))
        ):
            for wrong in (*invalid, True, False, 1.0, "1", None):
                args = [2, 1, 2, 1]
                args[index] = wrong
                with self.subTest(index=index, wrong=wrong):
                    with self.assertRaisesRegex(
                        GenericMLProjectionError, "outside its exact bound"
                    ):
                        GenericMLReferenceWork(*args)

    def test_model_and_whole_grid_bounds_are_independent(self) -> None:
        # 64 * (1023 + 1) reaches the model bound; two conditions and two
        # seeds reach the distinct complete-grid bound without allocation.
        self.assertEqual(
            GenericMLReferenceWork(10000, 2, 64, 1023).to_dict()[
                "candidate_primary_metric"
            ]["integer_multiplications"],
            1_309_440_000,
        )
        for args in ((2, 1, 64, 1024), (2, 3, 64, 1023)):
            with self.subTest(args=args):
                with self.assertRaisesRegex(
                    GenericMLProjectionError, "model grid exceeds"
                ):
                    GenericMLReferenceWork(*args)

    def test_counts_match_an_independent_finite_dense_reference_loop(self) -> None:
        for units in (1, 3):
            for seeds in (1, 2):
                for classes in (2, 4):
                    for features in (1, 5):
                        predictions = products = reductions = biases = comparisons = 0
                        for _ in range(units):
                            for _ in range(seeds):
                                predictions += 1
                                for _ in range(classes):
                                    for _ in range(features):
                                        products += 1
                                    for _ in range(1, features):
                                        reductions += 1
                                    biases += 1
                                for _ in range(1, classes):
                                    comparisons += 1
                        self.assertEqual(
                            GenericMLReferenceWork(
                                units, seeds, classes, features
                            ).to_dict()["candidate_primary_metric"],
                            {
                                "predictions": predictions,
                                "integer_multiplications": products,
                                "dot_reduction_additions": reductions,
                                "bias_additions": biases,
                                "argmax_score_comparisons": comparisons,
                            },
                        )

    def test_value_is_frozen_and_returned_views_cannot_mutate_it(self) -> None:
        work = GenericMLReferenceWork(2, 1, 2, 1)
        with self.assertRaises(FrozenInstanceError):
            work.unit_count = 9
        original = work.to_dict()
        changed = work.to_dict()
        changed["candidate_primary_metric"]["predictions"] = -1
        self.assertEqual(work.to_dict(), original)
        self.assertEqual(changed["baseline_primary_metric"]["predictions"], 2)


if __name__ == "__main__":
    unittest.main()
