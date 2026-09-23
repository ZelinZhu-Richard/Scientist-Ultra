"""Pure reporting controls, not execution or prospective-timing authority."""

from dataclasses import replace
import unittest

from scientist_one.scientific_design import (
    MetricDirection,
    MetricUnit,
    ReportingRegime,
    RunDisposition,
    ScientificDesignError,
    ScientificPromotionError,
    SeedReport,
    SeedReportingPlan,
    SeedRunRecord,
    validate_seed_report,
)
from tests.test_scientific_design import make_metric, successful_run


def best_plan() -> SeedReportingPlan:
    return SeedReportingPlan(
        seeds=(7, 11, 19),
        regime=ReportingRegime.BEST_OF_N,
        selection_policy="Select an optimal primary metric; retain all outcomes.",
        selection_defined_before_results=True,
        preserve_all_runs=True,
        technical_retry_rule="No retries in this pure test cohort.",
        best_of_n=3,
    )


def adverse_run(seed: int, disposition: RunDisposition) -> SeedRunRecord:
    return SeedRunRecord(
        run_id=f"run-{seed}",
        seed=seed,
        disposition=disposition,
        metric_value=None,
        artifact_sha256=None,
        failure_reason="Synthetic adverse outcome; no execution authority.",
    )


class SeedReportingEdgeCaseTests(unittest.TestCase):
    def test_complete_all_adverse_best_cohorts_have_no_eligible_selection(self):
        for dispositions in (
            (RunDisposition.FAILED,) * 3,
            (RunDisposition.INVALID,) * 3,
            (RunDisposition.FAILED, RunDisposition.INVALID, RunDisposition.FAILED),
        ):
            with self.subTest(dispositions=dispositions):
                records = tuple(
                    adverse_run(seed, disposition)
                    for seed, disposition in zip(best_plan().seeds, dispositions)
                )
                report = validate_seed_report(best_plan(), records, make_metric())
                self.assertEqual(report.regime, ReportingRegime.BEST_OF_N)
                self.assertEqual(report.total_runs, 3)
                self.assertEqual(report.successful_runs, 0)
                self.assertEqual(report.failed_runs, dispositions.count(RunDisposition.FAILED))
                self.assertEqual(report.invalid_runs, dispositions.count(RunDisposition.INVALID))
                self.assertEqual(report.successful_distribution, ())
                self.assertIsNone(report.selected_run_id)

    def test_all_adverse_report_cannot_omit_a_planned_seed(self):
        with self.assertRaisesRegex(ScientificPromotionError, "incomplete or selective"):
            validate_seed_report(
                best_plan(),
                tuple(adverse_run(seed, RunDisposition.FAILED) for seed in (7, 11)),
                make_metric(),
            )

    def test_summary_cannot_name_a_selection_without_any_success(self):
        with self.assertRaisesRegex(ScientificDesignError, "without a successful run"):
            SeedReport(ReportingRegime.BEST_OF_N, 3, 0, 2, 1, "run-7", ())

    def test_successful_best_cohort_still_requires_exactly_one_selection(self):
        records = tuple(successful_run(seed, 0.5) for seed in best_plan().seeds)
        for selected_indices in ((), (0, 1)):
            with self.subTest(selected_indices=selected_indices):
                with self.assertRaisesRegex(ScientificPromotionError, "exactly one"):
                    validate_seed_report(
                        best_plan(),
                        tuple(
                            replace(record, selected=index in selected_indices)
                            for index, record in enumerate(records)
                        ),
                        make_metric(),
                    )

    def test_adverse_record_still_cannot_be_selected(self):
        for disposition in (RunDisposition.FAILED, RunDisposition.INVALID):
            with self.subTest(disposition=disposition):
                with self.assertRaisesRegex(ScientificDesignError, "cannot be selected"):
                    replace(adverse_run(7, disposition), selected=True)

    def test_target_ties_accept_either_optimum_and_preserve_distribution_order(self):
        metric = make_metric(
            direction=MetricDirection.TARGET_IS_BEST,
            target_value=0.0,
            unit=MetricUnit.SCORE,
            name="Synthetic signed score",
            definition="A signed diagnostic score for pure ordering controls.",
        )
        records = (
            successful_run(7, -1.0),
            successful_run(11, 1.0),
            successful_run(19, 3.0),
        )
        for selected_index in (0, 1):
            with self.subTest(selected_index=selected_index):
                report = validate_seed_report(
                    best_plan(),
                    tuple(
                        replace(record, selected=index == selected_index)
                        for index, record in enumerate(records)
                    ),
                    metric,
                )
                self.assertEqual(report.selected_run_id, records[selected_index].run_id)
                self.assertEqual(report.successful_distribution, (-1.0, 1.0, 3.0))

    def test_target_distance_does_not_overflow_and_select_a_worse_run(self):
        metric = make_metric(
            direction=MetricDirection.TARGET_IS_BEST,
            target_value=1.7e308,
            unit=MetricUnit.SCORE,
            name="Synthetic signed score",
            definition="A signed diagnostic score for pure ordering controls.",
        )
        records = (
            successful_run(7, -1.7e308),
            successful_run(11, -1.6e308),
            successful_run(19, -1.5e308),
        )
        with self.assertRaisesRegex(ScientificPromotionError, "metric direction"):
            validate_seed_report(
                best_plan(), (replace(records[0], selected=True), *records[1:]), metric
            )
        report = validate_seed_report(
            best_plan(), (*records[:2], replace(records[2], selected=True)), metric
        )
        self.assertEqual(report.selected_run_id, "run-19")
        self.assertEqual(report.successful_distribution, (-1.7e308, -1.6e308, -1.5e308))

    def test_high_and_low_directions_keep_true_best_requirement(self):
        for direction, best_index in (
            (MetricDirection.HIGHER_IS_BETTER, 2),
            (MetricDirection.LOWER_IS_BETTER, 0),
        ):
            for selected_index in range(3):
                records = tuple(
                    successful_run(seed, float(index), selected=index == selected_index)
                    for index, seed in enumerate(best_plan().seeds)
                )
                with self.subTest(direction=direction, selected_index=selected_index):
                    if selected_index == best_index:
                        report = validate_seed_report(
                            best_plan(), records, make_metric(direction=direction)
                        )
                        self.assertEqual(report.selected_run_id, records[selected_index].run_id)
                    else:
                        with self.assertRaisesRegex(ScientificPromotionError, "metric direction"):
                            validate_seed_report(
                                best_plan(), records, make_metric(direction=direction)
                            )

    def test_best_of_n_requires_an_integer_not_numeric_equality(self):
        for seeds, count in (((7,), True), ((7, 11, 19), 3.0)):
            with self.subTest(seeds=seeds, count=count):
                with self.assertRaises(ScientificDesignError):
                    replace(best_plan(), seeds=seeds, best_of_n=count)

    def test_all_seeds_still_preserves_all_adverse_records_without_selection(self):
        plan = replace(best_plan(), regime=ReportingRegime.ALL_SEEDS, best_of_n=None)
        report = validate_seed_report(
            plan,
            tuple(adverse_run(seed, RunDisposition.FAILED) for seed in plan.seeds),
            make_metric(),
        )
        self.assertEqual((report.total_runs, report.failed_runs), (3, 3))
        self.assertIsNone(report.selected_run_id)
        self.assertEqual(report.successful_distribution, ())


if __name__ == "__main__":
    unittest.main()
