"""Independent result-semantics and raw-replay review; no scientific authority."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scientist_one.experiments import SeedRunStatus

from scientist_one.scientific_design import (
    HypothesisEvaluationFacts,
    HypothesisEvaluationPolicy,
    HypothesisStatus,
    ScientificPromotionError,
    ScientificResultOutcome,
    _derive_checked_result_evidence,
    derive_scientific_result_assessment,
    evaluate_hypothesis_policy,
)


class ResultOutcomeReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = HypothesisEvaluationPolicy(
            policy_id="review-result-policy",
            hypothesis_id="review-result-hypothesis",
            metric_id="review-result-metric",
            meaningful_effect=0.02,
            falsification_effect=0.02,
            alpha=0.05,
            minimum_sample_size=10,
        )

    def test_failure_to_support_does_not_establish_a_null_result(self) -> None:
        uncertain_cases = (
            # Meaningful benefit remains compatible with this one-sided CI.
            HypothesisEvaluationFacts(0.015, -0.001, 0.05, 0.4, 20),
            # Meaningful harm remains compatible; that is not equivalence.
            HypothesisEvaluationFacts(-0.015, -0.05, 0.001, 0.4, 20),
            # A multiplicity-adjusted non-rejection is not a null effect even
            # when an unadjusted interval is negative.
            HypothesisEvaluationFacts(-0.06, -0.1, -0.03, 0.2, 20),
        )
        for facts in uncertain_cases:
            with self.subTest(facts=facts):
                self.assertIs(
                    evaluate_hypothesis_policy(self.policy, facts),
                    HypothesisStatus.NOT_SUPPORTED,
                )
                decision = derive_scientific_result_assessment(self.policy, facts)
                self.assertIs(decision.outcome, ScientificResultOutcome.INCONCLUSIVE)
                self.assertIs(decision.hypothesis_status, HypothesisStatus.NOT_SUPPORTED)

    def test_underpowered_or_wide_results_remain_inconclusive(self) -> None:
        for facts in (
            HypothesisEvaluationFacts(0.0, -0.002, 0.002, 0.8, 4),
            HypothesisEvaluationFacts(0.0, -0.1, 0.1, 0.8, 20),
            HypothesisEvaluationFacts(0.0, -0.002, 0.002, None, 20),
        ):
            with self.subTest(facts=facts):
                decision = derive_scientific_result_assessment(self.policy, facts)
                self.assertIs(decision.outcome, ScientificResultOutcome.INCONCLUSIVE)

    def test_narrow_bounded_result_is_distinct_from_directional_evidence(self) -> None:
        cases = (
            (
                HypothesisEvaluationFacts(0.0, -0.002, 0.002, 0.8, 20),
                ScientificResultOutcome.NULL,
            ),
            (
                HypothesisEvaluationFacts(-0.01, -0.015, -0.005, 0.01, 20),
                ScientificResultOutcome.NEGATIVE,
            ),
            (
                HypothesisEvaluationFacts(-0.06, -0.1, -0.03, 0.01, 20),
                ScientificResultOutcome.FALSIFIED,
            ),
            (
                HypothesisEvaluationFacts(0.06, 0.03, 0.1, 0.01, 20),
                ScientificResultOutcome.POSITIVE,
            ),
        )
        for facts, expected_outcome in cases:
            with self.subTest(expected_outcome=expected_outcome):
                self.assertIs(
                    derive_scientific_result_assessment(self.policy, facts).outcome,
                    expected_outcome,
                )

    def test_decisive_adverse_raw_replay_preserves_falsification_without_issuing_authority(self) -> None:
        from tests.test_superiority_authority import _registered_inputs

        with TemporaryDirectory(prefix="root-falsified-result-review-") as task_dir:
            values = _registered_inputs(
                Path(task_dir),
                candidate_value=0.0,
                baseline_value=0.5,
                seed_status=SeedRunStatus.NEGATIVE,
                outcome_neutral=True,
            )
            arguments = {
                "contract_artifact_sha256": values["contract_record"].sha256,
                "aggregate_result_sha256": values["aggregate_record"].sha256,
                "statistical_analysis_sha256": values["statistics_record"].sha256,
                "evaluator_assessment_sha256": values["evaluator_record"].sha256,
                "scientific_obligations_sha256": values["obligations_record"].sha256,
                "baseline_exclusion_receipt_sha256s": (),
            }
            registry = values["registry"]
            before = registry.list_records()
            evidence = _derive_checked_result_evidence(registry, **arguments)
            self.assertIs(evidence.decision.outcome, ScientificResultOutcome.FALSIFIED)
            self.assertIs(evidence.decision.hypothesis_status, HypothesisStatus.FALSIFIED)
            self.assertLess(evidence.facts.confidence_high, -0.1)
            with self.assertRaises(ScientificPromotionError):
                _derive_checked_result_evidence(
                    registry, **arguments, require_superiority=True,
                )
            self.assertEqual(registry.list_records(), before)
            self.assertFalse(
                {record.logical_type for record in before}
                & {"scientific_execution_authority", "checked_result_assessment"}
            )


if __name__ == "__main__":
    unittest.main()
