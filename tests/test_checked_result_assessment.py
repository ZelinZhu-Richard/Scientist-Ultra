"""Outcome-neutral checked-result replay tests using non-evidentiary fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.experiments import SeedRunStatus
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    CHECKED_BOOTSTRAP_RESAMPLES_V1,
    CHECKED_BOOTSTRAP_SEED_V1,
    CHECKED_RESULT_OBLIGATION_EVIDENCE_SCHEMA,
    CHECKED_RESULT_OBLIGATIONS_SCHEMA,
    ScientificPromotionError,
    MetricDirection,
    ScientificResultOutcome,
    _derive_checked_result_evidence,
)

try:
    from .test_superiority_authority import _registered_inputs
except ImportError:  # Direct unittest discovery fallback.
    from test_superiority_authority import _registered_inputs  # type: ignore[no-redef]


class CheckedResultAssessmentReplayTests(unittest.TestCase):
    """Raw registry replay only; these tests never issue execution authority."""

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="checked-result-assessment-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _derive(values: dict[str, object], *, require_superiority: bool = False):
        return _derive_checked_result_evidence(
            values["registry"],
            contract_artifact_sha256=values["contract_record"].sha256,
            aggregate_result_sha256=values["aggregate_record"].sha256,
            statistical_analysis_sha256=values["statistics_record"].sha256,
            evaluator_assessment_sha256=values["evaluator_record"].sha256,
            scientific_obligations_sha256=values["obligations_record"].sha256,
            baseline_exclusion_receipt_sha256s=(),
            require_superiority=require_superiority,
        )

    def _replace_with_v2_obligations(
        self,
        values: dict[str, object],
        results: dict[str, str],
    ) -> ArtifactRecord:
        """Replay v2 result semantics with the legacy raw source parents intact."""

        registry: ArtifactRegistry = values["registry"]
        legacy: ArtifactRecord = values["obligations_record"]
        legacy_value = json.loads(registry.get_bytes(legacy.sha256))
        evidence_records: list[ArtifactRecord] = []
        entries: list[dict[str, object]] = []
        for entry in legacy_value["entries"]:
            old_record = registry.get_metadata(entry["evidence_sha256"])
            old_value = json.loads(registry.get_bytes(old_record.sha256))
            kind = entry["kind"]
            result = results[kind]
            replacement = registry.put_json(
                {
                    **old_value,
                    "schema_version": CHECKED_RESULT_OBLIGATION_EVIDENCE_SCHEMA,
                    "result": result,
                },
                logical_type="scientific_obligation_evidence",
                origin="explicitly non-evidentiary v2 checked-result fixture",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("test", "checked-result-assessment"),
                parent_artifacts=old_record.parent_artifacts,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(replacement.parent_artifacts, old_record.parent_artifacts)
            evidence_records.append(replacement)
            entries.append(
                {
                    "kind": kind,
                    "obligation_sha256": entry["obligation_sha256"],
                    "evidence_sha256": replacement.sha256,
                    "result": result,
                }
            )
        receipt = registry.put_json(
            {
                **legacy_value,
                "schema_version": CHECKED_RESULT_OBLIGATIONS_SCHEMA,
                "entries": entries,
            },
            logical_type="scientific_obligation_verification",
            origin="explicitly non-evidentiary v2 checked-result fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("test", "checked-result-assessment"),
            parent_artifacts=(
                values["contract_record"].sha256,
                values["spec_record"].sha256,
                values["manifest_record"].sha256,
                *(record.sha256 for record in evidence_records),
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        values["obligations_record"] = receipt
        return receipt

    def test_negative_completed_seed_results_remain_negative_without_positive_threshold(self) -> None:
        values = _registered_inputs(
            self.root,
            candidate_value=0.45,
            baseline_value=0.50,
            seed_status=SeedRunStatus.NEGATIVE,
            outcome_neutral=True,
        )
        evidence = self._derive(values)
        self.assertEqual(evidence.decision.outcome, ScientificResultOutcome.NEGATIVE)
        self.assertLess(evidence.facts.improvement_effect, 0.0)
        with self.assertRaises(ScientificPromotionError):
            self._derive(values, require_superiority=True)

    def test_exact_null_completed_seed_results_are_null_even_when_sign_test_is_one(self) -> None:
        values = _registered_inputs(
            self.root,
            candidate_value=0.50,
            baseline_value=0.50,
            seed_status=SeedRunStatus.NULL,
            outcome_neutral=True,
        )
        evidence = self._derive(values)
        self.assertEqual(evidence.decision.outcome, ScientificResultOutcome.NULL)
        self.assertEqual(evidence.facts.adjusted_p_value, 1.0)

    def test_underpowered_replay_is_inconclusive(self) -> None:
        values = _registered_inputs(
            self.root,
            candidate_value=1.0,
            baseline_value=0.0,
            units_per_seed=2,
            seed_status=SeedRunStatus.SUCCESS,
            outcome_neutral=True,
        )
        evidence = self._derive(values)
        self.assertEqual(evidence.facts.sample_size, 2)
        self.assertEqual(evidence.decision.outcome, ScientificResultOutcome.INCONCLUSIVE)

    def test_repeated_seeds_do_not_inflate_the_resampling_unit_count(self) -> None:
        values = _registered_inputs(self.root, outcome_neutral=True)
        evidence = self._derive(values)
        self.assertEqual(len(evidence.execution.spec.seeds), 3)
        self.assertEqual(len(evidence.execution.paired_output_records), 3)
        self.assertEqual(evidence.facts.sample_size, 24)
        self.assertEqual(len(evidence.execution.paired_unit_ids), 24)

    def test_seed_replicates_are_deterministically_averaged_within_unit(self) -> None:
        values = _registered_inputs(
            self.root,
            outcome_neutral=True,
            candidate_value=0.8,
            candidate_values_by_seed={7: 0.6, 11: 0.8, 19: 1.0},
            baseline_value=0.5,
        )
        evidence = self._derive(values)
        self.assertTrue(
            all(
                abs(value - 0.8) < 1e-12
                for value in evidence.execution.candidate_values
            )
        )
        self.assertEqual(evidence.execution.baseline_values, (0.5,) * 24)
        self.assertAlmostEqual(evidence.facts.improvement_effect, 0.3)
        self.assertEqual(evidence.facts.sample_size, 24)

    def test_reordered_seed_unit_grid_is_rejected(self) -> None:
        values = _registered_inputs(
            self.root,
            outcome_neutral=True,
            reordered_unit_grid_seed=11,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "identical ordered"):
            self._derive(values)

    def test_every_manifest_descriptor_must_be_consumed_by_checked_replay(self) -> None:
        values = _registered_inputs(
            self.root,
            outcome_neutral=True,
            include_unconsumed_manifest_output=True,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "unconsumed"):
            self._derive(values)

    def test_nonlinear_target_metric_with_varied_seed_values_is_unsupported(self) -> None:
        values = _registered_inputs(
            self.root,
            outcome_neutral=True,
            metric_direction=MetricDirection.TARGET_IS_BEST,
            target_value=0.5,
            candidate_value=1.0 / 3.0,
            candidate_values_by_seed={7: 0.0, 11: 1.0, 19: 0.0},
            baseline_value=0.25,
        )
        self.assertEqual(
            [payload["candidate_observation"] for payload in values["raw_payloads"]],
            [0.0, 1.0, 0.0],
        )
        with self.assertRaisesRegex(ScientificPromotionError, "TARGET_IS_BEST"):
            self._derive(values)

    def test_adverse_v2_obligations_are_retained_neutrally_but_reject_superiority(self) -> None:
        values = _registered_inputs(self.root, outcome_neutral=True)
        self._replace_with_v2_obligations(
            values,
            {
                "ROBUSTNESS": "FAIL",
                "STOPPING": "MET",
                "SUCCESS": "NOT_MET",
                "FAILURE": "TRIGGERED",
            },
        )
        neutral = self._derive(values)
        self.assertEqual(neutral.decision.outcome, ScientificResultOutcome.POSITIVE)
        with self.assertRaises(ScientificPromotionError):
            self._derive(values, require_superiority=True)

    def test_stopping_not_met_is_retained_but_blocks_incomplete_execution_inference(self) -> None:
        values = _registered_inputs(self.root, outcome_neutral=True)
        receipt = self._replace_with_v2_obligations(
            values,
            {
                "ROBUSTNESS": "FAIL",
                "STOPPING": "NOT_MET",
                "SUCCESS": "NOT_MET",
                "FAILURE": "TRIGGERED",
            },
        )
        registry: ArtifactRegistry = values["registry"]
        self.assertTrue(registry.verify(receipt.sha256, raise_on_error=True))
        with self.assertRaisesRegex(ScientificPromotionError, "stopping protocol"):
            self._derive(values)

    def test_free_prose_obligation_result_is_rejected(self) -> None:
        values = _registered_inputs(self.root, outcome_neutral=True)
        self._replace_with_v2_obligations(
            values,
            {
                "ROBUSTNESS": "looked robust to the reviewer",
                "STOPPING": "MET",
                "SUCCESS": "MET",
                "FAILURE": "NOT_TRIGGERED",
            },
        )
        with self.assertRaises(ScientificPromotionError):
            self._derive(values)

    def test_alternate_bootstrap_configuration_cannot_select_an_outcome(self) -> None:
        for field, value in (
            ("bootstrap_seed", CHECKED_BOOTSTRAP_SEED_V1 + 1),
            ("bootstrap_resamples", CHECKED_BOOTSTRAP_RESAMPLES_V1 + 1),
        ):
            with self.subTest(field=field):
                case_root = self.root / field
                case_root.mkdir()
                values = _registered_inputs(
                    case_root,
                    outcome_neutral=True,
                )
                registry: ArtifactRegistry = values["registry"]
                original: ArtifactRecord = values["statistics_record"]
                payload = json.loads(registry.get_bytes(original.sha256))
                payload[field] = value
                replacement = registry.put_json(
                    payload,
                    logical_type="statistical_analysis",
                    origin="SYSTEM_FIXTURE alternate checked bootstrap configuration",
                    creator_role=Role.STATISTICIAN,
                    creation_command=("test", "alternate-bootstrap-selection"),
                    parent_artifacts=original.parent_artifacts,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                values["statistics_record"] = replacement

                with self.assertRaisesRegex(ScientificPromotionError, "procedure v1"):
                    self._derive(values)

    def test_pre_fix_pooled_procedure_identities_are_ineligible(self) -> None:
        evaluator_root = self.root / "legacy-evaluator"
        evaluator_root.mkdir()
        evaluator_values = _registered_inputs(
            evaluator_root,
            outcome_neutral=True,
            evaluator_algorithm="paired_arithmetic_mean_v1",
        )
        with self.assertRaisesRegex(
            ScientificPromotionError,
            "supported evaluator implementation",
        ):
            self._derive(evaluator_values)

        statistics_root = self.root / "legacy-statistics"
        statistics_root.mkdir()
        statistics_values = _registered_inputs(
            statistics_root,
            outcome_neutral=True,
        )
        registry: ArtifactRegistry = statistics_values["registry"]
        original: ArtifactRecord = statistics_values["statistics_record"]
        payload = json.loads(registry.get_bytes(original.sha256))
        payload["effect_method"] = "paired_mean_directional_improvement"
        replacement = registry.put_json(
            payload,
            logical_type="statistical_analysis",
            origin="SYSTEM_FIXTURE legacy pooled procedure identity",
            creator_role=Role.STATISTICIAN,
            creation_command=("test", "legacy-pooled-procedure"),
            parent_artifacts=original.parent_artifacts,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        statistics_values["statistics_record"] = replacement
        with self.assertRaisesRegex(ScientificPromotionError, "substituted method"):
            self._derive(statistics_values)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
