"""Non-authoritative compatibility tests for checked-result assessments.

The test records here are explicitly non-evidentiary registry fixtures.  They
never represent scientific-execution, domain, projection, or admissibility
authority and never invoke a verifier map.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.errors import ArtifactCorruptionError
from scientist_one.execution_admissibility import (
    FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
    ScientificExecutionAdmissibilityPolicy,
)
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
import scientist_one.scientific_design as scientific_design
from scientist_one.scientific_design import (
    CHECKED_RESULT_ASSESSMENT_LOGICAL_TYPE,
    CHECKED_RESULT_ASSESSMENT_SCHEMA,
    CHECKED_RESULT_ASSESSMENT_SCHEMA_V2,
    CheckedResultAssessment,
    HypothesisStatus,
    MetricDirection,
    MetricScope,
    MetricUnit,
    ScientificPromotionError,
    ScientificResultOutcome,
    _derive_checked_result_evidence,
    build_checked_result_assessment,
    build_projection_checked_result_assessment,
    register_frozen_evaluation_contract,
)
from scientist_one.security import canonical_json_bytes

try:
    from .test_superiority_authority import _checked_contract, _registered_inputs
except ImportError:  # Direct unittest discovery can load this module at top level.
    from test_superiority_authority import (  # type: ignore[no-redef]
        _checked_contract,
        _registered_inputs,
    )


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ProjectionCheckedResultAssessmentTests(unittest.TestCase):
    """Compatibility and slot checks that confer no scientific authority."""

    def _assessment(
        self,
        *,
        projection_backed: bool,
        support_records: tuple[ArtifactRecord, ...] | None = None,
        assessment_id: str = "non-evidentiary-assessment",
        execution_run_id: str = "non-evidentiary-execution",
        execution_authority_sha256: str | None = None,
    ) -> CheckedResultAssessment:
        def value(label: str) -> str:
            return _digest(f"non-evidentiary:{label}")

        supports = support_records or ()
        contract = supports[0] if len(supports) > 0 else None
        execution = supports[1] if len(supports) > 1 else None
        aggregate = supports[2] if len(supports) > 2 else None
        statistics = supports[3] if len(supports) > 3 else None
        legacy_or_projection_one = supports[4] if len(supports) > 4 else None
        legacy_or_projection_two = supports[5] if len(supports) > 5 else None
        projection_domain = supports[6] if len(supports) > 6 else None
        return CheckedResultAssessment(
            assessment_id=assessment_id,
            ledger_run_id="non-evidentiary-ledger",
            execution_run_id=execution_run_id,
            hypothesis_id="non-evidentiary-hypothesis",
            contract_artifact_sha256=(contract.sha256 if contract else value("contract")),
            contract_sha256=value("contract-content"),
            contract_record_hash=(
                str(contract.record_hash) if contract else value("contract-record")
            ),
            scientific_execution_authority_artifact_sha256=(
                execution_authority_sha256
                or (execution.sha256 if execution else value("execution"))
            ),
            scientific_execution_authority_record_hash=(
                str(execution.record_hash) if execution else value("execution-record")
            ),
            frozen_run_spec_artifact_sha256=value("run-spec"),
            output_manifest_artifact_sha256=value("manifest"),
            aggregate_result_sha256=(aggregate.sha256 if aggregate else value("aggregate")),
            aggregate_record_hash=(
                str(aggregate.record_hash) if aggregate else value("aggregate-record")
            ),
            statistical_analysis_sha256=(
                statistics.sha256 if statistics else value("statistics")
            ),
            statistical_record_hash=(
                str(statistics.record_hash) if statistics else value("statistics-record")
            ),
            evaluator_assessment_sha256=(
                None if projection_backed else (
                    legacy_or_projection_one.sha256
                    if legacy_or_projection_one
                    else value("evaluator")
                )
            ),
            evaluator_record_hash=(
                None if projection_backed else (
                    str(legacy_or_projection_one.record_hash)
                    if legacy_or_projection_one
                    else value("evaluator-record")
                )
            ),
            scientific_obligations_sha256=(
                None if projection_backed else (
                    legacy_or_projection_two.sha256
                    if legacy_or_projection_two
                    else value("obligations")
                )
            ),
            obligations_record_hash=(
                None if projection_backed else (
                    str(legacy_or_projection_two.record_hash)
                    if legacy_or_projection_two
                    else value("obligations-record")
                )
            ),
            baseline_exclusion_receipt_sha256s=(),
            baseline_exclusion_receipt_record_hashes=(),
            metric_id="non-evidentiary-metric",
            metric_unit=MetricUnit.FRACTION,
            metric_scope=MetricScope.END_TO_END,
            baseline_id="non-evidentiary-baseline",
            candidate_value=0.4,
            baseline_value=0.5,
            improvement_effect=-0.1,
            confidence_low=-0.2,
            confidence_high=0.0,
            adjusted_p_value=0.5,
            sample_size=24,
            hypothesis_status=HypothesisStatus.NOT_SUPPORTED,
            outcome=ScientificResultOutcome.NEGATIVE,
            scientific_evidence_eligible=True,
            generic_ml_paired_metric_projection_authority_artifact_sha256=(
                legacy_or_projection_one.sha256
                if projection_backed and legacy_or_projection_one
                else (value("projection") if projection_backed else None)
            ),
            generic_ml_paired_metric_projection_authority_record_hash=(
                str(legacy_or_projection_one.record_hash)
                if projection_backed and legacy_or_projection_one
                else (value("projection-record") if projection_backed else None)
            ),
            scientific_execution_admissibility_authority_artifact_sha256=(
                legacy_or_projection_two.sha256
                if projection_backed and legacy_or_projection_two
                else (value("admissibility") if projection_backed else None)
            ),
            scientific_execution_admissibility_authority_record_hash=(
                str(legacy_or_projection_two.record_hash)
                if projection_backed and legacy_or_projection_two
                else (value("admissibility-record") if projection_backed else None)
            ),
            domain_validity_receipt_artifact_sha256=(
                projection_domain.sha256
                if projection_backed and projection_domain
                else (value("domain-validity") if projection_backed else None)
            ),
            domain_validity_receipt_record_hash=(
                str(projection_domain.record_hash)
                if projection_backed and projection_domain
                else (value("domain-validity-record") if projection_backed else None)
            ),
        )

    def test_v1_byte_shape_is_preserved_and_v2_roundtrips_exactly(self) -> None:
        v1_assessment = self._assessment(projection_backed=False)
        v1 = v1_assessment.to_dict()
        self.assertEqual(v1["schema_version"], CHECKED_RESULT_ASSESSMENT_SCHEMA)
        self.assertNotIn(
            "generic_ml_paired_metric_projection_authority_artifact_sha256", v1
        )
        self.assertNotIn(
            "scientific_execution_admissibility_authority_artifact_sha256", v1
        )
        self.assertEqual(
            canonical_json_bytes(CheckedResultAssessment.from_dict(v1).to_dict()),
            canonical_json_bytes(v1),
        )

        v2_assessment = self._assessment(projection_backed=True)
        v2 = v2_assessment.to_dict()
        self.assertEqual(v2["schema_version"], CHECKED_RESULT_ASSESSMENT_SCHEMA_V2)
        self.assertNotIn("evaluator_assessment_sha256", v2)
        self.assertNotIn("scientific_obligations_sha256", v2)
        self.assertEqual(CheckedResultAssessment.from_dict(v2), v2_assessment)

        with self.assertRaisesRegex(ScientificPromotionError, "one source-owner version"):
            replace(
                v1_assessment,
                generic_ml_paired_metric_projection_authority_artifact_sha256=(
                    _digest("mixed-projection")
                ),
                generic_ml_paired_metric_projection_authority_record_hash=(
                    _digest("mixed-projection-record")
                ),
                scientific_execution_admissibility_authority_artifact_sha256=(
                    _digest("mixed-admissibility")
                ),
                scientific_execution_admissibility_authority_record_hash=(
                    _digest("mixed-admissibility-record")
                ),
                domain_validity_receipt_artifact_sha256=(
                    _digest("mixed-domain-validity")
                ),
                domain_validity_receipt_record_hash=(
                    _digest("mixed-domain-validity-record")
                ),
            )

    def test_repeated_seed_unit_aggregation_uses_unique_units_without_inflating_n(self) -> None:
        with TemporaryDirectory(prefix="projection-checked-result-units-") as directory:
            values = _registered_inputs(
                Path(directory),
                outcome_neutral=True,
                candidate_value=0.8,
                candidate_values_by_seed={7: 0.6, 11: 0.8, 19: 1.0},
                baseline_value=0.5,
            )
            evidence = _derive_checked_result_evidence(
                values["registry"],
                contract_artifact_sha256=values["contract_record"].sha256,
                aggregate_result_sha256=values["aggregate_record"].sha256,
                statistical_analysis_sha256=values["statistics_record"].sha256,
                evaluator_assessment_sha256=values["evaluator_record"].sha256,
                scientific_obligations_sha256=values["obligations_record"].sha256,
                baseline_exclusion_receipt_sha256s=(),
            )
            self.assertEqual(len(evidence.execution.spec.seeds), 3)
            self.assertEqual(evidence.facts.sample_size, 24)
            self.assertEqual(len(evidence.execution.paired_unit_ids), 24)
            self.assertAlmostEqual(evidence.facts.improvement_effect, 0.3)
            self.assertTrue(
                all(
                    abs(value - 0.8) < 1e-12
                    for value in evidence.execution.candidate_values
                )
            )

    def test_target_is_best_is_rejected_by_checked_unit_seed_procedure(self) -> None:
        with TemporaryDirectory(prefix="projection-checked-result-target-") as directory:
            values = _registered_inputs(
                Path(directory),
                outcome_neutral=True,
                metric_direction=MetricDirection.TARGET_IS_BEST,
                target_value=0.5,
                candidate_value=1.0 / 3.0,
                candidate_values_by_seed={7: 0.0, 11: 1.0, 19: 0.0},
                baseline_value=0.25,
            )
            with self.assertRaisesRegex(ScientificPromotionError, "TARGET_IS_BEST"):
                _derive_checked_result_evidence(
                    values["registry"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    aggregate_result_sha256=values["aggregate_record"].sha256,
                    statistical_analysis_sha256=values["statistics_record"].sha256,
                    evaluator_assessment_sha256=values["evaluator_record"].sha256,
                    scientific_obligations_sha256=values["obligations_record"].sha256,
                    baseline_exclusion_receipt_sha256s=(),
                )

    def test_legacy_builder_rejects_prospective_v3_contract_before_sources(self) -> None:
        with TemporaryDirectory(prefix="projection-checked-result-v3-legacy-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/non-evidentiary/registry")
            ledger = EventLedger(root, "runs/non-evidentiary/events.jsonl")
            parent = registry.put_json(
                {"fixture": "non-evidentiary-v3-contract-parent"},
                logical_type="non_evidentiary_contract_source",
                origin="explicitly non-evidentiary contract fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("test", "projection-checked-result"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            contract = replace(
                _checked_contract(outcome_neutral=True),
                version=3,
                stopping_criteria=FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
                scientific_execution_admissibility_policy=(
                    ScientificExecutionAdmissibilityPolicy()
                ),
            )
            contract_record = register_frozen_evaluation_contract(
                registry,
                contract=contract,
                parent_artifact_sha256s=(parent.sha256,),
            )
            before = registry.verify_all(raise_on_error=True)
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "v3 contracts reject legacy",
            ):
                build_checked_result_assessment(
                    registry,
                    ledger,
                    assessment_id="non-evidentiary-legacy-assessment",
                    expected_ledger_run_id="non-evidentiary-ledger",
                    expected_execution_run_id="non-evidentiary-execution",
                    contract_artifact_sha256=contract_record.sha256,
                    scientific_execution_authority_artifact_sha256=(
                        _digest("missing-execution-authority")
                    ),
                    aggregate_result_sha256=_digest("missing-aggregate"),
                    statistical_analysis_sha256=_digest("missing-statistics"),
                    evaluator_assessment_sha256=_digest("missing-evaluator"),
                    scientific_obligations_sha256=_digest("missing-obligations"),
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), before)
            self.assertEqual(ledger.validate().event_count, 0)

    def test_registry_metadata_dispatch_detects_competing_v1_v2_execution_slot(self) -> None:
        for first_version in ("v1", "v2"):
            with self.subTest(first_version=first_version), TemporaryDirectory(
                prefix=f"projection-checked-result-slot-{first_version}-"
            ) as directory:
                root = Path(directory)
                registry = ArtifactRegistry(root, "runs/non-evidentiary/registry")
                support_records = tuple(
                    registry.put_json(
                        {"fixture": f"non-evidentiary-source-{index}"},
                        logical_type="non_evidentiary_assessment_source",
                        origin="explicitly non-evidentiary assessment fixture",
                        creator_role=Role.CLAIM_VERIFIER,
                        creation_command=("test", "projection-checked-result"),
                        schema_version="1.0",
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )
                    for index in range(9)
                )
                v1 = self._assessment(
                    projection_backed=False,
                    support_records=support_records[:6],
                )
                v2 = self._assessment(
                    projection_backed=True,
                    support_records=(
                        support_records[0],
                        support_records[1],
                        support_records[2],
                        support_records[3],
                        support_records[6],
                        support_records[7],
                        support_records[8],
                    ),
                    assessment_id="non-evidentiary-assessment-v2",
                    execution_authority_sha256=(
                        v1.scientific_execution_authority_artifact_sha256
                    ),
                )

                def put(assessment: CheckedResultAssessment) -> ArtifactRecord:
                    projection_backed = assessment.is_projection_backed
                    return registry.put_json(
                        assessment.to_dict(),
                        logical_type=CHECKED_RESULT_ASSESSMENT_LOGICAL_TYPE,
                        origin=(
                            scientific_design._CHECKED_RESULT_ASSESSMENT_V2_ORIGIN
                            if projection_backed
                            else scientific_design._CHECKED_RESULT_ASSESSMENT_ORIGIN
                        ),
                        creator_role=Role.CLAIM_VERIFIER,
                        creation_command=(
                            scientific_design._CHECKED_RESULT_ASSESSMENT_V2_COMMAND
                            if projection_backed
                            else scientific_design._CHECKED_RESULT_ASSESSMENT_COMMAND
                        ),
                        parent_artifacts=assessment.source_artifact_hashes,
                        schema_version="2.0" if projection_backed else "1.0",
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )

                first, second = (v1, v2) if first_version == "v1" else (v2, v1)
                first_record = put(first)
                self.assertEqual(
                    scientific_design._matching_checked_result_assessment_records(
                        registry,
                        registry.verify_all(raise_on_error=True),
                        assessment=first,
                    ),
                    ((first_record, first),),
                )
                put(second)
                with self.assertRaisesRegex(
                    ScientificPromotionError,
                    "competing execution slots",
                ):
                    scientific_design._matching_checked_result_assessment_records(
                        registry,
                        registry.verify_all(raise_on_error=True),
                        assessment=first,
                    )

    def test_v2_builder_fails_closed_without_real_source_owners_and_writes_nothing(self) -> None:
        with TemporaryDirectory(prefix="projection-checked-result-empty-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/non-evidentiary/registry")
            ledger = EventLedger(root, "runs/non-evidentiary/events.jsonl")
            with self.assertRaises(ArtifactCorruptionError):
                build_projection_checked_result_assessment(
                    registry,
                    ledger,
                    assessment_id="non-evidentiary-assessment",
                    expected_ledger_run_id="non-evidentiary-ledger",
                    expected_execution_run_id="non-evidentiary-execution",
                    generic_ml_projection_artifact_sha256=_digest("missing-projection"),
                    scientific_execution_admissibility_authority_artifact_sha256=(
                        _digest("missing-admissibility")
                    ),
                    domain_validity_receipt_artifact_sha256=(
                        _digest("missing-domain-validity")
                    ),
                )
            self.assertEqual(registry.verify_all(raise_on_error=True).count, 0)
            self.assertEqual(ledger.validate().event_count, 0)


if __name__ == "__main__":
    unittest.main()
