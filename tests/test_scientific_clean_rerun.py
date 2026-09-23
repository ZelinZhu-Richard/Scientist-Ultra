"""Non-evidentiary DTO and fail-closed tests for scientific clean reruns."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
from scientist_one.reproduction import (
    ReproductionError,
    SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
    SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
    ScientificCleanRerunAuthority,
    ScientificCleanRerunOutcome,
    ScientificCleanRerunPlan,
    _matching_clean_rerun_plan_events,
    _locked_clean_rerun_snapshot,
    _require_clean_rerun_snapshot_unchanged,
    derive_scientific_clean_rerun_comparison,
    register_scientific_clean_rerun_authority,
    register_scientific_clean_rerun_plan,
    resolve_scientific_clean_rerun_authority,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    CheckedResultAssessment,
    HypothesisStatus,
    MetricScope,
    MetricUnit,
    ScientificPromotionError,
    ScientificResultOutcome,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ScientificCleanRerunTests(unittest.TestCase):
    """All DTOs below are synthetic, local, and never registered as science."""

    def _assessment(
        self,
        execution_id: str,
        *,
        candidate_value: float = 0.7,
        hypothesis_id: str = "hypothesis-primary",
    ) -> CheckedResultAssessment:
        return CheckedResultAssessment(
            assessment_id=f"assessment-{execution_id}",
            ledger_run_id="clean-rerun-ledger",
            execution_run_id=execution_id,
            hypothesis_id=hypothesis_id,
            contract_artifact_sha256=_hash("contract-artifact"),
            contract_sha256=_hash("contract"),
            contract_record_hash=_hash("contract-record"),
            scientific_execution_authority_artifact_sha256=_hash(
                f"execution-authority-{execution_id}"
            ),
            scientific_execution_authority_record_hash=_hash(
                f"execution-authority-record-{execution_id}"
            ),
            frozen_run_spec_artifact_sha256=_hash(f"spec-{execution_id}"),
            output_manifest_artifact_sha256=_hash(f"manifest-{execution_id}"),
            aggregate_result_sha256=_hash(f"aggregate-{execution_id}"),
            aggregate_record_hash=_hash(f"aggregate-record-{execution_id}"),
            statistical_analysis_sha256=_hash(f"statistics-{execution_id}"),
            statistical_record_hash=_hash(f"statistics-record-{execution_id}"),
            evaluator_assessment_sha256=_hash(f"evaluator-{execution_id}"),
            evaluator_record_hash=_hash(f"evaluator-record-{execution_id}"),
            scientific_obligations_sha256=_hash(f"obligations-{execution_id}"),
            obligations_record_hash=_hash(f"obligations-record-{execution_id}"),
            baseline_exclusion_receipt_sha256s=(),
            baseline_exclusion_receipt_record_hashes=(),
            metric_id="accuracy",
            metric_unit=MetricUnit.FRACTION,
            metric_scope=MetricScope.END_TO_END,
            baseline_id="baseline-primary",
            candidate_value=candidate_value,
            baseline_value=0.5,
            improvement_effect=candidate_value - 0.5,
            confidence_low=candidate_value - 0.5,
            confidence_high=candidate_value - 0.5,
            adjusted_p_value=0.01,
            sample_size=30,
            hypothesis_status=HypothesisStatus.SUPPORTED,
            outcome=ScientificResultOutcome.POSITIVE,
            scientific_evidence_eligible=True,
        )

    def _comparison(self):
        return derive_scientific_clean_rerun_comparison(
            self._assessment("original-execution"),
            self._assessment("rerun-execution"),
            comparison_tolerance=0.0,
        )

    def _plan(self) -> ScientificCleanRerunPlan:
        return ScientificCleanRerunPlan(
            plan_id="clean-rerun-plan",
            ledger_run_id="clean-rerun-ledger",
            original_result_id="original-result",
            rerun_result_id="rerun-result",
            rerun_assessment_id="rerun-assessment",
            rerun_domain="SYSTEMS",
            rerun_domain_task_id="rerun-task",
            original_execution_run_id="original-execution",
            rerun_execution_run_id="rerun-execution",
            original_result_promotion_artifact_sha256=_hash("promotion"),
            original_result_promotion_record_hash=_hash("promotion-record"),
            original_result_assessment_artifact_sha256=_hash("assessment-original"),
            original_result_assessment_record_hash=_hash("assessment-original-record"),
            original_execution_authority_artifact_sha256=_hash("authority-original"),
            original_execution_authority_record_hash=_hash("authority-original-record"),
            rerun_frozen_run_spec_artifact_sha256=_hash("spec-rerun"),
            rerun_frozen_run_spec_record_hash=_hash("spec-rerun-record"),
            scientific_binding_sha256=_hash("scientific-binding"),
            comparison_tolerance=0.0,
            exact_match_fields=(
                "contract_sha256",
                "hypothesis_id",
                "metric_id",
                "metric_unit",
                "metric_scope",
                "baseline_id",
                "sample_size",
                "hypothesis_status",
                "outcome",
            ),
            numeric_comparison_fields=(
                "candidate_value",
                "baseline_value",
                "improvement_effect",
                "confidence_low",
                "confidence_high",
                "adjusted_p_value",
            ),
            planned_at="2026-09-04T00:00:00Z",
            ledger_event_id="clean-rerun-plan-event",
            ledger_event_hash=_hash("plan-event"),
            ledger_event_index=0,
        )

    def _authority(self) -> ScientificCleanRerunAuthority:
        comparison = self._comparison()
        return ScientificCleanRerunAuthority(
            authority_id="clean-rerun-authority",
            ledger_run_id="clean-rerun-ledger",
            plan_artifact_sha256=_hash("plan"),
            plan_record_hash=_hash("plan-record"),
            original_result_promotion_artifact_sha256=_hash("promotion"),
            original_result_promotion_record_hash=_hash("promotion-record"),
            original_result_id="original-result",
            rerun_result_id="rerun-result",
            rerun_assessment_id="rerun-assessment",
            rerun_domain_validity_receipt_artifact_sha256=_hash(
                "rerun-domain-receipt"
            ),
            rerun_domain_validity_receipt_record_hash=_hash(
                "rerun-domain-receipt-record"
            ),
            rerun_domain="SYSTEMS",
            rerun_domain_task_id="rerun-task",
            rerun_domain_validity_status="PASS",
            rerun_domain_evidence_scope="SCIENTIFIC_EVIDENCE",
            original_result_assessment_artifact_sha256=_hash("assessment-original"),
            original_result_assessment_record_hash=_hash("assessment-original-record"),
            rerun_result_assessment_artifact_sha256=_hash("assessment-rerun"),
            rerun_result_assessment_record_hash=_hash("assessment-rerun-record"),
            original_execution_authority_artifact_sha256=_hash("authority-original"),
            original_execution_authority_record_hash=_hash("authority-original-record"),
            rerun_execution_authority_artifact_sha256=_hash("authority-rerun"),
            rerun_execution_authority_record_hash=_hash("authority-rerun-record"),
            original_execution_run_id="original-execution",
            rerun_execution_run_id="rerun-execution",
            original_preparation_artifact_sha256=_hash("preparation-original"),
            rerun_preparation_artifact_sha256=_hash("preparation-rerun"),
            original_output_manifest_artifact_sha256=_hash("manifest-original"),
            rerun_output_manifest_artifact_sha256=_hash("manifest-rerun"),
            original_environment_artifact_sha256=_hash("environment-original"),
            original_environment_record_hash=_hash("environment-original-record"),
            rerun_environment_artifact_sha256=_hash("environment-rerun"),
            rerun_environment_record_hash=_hash("environment-rerun-record"),
            original_isolation_attestation_artifact_sha256=_hash("isolation-original"),
            rerun_isolation_attestation_artifact_sha256=_hash("isolation-rerun"),
            original_environment_fingerprint=_hash("same-environment-fingerprint"),
            rerun_environment_fingerprint=_hash("same-environment-fingerprint"),
            original_host_instance_id="same-host",
            rerun_host_instance_id="same-host",
            original_boot_session_id="same-boot",
            rerun_boot_session_id="same-boot",
            original_writable_storage_id="original-storage",
            rerun_writable_storage_id="rerun-storage",
            original_backend_namespace_sha256=_hash("backend-profile-original"),
            rerun_backend_namespace_sha256=_hash("backend-profile-rerun"),
            original_backend_job_id="same-backend-job",
            rerun_backend_job_id="same-backend-job",
            original_provider_invocation_id="same-provider-invocation",
            rerun_provider_invocation_id="same-provider-invocation",
            original_cache_used=True,
            original_checkpoint_used=True,
            original_resumed_from_checkpoint=True,
            rerun_cache_used=False,
            rerun_checkpoint_used=False,
            rerun_resumed_from_checkpoint=False,
            original_challenge_nonce="a" * 64,
            rerun_challenge_nonce="b" * 64,
            exact_mismatches=comparison.exact_mismatches,
            differences=comparison.differences,
            outcome=comparison.outcome,
            verification_event_id="clean-rerun-authority-event",
            verification_event_hash=_hash("authority-event"),
            verification_event_index=1,
        )

    def test_mechanical_comparison_pass_fail_and_outside_tolerance_are_non_evidentiary(self) -> None:
        original = self._assessment("original-execution")
        passing = derive_scientific_clean_rerun_comparison(
            original, self._assessment("rerun-execution"), comparison_tolerance=0.0
        )
        self.assertEqual(passing.outcome, ScientificCleanRerunOutcome.PASS)
        self.assertEqual(passing.authority_scope, "NON_EVIDENTIARY_MECHANICAL_COMPARISON")
        self.assertFalse(passing.scientific_evidence)

        exact_fail = derive_scientific_clean_rerun_comparison(
            original,
            self._assessment("rerun-execution", hypothesis_id="hypothesis-other"),
            comparison_tolerance=1.0,
        )
        self.assertEqual(exact_fail.outcome, ScientificCleanRerunOutcome.FAIL)
        self.assertEqual(exact_fail.exact_mismatches, ("hypothesis_id",))

        outside = derive_scientific_clean_rerun_comparison(
            original,
            self._assessment("rerun-execution", candidate_value=0.8),
            comparison_tolerance=0.01,
        )
        self.assertEqual(outside.outcome, ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE)
        self.assertFalse(outside.scientific_evidence)

    def test_authority_dto_scopes_execution_ids_to_backend_namespace(self) -> None:
        authority = self._authority()
        self.assertTrue(authority.reproduction_passed)
        self.assertEqual(authority.original_host_instance_id, authority.rerun_host_instance_id)
        self.assertEqual(authority.original_boot_session_id, authority.rerun_boot_session_id)
        self.assertEqual(
            authority.original_environment_fingerprint,
            authority.rerun_environment_fingerprint,
        )
        self.assertEqual(authority.original_backend_job_id, authority.rerun_backend_job_id)
        self.assertEqual(
            authority.original_provider_invocation_id,
            authority.rerun_provider_invocation_id,
        )
        self.assertNotEqual(
            authority.original_backend_namespace_sha256,
            authority.rerun_backend_namespace_sha256,
        )
        for replacement in (
            {
                "rerun_backend_namespace_sha256": (
                    authority.original_backend_namespace_sha256
                )
            },
            {
                "rerun_backend_namespace_sha256": (
                    authority.original_backend_namespace_sha256
                ),
                "rerun_backend_job_id": "distinct-backend-job",
            },
        ):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ReproductionError):
                    replace(authority, **replacement)
        same_namespace_distinct_execution = replace(
            authority,
            rerun_backend_namespace_sha256=(
                authority.original_backend_namespace_sha256
            ),
            rerun_backend_job_id="distinct-backend-job",
            rerun_provider_invocation_id="distinct-provider-invocation",
        )
        self.assertTrue(same_namespace_distinct_execution.reproduction_passed)
        self.assertTrue(authority.original_checkpoint_used)
        for name in (
            "rerun_cache_used",
            "rerun_checkpoint_used",
            "rerun_resumed_from_checkpoint",
        ):
            with self.subTest(rerun_clean_flag=name):
                with self.assertRaises(ReproductionError):
                    replace(authority, **{name: True})
        for rerun_field, original_field in (
            ("rerun_execution_run_id", "original_execution_run_id"),
            (
                "rerun_execution_authority_artifact_sha256",
                "original_execution_authority_artifact_sha256",
            ),
            ("rerun_preparation_artifact_sha256", "original_preparation_artifact_sha256"),
            (
                "rerun_output_manifest_artifact_sha256",
                "original_output_manifest_artifact_sha256",
            ),
            ("rerun_environment_artifact_sha256", "original_environment_artifact_sha256"),
            (
                "rerun_isolation_attestation_artifact_sha256",
                "original_isolation_attestation_artifact_sha256",
            ),
            ("rerun_writable_storage_id", "original_writable_storage_id"),
            ("rerun_challenge_nonce", "original_challenge_nonce"),
        ):
            with self.subTest(rerun_field=rerun_field):
                with self.assertRaises(ReproductionError):
                    replace(authority, **{rerun_field: getattr(authority, original_field)})

    def test_plan_dto_requires_distinct_runs_fixed_fields_and_prospective_scope(self) -> None:
        plan = self._plan()
        self.assertFalse(plan.scientific_evidence)
        self.assertEqual(plan.authority_scope, "PROSPECTIVE_SCIENTIFIC_CLEAN_RERUN")
        with self.assertRaises(ReproductionError):
            replace(plan, rerun_execution_run_id=plan.original_execution_run_id)
        with self.assertRaises(ReproductionError):
            replace(plan, rerun_result_id=plan.original_result_id)
        with self.assertRaises(ReproductionError):
            replace(plan, exact_match_fields=plan.exact_match_fields[:-1])
        with self.assertRaises(ReproductionError):
            replace(plan, numeric_comparison_fields=plan.numeric_comparison_fields[:-1])
        with self.assertRaises(ReproductionError):
            replace(plan, scientific_evidence=True)

    def test_plan_slot_reserves_result_and_assessment_ids_across_plans(self) -> None:
        def event(
            plan_id: str,
            result_id: str,
            assessment_id: str,
            execution_id: str,
        ) -> LedgerEvent:
            return LedgerEvent.create(
                run_id="clean-rerun-ledger",
                actor_role=Role.PROTOCOL_DESIGNER,
                state_before=MacroState.PREFLIGHT,
                requested_state_after=MacroState.PREFLIGHT,
                artifact_hashes=(),
                code_version="test",
                configuration_hash=_hash("config"),
                reason="non-evidentiary slot test",
                prior_event_hash=None,
                event_type="CHECKPOINT",
                metadata={
                    "scientific_clean_rerun_plan": {
                        "plan_id": plan_id,
                        "rerun_result_id": result_id,
                        "rerun_assessment_id": assessment_id,
                        "rerun_execution_run_id": execution_id,
                    }
                },
            )

        events = (
            event("plan-one", "reserved-result", "assessment-one", "rerun-one"),
            event("plan-two", "reserved-result", "assessment-two", "rerun-two"),
        )
        matches = _matching_clean_rerun_plan_events(
            events,
            plan_id="plan-three",
            rerun_result_id="reserved-result",
            rerun_assessment_id="assessment-three",
            rerun_execution_run_id="rerun-three",
        )
        self.assertEqual(len(matches), 2)

        assessment_collision = (
            event("plan-one", "result-one", "reserved-assessment", "rerun-one"),
            event("plan-two", "result-two", "reserved-assessment", "rerun-two"),
        )
        matches = _matching_clean_rerun_plan_events(
            assessment_collision,
            plan_id="plan-three",
            rerun_result_id="result-three",
            rerun_assessment_id="reserved-assessment",
            rerun_execution_run_id="rerun-three",
        )
        self.assertEqual(len(matches), 2)

    def test_authority_requires_exact_scientific_rerun_domain_pass(self) -> None:
        authority = self._authority()
        for field_name, value in (
            ("rerun_domain_validity_status", "FAIL"),
            ("rerun_domain_evidence_scope", "NON_EVIDENTIARY_FIXTURE"),
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaises(ReproductionError):
                    replace(authority, **{field_name: value})

    def test_locked_snapshot_detects_registry_change_without_issuing_authority(self) -> None:
        with TemporaryDirectory(prefix="clean-rerun-snapshot-") as raw_root:
            root = Path(raw_root)
            registry = ArtifactRegistry(root, "runs/clean-rerun/registry")
            ledger = EventLedger(root, "runs/clean-rerun/events.jsonl")
            registry_snapshot, ledger_snapshot = _locked_clean_rerun_snapshot(
                registry,
                ledger,
                "clean-rerun-ledger",
            )
            registry.put_json(
                {"schema_version": "system-fixture/v1", "value": "changed"},
                logical_type="system_fixture.clean_rerun_snapshot_change",
                origin="test-only clean-rerun snapshot mutation",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "test-clean-rerun-snapshot"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(
                ReproductionError,
                "sources changed during fresh replay",
            ):
                _require_clean_rerun_snapshot_unchanged(
                    registry,
                    ledger,
                    "clean-rerun-ledger",
                    registry_snapshot,
                    ledger_snapshot,
                )
            self.assertFalse(
                any(
                    record.logical_type
                    in {
                        SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
                        SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
                    }
                    for record in registry.list_records()
                )
            )

    def test_empty_or_forged_registry_cannot_issue_or_resolve_clean_rerun_artifacts(self) -> None:
        with TemporaryDirectory(prefix="clean-rerun-registry-") as raw_root:
            root = Path(raw_root)
            registry = ArtifactRegistry(root, "runs/clean-rerun/registry")
            ledger = EventLedger(root, "runs/clean-rerun/events.jsonl")
            forged = _hash("forged-artifact")
            with self.assertRaises((ReproductionError, ScientificPromotionError)):
                register_scientific_clean_rerun_plan(
                    registry,
                    ledger,
                    plan_id="forged-plan",
                    ledger_run_id="clean-rerun-ledger",
                    original_result_id="forged-result",
                    rerun_result_id="forged-rerun-result",
                    rerun_assessment_id="forged-rerun-assessment",
                    rerun_domain="SYSTEMS",
                    rerun_domain_task_id="forged-rerun-task",
                    original_execution_run_id="original-execution",
                    original_result_promotion_artifact_sha256=forged,
                    rerun_frozen_run_spec_artifact_sha256=_hash("forged-spec"),
                )
            with self.assertRaises((ReproductionError, ScientificPromotionError)):
                resolve_scientific_clean_rerun_authority(
                    registry,
                    ledger,
                    plan_artifact_sha256=forged,
                    expected_ledger_run_id="clean-rerun-ledger",
                    expected_original_execution_run_id="original-execution",
                    expected_rerun_execution_run_id="rerun-execution",
                )
            with self.assertRaises((ReproductionError, ScientificPromotionError)):
                register_scientific_clean_rerun_authority(
                    registry,
                    ledger,
                    plan_artifact_sha256=forged,
                    rerun_result_assessment_artifact_sha256=_hash("forged-rerun"),
                    rerun_domain_validity_receipt_artifact_sha256=_hash(
                        "forged-domain"
                    ),
                    expected_ledger_run_id="clean-rerun-ledger",
                    expected_original_execution_run_id="original-execution",
                    expected_rerun_execution_run_id="rerun-execution",
                )
            self.assertFalse(
                any(
                    record.logical_type
                    in {
                        SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
                        SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
                    }
                    for record in registry.list_records()
                )
            )

    def test_unknown_rerun_domain_cannot_reserve_a_plan_slot(self) -> None:
        with self.assertRaisesRegex(ReproductionError, "domain is unsupported"):
            replace(self._plan(), rerun_domain="BOGUS")

        with TemporaryDirectory(prefix="clean-rerun-domain-") as raw_root:
            root = Path(raw_root)
            registry = ArtifactRegistry(root, "runs/clean-rerun/registry")
            ledger = EventLedger(root, "runs/clean-rerun/events.jsonl")
            with self.assertRaisesRegex(ReproductionError, "domain is unsupported"):
                register_scientific_clean_rerun_plan(
                    registry,
                    ledger,
                    plan_id="invalid-domain-plan",
                    ledger_run_id="clean-rerun-ledger",
                    original_result_id="original-result",
                    rerun_result_id="rerun-result",
                    rerun_assessment_id="rerun-assessment",
                    rerun_domain="BOGUS",
                    rerun_domain_task_id="rerun-task",
                    original_execution_run_id="original-execution",
                    original_result_promotion_artifact_sha256=_hash("promotion"),
                    rerun_frozen_run_spec_artifact_sha256=_hash("spec-rerun"),
                )
            self.assertEqual(registry.list_records(), ())
            self.assertEqual(ledger.events(), ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
