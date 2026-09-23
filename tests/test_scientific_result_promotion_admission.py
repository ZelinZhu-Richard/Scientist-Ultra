"""Mechanical admission checks for outcome-neutral Result promotion v3.

These tests exercise only deterministic slot/publication validation.  They do
not install a scientific backend verifier or issue scientific evidence.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
    CheckedResultAssessment,
    HypothesisStatus,
    MetricScope,
    MetricUnit,
    ScientificPromotionError,
    ScientificResultPromotionReceiptV3,
    ScientificResultOutcome,
    _new_scientific_result_promotion_v3_event,
    _resolve_scientific_result_promotion_v3_event_from_events,
    _scientific_result_promotion_v3_event_binding,
    require_checked_result_assessment,
    require_scientific_result_promotion_authority_v3,
)


STAMP = "2026-09-04T12:00:00Z"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _record(
    label: str,
    *,
    logical_type: str = "system_fixture_result_source",
    parents: tuple[str, ...] = (),
) -> ArtifactRecord:
    sha256 = _hash(label)
    return ArtifactRecord(
        sha256=sha256,
        path=f"objects/{sha256}",
        relative_path=f"objects/{sha256}",
        metadata_path=f"metadata/{sha256}.json",
        logical_type=logical_type,
        schema_version="1.0",
        mime_type="application/json",
        size=2,
        origin="SYSTEM_FIXTURE mechanical admission object",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=("test", "mechanical-result-admission"),
        parent_artifacts=parents,
        validation_result="PASS",
        frozen=True,
        created_at=STAMP,
        record_hash=None,
    )


def _receipt(*, receipt_id: str = "receipt-primary") -> ScientificResultPromotionReceiptV3:
    return ScientificResultPromotionReceiptV3(
        receipt_id=receipt_id,
        ledger_run_id="ledger-run",
        execution_run_id="execution-run",
        result_id="result-primary",
        contract_artifact_sha256=_hash("contract"),
        checked_result_assessment_artifact_sha256=_hash("assessment"),
        scientific_execution_authority_artifact_sha256=_hash("execution"),
        scientific_timeline_receipt_artifact_sha256=_hash("timeline"),
        domain_validity_receipt_artifact_sha256=_hash("domain"),
        confirmation_authority_artifact_sha256=_hash("confirmation"),
    )


def _roots(
    receipt: ScientificResultPromotionReceiptV3,
) -> tuple[ArtifactRecord, tuple[ArtifactRecord, ...]]:
    sources = tuple(
        _record(f"source-{index}")
        for index, _value in enumerate(receipt.source_artifact_hashes)
    )
    # The deterministic event algorithm cares about exact ordered identities;
    # use the receipt's hashes while retaining unmistakable fixture metadata.
    sources = tuple(
        replace(record, sha256=artifact_sha256, record_hash=None)
        for record, artifact_sha256 in zip(sources, receipt.source_artifact_hashes)
    )
    receipt_record = replace(
        _record(
            "receipt-object",
            logical_type=SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
            parents=receipt.source_artifact_hashes,
        ),
        sha256=_hash("receipt-payload"),
        record_hash=None,
    )
    return receipt_record, sources


class ScientificResultPromotionAdmissionTests(unittest.TestCase):
    def test_exact_publication_event_round_trips_mechanically(self) -> None:
        receipt = _receipt()
        receipt_record, sources = _roots(receipt)
        binding = _scientific_result_promotion_v3_event_binding(
            receipt=receipt,
            receipt_record=receipt_record,
            source_records=sources,
        )
        event = _new_scientific_result_promotion_v3_event(
            receipt=receipt,
            events=(),
            receipt_record=receipt_record,
            source_records=sources,
            binding=binding,
        )

        self.assertEqual(
            _resolve_scientific_result_promotion_v3_event_from_events(
                (event,),
                receipt=receipt,
                receipt_record=receipt_record,
                source_records=sources,
                binding=binding,
            ),
            (event, 0),
        )

    def test_same_result_competing_publication_is_rejected(self) -> None:
        receipt = _receipt()
        receipt_record, sources = _roots(receipt)
        binding = _scientific_result_promotion_v3_event_binding(
            receipt=receipt,
            receipt_record=receipt_record,
            source_records=sources,
        )
        first = _new_scientific_result_promotion_v3_event(
            receipt=receipt,
            events=(),
            receipt_record=receipt_record,
            source_records=sources,
            binding=binding,
        )
        competing_receipt = _receipt(receipt_id="receipt-competing")
        competing_record = replace(
            receipt_record,
            sha256=_hash("competing-receipt"),
            record_hash=None,
        )
        competing_binding = _scientific_result_promotion_v3_event_binding(
            receipt=competing_receipt,
            receipt_record=competing_record,
            source_records=sources,
        )
        second = _new_scientific_result_promotion_v3_event(
            receipt=competing_receipt,
            events=(first,),
            receipt_record=competing_record,
            source_records=sources,
            binding=competing_binding,
        )

        with self.assertRaisesRegex(ScientificPromotionError, "substituted"):
            _resolve_scientific_result_promotion_v3_event_from_events(
                (first, second),
                receipt=receipt,
                receipt_record=receipt_record,
                source_records=sources,
                binding=binding,
            )

    def test_system_fixture_registry_slot_is_never_scientific_authority(self) -> None:
        with TemporaryDirectory(prefix="result-promotion-v3-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/ledger-run/registry")
            ledger = EventLedger(root, "runs/ledger-run/events.jsonl")
            source_records = tuple(
                registry.put_json(
                    {"fixture": index},
                    logical_type="system_fixture_result_source",
                    origin="SYSTEM_FIXTURE non-evidentiary result source",
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=("test", "mechanical-result-admission"),
                )
                for index in range(6)
            )
            receipt = ScientificResultPromotionReceiptV3(
                receipt_id="receipt-primary",
                ledger_run_id="ledger-run",
                execution_run_id="execution-run",
                result_id="result-primary",
                contract_artifact_sha256=source_records[0].sha256,
                checked_result_assessment_artifact_sha256=source_records[1].sha256,
                scientific_execution_authority_artifact_sha256=source_records[2].sha256,
                scientific_timeline_receipt_artifact_sha256=source_records[3].sha256,
                domain_validity_receipt_artifact_sha256=source_records[4].sha256,
                confirmation_authority_artifact_sha256=source_records[5].sha256,
            )
            forged = registry.put_json(
                receipt.to_dict(),
                logical_type=SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
                origin="SYSTEM_FIXTURE non-evidentiary forged promotion",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("test", "mechanical-result-admission"),
                parent_artifacts=receipt.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )

            with self.assertRaises(ScientificPromotionError):
                require_scientific_result_promotion_authority_v3(
                    registry,
                    ledger,
                    promotion_receipt_artifact_sha256=forged.sha256,
                    expected_ledger_run_id="ledger-run",
                    expected_execution_run_id="execution-run",
                    expected_result_id="result-primary",
                )

    def test_production_labeled_blob_without_publication_fails_closed(self) -> None:
        with TemporaryDirectory(prefix="result-promotion-v3-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/ledger-run/registry")
            ledger = EventLedger(root, "runs/ledger-run/events.jsonl")
            sources = tuple(
                registry.put_json(
                    {"fixture": index},
                    logical_type="system_fixture_result_source",
                    origin="SYSTEM_FIXTURE non-evidentiary result source",
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=("test", "mechanical-result-admission"),
                )
                for index in range(6)
            )
            receipt = ScientificResultPromotionReceiptV3(
                receipt_id="receipt-primary",
                ledger_run_id="ledger-run",
                execution_run_id="execution-run",
                result_id="result-primary",
                contract_artifact_sha256=sources[0].sha256,
                checked_result_assessment_artifact_sha256=sources[1].sha256,
                scientific_execution_authority_artifact_sha256=sources[2].sha256,
                scientific_timeline_receipt_artifact_sha256=sources[3].sha256,
                domain_validity_receipt_artifact_sha256=sources[4].sha256,
                confirmation_authority_artifact_sha256=sources[5].sha256,
            )
            forged = registry.put_json(
                receipt.to_dict(),
                logical_type=SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
                origin="source-owned outcome-neutral scientific result promotion",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "promote-scientific-result-v3"),
                parent_artifacts=receipt.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )

            with self.assertRaisesRegex(ScientificPromotionError, "publication event"):
                require_scientific_result_promotion_authority_v3(
                    registry,
                    ledger,
                    promotion_receipt_artifact_sha256=forged.sha256,
                    expected_ledger_run_id="ledger-run",
                    expected_execution_run_id="execution-run",
                    expected_result_id="result-primary",
                )

    def test_checked_assessment_replay_rejects_two_ids_for_one_execution(self) -> None:
        with TemporaryDirectory(prefix="checked-assessment-slot-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/ledger-run/registry")
            ledger = EventLedger(root, "runs/ledger-run/events.jsonl")
            sources = tuple(
                registry.put_json(
                    {"fixture": index},
                    logical_type="system_fixture_result_source",
                    origin="SYSTEM_FIXTURE non-evidentiary result source",
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=("test", "mechanical-result-admission"),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                for index in range(6)
            )
            assessment = CheckedResultAssessment(
                assessment_id="assessment-primary",
                ledger_run_id="ledger-run",
                execution_run_id="execution-run",
                hypothesis_id="hypothesis-primary",
                contract_artifact_sha256=sources[0].sha256,
                contract_sha256=_hash("contract-value"),
                contract_record_hash=str(sources[0].record_hash),
                scientific_execution_authority_artifact_sha256=sources[1].sha256,
                scientific_execution_authority_record_hash=str(
                    sources[1].record_hash
                ),
                frozen_run_spec_artifact_sha256=_hash("spec"),
                output_manifest_artifact_sha256=_hash("manifest"),
                aggregate_result_sha256=sources[2].sha256,
                aggregate_record_hash=str(sources[2].record_hash),
                statistical_analysis_sha256=sources[3].sha256,
                statistical_record_hash=str(sources[3].record_hash),
                evaluator_assessment_sha256=sources[4].sha256,
                evaluator_record_hash=str(sources[4].record_hash),
                scientific_obligations_sha256=sources[5].sha256,
                obligations_record_hash=str(sources[5].record_hash),
                baseline_exclusion_receipt_sha256s=(),
                baseline_exclusion_receipt_record_hashes=(),
                metric_id="metric-primary",
                metric_unit=MetricUnit.FRACTION,
                metric_scope=MetricScope.END_TO_END,
                baseline_id="baseline-primary",
                candidate_value=0.4,
                baseline_value=0.5,
                improvement_effect=-0.1,
                confidence_low=-0.2,
                confidence_high=0.0,
                adjusted_p_value=0.5,
                sample_size=20,
                hypothesis_status=HypothesisStatus.NOT_SUPPORTED,
                outcome=ScientificResultOutcome.NEGATIVE,
                scientific_evidence_eligible=True,
            )
            records = tuple(
                registry.put_json(
                    replace(
                        assessment,
                        assessment_id=assessment_id,
                    ).to_dict(),
                    logical_type="checked_result_assessment",
                    origin="source-owned outcome-neutral scientific result assessment",
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=("scientist-one", "assess-scientific-result"),
                    parent_artifacts=assessment.source_artifact_hashes,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                for assessment_id in (
                    "assessment-primary",
                    "assessment-competing",
                )
            )

            with self.assertRaisesRegex(ScientificPromotionError, "competing"):
                require_checked_result_assessment(
                    registry,
                    ledger,
                    assessment_artifact_sha256=records[0].sha256,
                    expected_ledger_run_id="ledger-run",
                    expected_execution_run_id="execution-run",
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
