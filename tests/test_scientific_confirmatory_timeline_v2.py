"""Non-evidentiary structural tests for the v2 confirmatory timeline.

No fixture in this module represents independent custody, a scientific result,
or a production verifier.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from types import MappingProxyType
import unittest

import scientist_one.scientific_design as scientific_design
from scientist_one.scientific_design import (
    ScientificConfirmatoryTimelineReceiptV2,
    ScientificConfirmatoryTimelineResolutionStatus,
    ScientificConfirmatoryTimelineUnavailable,
    ScientificDesignError,
    ScientificPromotionError,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ScientificConfirmatoryTimelineV2Tests(unittest.TestCase):
    """Typed chronology is not an independent-custody issuance path."""

    def _receipt(self) -> ScientificConfirmatoryTimelineReceiptV2:
        def source(name: str) -> str:
            return _digest(f"non-evidentiary-source:{name}")

        protocol = source("protocol-binding")
        execution = source("scientific-execution-authority")
        projection = source("generic-ml-projection")
        timeline = source("legacy-timeline")
        reveal = source("reveal-gate")
        protocol_record = source("protocol-binding-record")
        execution_record = source("scientific-execution-authority-record")
        projection_record = source("generic-ml-projection-record")
        timeline_record = source("legacy-timeline-record")
        reveal_record = source("reveal-gate-record")
        event_hashes = {
            name: source(f"event:{name}")
            for name in (
                "design",
                "preparation",
                "custody",
                "binding",
                "started",
                "execution",
                "reveal",
                "result",
                "projection",
            )
        }
        return ScientificConfirmatoryTimelineReceiptV2(
            receipt_id="non-evidentiary-timeline",
            ledger_run_id="non-evidentiary-ledger",
            execution_run_id="non-evidentiary-execution",
            protocol_binding_artifact_sha256=protocol,
            protocol_binding_record_hash=protocol_record,
            contract_artifact_sha256=source("contract"),
            contract_record_hash=source("contract-record"),
            scientific_execution_preparation_artifact_sha256=source("preparation"),
            scientific_execution_preparation_record_hash=source("preparation-record"),
            scientific_execution_authority_artifact_sha256=execution,
            scientific_execution_authority_record_hash=execution_record,
            output_manifest_artifact_sha256=source("manifest"),
            output_manifest_record_hash=source("manifest-record"),
            generic_ml_projection_artifact_sha256=projection,
            generic_ml_projection_record_hash=projection_record,
            confirmatory_timeline_receipt_artifact_sha256=timeline,
            confirmatory_timeline_receipt_record_hash=timeline_record,
            confirmation_reveal_gate_receipt_artifact_sha256=reveal,
            confirmation_reveal_gate_receipt_record_hash=reveal_record,
            direct_source_artifact_sha256s=(
                protocol,
                execution,
                projection,
                timeline,
                reveal,
            ),
            direct_source_artifact_record_hashes=(
                protocol_record,
                execution_record,
                projection_record,
                timeline_record,
                reveal_record,
            ),
            design_freeze_event_id="non-evidentiary-design",
            design_freeze_event_hash=event_hashes["design"],
            design_freeze_event_index=0,
            preparation_event_id="non-evidentiary-preparation",
            preparation_event_hash=event_hashes["preparation"],
            preparation_event_index=1,
            custody_freeze_event_id="non-evidentiary-custody",
            custody_freeze_event_hash=event_hashes["custody"],
            custody_freeze_event_index=2,
            protocol_binding_event_id="non-evidentiary-binding",
            protocol_binding_event_hash=event_hashes["binding"],
            protocol_binding_event_index=3,
            confirmatory_started_event_id="non-evidentiary-started",
            confirmatory_started_event_hash=event_hashes["started"],
            confirmatory_started_event_index=4,
            execution_event_id="non-evidentiary-execution-event",
            execution_event_hash=event_hashes["execution"],
            execution_event_index=5,
            reveal_event_id="non-evidentiary-reveal",
            reveal_event_hash=event_hashes["reveal"],
            reveal_event_index=6,
            result_visibility_event_id="non-evidentiary-result",
            result_visibility_event_hash=event_hashes["result"],
            result_visibility_event_index=7,
            projection_event_id="non-evidentiary-projection",
            projection_event_hash=event_hashes["projection"],
            projection_event_index=8,
            ledger_prefix_head_hash=event_hashes["projection"],
            scientific_gate_passed=True,
        )

    def test_receipt_accepts_exact_chronology_and_roundtrips(self) -> None:
        receipt = self._receipt()

        self.assertTrue(receipt.scientific_gate_passed)
        self.assertEqual(
            ScientificConfirmatoryTimelineReceiptV2.from_dict(receipt.to_dict()),
            receipt,
        )

    def test_receipt_rejects_reversed_chronology_substitution_and_closed_gate(self) -> None:
        receipt = self._receipt()
        with self.assertRaisesRegex(ScientificPromotionError, "chronology"):
            replace(receipt, reveal_event_index=receipt.execution_event_index)
        with self.assertRaisesRegex(ScientificPromotionError, "source closure"):
            replace(
                receipt,
                direct_source_artifact_sha256s=tuple(
                    reversed(receipt.direct_source_artifact_sha256s)
                ),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "custody gate"):
            replace(receipt, scientific_gate_passed=False)

    def test_unavailable_preserves_blocked_status_and_refuses_verified(self) -> None:
        for status in (
            ScientificConfirmatoryTimelineResolutionStatus.BLOCKED_LOCAL,
            ScientificConfirmatoryTimelineResolutionStatus.BLOCKED_EXTERNAL,
        ):
            with self.subTest(status=status):
                unavailable = ScientificConfirmatoryTimelineUnavailable(
                    status,
                    "NON_EVIDENTIARY_FIXTURE_BLOCKED",
                    "No independent custody is represented by this fixture.",
                )
                self.assertIs(unavailable.resolution_status, status)
                self.assertEqual(
                    unavailable.reason_code, "NON_EVIDENTIARY_FIXTURE_BLOCKED"
                )
        with self.assertRaisesRegex(ScientificDesignError, "cannot be unavailable"):
            ScientificConfirmatoryTimelineUnavailable(
                ScientificConfirmatoryTimelineResolutionStatus.VERIFIED,
                "SHOULD_NOT_EXIST",
                "A verified timeline is never unavailable.",
            )

    def test_independent_custody_verifier_map_is_closed_empty_and_immutable(self) -> None:
        verifiers = scientific_design._SCIENTIFIC_CONFIRMATORY_INDEPENDENT_CUSTODY_VERIFIERS

        self.assertIsInstance(verifiers, MappingProxyType)
        self.assertEqual(dict(verifiers), {})
        with self.assertRaises(TypeError):
            verifiers[("non-evidentiary", "v1")] = object()  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
