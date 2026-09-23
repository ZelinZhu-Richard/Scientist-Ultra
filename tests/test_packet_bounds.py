"""Focused defensive bounds for evaluator and release-packet metadata."""

from __future__ import annotations

from itertools import repeat
from pathlib import Path
import types
import unittest
from unittest import mock

from scientist_one.evaluators import (
    Decision,
    Evaluation,
    EvaluatorClass,
    MAX_EVALUATION_ARTIFACT_HASHES,
    MAX_EVALUATION_REASON_BYTES,
    MAX_EVALUATION_RECEIPTS,
    RCheck,
    AuditSummary,
    require_gate,
)
from scientist_one.packaging import (
    MAX_INVENTORY_ENTRIES,
    PackagingError,
    _inventory_plan_from_bytes,
    _ledger_evaluator_projection,
)
from scientist_one.roles import Role, transition_role_context_sha256
from scientist_one.security import canonical_json_bytes
from scientist_one.state_machine import legacy_evaluation_receipt


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class EvaluatorMetadataBoundTests(unittest.TestCase):
    def test_evaluation_rejects_oversized_receipt_collections_and_reason(self) -> None:
        digest = "a" * 64
        with self.assertRaisesRegex(ValueError, "bounded SHA-256 tuple"):
            Evaluation(
                EvaluatorClass.E0,
                Role.ORCHESTRATOR,
                Decision.PASS,
                (digest,) * (MAX_EVALUATION_ARTIFACT_HASHES + 1),
                "bounded review",
            )
        with self.assertRaisesRegex(ValueError, "bounded text"):
            Evaluation(
                EvaluatorClass.E0,
                Role.ORCHESTRATOR,
                Decision.PASS,
                (),
                "x" * (MAX_EVALUATION_REASON_BYTES + 1),
            )
        with self.assertRaisesRegex(ValueError, "bounded typed tuple"):
            Evaluation(
                EvaluatorClass.E0,
                Role.ORCHESTRATOR,
                Decision.PASS,
                (),
                "bounded review",
                (RCheck.R0,) * (len(RCheck) + 1),
            )

    def test_evaluation_accepts_legitimate_bounded_receipt(self) -> None:
        evaluation = Evaluation(
            EvaluatorClass.E2,
            Role.SCIENTIFIC_REVIEWER,
            Decision.PASS,
            tuple(
                f"{index:064x}"
                for index in range(MAX_EVALUATION_ARTIFACT_HASHES)
            ),
            "x" * MAX_EVALUATION_REASON_BYTES,
            tuple(RCheck),
            producer_role=Role.PROTOCOL_DESIGNER,
        )
        self.assertEqual(len(evaluation.sha256), 64)

    def test_ledger_projection_rejects_oversized_evaluator_receipt(self) -> None:
        base_output = {
            "evaluator_class": "E0",
            "authority": Role.ORCHESTRATOR.value,
            "decision": "PASS",
            "critical_objection": False,
            "artifact_hashes": [],
            "evaluation_sha256": "f" * 64,
            "frozen_context_sha256": "0" * 64,
            "producer_role": None,
            "reason": "bounded review",
            "r_checks": [],
            "logically_separated": True,
            "human_independence_claimed": False,
            "run_id": "run-bounds",
            "gate_id": "E0:CALIBRATE",
        }
        unsafe_values = (
            (
                "artifact_hashes",
                ["e" * 64] * (MAX_EVALUATION_ARTIFACT_HASHES + 1),
            ),
            ("artifact_hashes", ["e" * 65]),
            ("reason", "é" * MAX_EVALUATION_REASON_BYTES),
            ("r_checks", [RCheck.R0.value] * (len(RCheck) + 1)),
            ("r_checks", ["R" * (MAX_EVALUATION_REASON_BYTES + 1)]),
        )
        for field, value in unsafe_values:
            with self.subTest(field=field):
                output = {**base_output, field: value}
                event = types.SimpleNamespace(
                    metadata={"evaluator_keys": ["E0:CALIBRATE"]},
                    evaluator_outputs=(output,),
                    event_type="TRANSITION",
                    state_before=types.SimpleNamespace(value="CALIBRATE"),
                    requested_state_after=types.SimpleNamespace(value="CHARTER"),
                )
                with mock.patch(
                    "scientist_one.packaging.canonical_json_bytes",
                    side_effect=AssertionError("canonicalization must not run"),
                ) as canonicalize, self.assertRaisesRegex(
                    PackagingError, "receipt is malformed"
                ):
                    _ledger_evaluator_projection((event,))
                canonicalize.assert_not_called()

    def test_ledger_projection_accepts_exact_bounded_evaluator_receipt(self) -> None:
        hashes = tuple(
            f"{index:064x}" for index in range(MAX_EVALUATION_ARTIFACT_HASHES)
        )
        reason = "x" * MAX_EVALUATION_REASON_BYTES
        evaluation = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            hashes,
            reason,
            tuple(RCheck),
            run_id="run-bounds",
            gate_id="E0:CALIBRATE",
            frozen_context_sha256=transition_role_context_sha256(
                Role.ORCHESTRATOR,
                "run-bounds",
                hashes,
                "E0:CALIBRATE",
            ),
        )
        output = legacy_evaluation_receipt(evaluation)
        event = types.SimpleNamespace(
            metadata={"evaluator_keys": ["E0:CALIBRATE"]},
            evaluator_outputs=(output,),
            event_type="TRANSITION",
            state_before=types.SimpleNamespace(value="CALIBRATE"),
            requested_state_after=types.SimpleNamespace(value="CHARTER"),
        )
        self.assertEqual(
            _ledger_evaluator_projection((event,)),
            {"E0:CALIBRATE": output},
        )

    def test_evaluator_receipt_collections_are_bounded_before_retention(self) -> None:
        evaluation = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            (),
            "bounded review",
        )
        summary = AuditSummary([evaluation] * MAX_EVALUATION_RECEIPTS)
        with self.assertRaisesRegex(ValueError, "bounded receipt list"):
            summary.add(evaluation)
        with self.assertRaisesRegex(ValueError, "bounded receipt list"):
            AuditSummary([evaluation] * (MAX_EVALUATION_RECEIPTS + 1))
        with self.assertRaisesRegex(ValueError, "bounded typed collection"):
            require_gate(
                AuditSummary([], "f" * 64),
                repeat(EvaluatorClass.E0),
                r_checks=(RCheck.R0,),
                registry=object(),
                ledger=object(),
                run_id="run-1",
            )


class SnapshotMetadataBoundTests(unittest.TestCase):
    def test_combined_snapshot_input_rejects_inventory_entry_overflow(self) -> None:
        entries = [
            {
                "path": f"src/scientist_one/z{index:04d}.py",
                "sha256": "c" * 64,
                "size": 0,
            }
            for index in range(MAX_INVENTORY_ENTRIES + 1)
        ]
        payload = canonical_json_bytes(
            {
                "schema_version": "1.0",
                "kind": "FROZEN_SOURCE_INVENTORY",
                "entries": entries,
                "aggregate_sha256": "d" * 64,
            }
        )
        with self.assertRaisesRegex(PackagingError, "frozen schema"):
            _inventory_plan_from_bytes(
                PROJECT_ROOT,
                payload,
                "frozen_source_inventory",
                require_live=False,
            )


if __name__ == "__main__":
    unittest.main()
