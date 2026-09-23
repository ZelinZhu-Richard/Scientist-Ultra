"""Operational visibility and fail-closed verification for vNext fixtures."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.autonomous_implementation import (
    PROVIDER_NEUTRALITY_SCHEMA_VERSION,
)
from scientist_one.ledger import EventLedger
from scientist_one.orchestrator import (
    VNEXT_MAX_RESTART_LINEAGE_DEPTH,
    OrchestrationError,
    ScientistOneOrchestrator,
    _consume_guarded_launch_capability,
    _consume_guarded_restart_lineage,
    _replay_vnext_autonomous_summary_roots,
)
from scientist_one.research_os import _write_fixture_operation_status
import scientist_one.research_os as research_os_module
from scientist_one.roles import Role


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NOTICE = (
    "Synthetic integration fixture only; no publishable scientific conclusion."
)


def _copy_fixture_tree(destination: Path) -> None:
    shutil.copytree(
        PROJECT_ROOT / "src" / "scientist_one",
        destination / "src" / "scientist_one",
    )
    (destination / "scripts").mkdir(parents=True)
    shutil.copy2(
        PROJECT_ROOT / "scripts" / "vnext_fixture_experiment.py",
        destination / "scripts" / "vnext_fixture_experiment.py",
    )
    (destination / "fixtures").mkdir(parents=True)
    shutil.copy2(
        PROJECT_ROOT / "fixtures" / "vnext_research_dataset.json",
        destination / "fixtures" / "vnext_research_dataset.json",
    )
    shutil.copytree(PROJECT_ROOT / "configs", destination / "configs")


@contextlib.contextmanager
def _without_captured_evidence_dispatch():
    """Model a production dispatch inside the captured evidence test worker."""

    attribute = "_scientist_one_captured_evidence_capability"
    sentinel = object()
    previous = sys.__dict__.pop(attribute, sentinel)
    try:
        yield
    finally:
        if previous is not sentinel:
            sys.__dict__[attribute] = previous


def _operation(run_id: str, status: str) -> dict[str, object]:
    error_type = "RuntimeError" if status == "FAILED" else None
    policy = {
        "IN_PROGRESS": "IN_PROGRESS_NO_DOWNSTREAM_AUTHORITY",
        "FAILED": "FAIL_CLOSED_START_NEW_RUN_ID",
    }[status]
    return {
        "created_at": "2026-08-29T12:00:00Z",
        "error_type": error_type,
        "fixture_notice": FIXTURE_NOTICE,
        "recovery_policy": policy,
        "run_id": run_id,
        "schema_version": "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V1",
        "status": status,
        "updated_at": "2026-08-29T12:00:01Z",
    }


def _operation_v2(run_id: str, status: str) -> dict[str, object]:
    value = _operation(run_id, status)
    value.update(
        {
            "guarded_launch_receipt_sha256": None,
            "launch_mode": "DIRECT_TEST_API",
            "schema_version": "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2",
        }
    )
    return value


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _guarded_source_inventory() -> dict[str, object]:
    entries = [
        {
            "path": "scripts/scientist_one_cli.py",
            "sha256": "b" * 64,
            "size": 1,
        },
        {
            "path": "src/scientist_one/orchestrator.py",
            "sha256": "c" * 64,
            "size": 1,
        },
    ]
    return {
        "aggregate_sha256": hashlib.sha256(
            _canonical_bytes(entries)
        ).hexdigest(),
        "entries": entries,
        "kind": "FROZEN_SOURCE_INVENTORY",
        "schema_version": "1.0",
    }


class VNextOperationTests(unittest.TestCase):
    def _orchestrator(self, root: Path) -> ScientistOneOrchestrator:
        with mock.patch(
            "scientist_one.orchestrator._safe_root", return_value=root
        ), mock.patch(
            "scientist_one.orchestrator._captured_project_root",
            return_value=None,
        ):
            return ScientistOneOrchestrator(root)

    def _write_operation(
        self,
        root: Path,
        run_id: str,
        value: dict[str, object],
    ) -> None:
        run_dir = root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "fixture-operation.json").write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def _write_guarded_in_progress(
        self,
        root: Path,
        run_id: str,
        orchestrator: ScientistOneOrchestrator,
        *,
        source_inventory: dict[str, object],
    ) -> tuple[dict[str, object], bytes]:
        guarded = {
            "canonical_project_root": str(root),
            "captured_source_inventory": source_inventory,
            "command_context": [
                "python3",
                "-I",
                "-S",
                "-B",
                "scripts/scientist_one_cli.py",
                "research-os-fixture",
                "--run-id",
                run_id,
            ],
            "created_at": "2026-08-29T12:00:00Z",
            "launch_mode": "GUARDED_PRODUCTION",
            "root_identity": {
                "device": orchestrator._root_identity[0],
                "inode": orchestrator._root_identity[1],
            },
            "run_id": run_id,
            "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
            "scientific_authority": False,
        }
        guarded_bytes = _canonical_bytes(guarded)
        operation = _operation_v2(run_id, "IN_PROGRESS")
        operation["guarded_launch_receipt_sha256"] = hashlib.sha256(
            guarded_bytes
        ).hexdigest()
        operation["launch_mode"] = "GUARDED_PRODUCTION"
        self._write_operation(root, run_id, operation)
        (root / "runs" / run_id / "guarded-launch.json").write_bytes(
            guarded_bytes
        )
        return operation, guarded_bytes

    def _write_guarded_restart_in_progress(
        self,
        root: Path,
        run_id: str,
        restart_from_run_id: str,
        orchestrator: ScientistOneOrchestrator,
        *,
        source_inventory: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        abandoned = orchestrator._fixture_operation_receipt(
            restart_from_run_id,
            required=True,
        )
        self.assertIsNotNone(abandoned)
        assert abandoned is not None
        orchestrator._guarded_launch_receipt(
            restart_from_run_id,
            abandoned,
        )
        if (
            abandoned["schema_version"]
            == "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3"
        ):
            orchestrator._restart_lineage_receipt(
                restart_from_run_id,
                abandoned,
            )
        abandoned_raw = (
            root
            / "runs"
            / restart_from_run_id
            / "fixture-operation.json"
        ).read_bytes()
        created_at = "2026-08-29T12:00:00Z"
        guarded = {
            "canonical_project_root": str(root),
            "captured_source_inventory": source_inventory,
            "command_context": [
                "python3",
                "-I",
                "-S",
                "-B",
                "scripts/scientist_one_cli.py",
                "research-os-fixture",
                "--run-id",
                run_id,
                "--restart-from",
                restart_from_run_id,
            ],
            "created_at": created_at,
            "launch_mode": "GUARDED_PRODUCTION",
            "root_identity": {
                "device": orchestrator._root_identity[0],
                "inode": orchestrator._root_identity[1],
            },
            "run_id": run_id,
            "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
            "scientific_authority": False,
        }
        guarded_bytes = _canonical_bytes(guarded)
        lineage = {
            "abandoned_guarded_launch_receipt_sha256": abandoned[
                "guarded_launch_receipt_sha256"
            ],
            "abandoned_launch_mode": "GUARDED_PRODUCTION",
            "abandoned_operation_sha256": hashlib.sha256(
                abandoned_raw
            ).hexdigest(),
            "abandoned_operation_schema_version": abandoned[
                "schema_version"
            ],
            "abandoned_operation_status": "IN_PROGRESS",
            "abandoned_resume_supported": False,
            "abandoned_run_id": restart_from_run_id,
            "canonical_project_root": str(root),
            "created_at": created_at,
            "kind": "GUARDED_NEW_RUN_RESTART_LINEAGE",
            "new_run_id": run_id,
            "protected_resources_reused": False,
            "recovery_semantics": "NEW_RUN_NO_SAME_ID_RESUME",
            "schema_version": (
                "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1"
            ),
            "scientific_authority": False,
        }
        lineage_bytes = _canonical_bytes(lineage)
        operation = _operation_v2(run_id, "IN_PROGRESS")
        operation.update(
            {
                "guarded_launch_receipt_sha256": hashlib.sha256(
                    guarded_bytes
                ).hexdigest(),
                "launch_mode": "GUARDED_PRODUCTION",
                "restart_from_run_id": restart_from_run_id,
                "restart_lineage_receipt_sha256": hashlib.sha256(
                    lineage_bytes
                ).hexdigest(),
                "schema_version": "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3",
            }
        )
        self._write_operation(root, run_id, operation)
        run_dir = root / "runs" / run_id
        (run_dir / "guarded-launch.json").write_bytes(guarded_bytes)
        (run_dir / "restart-lineage.json").write_bytes(lineage_bytes)
        return operation, lineage

    def _rehash_summary_authority(
        self,
        root: Path,
        run_id: str,
        summary: dict[str, object],
        *,
        parent_artifacts: tuple[str, ...],
    ) -> str:
        """Publish a fully hash-valid replacement summary and completion head.

        This deliberately models semantic forgery rather than byte corruption:
        registry objects, metadata, ledger hashes, and the operation receipt are
        all reconciled before the independent verifier is invoked.
        """

        registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
        ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
        summary_record = registry.put_json(
            summary,
            logical_type="research_os_run_summary",
            origin="adversarial fully rehashed vNext summary fixture",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "test", "rehash-vnext-summary"),
            parent_artifacts=parent_artifacts,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        prior = ledger.validate(raise_on_error=True).events[-1]
        ledger.record(
            run_id=run_id,
            actor_role=Role.ORCHESTRATOR,
            state_before=prior.requested_state_after,
            requested_state_after=prior.requested_state_after,
            artifact_hashes=(summary_record.sha256,),
            code_version=prior.code_version,
            configuration_hash=prior.configuration_hash,
            dataset_identifiers=prior.dataset_identifiers,
            random_seeds=(),
            evaluator_outputs=(),
            reason="adversarial rehashed final summary authority",
            event_type="CHECKPOINT",
            metadata={
                "phase": "FINAL_VERIFICATION",
                "research_os_materialization": "REGISTERED_BEFORE_CONSUMPTION",
                "system_fixture_integrity": "PASS",
            },
        )
        registry_result = registry.verify_all(raise_on_error=True)
        ledger_result = ledger.validate(raise_on_error=True)
        operation_path = root / "runs" / run_id / "fixture-operation.json"
        operation = json.loads(operation_path.read_bytes())
        operation["artifact_registry"]["artifact_count"] = registry_result.count
        operation["event_ledger"]["event_count"] = ledger_result.event_count
        operation["event_ledger"]["head_hash"] = ledger_result.head_hash
        operation["summary_artifact_sha256"] = summary_record.sha256
        operation_path.write_text(
            json.dumps(operation, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return summary_record.sha256

    def test_golden_provider_bound_v1_summary_replays_without_neutral_upgrade(
        self,
    ) -> None:
        golden = json.loads(
            (
                PROJECT_ROOT
                / "fixtures"
                / "autonomous_implementation_v1_golden.json"
            ).read_bytes()
        )
        self.assertEqual(
            golden["fixture_schema_version"],
            "SCIENTIST_ONE_AUTONOMOUS_IMPLEMENTATION_V1_GOLDEN_V1",
        )

        summary_bytes = base64.b64decode(
            "".join(golden["summary_payload_base64_chunks"]),
            validate=True,
        )
        summary_digest = hashlib.sha256(summary_bytes).hexdigest()
        self.assertEqual(summary_digest, golden["summary_artifact_sha256"])
        summary_record = ArtifactRecord.from_dict(golden["summary_metadata"])
        self.assertEqual(summary_record.sha256, summary_digest)
        self.assertEqual(summary_record.size, len(summary_bytes))
        self.assertEqual(summary_record.to_dict(), golden["summary_metadata"])

        attempt_bytes = base64.b64decode(
            "".join(golden["provider_attempt_payload_base64_chunks"]),
            validate=True,
        )
        attempt_digest = hashlib.sha256(attempt_bytes).hexdigest()
        self.assertEqual(
            attempt_digest,
            golden["provider_attempt_artifact_sha256"],
        )
        attempt_record = ArtifactRecord.from_dict(
            golden["provider_attempt_metadata"]
        )
        self.assertEqual(attempt_record.sha256, attempt_digest)
        self.assertEqual(attempt_record.size, len(attempt_bytes))
        self.assertEqual(
            attempt_record.to_dict(), golden["provider_attempt_metadata"]
        )

        summary = json.loads(summary_bytes)
        autonomous = summary["autonomous_implementation"]
        provider_neutral, artifacts, _ = (
            _replay_vnext_autonomous_summary_roots(
                autonomous,
                provider_neutrality_schema=(
                    PROVIDER_NEUTRALITY_SCHEMA_VERSION
                ),
                registry_records={attempt_digest: attempt_record},
            )
        )
        self.assertFalse(provider_neutral)
        self.assertEqual(artifacts["proposal"], attempt_digest)
        self.assertNotIn("provider_attempt", artifacts)
        self.assertNotIn("provider_admission_link", artifacts)
        self.assertNotIn("execution_input_binding", artifacts)
        self.assertNotIn("provider_neutrality_schema", autonomous)
        self.assertEqual(
            golden["expected_replay"],
            {
                "current_production_eligible": False,
                "provider_neutral": False,
                "provider_neutrality_schema": None,
                "scientific_evidence": False,
            },
        )

        adjacent_roots = dict(autonomous)
        adjacent_roots["artifact_sha256s"] = {
            **artifacts,
            "provider_attempt": attempt_digest,
            "provider_admission_link": "1" * 64,
            "execution_input_binding": "2" * 64,
        }
        with self.assertRaisesRegex(
            OrchestrationError,
            "autonomous artifact roots has missing or unknown fields",
        ):
            _replay_vnext_autonomous_summary_roots(
                adjacent_roots,
                provider_neutrality_schema=(
                    PROVIDER_NEUTRALITY_SCHEMA_VERSION
                ),
                registry_records={attempt_digest: attempt_record},
            )

        adjacent_roots["provider_neutrality_schema"] = (
            PROVIDER_NEUTRALITY_SCHEMA_VERSION
        )
        with self.assertRaisesRegex(
            OrchestrationError,
            "provider-neutral roots do not match their exact generation",
        ):
            _replay_vnext_autonomous_summary_roots(
                adjacent_roots,
                provider_neutrality_schema=(
                    PROVIDER_NEUTRALITY_SCHEMA_VERSION
                ),
                registry_records={attempt_digest: attempt_record},
            )

    def test_operation_v2_schema_and_transitions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-operation-schema-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            malformed_cases: list[tuple[str, dict[str, object], str]] = []
            missing = _operation_v2("vnext-missing-launch", "IN_PROGRESS")
            missing.pop("launch_mode")
            malformed_cases.append(
                ("vnext-missing-launch", missing, "schema is invalid")
            )
            unknown = _operation_v2("vnext-unknown-launch", "IN_PROGRESS")
            unknown["caller_asserted_production"] = True
            malformed_cases.append(
                ("vnext-unknown-launch", unknown, "schema is invalid")
            )
            direct_rebound = _operation_v2(
                "vnext-direct-rebound", "IN_PROGRESS"
            )
            direct_rebound["guarded_launch_receipt_sha256"] = "0" * 64
            malformed_cases.append(
                (
                    "vnext-direct-rebound",
                    direct_rebound,
                    "direct vNext fixture operation binds a guarded receipt",
                )
            )
            guarded_placeholder = _operation_v2(
                "vnext-guarded-placeholder", "IN_PROGRESS"
            )
            guarded_placeholder["launch_mode"] = "GUARDED_PRODUCTION"
            malformed_cases.append(
                (
                    "vnext-guarded-placeholder",
                    guarded_placeholder,
                    "guarded vNext fixture receipt hash is invalid",
                )
            )
            for run_id, value, expected in malformed_cases:
                with self.subTest(run_id=run_id):
                    self._write_operation(root, run_id, value)
                    with self.assertRaisesRegex(OrchestrationError, expected):
                        orchestrator.status(run_id)

            noncanonical_run_id = "vnext-noncanonical-operation"
            noncanonical_value = _operation_v2(
                noncanonical_run_id, "IN_PROGRESS"
            )
            self._write_operation(
                root, noncanonical_run_id, noncanonical_value
            )
            noncanonical_path = (
                root
                / "runs"
                / noncanonical_run_id
                / "fixture-operation.json"
            )
            noncanonical_path.write_text(
                json.dumps(
                    dict(reversed(tuple(noncanonical_value.items()))),
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                OrchestrationError, "not canonical JSON"
            ):
                orchestrator.status(noncanonical_run_id)

            run_id = "vnext-transition-binding"
            run_dir = root / "runs" / run_id
            run_dir.mkdir(parents=True)
            created_at = "2026-08-29T12:00:00Z"
            _write_fixture_operation_status(
                root,
                run_id,
                created_at=created_at,
                status="IN_PROGRESS",
                launch_mode="DIRECT_TEST_API",
                guarded_launch_receipt_sha256=None,
            )
            operation_path = run_dir / "fixture-operation.json"
            in_progress = json.loads(operation_path.read_bytes())
            self.assertEqual(
                set(in_progress),
                {
                    "created_at",
                    "error_type",
                    "fixture_notice",
                    "guarded_launch_receipt_sha256",
                    "launch_mode",
                    "recovery_policy",
                    "run_id",
                    "schema_version",
                    "status",
                    "updated_at",
                },
            )
            self.assertEqual(
                in_progress["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2",
            )
            with self.assertRaisesRegex(ValueError, "transition is invalid"):
                _write_fixture_operation_status(
                    root,
                    run_id,
                    created_at=created_at,
                    status="IN_PROGRESS",
                    launch_mode="DIRECT_TEST_API",
                    guarded_launch_receipt_sha256=None,
                )
            with self.assertRaisesRegex(ValueError, "transition binding changed"):
                _write_fixture_operation_status(
                    root,
                    run_id,
                    created_at=created_at,
                    status="FAILED",
                    launch_mode="GUARDED_PRODUCTION",
                    guarded_launch_receipt_sha256="0" * 64,
                    error_type="RuntimeError",
                )
            _write_fixture_operation_status(
                root,
                run_id,
                created_at=created_at,
                status="FAILED",
                launch_mode="DIRECT_TEST_API",
                guarded_launch_receipt_sha256=None,
                error_type="RuntimeError",
            )
            failed_bytes = operation_path.read_bytes()
            failed = json.loads(failed_bytes)
            self.assertEqual(failed["status"], "FAILED")
            self.assertEqual(failed["error_type"], "RuntimeError")
            with self.assertRaisesRegex(ValueError, "transition is invalid"):
                _write_fixture_operation_status(
                    root,
                    run_id,
                    created_at=created_at,
                    status="COMPLETE",
                    launch_mode="DIRECT_TEST_API",
                    guarded_launch_receipt_sha256=None,
                    result={
                        "artifact_registry": {},
                        "event_ledger": {},
                        "summary_artifact_sha256": "0" * 64,
                        "system_fixture_integrity": "PASS",
                    },
                )
            self.assertEqual(operation_path.read_bytes(), failed_bytes)

    def test_guarded_launch_capability_is_production_bound_and_one_shot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-capability-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            run_id = "guarded-capability-once"
            orchestrator.set_command_context(
                (
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    run_id,
                )
            )
            source_inventory = {
                "aggregate_sha256": "a" * 64,
                "entries": [
                    {
                        "path": "scripts/scientist_one_cli.py",
                        "sha256": "b" * 64,
                        "size": 1,
                    },
                    {
                        "path": "src/scientist_one/orchestrator.py",
                        "sha256": "c" * 64,
                        "size": 1,
                    },
                ],
                "kind": "FROZEN_SOURCE_INVENTORY",
                "schema_version": "1.0",
            }
            captured_root = (root, orchestrator._root_identity)
            with (
                _without_captured_evidence_dispatch(),
                mock.patch.object(
                    sys,
                    "_scientist_one_isolated_launcher",
                    True,
                    create=True,
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_dispatch_loader",
                    return_value=object(),
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_project_root",
                    return_value=captured_root,
                ),
                mock.patch(
                    "scientist_one.orchestrator._source_inventory",
                    return_value=source_inventory,
                ),
            ):
                with self.assertRaisesRegex(
                    OrchestrationError, "active command guard"
                ):
                    orchestrator._mint_guarded_launch_capability(run_id)
                with orchestrator._command_root_guard():
                    capability = orchestrator._mint_guarded_launch_capability(
                        run_id
                    )
                    receipt = _consume_guarded_launch_capability(
                        capability,
                        root=root,
                        run_id=run_id,
                        created_at="2026-08-29T12:00:00Z",
                    )
                    self.assertEqual(
                        receipt["launch_mode"], "GUARDED_PRODUCTION"
                    )
                    self.assertFalse(receipt["scientific_authority"])
                    with self.assertRaisesRegex(
                        OrchestrationError, "already used"
                    ):
                        _consume_guarded_launch_capability(
                            capability,
                            root=root,
                            run_id=run_id,
                            created_at="2026-08-29T12:00:01Z",
                        )

    def test_guarded_restart_lineage_binds_exact_abandoned_operation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-restart-lineage-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            abandoned_run_id = "guarded-abandoned-source"
            new_run_id = "guarded-restart-destination"
            source_inventory = _guarded_source_inventory()
            abandoned_operation, _ = self._write_guarded_in_progress(
                root,
                abandoned_run_id,
                orchestrator,
                source_inventory=source_inventory,
            )
            orchestrator.set_command_context(
                (
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    new_run_id,
                    "--restart-from",
                    abandoned_run_id,
                )
            )
            captured_root = (root, orchestrator._root_identity)
            with (
                _without_captured_evidence_dispatch(),
                mock.patch.object(
                    sys,
                    "_scientist_one_isolated_launcher",
                    True,
                    create=True,
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_dispatch_loader",
                    return_value=object(),
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_project_root",
                    return_value=captured_root,
                ),
                mock.patch(
                    "scientist_one.orchestrator._source_inventory",
                    return_value=source_inventory,
                ),
            ):
                with orchestrator._command_root_guard():
                    capability = orchestrator._mint_guarded_launch_capability(
                        new_run_id,
                        restart_from_run_id=abandoned_run_id,
                    )
                    _consume_guarded_launch_capability(
                        capability,
                        root=root,
                        run_id=new_run_id,
                        created_at="2026-08-29T12:01:00Z",
                    )
                    lineage = _consume_guarded_restart_lineage(
                        capability,
                        root=root,
                        run_id=new_run_id,
                        restart_from_run_id=abandoned_run_id,
                        created_at="2026-08-29T12:01:00Z",
                    )
            self.assertEqual(
                lineage["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1",
            )
            self.assertEqual(lineage["new_run_id"], new_run_id)
            self.assertEqual(
                lineage["abandoned_run_id"], abandoned_run_id
            )
            self.assertEqual(
                lineage["abandoned_guarded_launch_receipt_sha256"],
                abandoned_operation["guarded_launch_receipt_sha256"],
            )
            self.assertFalse(lineage["abandoned_resume_supported"])
            self.assertFalse(lineage["protected_resources_reused"])
            self.assertFalse(lineage["scientific_authority"])

            tampered_abandoned_run_id = "guarded-abandoned-tampered"
            tampered_new_run_id = "guarded-restart-tampered"
            tampered_operation, _ = self._write_guarded_in_progress(
                root,
                tampered_abandoned_run_id,
                orchestrator,
                source_inventory=source_inventory,
            )
            orchestrator.set_command_context(
                (
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    tampered_new_run_id,
                    "--restart-from",
                    tampered_abandoned_run_id,
                )
            )
            with (
                _without_captured_evidence_dispatch(),
                mock.patch.object(
                    sys,
                    "_scientist_one_isolated_launcher",
                    True,
                    create=True,
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_dispatch_loader",
                    return_value=object(),
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_project_root",
                    return_value=captured_root,
                ),
                mock.patch(
                    "scientist_one.orchestrator._source_inventory",
                    return_value=source_inventory,
                ),
            ):
                with orchestrator._command_root_guard():
                    capability = orchestrator._mint_guarded_launch_capability(
                        tampered_new_run_id,
                        restart_from_run_id=tampered_abandoned_run_id,
                    )
                    tampered_operation["updated_at"] = (
                        "2026-08-29T12:00:02Z"
                    )
                    self._write_operation(
                        root,
                        tampered_abandoned_run_id,
                        tampered_operation,
                    )
                    _consume_guarded_launch_capability(
                        capability,
                        root=root,
                        run_id=tampered_new_run_id,
                        created_at="2026-08-29T12:01:00Z",
                    )
                    with self.assertRaisesRegex(
                        OrchestrationError,
                        "changed after admission",
                    ):
                        _consume_guarded_restart_lineage(
                            capability,
                            root=root,
                            run_id=tampered_new_run_id,
                            restart_from_run_id=tampered_abandoned_run_id,
                            created_at="2026-08-29T12:01:00Z",
                        )

    def test_guarded_v3_restart_can_start_another_distinct_guarded_run(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-v3-restart-chain-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            source_inventory = _guarded_source_inventory()
            base_run_id = "guarded-restart-chain-base"
            intermediate_run_id = "guarded-restart-chain-intermediate"
            final_run_id = "guarded-restart-chain-final"
            self._write_guarded_in_progress(
                root,
                base_run_id,
                orchestrator,
                source_inventory=source_inventory,
            )
            intermediate_operation, _ = (
                self._write_guarded_restart_in_progress(
                    root,
                    intermediate_run_id,
                    base_run_id,
                    orchestrator,
                    source_inventory=source_inventory,
                )
            )
            self.assertEqual(
                orchestrator._restart_lineage_receipt(
                    intermediate_run_id,
                    intermediate_operation,
                )["abandoned_run_id"],
                base_run_id,
            )
            orchestrator.set_command_context(
                (
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    final_run_id,
                    "--restart-from",
                    intermediate_run_id,
                )
            )
            captured_root = (root, orchestrator._root_identity)
            with (
                _without_captured_evidence_dispatch(),
                mock.patch.object(
                    sys,
                    "_scientist_one_isolated_launcher",
                    True,
                    create=True,
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_dispatch_loader",
                    return_value=object(),
                ),
                mock.patch(
                    "scientist_one.orchestrator._captured_project_root",
                    return_value=captured_root,
                ),
                mock.patch(
                    "scientist_one.orchestrator._source_inventory",
                    return_value=source_inventory,
                ),
            ):
                with orchestrator._command_root_guard():
                    capability = orchestrator._mint_guarded_launch_capability(
                        final_run_id,
                        restart_from_run_id=intermediate_run_id,
                    )
                    _consume_guarded_launch_capability(
                        capability,
                        root=root,
                        run_id=final_run_id,
                        created_at="2026-08-29T12:01:00Z",
                    )
                    lineage = _consume_guarded_restart_lineage(
                        capability,
                        root=root,
                        run_id=final_run_id,
                        restart_from_run_id=intermediate_run_id,
                        created_at="2026-08-29T12:01:00Z",
                    )
            self.assertEqual(
                lineage["abandoned_operation_schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3",
            )
            self.assertEqual(
                lineage["abandoned_run_id"], intermediate_run_id
            )
            self.assertNotEqual(lineage["new_run_id"], intermediate_run_id)

    def test_guarded_restart_rejects_forged_schema_cycle_and_depth(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-restart-bounds-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            source_inventory = _guarded_source_inventory()
            base_run_id = "guarded-restart-bounds-base"
            intermediate_run_id = "guarded-restart-bounds-intermediate"
            self._write_guarded_in_progress(
                root,
                base_run_id,
                orchestrator,
                source_inventory=source_inventory,
            )
            intermediate_operation, lineage = (
                self._write_guarded_restart_in_progress(
                    root,
                    intermediate_run_id,
                    base_run_id,
                    orchestrator,
                    source_inventory=source_inventory,
                )
            )
            lineage_path = (
                root
                / "runs"
                / intermediate_run_id
                / "restart-lineage.json"
            )
            forged_lineage = dict(lineage)
            forged_lineage["abandoned_operation_schema_version"] = (
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3"
            )
            forged_lineage_bytes = _canonical_bytes(forged_lineage)
            lineage_path.write_bytes(forged_lineage_bytes)
            forged_operation = dict(intermediate_operation)
            forged_operation["restart_lineage_receipt_sha256"] = (
                hashlib.sha256(forged_lineage_bytes).hexdigest()
            )
            self._write_operation(
                root,
                intermediate_run_id,
                forged_operation,
            )
            with self.assertRaisesRegex(
                OrchestrationError,
                "source is no longer abandoned",
            ):
                orchestrator._restart_lineage_receipt(
                    intermediate_run_id,
                    forged_operation,
                )
            with self.assertRaisesRegex(
                OrchestrationError,
                "cycle or duplicate",
            ):
                orchestrator._restart_lineage_receipt(
                    intermediate_run_id,
                    forged_operation,
                    _visited_run_ids=frozenset({intermediate_run_id}),
                )
            with self.assertRaisesRegex(
                OrchestrationError,
                "bounded maximum depth",
            ):
                orchestrator._restart_lineage_receipt(
                    intermediate_run_id,
                    forged_operation,
                    _depth=VNEXT_MAX_RESTART_LINEAGE_DEPTH,
                )

    def test_restart_operation_v3_transitions_preserve_lineage(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-restart-operation-v3-"
        ) as raw_root:
            root = Path(raw_root)
            run_id = "guarded-restart-v3"
            abandoned_run_id = "guarded-restart-v3-source"
            run_dir = root / "runs" / run_id
            run_dir.mkdir(parents=True)
            created_at = "2026-08-29T12:00:00Z"
            guarded_hash = "a" * 64
            lineage_hash = "b" * 64
            _write_fixture_operation_status(
                root,
                run_id,
                created_at=created_at,
                status="IN_PROGRESS",
                launch_mode="GUARDED_PRODUCTION",
                guarded_launch_receipt_sha256=guarded_hash,
                restart_from_run_id=abandoned_run_id,
                restart_lineage_receipt_sha256=lineage_hash,
            )
            operation_path = run_dir / "fixture-operation.json"
            in_progress = json.loads(operation_path.read_bytes())
            self.assertEqual(
                in_progress["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3",
            )
            self.assertEqual(
                in_progress["restart_from_run_id"], abandoned_run_id
            )
            self.assertEqual(
                in_progress["restart_lineage_receipt_sha256"],
                lineage_hash,
            )
            with self.assertRaisesRegex(
                ValueError,
                "transition binding changed",
            ):
                _write_fixture_operation_status(
                    root,
                    run_id,
                    created_at=created_at,
                    status="FAILED",
                    launch_mode="GUARDED_PRODUCTION",
                    guarded_launch_receipt_sha256=guarded_hash,
                    restart_from_run_id=abandoned_run_id,
                    restart_lineage_receipt_sha256="c" * 64,
                    error_type="RuntimeError",
                )
            _write_fixture_operation_status(
                root,
                run_id,
                created_at=created_at,
                status="FAILED",
                launch_mode="GUARDED_PRODUCTION",
                guarded_launch_receipt_sha256=guarded_hash,
                restart_from_run_id=abandoned_run_id,
                restart_lineage_receipt_sha256=lineage_hash,
                error_type="RuntimeError",
            )
            failed = json.loads(operation_path.read_bytes())
            self.assertEqual(failed["status"], "FAILED")
            self.assertEqual(
                failed["restart_lineage_receipt_sha256"], lineage_hash
            )
            with self.assertRaisesRegex(
                ValueError,
                "restart lineage binding is invalid",
            ):
                _write_fixture_operation_status(
                    root,
                    "direct-restart-forbidden",
                    created_at=created_at,
                    status="IN_PROGRESS",
                    launch_mode="DIRECT_TEST_API",
                    guarded_launch_receipt_sha256=None,
                    restart_from_run_id=abandoned_run_id,
                    restart_lineage_receipt_sha256=lineage_hash,
                )

    def test_restart_lineage_status_revalidates_abandoned_source(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-restart-status-binding-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            source_inventory = _guarded_source_inventory()
            abandoned_run_id = "restart-status-abandoned"
            new_run_id = "restart-status-new"
            abandoned_operation, _ = self._write_guarded_in_progress(
                root,
                abandoned_run_id,
                orchestrator,
                source_inventory=source_inventory,
            )
            abandoned_operation_raw = (
                root
                / "runs"
                / abandoned_run_id
                / "fixture-operation.json"
            ).read_bytes()
            created_at = "2026-08-29T12:05:00Z"
            guarded = {
                "canonical_project_root": str(root),
                "captured_source_inventory": source_inventory,
                "command_context": [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    new_run_id,
                    "--restart-from",
                    abandoned_run_id,
                ],
                "created_at": created_at,
                "launch_mode": "GUARDED_PRODUCTION",
                "root_identity": {
                    "device": orchestrator._root_identity[0],
                    "inode": orchestrator._root_identity[1],
                },
                "run_id": new_run_id,
                "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
                "scientific_authority": False,
            }
            guarded_bytes = _canonical_bytes(guarded)
            lineage = {
                "abandoned_guarded_launch_receipt_sha256": (
                    abandoned_operation["guarded_launch_receipt_sha256"]
                ),
                "abandoned_launch_mode": "GUARDED_PRODUCTION",
                "abandoned_operation_sha256": hashlib.sha256(
                    abandoned_operation_raw
                ).hexdigest(),
                "abandoned_operation_schema_version": (
                    "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2"
                ),
                "abandoned_operation_status": "IN_PROGRESS",
                "abandoned_resume_supported": False,
                "abandoned_run_id": abandoned_run_id,
                "canonical_project_root": str(root),
                "created_at": created_at,
                "kind": "GUARDED_NEW_RUN_RESTART_LINEAGE",
                "new_run_id": new_run_id,
                "protected_resources_reused": False,
                "recovery_semantics": "NEW_RUN_NO_SAME_ID_RESUME",
                "schema_version": (
                    "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1"
                ),
                "scientific_authority": False,
            }
            lineage_bytes = _canonical_bytes(lineage)
            operation = _operation_v2(new_run_id, "IN_PROGRESS")
            operation.update(
                {
                    "created_at": created_at,
                    "guarded_launch_receipt_sha256": hashlib.sha256(
                        guarded_bytes
                    ).hexdigest(),
                    "launch_mode": "GUARDED_PRODUCTION",
                    "restart_from_run_id": abandoned_run_id,
                    "restart_lineage_receipt_sha256": hashlib.sha256(
                        lineage_bytes
                    ).hexdigest(),
                    "schema_version": (
                        "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3"
                    ),
                    "updated_at": created_at,
                }
            )
            self._write_operation(root, new_run_id, operation)
            new_run_dir = root / "runs" / new_run_id
            (new_run_dir / "guarded-launch.json").write_bytes(
                guarded_bytes
            )
            lineage_path = new_run_dir / "restart-lineage.json"
            lineage_path.write_bytes(lineage_bytes)

            verification = orchestrator.verify(new_run_id)
            self.assertEqual(verification["status"], "FAIL")
            self.assertEqual(
                verification["issues"], ["OPERATION_IN_PROGRESS"]
            )
            self.assertTrue(
                verification["restart_lineage"]["receipt_valid"]
            )
            self.assertFalse(verification["restart_lineage"]["valid"])
            status = orchestrator.status(new_run_id)
            self.assertEqual(status["status"], "PASS")
            self.assertEqual(status["operation_status"], "IN_PROGRESS")
            self.assertEqual(
                status["restart_lineage"]["abandoned_run_id"],
                abandoned_run_id,
            )
            self.assertFalse(status["resume_supported"])

            tampered = dict(lineage)
            tampered["scientific_authority"] = True
            lineage_path.write_bytes(_canonical_bytes(tampered))
            tampered_verification = orchestrator.verify(new_run_id)
            self.assertTrue(
                any(
                    "RESTART_LINEAGE_INVALID" in issue
                    for issue in tampered_verification["issues"]
                )
            )
            self.assertFalse(
                tampered_verification["restart_lineage"]["receipt_valid"]
            )

            lineage_path.write_bytes(lineage_bytes)
            abandoned_path = (
                root
                / "runs"
                / abandoned_run_id
                / "fixture-operation.json"
            )
            changed_abandoned = dict(abandoned_operation)
            changed_abandoned["updated_at"] = "2026-08-29T12:00:02Z"
            abandoned_path.write_bytes(_canonical_bytes(changed_abandoned))
            changed_source = orchestrator.verify(new_run_id)
            self.assertTrue(
                any(
                    "source operation differs" in issue
                    for issue in changed_source["issues"]
                )
            )

    def test_guarded_receipt_publication_failure_never_falls_back_to_direct(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-publication-failure-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "guarded-publication-failure"
            identity = root.stat()

            def consume(
                _capability: object,
                *,
                root: Path,
                run_id: str,
                created_at: str,
            ) -> dict[str, object]:
                return {
                    "canonical_project_root": str(root),
                    "captured_source_inventory": {
                        "aggregate_sha256": "a" * 64,
                        "entries": [
                            {
                                "path": "scripts/scientist_one_cli.py",
                                "sha256": "b" * 64,
                                "size": 1,
                            }
                        ],
                        "kind": "FROZEN_SOURCE_INVENTORY",
                        "schema_version": "1.0",
                    },
                    "command_context": [
                        "python3",
                        "-I",
                        "-S",
                        "-B",
                        "scripts/scientist_one_cli.py",
                        "research-os-fixture",
                        "--run-id",
                        run_id,
                    ],
                    "created_at": created_at,
                    "launch_mode": "GUARDED_PRODUCTION",
                    "root_identity": {
                        "device": identity.st_dev,
                        "inode": identity.st_ino,
                    },
                    "run_id": run_id,
                    "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
                    "scientific_authority": False,
                }

            real_atomic_write_json = research_os_module.atomic_write_json

            def publish(
                project_root: Path,
                relative: str | Path,
                value: object,
                **kwargs: object,
            ) -> Path:
                if Path(relative).name == "guarded-launch.json":
                    raise RuntimeError("simulated guarded receipt publication failure")
                return real_atomic_write_json(
                    project_root,
                    relative,
                    value,
                    **kwargs,
                )

            with (
                mock.patch(
                    "scientist_one.orchestrator._consume_guarded_launch_capability",
                    side_effect=consume,
                ),
                mock.patch.object(
                    research_os_module,
                    "atomic_write_json",
                    side_effect=publish,
                ),
                mock.patch.object(
                    research_os_module,
                    "_execute_research_os_fixture",
                ) as execute,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "simulated guarded receipt publication failure"
                ):
                    research_os_module._run_research_os_fixture(
                        root,
                        run_id=run_id,
                        guarded_launch_capability=object(),
                    )
            execute.assert_not_called()
            run_dir = root / "runs" / run_id
            operation = json.loads(
                (run_dir / "fixture-operation.json").read_bytes()
            )
            self.assertEqual(operation["status"], "FAILED")
            self.assertEqual(operation["launch_mode"], "GUARDED_PRODUCTION")
            self.assertIsInstance(
                operation["guarded_launch_receipt_sha256"], str
            )
            self.assertEqual(operation["error_type"], "RuntimeError")
            self.assertFalse((run_dir / "guarded-launch.json").exists())
            orchestrator = self._orchestrator(root)
            status = orchestrator.status(run_id)
            self.assertEqual(status["operation_status"], "FAILED")
            self.assertFalse(status["completion_authorities_valid"])
            self.assertFalse(status["production_completion_valid"])
            self.assertFalse(
                status["launch_provenance"]["declaration_valid"]
            )

    def test_guarded_restart_publishes_v3_lineage_before_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-guarded-restart-publication-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "guarded-restart-publication"
            abandoned_run_id = "guarded-restart-publication-source"
            identity = root.stat()
            created_lineage: dict[str, object] = {}

            def consume_launch(
                _capability: object,
                *,
                root: Path,
                run_id: str,
                created_at: str,
            ) -> dict[str, object]:
                return {
                    "canonical_project_root": str(root),
                    "captured_source_inventory": {
                        "aggregate_sha256": "a" * 64,
                        "entries": [
                            {
                                "path": "scripts/scientist_one_cli.py",
                                "sha256": "b" * 64,
                                "size": 1,
                            }
                        ],
                        "kind": "FROZEN_SOURCE_INVENTORY",
                        "schema_version": "1.0",
                    },
                    "command_context": [
                        "python3",
                        "-I",
                        "-S",
                        "-B",
                        "scripts/scientist_one_cli.py",
                        "research-os-fixture",
                        "--run-id",
                        run_id,
                        "--restart-from",
                        abandoned_run_id,
                    ],
                    "created_at": created_at,
                    "launch_mode": "GUARDED_PRODUCTION",
                    "root_identity": {
                        "device": identity.st_dev,
                        "inode": identity.st_ino,
                    },
                    "run_id": run_id,
                    "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
                    "scientific_authority": False,
                }

            def consume_restart(
                _capability: object,
                *,
                root: Path,
                run_id: str,
                restart_from_run_id: str | None,
                created_at: str,
            ) -> dict[str, object]:
                self.assertEqual(restart_from_run_id, abandoned_run_id)
                created_lineage.update(
                    {
                        "abandoned_guarded_launch_receipt_sha256": "c" * 64,
                        "abandoned_launch_mode": "GUARDED_PRODUCTION",
                        "abandoned_operation_sha256": "d" * 64,
                        "abandoned_operation_schema_version": (
                            "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2"
                        ),
                        "abandoned_operation_status": "IN_PROGRESS",
                        "abandoned_resume_supported": False,
                        "abandoned_run_id": abandoned_run_id,
                        "canonical_project_root": str(root),
                        "created_at": created_at,
                        "kind": "GUARDED_NEW_RUN_RESTART_LINEAGE",
                        "new_run_id": run_id,
                        "protected_resources_reused": False,
                        "recovery_semantics": "NEW_RUN_NO_SAME_ID_RESUME",
                        "schema_version": (
                            "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1"
                        ),
                        "scientific_authority": False,
                    }
                )
                return dict(created_lineage)

            def execute(
                _root: Path,
                *,
                identifier: str,
                timestamp: str,
                restart_lineage: object,
            ) -> dict[str, object]:
                self.assertEqual(identifier, run_id)
                self.assertIsInstance(timestamp, str)
                self.assertEqual(restart_lineage, created_lineage)
                return {
                    "artifact_registry": {
                        "artifact_count": 1,
                        "base_path": f"runs/{run_id}/registry",
                        "status": "PASS",
                    },
                    "event_ledger": {
                        "event_count": 1,
                        "head_hash": "e" * 64,
                        "path": f"runs/{run_id}/events.jsonl",
                        "status": "PASS",
                    },
                    "summary_artifact_sha256": "f" * 64,
                    "system_fixture_integrity": "PASS",
                }

            with (
                mock.patch(
                    "scientist_one.orchestrator._consume_guarded_launch_capability",
                    side_effect=consume_launch,
                ),
                mock.patch(
                    "scientist_one.orchestrator._consume_guarded_restart_lineage",
                    side_effect=consume_restart,
                ),
                mock.patch.object(
                    research_os_module,
                    "_execute_research_os_fixture",
                    side_effect=execute,
                ) as execute_mock,
            ):
                research_os_module._run_research_os_fixture(
                    root,
                    run_id=run_id,
                    guarded_launch_capability=object(),
                    restart_from_run_id=abandoned_run_id,
                )
            execute_mock.assert_called_once()
            run_dir = root / "runs" / run_id
            operation = json.loads(
                (run_dir / "fixture-operation.json").read_bytes()
            )
            self.assertEqual(operation["status"], "COMPLETE")
            self.assertEqual(
                operation["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3",
            )
            self.assertEqual(
                operation["restart_from_run_id"], abandoned_run_id
            )
            self.assertEqual(
                (run_dir / "restart-lineage.json").read_bytes(),
                _canonical_bytes(created_lineage),
            )
            self.assertTrue((run_dir / "guarded-launch.json").exists())

    def test_restart_lineage_publication_failure_never_executes_or_falls_back(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-restart-lineage-publication-failure-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "guarded-restart-lineage-publication-failure"
            abandoned_run_id = "guarded-restart-lineage-publication-source"
            identity = root.stat()

            def consume_launch(
                _capability: object,
                *,
                root: Path,
                run_id: str,
                created_at: str,
            ) -> dict[str, object]:
                return {
                    "canonical_project_root": str(root),
                    "captured_source_inventory": {
                        "aggregate_sha256": "a" * 64,
                        "entries": [
                            {
                                "path": "scripts/scientist_one_cli.py",
                                "sha256": "b" * 64,
                                "size": 1,
                            }
                        ],
                        "kind": "FROZEN_SOURCE_INVENTORY",
                        "schema_version": "1.0",
                    },
                    "command_context": [
                        "python3",
                        "-I",
                        "-S",
                        "-B",
                        "scripts/scientist_one_cli.py",
                        "research-os-fixture",
                        "--run-id",
                        run_id,
                        "--restart-from",
                        abandoned_run_id,
                    ],
                    "created_at": created_at,
                    "launch_mode": "GUARDED_PRODUCTION",
                    "root_identity": {
                        "device": identity.st_dev,
                        "inode": identity.st_ino,
                    },
                    "run_id": run_id,
                    "schema_version": "SCIENTIST_ONE_GUARDED_LAUNCH_V1",
                    "scientific_authority": False,
                }

            def consume_restart(
                _capability: object,
                *,
                root: Path,
                run_id: str,
                restart_from_run_id: str | None,
                created_at: str,
            ) -> dict[str, object]:
                self.assertEqual(restart_from_run_id, abandoned_run_id)
                return {
                    "abandoned_guarded_launch_receipt_sha256": "c" * 64,
                    "abandoned_launch_mode": "GUARDED_PRODUCTION",
                    "abandoned_operation_sha256": "d" * 64,
                    "abandoned_operation_schema_version": (
                        "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2"
                    ),
                    "abandoned_operation_status": "IN_PROGRESS",
                    "abandoned_resume_supported": False,
                    "abandoned_run_id": abandoned_run_id,
                    "canonical_project_root": str(root),
                    "created_at": created_at,
                    "kind": "GUARDED_NEW_RUN_RESTART_LINEAGE",
                    "new_run_id": run_id,
                    "protected_resources_reused": False,
                    "recovery_semantics": "NEW_RUN_NO_SAME_ID_RESUME",
                    "schema_version": (
                        "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1"
                    ),
                    "scientific_authority": False,
                }

            real_atomic_write_json = research_os_module.atomic_write_json

            def publish(
                project_root: Path,
                relative: str | Path,
                value: object,
                **kwargs: object,
            ) -> Path:
                if Path(relative).name == "restart-lineage.json":
                    raise RuntimeError(
                        "simulated restart lineage publication failure"
                    )
                return real_atomic_write_json(
                    project_root,
                    relative,
                    value,
                    **kwargs,
                )

            with (
                mock.patch(
                    "scientist_one.orchestrator._consume_guarded_launch_capability",
                    side_effect=consume_launch,
                ),
                mock.patch(
                    "scientist_one.orchestrator._consume_guarded_restart_lineage",
                    side_effect=consume_restart,
                ),
                mock.patch.object(
                    research_os_module,
                    "atomic_write_json",
                    side_effect=publish,
                ),
                mock.patch.object(
                    research_os_module,
                    "_execute_research_os_fixture",
                ) as execute,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "simulated restart lineage publication failure",
                ):
                    research_os_module._run_research_os_fixture(
                        root,
                        run_id=run_id,
                        guarded_launch_capability=object(),
                        restart_from_run_id=abandoned_run_id,
                    )
            execute.assert_not_called()
            run_dir = root / "runs" / run_id
            operation = json.loads(
                (run_dir / "fixture-operation.json").read_bytes()
            )
            self.assertEqual(operation["status"], "FAILED")
            self.assertEqual(
                operation["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3",
            )
            self.assertEqual(operation["launch_mode"], "GUARDED_PRODUCTION")
            self.assertEqual(
                operation["restart_from_run_id"], abandoned_run_id
            )
            self.assertEqual(operation["error_type"], "RuntimeError")
            self.assertTrue((run_dir / "guarded-launch.json").exists())
            self.assertFalse((run_dir / "restart-lineage.json").exists())
            status = self._orchestrator(root).status(run_id)
            self.assertEqual(status["operation_status"], "FAILED")
            self.assertFalse(status["completion_authorities_valid"])
            self.assertFalse(status["production_completion_valid"])
            self.assertFalse(status["restart_lineage"]["receipt_valid"])

    def test_private_guarded_runner_rejects_unsealed_capability_before_reservation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-unsealed-capability-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "unsealed-capability"
            with self.assertRaisesRegex(
                OrchestrationError, "capability type is invalid"
            ):
                research_os_module._run_research_os_fixture(
                    root,
                    run_id=run_id,
                    guarded_launch_capability=object(),
                )
            self.assertFalse((root / "runs" / run_id).exists())

    def test_direct_orchestrator_cannot_request_restart_lineage(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-direct-restart-forbidden-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            with self.assertRaisesRegex(
                OrchestrationError,
                "guarded production dispatch",
            ):
                orchestrator.research_os_fixture(
                    "direct-restart-new",
                    restart_from_run_id="direct-restart-old",
                )
            self.assertFalse(
                (root / "runs" / "direct-restart-new").exists()
            )

    def test_marker_only_dispatch_cannot_claim_guarded_or_fall_back_to_direct(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-marker-only-launch-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            run_id = "marker-only-launch"
            orchestrator.set_command_context(
                (
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    run_id,
                )
            )
            with (
                _without_captured_evidence_dispatch(),
                mock.patch.object(
                    sys,
                    "_scientist_one_isolated_launcher",
                    True,
                    create=True,
                ),
                mock.patch("scientist_one.orchestrator.__loader__", object()),
            ):
                with self.assertRaisesRegex(
                    OrchestrationError, "captured dispatch capability is invalid"
                ):
                    orchestrator.research_os_fixture(run_id)
            self.assertFalse((root / "runs" / run_id).exists())

    def test_incomplete_operations_are_visible_but_cannot_verify(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-operation-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            for run_id, operation_status in (
                ("vnext-in-progress", "IN_PROGRESS"),
                ("vnext-failed", "FAILED"),
            ):
                self._write_operation(
                    root,
                    run_id,
                    _operation(run_id, operation_status),
                )

                status = orchestrator.status(run_id)
                self.assertEqual(status["status"], "PASS")
                self.assertEqual(status["kind"], "RESEARCH_OS_FIXTURE")
                self.assertEqual(status["operation_status"], operation_status)
                self.assertFalse(status["completion_verified"])
                self.assertFalse(status["completion_authorities_valid"])
                self.assertFalse(status["resumable"])
                self.assertFalse(status["resume_supported"])
                self.assertFalse(status["reproduce_supported"])
                self.assertFalse(status["package_supported"])
                self.assertEqual(
                    status["system_fixture_integrity"], "NOT_ESTABLISHED"
                )

                verification = orchestrator.verify(run_id)
                self.assertEqual(verification["status"], "FAIL")
                self.assertEqual(
                    verification["issues"], [f"OPERATION_{operation_status}"]
                )
                self.assertFalse(verification["completion_authorities_valid"])
                self.assertFalse(
                    verification["scientific_evidence_established"]
                )
                self.assertEqual(
                    verification["launch_provenance"]["mode"],
                    "UNKNOWN_LEGACY",
                )
                self.assertFalse(verification["production_completion_valid"])

            # Model abrupt process death after durable reservation and before
            # any COMPLETE/ledger authority exists. Even orphaned registry data
            # must remain visible only as the original, nonresumable run ID.
            abrupt_run_id = "vnext-abrupt-process-death"
            abrupt_operation = _operation_v2(abrupt_run_id, "IN_PROGRESS")
            self._write_operation(root, abrupt_run_id, abrupt_operation)
            orphan_registry = ArtifactRegistry(
                root, f"runs/{abrupt_run_id}/registry"
            )
            orphan_registry.put_json(
                {"orphaned": True},
                logical_type="orphaned_fixture_artifact",
                origin="abrupt process death fixture",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test", "abrupt-death"),
                validation_result="PASS",
                frozen=True,
            )
            operation_path = (
                root / "runs" / abrupt_run_id / "fixture-operation.json"
            )
            original_operation = operation_path.read_bytes()
            abrupt_status = orchestrator.status(abrupt_run_id)
            self.assertEqual(abrupt_status["status"], "PASS")
            self.assertEqual(abrupt_status["run_id"], abrupt_run_id)
            self.assertEqual(abrupt_status["operation_status"], "IN_PROGRESS")
            self.assertFalse(abrupt_status["completion_verified"])
            self.assertFalse(abrupt_status["completion_authorities_valid"])
            self.assertFalse(abrupt_status["production_completion_valid"])
            self.assertFalse(abrupt_status["resumable"])
            self.assertFalse(abrupt_status["resume_supported"])
            abrupt_verify = orchestrator.verify(abrupt_run_id)
            self.assertEqual(abrupt_verify["status"], "FAIL")
            self.assertEqual(abrupt_verify["issues"], ["OPERATION_IN_PROGRESS"])
            self.assertFalse(abrupt_verify["completion_authorities_valid"])
            self.assertEqual(operation_path.read_bytes(), original_operation)

            listing = orchestrator.status()
            by_id = {item["run_id"]: item for item in listing["runs"]}
            self.assertEqual(listing["count"], 3)
            self.assertEqual(
                by_id["vnext-in-progress"]["operation_status"], "IN_PROGRESS"
            )
            self.assertEqual(
                by_id["vnext-failed"]["operation_status"], "FAILED"
            )
            self.assertEqual(
                by_id[abrupt_run_id]["operation_status"], "IN_PROGRESS"
            )

            ambiguous = "vnext-ambiguous"
            self._write_operation(
                root,
                ambiguous,
                _operation(ambiguous, "FAILED"),
            )
            (root / "runs" / ambiguous / "manifest.json").write_text(
                "{}\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                OrchestrationError, "ambiguous legacy and vNext"
            ):
                orchestrator.status(ambiguous)

    def test_orphan_registry_and_counterfeit_complete_gain_no_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-orphan-complete-"
        ) as raw_root:
            root = Path(raw_root)
            orchestrator = self._orchestrator(root)
            run_id = "vnext-orphan-counterfeit-complete"
            run_dir = root / "runs" / run_id
            run_dir.mkdir(parents=True)
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            orphan = registry.put_json(
                {"orphaned": True},
                logical_type="orphaned_fixture_artifact",
                origin="counterfeit COMPLETE fixture",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test", "orphan-complete"),
                validation_result="PASS",
                frozen=True,
            )
            operation = _operation_v2(run_id, "IN_PROGRESS")
            operation.update(
                {
                    "artifact_registry": {
                        "artifact_count": 1,
                        "base_path": f"runs/{run_id}/registry",
                        "status": "PASS",
                    },
                    "event_ledger": {
                        "event_count": 1,
                        "head_hash": "0" * 64,
                        "path": f"runs/{run_id}/events.jsonl",
                        "status": "PASS",
                    },
                    "recovery_policy": "IMMUTABLE_COMPLETE",
                    "status": "COMPLETE",
                    "summary_artifact_sha256": orphan.sha256,
                    "system_fixture_integrity": "PASS",
                }
            )
            self._write_operation(root, run_id, operation)

            verification = orchestrator.verify(run_id)
            self.assertEqual(verification["status"], "FAIL")
            self.assertFalse(verification["completion_authorities_valid"])
            self.assertFalse(verification["production_completion_valid"])
            self.assertFalse(
                verification["artifact_registry"]["ledger_closure_valid"]
            )
            status = orchestrator.status(run_id)
            self.assertEqual(status["status"], "FAIL")
            self.assertEqual(status["operation_status"], "COMPLETE")
            self.assertEqual(status["outcome"], "COMPLETE_BUT_UNVERIFIED")
            self.assertFalse(status["completion_verified"])

    def test_complete_fixture_rehydrates_all_authorities_and_count_tampering_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-operation-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            orchestrator = self._orchestrator(root)
            run_id = "vnext-operation-complete"

            result = orchestrator.research_os_fixture(run_id)
            self.assertEqual(result["status"], "PASS")

            status = orchestrator.status(run_id)
            self.assertEqual(status["status"], "PASS", orchestrator.verify(run_id))
            self.assertEqual(status["kind"], "RESEARCH_OS_FIXTURE")
            self.assertEqual(status["operation_status"], "COMPLETE")
            self.assertTrue(status["completion_verified"])
            self.assertTrue(status["completion_authorities_valid"])
            self.assertEqual(
                status["outcome"],
                "SYSTEM_FIXTURE_COMPLETE_DIRECT_TEST_API",
            )
            self.assertEqual(
                status["launch_provenance"]["mode"], "DIRECT_TEST_API"
            )
            self.assertTrue(
                status["launch_provenance"]["declaration_valid"]
            )
            self.assertFalse(status["production_completion_valid"])
            self.assertNotIn("safe_resume_command", status)

            verification = orchestrator.verify(run_id)
            self.assertEqual(verification["status"], "PASS", verification)
            self.assertTrue(verification["completion_authorities_valid"])
            self.assertEqual(
                verification["launch_provenance"]["mode"], "DIRECT_TEST_API"
            )
            self.assertTrue(
                verification["launch_provenance"]["declaration_valid"]
            )
            self.assertFalse(
                verification["launch_provenance"]["receipt_valid"]
            )
            self.assertFalse(verification["production_completion_valid"])
            self.assertTrue(
                verification["artifact_registry"]["ledger_closure_valid"]
            )
            self.assertTrue(
                verification["event_ledger"]["artifact_references_valid"]
            )
            self.assertTrue(verification["summary"]["final_event_binding_valid"])
            self.assertTrue(verification["canonical_research_state"]["valid"])
            self.assertTrue(
                verification["canonical_research_state"][
                    "non_evidentiary_reproduction_valid"
                ]
            )
            self.assertTrue(
                verification["scientific_soundness_authority"]["valid"]
            )
            self.assertEqual(
                verification["scientific_soundness_authority"][
                    "central_claim_ids"
                ],
                ["claim-threshold-fixture"],
            )
            self.assertEqual(
                verification["scientific_soundness_authority"]["verdict"],
                "MORE_EXPERIMENTS_REQUIRED",
            )
            self.assertEqual(
                verification["canonical_research_state"]["object_type_count"],
                21,
            )
            autonomous = verification["autonomous_implementation"]
            self.assertTrue(autonomous["valid"])
            self.assertTrue(autonomous["summary_binding_valid"])
            self.assertTrue(autonomous["artifact_graph_valid"])
            self.assertTrue(autonomous["execution_binding_valid"])
            self.assertTrue(autonomous["semantic_recomputation_valid"])
            self.assertTrue(autonomous["ledger_binding_valid"])
            self.assertTrue(autonomous["canonical_state_binding_valid"])
            self.assertTrue(autonomous["claim_paper_exclusion_valid"])
            self.assertTrue(autonomous["provider_neutral"])
            self.assertEqual(
                autonomous["provider_neutrality_schema"],
                PROVIDER_NEUTRALITY_SCHEMA_VERSION,
            )
            self.assertFalse(autonomous["historical_v1_replay"])
            self.assertTrue(autonomous["current_production_eligible"])
            self.assertEqual(
                autonomous["network_use_status"], "UNKNOWN_UNATTESTED"
            )
            self.assertFalse(autonomous["scientific_evidence"])
            self.assertFalse(verification["scientific_evidence_established"])

            receipt_path = root / "runs" / run_id / "fixture-operation.json"
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(
                receipt["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2",
            )
            self.assertEqual(receipt["launch_mode"], "DIRECT_TEST_API")
            self.assertIsNone(receipt["guarded_launch_receipt_sha256"])
            self.assertFalse(
                (root / "runs" / run_id / "guarded-launch.json").exists()
            )

            guarded_path = root / "runs" / run_id / "guarded-launch.json"
            guarded_path.write_text("{}\n", encoding="utf-8")
            ambiguous_direct = orchestrator.verify(run_id)
            self.assertEqual(ambiguous_direct["status"], "FAIL")
            self.assertFalse(
                ambiguous_direct["completion_authorities_valid"]
            )
            self.assertTrue(
                any(
                    "ambiguous guarded launch data" in issue
                    for issue in ambiguous_direct["issues"]
                )
            )
            guarded_path.unlink()

            # Historical V1 completion remains readable but is never rewritten
            # or promoted to guarded production launch provenance.
            legacy_receipt = dict(receipt)
            legacy_receipt["schema_version"] = (
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V1"
            )
            legacy_receipt.pop("launch_mode")
            legacy_receipt.pop("guarded_launch_receipt_sha256")
            legacy_bytes = (
                json.dumps(legacy_receipt, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            receipt_path.write_bytes(legacy_bytes)
            legacy_status = orchestrator.status(run_id)
            self.assertEqual(legacy_status["status"], "PASS")
            self.assertEqual(
                legacy_status["outcome"],
                "SYSTEM_FIXTURE_COMPLETE_LEGACY_LAUNCH_UNATTESTED",
            )
            self.assertEqual(
                legacy_status["launch_provenance"]["mode"],
                "UNKNOWN_LEGACY",
            )
            self.assertTrue(legacy_status["completion_authorities_valid"])
            self.assertFalse(legacy_status["production_completion_valid"])
            legacy_verification = orchestrator.verify(run_id)
            self.assertEqual(
                legacy_verification["status"], "PASS", legacy_verification
            )
            self.assertTrue(
                legacy_verification["completion_authorities_valid"]
            )
            self.assertFalse(
                legacy_verification["production_completion_valid"]
            )
            self.assertEqual(receipt_path.read_bytes(), legacy_bytes)

            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            receipt["artifact_registry"]["artifact_count"] += 1
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            failed = orchestrator.verify(run_id)
            self.assertEqual(failed["status"], "FAIL")
            self.assertFalse(failed["completion_authorities_valid"])
            self.assertFalse(
                failed["artifact_registry"]["receipt_binding_valid"]
            )
            failed_status = orchestrator.status(run_id)
            self.assertEqual(failed_status["status"], "FAIL")
            self.assertEqual(failed_status["outcome"], "COMPLETE_BUT_UNVERIFIED")
            self.assertFalse(failed_status["completion_verified"])

    def test_hash_valid_autonomous_semantic_and_network_forgery_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-autonomous-verify-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            orchestrator = self._orchestrator(root)
            run_id = "vnext-autonomous-deep-verification"

            completed = orchestrator.research_os_fixture(run_id)
            self.assertEqual(completed["status"], "PASS")
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            original_summary_record = registry.get_metadata(
                completed["summary_artifact_sha256"]
            )
            original_summary = json.loads(
                registry.get_bytes(original_summary_record.sha256)
            )

            # Reconcile three hash-valid proposal variants into otherwise
            # valid summary/ledger heads. The deep verifier must reject the
            # missing, reordered, or substituted provider-custody edge rather
            # than relying on registry/ledger structure alone.
            original_proposal_hash = original_summary[
                "autonomous_implementation"
            ]["artifact_sha256s"]["provider_attempt"]
            original_proposal_record = registry.get_metadata(
                original_proposal_hash
            )
            original_proposal_payload = json.loads(
                registry.get_bytes(original_proposal_hash)
            )
            proposal_parent_types = tuple(
                registry.get_metadata(parent).logical_type
                for parent in original_proposal_record.parent_artifacts
            )
            request_body_index = proposal_parent_types.index(
                "model_provider_request_body"
            )
            request_intent_index = proposal_parent_types.index(
                "model_provider_request_intent"
            )
            omitted_parents = tuple(
                parent
                for index, parent in enumerate(
                    original_proposal_record.parent_artifacts
                )
                if index != request_body_index
            )
            reordered_parent_list = list(
                original_proposal_record.parent_artifacts
            )
            (
                reordered_parent_list[request_body_index],
                reordered_parent_list[request_intent_index],
            ) = (
                reordered_parent_list[request_intent_index],
                reordered_parent_list[request_body_index],
            )
            substituted_parent_list = list(
                original_proposal_record.parent_artifacts
            )
            substituted_parent_list[request_body_index] = (
                original_summary_record.sha256
            )
            provider_parent_cases = (
                ("omitted", omitted_parents),
                ("reordered", tuple(reordered_parent_list)),
                ("substituted", tuple(substituted_parent_list)),
            )
            for marker, forged_parents in provider_parent_cases:
                with self.subTest(provider_parent_graph=marker):
                    forged_proposal_payload = json.loads(
                        json.dumps(original_proposal_payload)
                    )
                    forged_proposal_payload["output"]["rationale"] += (
                        f" Adversarial {marker} custody graph."
                    )
                    forged_proposal = registry.put_json(
                        forged_proposal_payload,
                        logical_type=(
                            "autonomous_implementation.model_proposal"
                        ),
                        origin=(
                            "adversarial fully rehashed provider-custody "
                            f"{marker} fixture"
                        ),
                        creator_role=Role.ORCHESTRATOR,
                        creation_command=(
                            "scientist-one",
                            "test",
                            f"forge-provider-graph-{marker}",
                        ),
                        parent_artifacts=forged_parents,
                        schema_version="1.0",
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )
                    forged_summary = json.loads(json.dumps(original_summary))
                    forged_summary["autonomous_implementation"][
                        "artifact_sha256s"
                    ]["provider_attempt"] = forged_proposal.sha256
                    forged_summary_parents = tuple(
                        dict.fromkeys(
                            (
                                *(
                                    forged_proposal.sha256
                                    if parent == original_proposal_hash
                                    else parent
                                    for parent in original_summary_record.parent_artifacts
                                ),
                                forged_proposal.sha256,
                            )
                        )
                    )
                    self._rehash_summary_authority(
                        root,
                        run_id,
                        forged_summary,
                        parent_artifacts=forged_summary_parents,
                    )
                    failed_provider_graph = orchestrator.verify(run_id)
                    self.assertEqual(
                        failed_provider_graph["status"],
                        "FAIL",
                        failed_provider_graph,
                    )
                    self.assertTrue(
                        failed_provider_graph["artifact_registry"]["valid"]
                    )
                    self.assertTrue(
                        failed_provider_graph["event_ledger"]["valid"]
                    )
                    self.assertTrue(
                        failed_provider_graph["artifact_registry"][
                            "ledger_closure_valid"
                        ]
                    )
                    self.assertTrue(failed_provider_graph["summary"]["valid"])
                    self.assertFalse(
                        failed_provider_graph["autonomous_implementation"][
                            "artifact_graph_valid"
                        ]
                    )
                    self.assertTrue(
                        any(
                            "captured provider" in issue
                            or "provider provenance" in issue
                            for issue in failed_provider_graph["issues"]
                        )
                    )

            # A false network attestation is fully content-addressed and becomes
            # the new ledger head. Structural registry/ledger checks must still
            # pass while the autonomous semantic verifier rejects it.
            network_forgery = json.loads(json.dumps(original_summary))
            network_forgery["autonomous_implementation"][
                "network_use_status"
            ] = "NOT_USED_ATTESTED"
            self._rehash_summary_authority(
                root,
                run_id,
                network_forgery,
                parent_artifacts=original_summary_record.parent_artifacts,
            )
            failed_network = orchestrator.verify(run_id)
            self.assertEqual(failed_network["status"], "FAIL")
            self.assertTrue(failed_network["artifact_registry"]["valid"])
            self.assertTrue(
                failed_network["artifact_registry"]["ledger_closure_valid"]
            )
            self.assertTrue(failed_network["event_ledger"]["valid"])
            self.assertTrue(failed_network["summary"]["valid"])
            self.assertFalse(
                failed_network["autonomous_implementation"][
                    "summary_binding_valid"
                ]
            )
            self.assertTrue(
                any(
                    "misclassifies the autonomous execution" in issue
                    for issue in failed_network["issues"]
                )
            )

            # The semantic receipt's execution-input binding is content and
            # ancestry, not advisory metadata.  A fully rehashed receipt must
            # fail when the binding is either omitted or substituted.
            binding_semantic_hash = original_summary[
                "autonomous_implementation"
            ]["artifact_sha256s"]["semantic_validation"]
            binding_semantic_record = registry.get_metadata(
                binding_semantic_hash
            )
            binding_semantic_payload = json.loads(
                registry.get_bytes(binding_semantic_hash)
            )
            execution_input_binding_hash = binding_semantic_payload[
                "execution_input_binding_artifact_sha256"
            ]
            replacement_binding_hash = original_summary[
                "autonomous_implementation"
            ]["artifact_sha256s"]["execution_plan_binding"]
            for marker in ("omitted", "substituted"):
                with self.subTest(
                    semantic_execution_input_binding=marker
                ):
                    forged_payload = json.loads(
                        json.dumps(binding_semantic_payload)
                    )
                    if marker == "omitted":
                        forged_payload.pop(
                            "execution_input_binding_artifact_sha256"
                        )
                        forged_parents = tuple(
                            parent
                            for parent in binding_semantic_record.parent_artifacts
                            if parent != execution_input_binding_hash
                        )
                    else:
                        forged_payload[
                            "execution_input_binding_artifact_sha256"
                        ] = replacement_binding_hash
                        forged_parents = tuple(
                            dict.fromkeys(
                                replacement_binding_hash
                                if parent == execution_input_binding_hash
                                else parent
                                for parent in binding_semantic_record.parent_artifacts
                            )
                        )
                    forged_binding_semantic = registry.put_json(
                        forged_payload,
                        logical_type=(
                            "autonomous_implementation.semantic_validation"
                        ),
                        origin=(
                            "adversarial hash-valid autonomous input-binding "
                            f"{marker} fixture"
                        ),
                        creator_role=Role.SCIENTIFIC_REVIEWER,
                        creation_command=(
                            "scientist-one",
                            "test",
                            f"forge-autonomous-input-binding-{marker}",
                        ),
                        parent_artifacts=forged_parents,
                        schema_version="1.0",
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )
                    forged_binding_summary = json.loads(
                        json.dumps(original_summary)
                    )
                    forged_binding_summary["autonomous_implementation"][
                        "artifact_sha256s"
                    ]["semantic_validation"] = forged_binding_semantic.sha256
                    self._rehash_summary_authority(
                        root,
                        run_id,
                        forged_binding_summary,
                        parent_artifacts=tuple(
                            dict.fromkeys(
                                (
                                    *original_summary_record.parent_artifacts,
                                    forged_binding_semantic.sha256,
                                )
                            )
                        ),
                    )
                    failed_binding = orchestrator.verify(run_id)
                    self.assertEqual(failed_binding["status"], "FAIL")
                    self.assertTrue(
                        failed_binding["artifact_registry"]["valid"]
                    )
                    self.assertTrue(
                        failed_binding["event_ledger"]["valid"]
                    )
                    self.assertFalse(
                        failed_binding["autonomous_implementation"][
                            "semantic_recomputation_valid"
                        ]
                    )
                    self.assertTrue(
                        any(
                            "semantic validation receipt is not the exact "
                            "recomputation" in issue
                            for issue in failed_binding["issues"]
                        )
                    )

            # Restore truthful summary fields but mint a hash-valid PASS receipt
            # with an altered recomputed metric. The verifier must independently
            # recompute from frozen data/config/output, not trust the receipt.
            semantic_forgery_summary = json.loads(json.dumps(original_summary))
            semantic_hash = semantic_forgery_summary[
                "autonomous_implementation"
            ]["artifact_sha256s"]["semantic_validation"]
            semantic_record = registry.get_metadata(semantic_hash)
            semantic_payload = json.loads(registry.get_bytes(semantic_hash))
            semantic_payload["recomputed_metric"] = (
                float(semantic_payload["recomputed_metric"]) + 1.0
            )
            forged_semantic = registry.put_json(
                semantic_payload,
                logical_type="autonomous_implementation.semantic_validation",
                origin="adversarial hash-valid false autonomous recomputation",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=(
                    "scientist-one",
                    "test",
                    "forge-autonomous-semantic-validation",
                ),
                parent_artifacts=semantic_record.parent_artifacts,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            semantic_forgery_summary["autonomous_implementation"][
                "artifact_sha256s"
            ]["semantic_validation"] = forged_semantic.sha256
            self._rehash_summary_authority(
                root,
                run_id,
                semantic_forgery_summary,
                parent_artifacts=tuple(
                    dict.fromkeys(
                        (
                            *original_summary_record.parent_artifacts,
                            forged_semantic.sha256,
                        )
                    )
                ),
            )
            failed_semantic = orchestrator.verify(run_id)
            self.assertEqual(failed_semantic["status"], "FAIL")
            self.assertTrue(failed_semantic["artifact_registry"]["valid"])
            self.assertTrue(
                failed_semantic["artifact_registry"]["ledger_closure_valid"]
            )
            self.assertTrue(failed_semantic["event_ledger"]["valid"])
            self.assertTrue(
                failed_semantic["autonomous_implementation"][
                    "execution_binding_valid"
                ]
            )
            self.assertFalse(
                failed_semantic["autonomous_implementation"][
                    "semantic_recomputation_valid"
                ]
            )
            self.assertTrue(
                any(
                    "semantic validation receipt is not the exact recomputation"
                    in issue
                    for issue in failed_semantic["issues"]
                )
            )


if __name__ == "__main__":
    unittest.main()
