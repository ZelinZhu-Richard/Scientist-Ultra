"""Legitimate end-to-end verification of the nonpublishable vNext fixture."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.claims import (
    ClaimDecision,
    ClaimEvidenceGraph,
    REQUIRED_EVIDENCE_KINDS,
    artifact_registry_resolver,
)
from scientist_one.ledger import EventLedger
from scientist_one import research_os as research_os_module
from scientist_one.research_os import run_research_os_fixture
from scientist_one.research_state import ResearchStateRepository
from scientist_one.security import canonical_json_bytes
from scientist_one.terminal_outcomes import (
    ResearchTerminalOutcome,
    load_terminal_outcome,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CANONICAL_TYPES = frozenset(
    {
        "Ablation",
        "Baseline",
        "Challenge",
        "Claim",
        "Critique",
        "Dataset",
        "Decision",
        "Evidence",
        "Experiment",
        "Hypothesis",
        "Implementation",
        "Method",
        "Metric",
        "PriorWork",
        "ReproducibilityPackage",
        "ResearchQuestion",
        "Result",
        "Run",
        "Split",
        "StatisticalTest",
        "VenueAssessment",
    }
)


def _copy_fixture_tree(destination: Path) -> None:
    """Copy the package, fixture inputs, and frozen policy configuration."""

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


def _replace_child_source(destination: Path, old: str, new: str) -> None:
    """Apply one exact adversarial mutation to the copied child program."""

    path = destination / "scripts" / "vnext_fixture_experiment.py"
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise AssertionError("adversarial child mutation target is not unique")
    path.write_text(source.replace(old, new), encoding="utf-8")


def _experiment_manifests(root: Path, experiment_id: str) -> tuple[Path, ...]:
    """Select backend manifests by their immutable neighboring run spec."""

    selected: list[Path] = []
    jobs = root / ".scientist-one-build" / "experiments" / "local-mac"
    for spec_path in jobs.glob("*/frozen-run-spec.json"):
        spec = json.loads(spec_path.read_bytes())
        if spec["experiment_id"] == experiment_id:
            selected.append(spec_path.with_name("output-manifest.json"))
    return tuple(sorted(selected))


class ResearchOSEndToEndTests(unittest.TestCase):
    def _operation_receipt(self, root: Path, run_id: str) -> dict[str, object]:
        value = json.loads(
            (root / "runs" / run_id / "fixture-operation.json").read_bytes()
        )
        self.assertIsInstance(value, dict)
        return value

    def _assert_failed_operation(
        self,
        root: Path,
        run_id: str,
        *,
        error_type: str,
    ) -> None:
        receipt_path = root / "runs" / run_id / "fixture-operation.json"
        receipt = self._operation_receipt(root, run_id)
        self.assertEqual(
            receipt["schema_version"], "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2"
        )
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["error_type"], error_type)
        self.assertEqual(receipt["run_id"], run_id)
        self.assertEqual(
            receipt["recovery_policy"], "FAIL_CLOSED_START_NEW_RUN_ID"
        )
        self.assertEqual(receipt["launch_mode"], "DIRECT_TEST_API")
        self.assertIsNone(receipt["guarded_launch_receipt_sha256"])
        self.assertFalse(
            (root / "runs" / run_id / "guarded-launch.json").exists()
        )
        self.assertNotIn("summary_artifact_sha256", receipt)
        self.assertNotIn("system_fixture_integrity", receipt)
        frozen_receipt = receipt_path.read_bytes()
        with self.assertRaisesRegex(
            ValueError, "research-os fixture run ID already exists"
        ):
            run_research_os_fixture(root, run_id=run_id)
        self.assertEqual(receipt_path.read_bytes(), frozen_receipt)

    def _one_record(
        self,
        records: tuple[ArtifactRecord, ...],
        logical_type: str,
    ) -> ArtifactRecord:
        matches = tuple(
            record for record in records if record.logical_type == logical_type
        )
        self.assertEqual(
            len(matches),
            1,
            f"expected one authoritative {logical_type!r} artifact",
        )
        return matches[0]

    def _payload(
        self,
        registry: ArtifactRegistry,
        records: tuple[ArtifactRecord, ...],
        logical_type: str,
    ) -> dict[str, object]:
        record = self._one_record(records, logical_type)
        value = json.loads(registry.get_bytes(record.sha256))
        self.assertIsInstance(value, dict)
        return value

    def test_real_local_fixture_materializes_conservative_authorities(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-e2e-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "vnext-e2e-fixture"

            # No backend, provider, gateway, registry, or subprocess is mocked.
            result = run_research_os_fixture(root, run_id=run_id)

            # Top-level PASS is explicitly system-fixture integrity only.
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["system_fixture_integrity"], "PASS")
            self.assertEqual(
                result["fixture_notice"],
                "Synthetic integration fixture only; no publishable scientific conclusion.",
            )
            self.assertEqual(
                result["capability_level"], "AUTONOMOUS_EXPLORATION_READY"
            )

            registry = ArtifactRegistry(
                root, str(result["artifact_registry"]["base_path"])
            )
            registry_validation = registry.verify_all(raise_on_error=True)
            self.assertTrue(registry_validation.valid)
            self.assertEqual(result["artifact_registry"]["status"], "PASS")
            self.assertEqual(
                registry_validation.count,
                result["artifact_registry"]["artifact_count"],
            )
            records = registry_validation.records

            ledger = EventLedger(root, str(result["event_ledger"]["path"]))
            ledger_validation = ledger.validate(raise_on_error=True)
            self.assertTrue(ledger_validation.valid)
            self.assertEqual(result["event_ledger"]["status"], "PASS")
            self.assertEqual(
                ledger_validation.event_count,
                result["event_ledger"]["event_count"],
            )
            self.assertEqual(
                ledger_validation.head_hash,
                result["event_ledger"]["head_hash"],
            )
            known_hashes = {record.sha256 for record in records}
            self.assertTrue(ledger_validation.events)
            self.assertTrue(
                all(
                    digest in known_hashes
                    for event in ledger_validation.events
                    for digest in event.artifact_hashes
                )
            )

            summary_record = registry.get_metadata(
                str(result["summary_artifact_sha256"])
            )
            self.assertEqual(summary_record.logical_type, "research_os_run_summary")
            summary = json.loads(registry.get_bytes(summary_record.sha256))
            for key, value in summary.items():
                self.assertEqual(result[key], value)

            # Rehydrate the canonical state from the sole registry and ledger.
            state_records = tuple(
                record
                for record in records
                if record.logical_type.startswith("research_state.")
            )
            self.assertTrue(state_records)
            first_state = json.loads(registry.get_bytes(state_records[0].sha256))
            repository = ResearchStateRepository(
                registry,
                ledger,
                run_id=run_id,
                code_version=first_state["code_version"],
                configuration_hash=ledger_validation.events[0].configuration_hash,
                creation_command=(
                    "scientist-one",
                    "research-os-fixture",
                    "materialize-state",
                ),
            )
            state_validation = repository.validate_state(
                expected_code_version=first_state["code_version"]
            )
            self.assertTrue(state_validation.valid, state_validation.issues)
            objects = repository.objects()
            observed_types = {item.object_type for item in objects}
            self.assertEqual(observed_types, EXPECTED_CANONICAL_TYPES)
            self.assertEqual(len(observed_types), 21)
            self.assertEqual(len(objects), state_validation.object_count)
            reproduction_packages = tuple(
                item
                for item in objects
                if item.object_type == "ReproducibilityPackage"
            )
            self.assertEqual(len(reproduction_packages), 1)
            reproduction_package = reproduction_packages[0]
            self.assertEqual(
                reproduction_package.reproduction_status.value, "NOT_RUN"
            )
            self.assertIsNone(reproduction_package.reproduced_at)
            self.assertFalse(
                reproduction_package.metadata["scientific_evidence_eligible"]
            )
            self.assertEqual(
                reproduction_package.metadata["scientific_reproduction_status"],
                "NOT_RUN",
            )
            self.assertTrue(
                reproduction_package.metadata["system_reproduction_passed"]
            )
            self.assertEqual(
                result["canonical_research_state"]["object_count"],
                state_validation.object_count,
            )
            self.assertEqual(
                result["canonical_research_state"]["object_type_count"], 21
            )
            final_state = self._payload(
                registry, records, "canonical_research_state_final_snapshot"
            )
            self.assertTrue(final_state["state_valid"])
            self.assertEqual(set(final_state["object_types"]), observed_types)
            self.assertEqual(
                final_state["canonical_object_count"], state_validation.object_count
            )
            terminal_summary = result["terminal_outcome"]
            self.assertEqual(
                terminal_summary["outcome"],
                ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED.value,
            )
            terminal_record = load_terminal_outcome(
                registry,
                terminal_summary["artifact_sha256"],
                repository=repository,
            )
            self.assertIs(
                terminal_record.outcome,
                ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
            )
            self.assertEqual(terminal_record.run_id, run_id)

            # A fresh resolver must independently reproduce claim eligibility.
            claim_payload = self._payload(
                registry, records, "claim_evidence_graph"
            )
            graph_value = claim_payload["graph"]
            self.assertIsInstance(graph_value, dict)
            graph = ClaimEvidenceGraph.from_dict(
                graph_value,
                evidence_resolver=artifact_registry_resolver(
                    registry, resolver_id="e2e-registry-readback"
                ),
            )
            claim_id = graph.claims[0].claim_id
            claim_decision = graph.verify_claim(
                claim_id,
                verifier_id="fixture-claim-verifier",
                confirmatory_evidence_valid=False,
                raise_on_rejection=True,
            )
            self.assertIs(claim_decision.decision, ClaimDecision.ELIGIBLE)
            self.assertEqual(graph.writer_view(), ())
            diagnostic_claims = graph.writer_view(include_nonscientific=True)
            self.assertEqual(len(diagnostic_claims), 1)
            self.assertEqual(
                diagnostic_claims[0]["evidence_use"], "SYSTEM_FIXTURE"
            )
            self.assertEqual(result["claim"]["decision"], "ELIGIBLE")
            self.assertEqual(result["claim"]["evidence_use"], "SYSTEM_FIXTURE")
            self.assertFalse(result["claim"]["scientific_writer_eligible"])
            self.assertEqual(len(graph.evidence), 12)
            self.assertEqual(len(REQUIRED_EVIDENCE_KINDS), 12)
            self.assertEqual(
                {item.kind for item in graph.evidence},
                set(REQUIRED_EVIDENCE_KINDS),
            )
            self.assertEqual(result["claim"]["evidence_kind_count"], 12)

            autonomous = result["autonomous_implementation"]
            self.assertEqual(autonomous["admission_status"], "ADMITTED")
            self.assertEqual(autonomous["execution_state"], "SUCCEEDED")
            self.assertEqual(autonomous["provider_status"], "COMPLETED")
            self.assertEqual(autonomous["template_id"], "affine-mean-v1")
            self.assertFalse(autonomous["network_used"])
            self.assertFalse(autonomous["scientific_evidence"])
            descriptor = self._payload(
                registry,
                records,
                "autonomous_implementation.admitted_descriptor",
            )
            self.assertEqual(
                descriptor["execution_boundary"],
                "FROZEN_RUN_SPEC_LOCAL_MAC_ONLY",
            )
            self.assertFalse(descriptor["shell_allowed"])
            self.assertFalse(descriptor["network_allowed"])
            self.assertFalse(descriptor["scientific_evidence"])
            autonomous_spec = self._payload(
                registry,
                records,
                "autonomous_implementation.frozen_run_spec",
            )
            self.assertEqual(autonomous_spec["evidence_class"], "NON_EVIDENTIARY")
            self.assertFalse(autonomous_spec["shell_allowed"])
            self.assertFalse(autonomous_spec["network_allowed"])
            autonomous_receipt = self._payload(
                registry,
                records,
                "autonomous_implementation.execution_receipt",
            )
            self.assertEqual(autonomous_receipt["state"], "SUCCEEDED")
            self.assertFalse(autonomous_receipt["scientific_evidence"])

            discovery = self._payload(
                registry, records, "discovery_state_snapshot"
            )
            branches = discovery["snapshot"]["branches"]
            retained_statuses = {branch["status"] for branch in branches}
            self.assertIn("NEGATIVE_RESULT", retained_statuses)
            self.assertIn("NULL_RESULT", retained_statuses)
            self.assertTrue(all(branch["retained"] for branch in branches))
            promoted_branches = [
                branch for branch in branches if branch["status"] == "PROMOTED"
            ]
            self.assertEqual(len(promoted_branches), 1)
            self.assertEqual(
                promoted_branches[0]["evidence_authority"],
                "REGISTRY_EVALUATOR_VERIFIED",
            )
            checked_receipt = promoted_branches[0]["evaluation_receipt_sha256"]
            promotion_receipt = promoted_branches[0]["promotion_receipt_sha256"]
            self.assertIsInstance(checked_receipt, str)
            self.assertIsInstance(promotion_receipt, str)
            self.assertIsNone(
                promoted_branches[0]["evidence"]["robustness_passed"]
            )
            self.assertTrue(
                any(
                    record.sha256 == checked_receipt
                    and record.logical_type
                    == "discovery.checked_result_evaluation"
                    and record.frozen
                    and record.validation_result == "PASS"
                    for record in records
                )
            )
            self.assertTrue(
                any(
                    record.sha256 == promotion_receipt
                    and record.logical_type == "discovery.branch_promotion"
                    and checked_receipt in record.parent_artifacts
                    and record.frozen
                    and record.validation_result == "PASS"
                    for record in records
                )
            )
            self.assertTrue(
                all(
                    branch["evidence_authority"] == "DIAGNOSTIC_ONLY"
                    for branch in branches
                    if branch["status"] in {"NEGATIVE_RESULT", "NULL_RESULT"}
                )
            )
            self.assertIn("NEGATIVE_RESULT", result["discovery"]["retained_statuses"])
            self.assertIn("NULL_RESULT", result["discovery"]["retained_statuses"])

            # The two executed local attempts freeze the isolated child path.
            # The third spec is the deliberately nonexecuted GPU planning
            # boundary and retains its provider-neutral sentinel argv.
            frozen_specs = tuple(
                json.loads(registry.get_bytes(record.sha256))
                for record in records
                if record.logical_type == "frozen_run_spec"
            )
            self.assertEqual(len(frozen_specs), 3)
            local_specs = tuple(
                spec
                for spec in frozen_specs
                if spec["compute_profile"]["mode"] == "LOCAL_MAC"
            )
            gpu_specs = tuple(
                spec
                for spec in frozen_specs
                if spec["compute_profile"]["mode"] == "GPU_CLOUD"
            )
            self.assertEqual(len(local_specs), 2)
            self.assertEqual(len(gpu_specs), 1)
            for spec in local_specs:
                self.assertEqual(
                    spec["argv"],
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-S",
                        "-B",
                        "scripts/vnext_fixture_experiment.py",
                    ],
                )
            self.assertEqual(
                gpu_specs[0]["argv"],
                ["scientist-one-gpu-fixture-entrypoint"],
            )
            self.assertEqual(
                gpu_specs[0]["compute_profile"]["validation_status"],
                "UNTESTED",
            )
            for spec in frozen_specs:
                self.assertEqual(spec["evidence_class"], "NON_EVIDENTIARY")
                self.assertFalse(spec["network_allowed"])

            # Every backend execution plan is captured byte-for-byte. The raw
            # plan is safely deduplicated, while each of the three jobs has a
            # distinct frozen spec-to-plan custody binding in the registry and
            # the same authoritative ledger checkpoint.
            plan_records = tuple(
                record
                for record in records
                if record.logical_type == "adaptive_execution_plan"
            )
            binding_records = tuple(
                record
                for record in records
                if record.logical_type == "adaptive_execution_plan_binding"
            )
            self.assertEqual(len(plan_records), 2)
            self.assertEqual(len(binding_records), 3)
            plans_by_sha256 = {record.sha256: record for record in plan_records}
            bindings_by_job_id = {
                json.loads(registry.get_bytes(record.sha256))["job_id"]: record
                for record in binding_records
            }
            jobs_root = (
                root / ".scientist-one-build" / "experiments" / "local-mac"
            )
            job_directories = tuple(
                path for path in jobs_root.iterdir() if path.is_dir()
            )
            self.assertEqual(len(job_directories), 3)
            for job_directory in job_directories:
                raw_plan = (job_directory / "execution-plan.json").read_bytes()
                plan_value = json.loads(raw_plan)
                plan_artifact_sha256 = hashlib.sha256(raw_plan).hexdigest()
                raw_input_binding = (
                    job_directory / "execution-input-binding.json"
                ).read_bytes()
                input_binding_artifact_sha256 = hashlib.sha256(
                    raw_input_binding
                ).hexdigest()
                plan_sha256 = hashlib.sha256(
                    canonical_json_bytes(plan_value)
                ).hexdigest()
                plan_record = plans_by_sha256[plan_artifact_sha256]
                self.assertTrue(plan_record.frozen)
                self.assertEqual(plan_record.validation_result, "PASS")
                self.assertEqual(registry.get_bytes(plan_record.sha256), raw_plan)

                binding_record = bindings_by_job_id[job_directory.name]
                binding = json.loads(registry.get_bytes(binding_record.sha256))
                spec_value = json.loads(
                    (job_directory / "frozen-run-spec.json").read_bytes()
                )
                spec_sha256 = hashlib.sha256(
                    canonical_json_bytes(spec_value)
                ).hexdigest()
                self.assertTrue(binding["agreement"])
                self.assertEqual(binding["run_id"], spec_value["run_id"])
                self.assertEqual(binding["spec_sha256"], spec_sha256)
                self.assertEqual(binding["submission_spec_sha256"], spec_sha256)
                self.assertEqual(binding["collected_spec_sha256"], spec_sha256)
                self.assertEqual(binding["submission_backend_id"], "local-mac")
                self.assertEqual(binding["collected_backend_id"], "local-mac")
                self.assertEqual(binding["execution_plan_sha256"], plan_sha256)
                self.assertEqual(
                    binding["submission_execution_plan_sha256"], plan_sha256
                )
                self.assertEqual(
                    binding["collected_execution_plan_sha256"], plan_sha256
                )
                self.assertEqual(
                    binding["execution_plan_artifact_sha256"],
                    plan_artifact_sha256,
                )
                self.assertEqual(
                    binding["execution_input_binding_artifact_sha256"],
                    input_binding_artifact_sha256,
                )
                self.assertEqual(
                    binding["execution_input_binding_sha256"],
                    input_binding_artifact_sha256,
                )
                self.assertEqual(
                    binding_record.parent_artifacts,
                    (
                        plan_artifact_sha256,
                        input_binding_artifact_sha256,
                        binding["spec_artifact_sha256"],
                    ),
                )
                self.assertTrue(
                    any(
                        {
                            plan_artifact_sha256,
                            input_binding_artifact_sha256,
                            binding_record.sha256,
                            binding["spec_artifact_sha256"],
                        }.issubset(event.artifact_hashes)
                        for event in ledger_validation.events
                    )
                )
            comparison = self._payload(
                registry, records, "clean_reproduction_comparison"
            )
            self.assertEqual(
                comparison["comparison"]["status"], "NON_EVIDENTIARY"
            )
            self.assertFalse(comparison["scientific_evidence_eligible"])
            self.assertTrue(comparison["system_reproduction_passed"])
            self.assertFalse(result["local_mac"]["scientific_evidence"])
            self.assertFalse(result["local_mac"]["os_enforced_sandbox"])
            self.assertEqual(
                result["local_mac"]["comparison_status"], "NON_EVIDENTIARY"
            )
            self.assertTrue(result["local_mac"]["system_reproduction_passed"])

            gpu = self._payload(registry, records, "gpu_cloud_boundary_status")
            self.assertEqual(gpu["external_validation"], "UNTESTED")
            self.assertFalse(gpu["scientific_evidence"])
            self.assertEqual(result["gpu_cloud"]["external_validation"], "UNTESTED")
            self.assertFalse(result["gpu_cloud"]["scientific_evidence"])
            self.assertEqual(result["literature"]["live_status"], "BLOCKED_EXTERNAL")
            self.assertFalse(result["literature"]["network_used"])
            self.assertIn(
                result["model_provider"]["external_validation"],
                {"UNTESTED", "BLOCKED_EXTERNAL"},
            )
            self.assertIn(
                result["model_provider"]["live_availability"],
                {"UNTESTED", "BLOCKED_EXTERNAL"},
            )
            self.assertFalse(result["model_provider"]["network_used"])
            self.assertFalse(result["model_provider"]["scientific_evidence"])

            superiority_record = self._one_record(
                records, "superiority_promotion_diagnostic"
            )
            superiority = self._payload(
                registry, records, "superiority_promotion_diagnostic"
            )
            self.assertEqual(
                superiority["schema_version"],
                "superiority-promotion-diagnostic/v1",
            )
            self.assertEqual(superiority["authority_status"], "DIAGNOSTIC_ONLY")
            self.assertFalse(superiority["authoritative"])
            self.assertFalse(superiority["scientific_evidence_eligible"])
            self.assertFalse(superiority["scientific_promotion_authorized"])
            self.assertEqual(
                superiority["diagnostic"]["status"], "DIAGNOSTIC_ONLY"
            )

            paper_bundle = self._payload(
                registry, records, "authoritative_research_bundle"
            )
            bundle = paper_bundle["bundle"]
            self.assertFalse(bundle["required_baselines_complete"])
            self.assertFalse(bundle["statistics_valid"])
            self.assertNotIn(
                superiority_record.sha256,
                bundle["authoritative_evidence_hashes"],
            )
            controls = paper_bundle["deterministic_control_derivations"]
            self.assertFalse(controls["required_baselines_complete"])
            self.assertFalse(controls["statistics_valid"])

            soundness = self._payload(
                registry, records, "scientific_soundness_assessment"
            )
            self.assertEqual(
                soundness["assessment"]["verdict"],
                "MORE_EXPERIMENTS_REQUIRED",
            )
            self.assertEqual(
                result["scientific_soundness"], "MORE_EXPERIMENTS_REQUIRED"
            )
            paper = self._payload(registry, records, "paper_verification")
            venue = self._payload(
                registry, records, "venue_readiness_assessment"
            )
            self.assertFalse(paper["verification"]["passed"])
            self.assertEqual(result["paper"]["status"], "BLOCKED")
            self.assertEqual(venue["assessment"]["classification"], "NOT_READY")
            self.assertEqual(result["paper"]["venue_classification"], "NOT_READY")

            gates = self._payload(
                registry, records, "human_and_scientific_gate_status"
            )
            self.assertFalse(gates["human_e4_synthesized"])
            self.assertEqual(
                {
                    "compute_escalation",
                    "confirmation_reveal",
                    "contract_freeze",
                    "final_release",
                    "fixture_notice",
                    "human_e4_synthesized",
                    "novelty",
                    "research_question",
                    "soundness_promotion",
                },
                set(gates),
            )
            self.assertEqual(
                gates["contract_freeze"]["outcome"],
                "AUTHORIZED_AUTONOMOUSLY",
            )
            self.assertEqual(
                gates["compute_escalation"]["outcome"],
                "AUTHORIZED_AUTONOMOUSLY",
            )
            self.assertTrue(
                gates["compute_escalation"]["scientific_gate_passed"]
            )
            for gate_name in (
                "confirmation_reveal",
                "novelty",
                "research_question",
                "soundness_promotion",
            ):
                self.assertEqual(
                    gates[gate_name]["outcome"],
                    "BLOCKED_SCIENTIFICALLY",
                )
            self.assertEqual(
                gates["final_release"]["outcome"], "BLOCKED_SCIENTIFICALLY"
            )
            self.assertEqual(
                result["human_and_scientific_gates"],
                {
                    "COMPUTE_ESCALATION": "AUTHORIZED_AUTONOMOUSLY",
                    "CONFIRMATION_REVEAL": "BLOCKED_SCIENTIFICALLY",
                    "EVALUATION_CONTRACT_FREEZE": "AUTHORIZED_AUTONOMOUSLY",
                    "FINAL_RELEASE": "BLOCKED_SCIENTIFICALLY",
                    "NOVELTY": "BLOCKED_SCIENTIFICALLY",
                    "RESEARCH_QUESTION": "BLOCKED_SCIENTIFICALLY",
                    "SOUNDNESS_PROMOTION": "BLOCKED_SCIENTIFICALLY",
                },
            )
            self.assertFalse(result["human_e4_synthesized"])

            operation = self._operation_receipt(root, run_id)
            self.assertEqual(
                operation["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2",
            )
            self.assertEqual(operation["status"], "COMPLETE")
            self.assertIsNone(operation["error_type"])
            self.assertEqual(operation["recovery_policy"], "IMMUTABLE_COMPLETE")
            self.assertEqual(operation["system_fixture_integrity"], "PASS")
            self.assertEqual(
                operation["summary_artifact_sha256"],
                result["summary_artifact_sha256"],
            )
            self.assertEqual(
                operation["artifact_registry"], result["artifact_registry"]
            )
            self.assertEqual(operation["event_ledger"], result["event_ledger"])
            self.assertEqual(operation["launch_mode"], "DIRECT_TEST_API")
            self.assertIsNone(operation["guarded_launch_receipt_sha256"])
            self.assertFalse(
                (root / "runs" / run_id / "guarded-launch.json").exists()
            )

            # A completed run identity is immutable and cannot be overwritten.
            with self.assertRaisesRegex(
                ValueError, "research-os fixture run ID already exists"
            ):
                run_research_os_fixture(root, run_id=run_id)

    def test_hash_consistent_wrong_manifest_metric_fails_semantic_recomputation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-wrong-metric-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            _replace_child_source(
                root,
                '                "metric": candidate_accuracy,\n',
                '                "metric": 0.0,\n',
            )
            run_id = "vnext-adversarial-manifest-metric"

            with self.assertRaisesRegex(
                RuntimeError,
                "reported seed metric differs from deterministic frozen-evaluator recomputation",
            ):
                run_research_os_fixture(root, run_id=run_id)

            # The child recomputed all content hashes and emitted a structurally
            # valid manifest; rejection occurs only at semantic recomputation.
            manifests = _experiment_manifests(
                root,
                "experiment-threshold-fixture",
            )
            self.assertEqual(len(manifests), 2)
            for manifest_path in manifests:
                manifest = json.loads(manifest_path.read_bytes())
                self.assertEqual(
                    {item["metric"] for item in manifest["seed_results"]},
                    {0.0},
                )
                for output in manifest["artifacts"]:
                    output_path = manifest_path.parent / output["path"]
                    output_bytes = output_path.read_bytes()
                    self.assertEqual(len(output_bytes), output["size"])
                    self.assertEqual(
                        hashlib.sha256(output_bytes).hexdigest(), output["sha256"]
                    )
            self._assert_failed_operation(root, run_id, error_type="RuntimeError")

    def test_hash_consistent_fabricated_ablation_without_vector_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-fake-ablation-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            _replace_child_source(
                root,
                '            "accuracy": baseline_accuracy,\n'
                '            "ablated_correctness": baseline_correctness,\n',
                '            "accuracy": 1.0,\n'
                '            "claimed_semantics": "fabricated PASS without recomputable vector",\n',
            )
            _replace_child_source(
                root,
                '            "intervention": "replace candidate with frozen constant-zero baseline",\n',
                '            "intervention": "fabricated removal semantics",\n',
            )
            run_id = "vnext-adversarial-ablation-semantics"

            with self.assertRaisesRegex(
                RuntimeError,
                "ablated correctness must be a non-empty binary vector",
            ):
                run_research_os_fixture(root, run_id=run_id)

            manifests = _experiment_manifests(
                root,
                "experiment-threshold-fixture",
            )
            self.assertEqual(len(manifests), 2)
            for manifest_path in manifests:
                manifest = json.loads(manifest_path.read_bytes())
                ablation = manifest["ablations"][0]
                self.assertEqual(ablation["status"], "PASS")
                artifact = next(
                    item
                    for item in manifest["artifacts"]
                    if item["sha256"] == ablation["artifact_sha256"]
                )
                artifact_bytes = (
                    manifest_path.parent / artifact["path"]
                ).read_bytes()
                payload = json.loads(artifact_bytes)
                self.assertEqual(len(artifact_bytes), artifact["size"])
                self.assertEqual(
                    hashlib.sha256(artifact_bytes).hexdigest(), artifact["sha256"]
                )
                self.assertNotIn("ablated_correctness", payload)
                self.assertEqual(payload["accuracy"], 1.0)
                self.assertEqual(
                    payload["claimed_semantics"],
                    "fabricated PASS without recomputable vector",
                )
            self._assert_failed_operation(root, run_id, error_type="RuntimeError")

    def test_execution_plan_changed_after_collection_fails_before_promotion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-plan-tamper-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            original_promote = research_os_module._promote_collected_run
            tampered = False

            def promote_then_tamper(*args, **kwargs):
                nonlocal tampered
                collected = kwargs["collected"]
                submission = kwargs["submission"]
                if (
                    not tampered
                    and collected.spec.experiment_id
                    == "experiment-threshold-fixture"
                ):
                    plan_path = (
                        root
                        / ".scientist-one-build"
                        / "experiments"
                        / "local-mac"
                        / submission.job_id
                        / "execution-plan.json"
                    )
                    value = json.loads(plan_path.read_bytes())
                    value["batch_size"] += 1
                    plan_path.chmod(0o600)
                    plan_path.write_bytes(canonical_json_bytes(value) + b"\n")
                    tampered = True
                return original_promote(*args, **kwargs)

            run_id = "vnext-adversarial-plan-tamper"
            with mock.patch.object(
                research_os_module,
                "_promote_collected_run",
                new=promote_then_tamper,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "persisted backend execution plan differs from submission or collection",
                ):
                    run_research_os_fixture(root, run_id=run_id)
            self.assertTrue(tampered)
            self._assert_failed_operation(root, run_id, error_type="RuntimeError")

    def test_collected_execution_plan_identity_cannot_be_rebound(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-plan-rebind-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            original_promote = research_os_module._promote_collected_run
            rebound = False

            def promote_then_rebind(*args, **kwargs):
                nonlocal rebound
                collected = kwargs["collected"]
                if (
                    not rebound
                    and collected.spec.experiment_id
                    == "experiment-threshold-fixture"
                ):
                    kwargs = dict(kwargs)
                    kwargs["collected"] = replace(
                        collected,
                        execution_plan_sha256="0" * 64,
                    )
                    rebound = True
                return original_promote(*args, **kwargs)

            run_id = "vnext-adversarial-plan-rebind"
            with mock.patch.object(
                research_os_module,
                "_promote_collected_run",
                new=promote_then_rebind,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "persisted backend execution plan differs from submission or collection",
                ):
                    run_research_os_fixture(root, run_id=run_id)
            self.assertTrue(rebound)
            self._assert_failed_operation(root, run_id, error_type="RuntimeError")

    def test_same_run_id_reservation_is_atomic_under_concurrency(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-concurrent-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            run_id = "vnext-concurrent-reservation"
            barrier = threading.Barrier(2)

            def invoke() -> tuple[str, object]:
                barrier.wait(timeout=10)
                try:
                    return "result", run_research_os_fixture(root, run_id=run_id)
                except BaseException as exc:
                    return "error", exc

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = tuple(executor.map(lambda _index: invoke(), range(2)))

            results = tuple(value for kind, value in outcomes if kind == "result")
            errors = tuple(value for kind, value in outcomes if kind == "error")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "PASS")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertEqual(
                str(errors[0]), "research-os fixture run ID already exists"
            )
            operation = self._operation_receipt(root, run_id)
            self.assertEqual(operation["status"], "COMPLETE")
            self.assertEqual(operation["recovery_policy"], "IMMUTABLE_COMPLETE")
            job_directories = tuple(
                path
                for path in (
                    root / ".scientist-one-build" / "experiments" / "local-mac"
                ).iterdir()
                if path.is_dir()
            )
            self.assertEqual(len(job_directories), 3)
            self.assertEqual(
                {
                    json.loads((path / "frozen-run-spec.json").read_bytes())[
                        "experiment_id"
                    ]
                    for path in job_directories
                },
                {
                    "experiment-autonomous-component-fixture",
                    "experiment-threshold-fixture",
                },
            )

    def test_missing_fixture_input_fails_before_run_creation(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-missing-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)
            (root / "fixtures" / "vnext_research_dataset.json").unlink()

            with self.assertRaisesRegex(
                ValueError,
                "required fixture input is absent: fixtures/vnext_research_dataset.json",
            ):
                run_research_os_fixture(root, run_id="vnext-missing-input")
            self.assertFalse((root / "runs" / "vnext-missing-input").exists())

    def test_public_fixture_api_cannot_select_guarded_launch_authority(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="scientist-one-vnext-public-launch-"
        ) as raw_root:
            root = Path(raw_root)
            _copy_fixture_tree(root)

            with self.assertRaises(TypeError):
                run_research_os_fixture(  # type: ignore[call-arg]
                    root,
                    run_id="vnext-public-mode-forbidden",
                    launch_mode="GUARDED_PRODUCTION",
                )
            with self.assertRaises(TypeError):
                run_research_os_fixture(  # type: ignore[call-arg]
                    root,
                    run_id="vnext-public-capability-forbidden",
                    capability=object(),
                )
            with self.assertRaises(TypeError):
                run_research_os_fixture(  # type: ignore[call-arg]
                    root,
                    run_id="vnext-public-restart-forbidden",
                    restart_from_run_id="vnext-abandoned",
                )
            self.assertFalse((root / "runs").exists())


if __name__ == "__main__":
    unittest.main()
