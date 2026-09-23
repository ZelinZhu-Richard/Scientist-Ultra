"""Offline tests for discovery retention and experiment compute boundaries."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest

import scientist_one.discovery as discovery_module
from scientist_one.discovery import (
    AblationEvidence,
    BranchEvidence,
    BranchStatus,
    DiscoveryAction,
    DiscoveryBudget,
    DiscoveryCheck,
    DiscoveryEngine,
    DiscoveryEvidenceAuthority,
    DiscoveryError,
    DiscoveryIntegrityError,
    DiscoveryProposal,
    RegisteredBranchEvidence,
    RegistryDiscoveryEvidenceResolver,
    SeedObservation,
    SeedStatus,
    SelectionDecision,
)
from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.errors import CommandSecurityError, IntegrityError, ValidationError
from scientist_one.experiments import (
    AdaptiveExecutionPlan,
    AblationResult,
    CollectedRun,
    ConfirmatoryPolicyError,
    EvidenceClass,
    ExecutionResult,
    ExperimentClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    FakeGPUCloudBackend,
    FrozenRunSpec,
    LocalMacBackend,
    LocalMacExecutionMode,
    OutputArtifact,
    OutputManifest,
    ReproductionStatus,
    ResourceEstimate,
    RunState,
    SeedRunResult,
    SeedRunStatus,
    SubmissionConflictError,
    ValidationStatus,
    compare_clean_rerun,
    require_no_backend_fallback,
    validate_explicit_retry,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads


def _digest(character: str) -> str:
    return character * 64


def _proposal(
    proposal_id: str,
    *,
    action: DiscoveryAction = DiscoveryAction.FRESH_IDEA,
    parent_branch_id: str | None = None,
    variant: str = "base",
    compute_units: int = 2,
    information: int = 10,
    importance: int = 10,
    uncertainty: int = 10,
    required_ablations: tuple[str, ...] = (),
    confirmatory_units: int = 0,
    metadata: dict[str, object] | None = None,
) -> DiscoveryProposal:
    return DiscoveryProposal(
        proposal_id=proposal_id,
        action=action,
        hypothesis_id="hypothesis-1",
        method_identity="bounded method identity",
        code_sha256=_digest("a"),
        configuration_sha256=_digest("b"),
        planned_seeds=(1, 2),
        compute_units=compute_units,
        expected_information_value=information,
        scientific_importance=importance,
        uncertainty_reduction=uncertainty,
        parent_branch_id=parent_branch_id,
        variant_identity=variant,
        required_ablations=required_ablations,
        confirmatory_compute_units=confirmatory_units,
        metadata=metadata or {},
    )


def _successful_evidence(
    *,
    first: float = 1.0,
    second: float = 1.1,
    ablations: tuple[AblationEvidence, ...] = (),
) -> BranchEvidence:
    return BranchEvidence(
        seed_observations=(
            SeedObservation(1, SeedStatus.SUCCESS, first, _digest("c")),
            SeedObservation(2, SeedStatus.SUCCESS, second, _digest("d")),
        ),
        ablations=ablations,
    )


class DiscoveryTests(unittest.TestCase):
    def test_action_inventory_is_complete(self) -> None:
        self.assertEqual(
            {item.value for item in DiscoveryAction},
            {
                "FRESH_IDEA",
                "INDEPENDENT_BRANCH",
                "REFINE_BRANCH",
                "DEBUG_BRANCH",
                "ABLATE",
                "RUN_CONTROL",
                "RUN_ROBUSTNESS",
                "RUN_FALSIFICATION",
                "TERMINATE_BRANCH",
                "PROMOTE_CANDIDATE",
            },
        )

    def test_deterministic_selection_duplicate_suppression_and_full_history(self) -> None:
        engine = DiscoveryEngine(
            DiscoveryBudget(maximum_branches=4, maximum_actions=4, maximum_compute_units=6)
        )
        lower = _proposal("proposal-low", variant="low", information=3)
        higher = _proposal("proposal-high", variant="high", information=20)
        selected = engine.select_next((lower, higher))
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.proposal.proposal_id, "proposal-high")
        self.assertEqual(
            engine.selection_history[0].considered_proposal_ids,
            ("proposal-high", "proposal-low"),
        )

        duplicate = _proposal("proposal-high-copy", variant="high", information=999)
        rejected = engine.submit(duplicate)
        self.assertEqual(rejected.status, BranchStatus.REJECTED)
        self.assertEqual(rejected.duplicate_of, selected.branch_id)
        self.assertTrue(rejected.retained)
        self.assertEqual(
            engine.selection_history[-1].decision,
            SelectionDecision.DUPLICATE_SUPPRESSED,
        )
        self.assertEqual(len(engine.branches), 2)

    def test_branch_isolation_freezes_parent_snapshot_and_metadata(self) -> None:
        metadata = {"nested": {"weights": [1, 2]}}
        engine = DiscoveryEngine(DiscoveryBudget())
        parent = engine.submit(_proposal("proposal-parent", metadata=metadata))
        metadata["nested"]["weights"].append(3)  # type: ignore[index,union-attr]
        child = engine.submit(
            _proposal(
                "proposal-child",
                action=DiscoveryAction.REFINE_BRANCH,
                parent_branch_id=parent.branch_id,
                variant="child",
            )
        )
        self.assertIsNotNone(child.parent_snapshot_sha256)
        self.assertEqual(parent.proposal.metadata["nested"]["weights"], (1, 2))
        with self.assertRaises(TypeError):
            parent.proposal.metadata["new"] = True  # type: ignore[index]

        engine.record_result(parent.branch_id, _successful_evidence())
        self.assertEqual(
            engine.get_branch(child.branch_id).parent_snapshot_sha256,
            child.parent_snapshot_sha256,
        )

    def test_selective_seeds_and_missing_or_fabricated_ablations_are_retained_invalid(self) -> None:
        engine = DiscoveryEngine(DiscoveryBudget())
        selective = engine.submit(_proposal("proposal-selective", variant="selective"))
        selective_result = engine.record_result(
            selective.branch_id,
            BranchEvidence(
                seed_observations=(
                    SeedObservation(1, SeedStatus.SUCCESS, 99.0, _digest("e")),
                )
            ),
        )
        self.assertEqual(selective_result.status, BranchStatus.INVALID)
        self.assertIn("INCOMPLETE_ALL_SEED_REPORTING", selective_result.reason_codes)
        engine.promote(selective.branch_id)
        self.assertFalse(engine.is_promotion_eligible(selective.branch_id))

        missing = engine.submit(
            _proposal(
                "proposal-missing-ablation",
                variant="missing-ablation",
                required_ablations=("remove-component",),
            )
        )
        missing_result = engine.record_result(missing.branch_id, _successful_evidence())
        self.assertEqual(missing_result.status, BranchStatus.INVALID)
        self.assertIn("MISSING_ABLATION:remove-component", missing_result.reason_codes)

        fabricated = engine.submit(
            _proposal(
                "proposal-fabricated-ablation",
                variant="fabricated-ablation",
                required_ablations=("remove-component",),
            )
        )
        fabricated_result = engine.record_result(
            fabricated.branch_id,
            _successful_evidence(
                ablations=(
                    AblationEvidence(
                        "remove-component",
                        _digest("f"),
                        False,
                        "experiment-ablation",
                    ),
                )
            ),
        )
        self.assertEqual(fabricated_result.status, BranchStatus.INVALID)
        self.assertIn("UNVERIFIED_ABLATION:remove-component", fabricated_result.reason_codes)
        self.assertTrue(all(branch.retained for branch in engine.branches))

    def test_negative_null_failed_invalid_and_rejected_branches_are_never_dropped(self) -> None:
        engine = DiscoveryEngine(
            DiscoveryBudget(maximum_branches=5, maximum_actions=5, maximum_compute_units=20)
        )
        statuses = (
            ("negative", SeedStatus.NEGATIVE, BranchStatus.NEGATIVE_RESULT),
            ("null", SeedStatus.NULL, BranchStatus.NULL_RESULT),
            ("failed", SeedStatus.FAILED, BranchStatus.FAILED),
            ("invalid", SeedStatus.INVALID, BranchStatus.INVALID),
        )
        for index, (variant, seed_status, expected) in enumerate(statuses):
            branch = engine.submit(_proposal(f"proposal-{variant}", variant=variant))
            if seed_status in {SeedStatus.FAILED, SeedStatus.INVALID}:
                observations = (
                    SeedObservation(1, seed_status, reason=f"reason-{variant}"),
                    SeedObservation(2, seed_status, reason=f"reason-{variant}"),
                )
            else:
                observations = (
                    SeedObservation(1, seed_status, float(index), _digest("1")),
                    SeedObservation(2, seed_status, float(index), _digest("2")),
                )
            result = engine.record_result(
                branch.branch_id,
                BranchEvidence(seed_observations=observations),
            )
            self.assertEqual(result.status, expected)

        confirmatory = engine.submit(
            _proposal(
                "proposal-confirmatory",
                variant="confirmatory",
                confirmatory_units=1,
            )
        )
        self.assertEqual(confirmatory.status, BranchStatus.REJECTED)
        self.assertEqual(len(engine.branches), 5)
        self.assertEqual(len(engine.ranked_candidates()), 5)
        self.assertTrue(all(item.retained for item in engine.branches))

    def test_budget_rejection_and_scientific_ranking_are_deterministic(self) -> None:
        engine = DiscoveryEngine(
            DiscoveryBudget(maximum_branches=2, maximum_actions=2, maximum_compute_units=4)
        )
        lower = engine.submit(_proposal("proposal-lower", variant="lower"))
        higher = engine.submit(_proposal("proposal-higher", variant="higher"))
        engine.record_result(lower.branch_id, _successful_evidence(first=0.1, second=0.2))
        engine.record_result(higher.branch_id, _successful_evidence(first=0.8, second=0.9))
        rejected = engine.submit(_proposal("proposal-over-budget", variant="over-budget"))
        self.assertEqual(rejected.status, BranchStatus.REJECTED)
        self.assertEqual(
            engine.selection_history[-1].decision,
            SelectionDecision.BUDGET_REJECTED,
        )
        self.assertEqual(engine.ranked_candidates()[0].branch_id, higher.branch_id)
        self.assertEqual(engine.promote(higher.branch_id).status, BranchStatus.SUCCEEDED)
        self.assertEqual(
            engine.get_branch(higher.branch_id).evidence_authority,
            DiscoveryEvidenceAuthority.DIAGNOSTIC_ONLY,
        )
        self.assertEqual(
            engine.selection_history[-1].decision,
            SelectionDecision.PROMOTION_REJECTED,
        )


class CheckedDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root, "runs/discovery/registry")
        self.ledger = EventLedger(self.root, "runs/discovery/events.jsonl")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _put_json(
        self,
        value: object,
        *,
        logical_type: str,
        role: Role,
        parents: tuple[str, ...] = (),
    ) -> ArtifactRecord:
        return self.registry.put_json(
            value,
            logical_type=logical_type,
            origin=f"test {logical_type}",
            creator_role=role,
            parent_artifacts=parents,
            mime_type="application/json",
        )

    def _checked_fixture(
        self,
        *,
        reported_metrics: tuple[float, float] | None = None,
        control_passed: bool = True,
        robustness_passed: bool = True,
        falsification_survived: bool = True,
        forge_correctness_vector: bool = False,
        evaluation_split: str = "development",
        execution_split: str | None = None,
        ablation_intervention: str = (
            "replace candidate with frozen constant-zero baseline"
        ),
        binding_backend: str = "local-mac",
        metric_direction: str = "maximize",
    ) -> tuple[DiscoveryEngine, object, RegisteredBranchEvidence]:
        implementation_source = Path(discovery_module.__file__).read_bytes()
        implementation = self._put_json(
            {
                "captured_at": "2026-08-29T00:00:00Z",
                "files": [
                    {
                        "path": "src/scientist_one/discovery.py",
                        "sha256": hashlib.sha256(
                            implementation_source
                        ).hexdigest(),
                    }
                ],
                "schema_version": "SCIENTIST_ONE_VNEXT_SOURCE_SNAPSHOT_V1",
            },
            logical_type="vnext_source_snapshot",
            role=Role.ORCHESTRATOR,
        )
        code = self.registry.put_bytes(
            b"deterministic experiment code\n",
            logical_type="experiment_code",
            origin="test experiment code",
            creator_role=Role.IMPLEMENTER,
            parent_artifacts=(implementation.sha256,),
            mime_type="text/plain",
        )
        signals = (0.1, 0.9, 0.8, 0.2) if control_passed else (0.1, 0.1, 0.2, 0.2)
        rows = [
            {"label": 0, "signal": signals[0], "split": "development"},
            {"label": 1, "signal": signals[1], "split": "development"},
            {"label": 1, "signal": signals[2], "split": "development"},
            {"label": 1, "signal": signals[3], "split": "development"},
        ]
        if execution_split is not None and execution_split != "development":
            rows.extend(
                {**row, "split": execution_split}
                for row in tuple(rows)
            )
        data = self._put_json(
            {
                "dataset_id": "checked-fixture",
                "rows": rows,
            },
            logical_type="dataset_fixture",
            role=Role.EVIDENCE_CURATOR,
        )
        configuration = self._put_json(
            {
                "ablation_interventions": {
                    "remove-signal": ablation_intervention
                },
                "candidate_threshold": 0.5,
                "dataset_path": "fixtures/checked-discovery.json",
                "evaluation_split": evaluation_split,
                "planned_seeds": [1, 2],
                "required_ablations": ["remove-signal"],
            },
            logical_type="experiment_configuration",
            role=Role.PROTOCOL_DESIGNER,
            parents=(code.sha256, data.sha256),
        )
        evaluator_record = self._put_json(
            {
                "aggregation": "arithmetic mean over all declared seeds",
                "definition": "correct development subjects divided by all development subjects",
                "metric_id": "subject-accuracy",
                "unit": "fraction",
                "version": "accuracy-evaluator-v1",
            },
            logical_type="metric_evaluator",
            role=Role.PROTOCOL_DESIGNER,
            parents=(configuration.sha256,),
        )
        proposal = replace(
            _proposal(
                "proposal-checked",
                variant="checked",
                required_ablations=("remove-signal",),
            ),
            method_identity="pinned-threshold-0.5",
            code_sha256=code.sha256,
            data_sha256=data.sha256,
            configuration_sha256=configuration.sha256,
            experiment_id="experiment-checked",
            evaluator_sha256=evaluator_record.sha256,
            evaluator_implementation_sha256=implementation.sha256,
            metric_direction=metric_direction,
            metadata={"split": evaluation_split},
        )
        spec = replace(
            _spec(
                "run-checked",
                seeds=(1, 2),
                required_ablations=("remove-signal",),
                argv=(
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/vnext_fixture_experiment.py",
                ),
                metadata={
                    "candidate_threshold": 0.5,
                    "dataset_path": "fixtures/checked-discovery.json",
                    "discovery_evaluator_implementation_sha256": (
                        implementation.sha256
                    ),
                    "discovery_proposal_fingerprint": (
                        proposal.scientific_fingerprint()
                    ),
                    "evaluation_split": execution_split or evaluation_split,
                    "scientific_evidence_eligible": False,
                },
            ),
            experiment_id="experiment-checked",
            hypothesis_id="hypothesis-1",
            code_sha256=code.sha256,
            data_sha256=data.sha256,
            configuration_sha256=configuration.sha256,
            evaluator_sha256=evaluator_record.sha256,
        )
        spec_record = self._put_json(
            spec.to_dict(),
            logical_type="frozen_run_spec",
            role=Role.EXPERIMENT_RUNNER,
            parents=(
                code.sha256,
                data.sha256,
                configuration.sha256,
                evaluator_record.sha256,
                implementation.sha256,
            ),
        )

        baseline_vector = [1, 0, 0, 0]
        normal_candidate = (
            [1, 1, 0, 0]
            if forge_correctness_vector
            else ([1, 1, 1, 0] if control_passed else list(baseline_vector))
        )
        # Deterministic repeat equality is not independent robustness evidence;
        # the reviewed path records robustness as N/A rather than PASS.
        second_candidate = list(normal_candidate)
        selected_metrics = reported_metrics or (
            sum(normal_candidate) / len(normal_candidate),
            sum(second_candidate) / len(second_candidate),
        )
        seed_values = {
            1: {
                "baseline_accuracy": 0.25,
                "baseline_correctness": baseline_vector,
                "candidate_accuracy": selected_metrics[0],
                "candidate_correctness": normal_candidate,
                "dataset_sha256": data.sha256,
                "run_id": spec.run_id,
                "seed": 1,
                "spec_sha256": spec.sha256,
            },
            2: {
                "baseline_accuracy": 0.25,
                "baseline_correctness": baseline_vector,
                "candidate_accuracy": selected_metrics[1],
                "candidate_correctness": second_candidate,
                "dataset_sha256": data.sha256,
                "run_id": spec.run_id,
                "seed": 2,
                "spec_sha256": spec.sha256,
            },
        }
        ablated_vector = (
            list(baseline_vector)
            if falsification_survived
            else list(normal_candidate)
        )
        ablation_value = {
            "ablation_id": "remove-signal",
            "accuracy": sum(ablated_vector) / len(ablated_vector),
            "ablated_correctness": ablated_vector,
            "dataset_sha256": data.sha256,
            "evaluator_sha256": evaluator_record.sha256,
            "intervention": ablation_intervention,
            "run_id": spec.run_id,
            "spec_sha256": spec.sha256,
        }
        seed_payloads = {
            seed: canonical_json_bytes(value) + b"\n"
            for seed, value in seed_values.items()
        }
        ablation_payload = canonical_json_bytes(ablation_value) + b"\n"
        seed_digests = {
            seed: hashlib.sha256(payload).hexdigest()
            for seed, payload in seed_payloads.items()
        }
        ablation_digest = hashlib.sha256(ablation_payload).hexdigest()
        manifest = OutputManifest(
            run_id=spec.run_id,
            spec_sha256=spec.sha256,
            code_sha256=code.sha256,
            data_sha256=data.sha256,
            configuration_sha256=configuration.sha256,
            evaluator_sha256=evaluator_record.sha256,
            planned_seeds=(1, 2),
            seed_results=(
                SeedRunResult(1, SeedRunStatus.SUCCESS, selected_metrics[0], seed_digests[1]),
                SeedRunResult(2, SeedRunStatus.SUCCESS, selected_metrics[1], seed_digests[2]),
            ),
            artifacts=(
                OutputArtifact("seed-1.json", seed_digests[1], len(seed_payloads[1]), "seed_result"),
                OutputArtifact("seed-2.json", seed_digests[2], len(seed_payloads[2]), "seed_result"),
                OutputArtifact(
                    "ablation-remove-signal.json",
                    ablation_digest,
                    len(ablation_payload),
                    "ablation_result",
                ),
            ),
            ablations=(AblationResult("remove-signal", ablation_digest),),
        )
        manifest_record = self._put_json(
            manifest.to_dict(),
            logical_type="experiment_output_manifest",
            role=Role.EXPERIMENT_RUNNER,
            parents=(spec_record.sha256,),
        )
        seed_hashes: dict[int, str] = {}
        for seed in (1, 2):
            output = self.registry.put_bytes(
                seed_payloads[seed],
                logical_type="experiment_output.seed_result",
                origin="test seed output",
                creator_role=Role.EXPERIMENT_RUNNER,
                parent_artifacts=(manifest_record.sha256, spec_record.sha256),
                mime_type="application/json",
            )
            seed_hashes[seed] = output.sha256
        ablation = self.registry.put_bytes(
            ablation_payload,
            logical_type="experiment_output.ablation_result",
            origin="test ablation output",
            creator_role=Role.EXPERIMENT_RUNNER,
            parent_artifacts=(manifest_record.sha256, spec_record.sha256),
            mime_type="application/json",
        )
        plan = AdaptiveExecutionPlan(
            profile_sha256=spec.compute_profile.sha256,
            usable_memory_bytes=1024,
            memory_limit_per_worker_bytes=1024,
            concurrency=1,
            batch_size=1,
            cache_key=_digest("e"),
            estimated_wall_clock_seconds=1.0,
            estimated_monetary_cost=0.0,
        )
        plan_record = self._put_json(
            plan.to_dict(),
            logical_type="adaptive_execution_plan",
            role=Role.EXPERIMENT_RUNNER,
        )
        output_hashes = [
            seed_hashes[1],
            seed_hashes[2],
            ablation.sha256,
        ]
        execution_input_binding = self.registry.put_json(
            {
                "schema_version": "SCIENTIST_ONE_LOCAL_MAC_EXECUTION_INPUT_BINDING_V1",
                "spec_sha256": spec.sha256,
                "inputs": [
                    {
                        "kind": "code",
                        "sha256": code.sha256,
                        "size": len(self.registry.get_bytes(code.sha256)),
                        "staged_name": "frozen-input-code.py",
                    },
                    {
                        "kind": "data",
                        "sha256": data.sha256,
                        "size": len(self.registry.get_bytes(data.sha256)),
                        "staged_name": "frozen-input-data.bin",
                    },
                    {
                        "kind": "configuration",
                        "sha256": configuration.sha256,
                        "size": len(self.registry.get_bytes(configuration.sha256)),
                        "staged_name": "frozen-input-configuration.bin",
                    },
                    {
                        "kind": "evaluator",
                        "sha256": evaluator_record.sha256,
                        "size": len(self.registry.get_bytes(evaluator_record.sha256)),
                        "staged_name": "frozen-input-evaluator.bin",
                    },
                ],
                "consumption": "PARENT_HELD_READ_DESCRIPTORS",
                "scientific_evidence": False,
            },
            logical_type="execution_input_binding",
            origin="exact local execution input-byte binding",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=(
                "scientist-one",
                "research-os-fixture",
                "capture-execution-input-binding",
            ),
            parent_artifacts=(spec_record.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        binding = self._put_json(
            {
                "agreement": True,
                "backend_id": binding_backend,
                "collected_backend_id": binding_backend,
                "collected_execution_plan_sha256": plan.sha256,
                "collected_execution_input_binding_sha256": execution_input_binding.sha256,
                "collected_manifest_sha256": manifest_record.sha256,
                "collected_network_isolation_attested": False,
                "collected_network_used": False,
                "collected_returned_artifact_sha256s": output_hashes,
                "collected_scientific_evidence": False,
                "collected_spec_sha256": spec.sha256,
                "collected_validation_status": "VALIDATED_LOCAL",
                "execution_plan_artifact_sha256": plan_record.sha256,
                "execution_plan_sha256": plan.sha256,
                "execution_input_binding_artifact_sha256": execution_input_binding.sha256,
                "execution_input_binding_sha256": execution_input_binding.sha256,
                "job_id": "local-checked",
                "run_id": spec.run_id,
                "spec_artifact_sha256": spec_record.sha256,
                "spec_sha256": spec.sha256,
                "submission_backend_id": binding_backend,
                "submission_execution_plan_sha256": plan.sha256,
                "submission_execution_input_binding_sha256": execution_input_binding.sha256,
                "submission_idempotency_key": "submit-checked",
                "submission_network_isolation_attested": False,
                "submission_network_used": False,
                "submission_scientific_evidence": False,
                "submission_spec_sha256": spec.sha256,
                "submission_state": "SUCCEEDED",
                "submission_validation_status": "VALIDATED_LOCAL",
            },
            logical_type="adaptive_execution_plan_binding",
            role=Role.EXPERIMENT_RUNNER,
            parents=(
                plan_record.sha256,
                execution_input_binding.sha256,
                spec_record.sha256,
            ),
        )
        ledger_event = self.ledger.record(
            run_id="global-discovery",
            actor_role=Role.EXPERIMENT_RUNNER,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(
                spec_record.sha256,
                plan_record.sha256,
                execution_input_binding.sha256,
                binding.sha256,
                manifest_record.sha256,
                *output_hashes,
            ),
            code_version=f"sha256:{implementation.sha256}",
            configuration_hash=configuration.sha256,
            dataset_identifiers=("checked-fixture",),
            random_seeds=(1, 2),
            evaluator_outputs=(
                {
                    "evidence_class": "SYSTEM_FIXTURE",
                    "execution_plan_artifact_sha256": plan_record.sha256,
                    "execution_plan_sha256": plan.sha256,
                    "manifest_sha256": manifest_record.sha256,
                    "os_enforced_sandbox": False,
                    "scientific_evidence": False,
                    "validation_status": "VALIDATED_LOCAL",
                },
            ),
            reason="test backend run promoted into exact discovery custody",
            event_type="CHECKPOINT",
            metadata={
                "backend_id": binding_backend,
                "experiment_run_id": spec.run_id,
                "execution_plan_binding_sha256": binding.sha256,
                "promotion": "EXPERIMENT_OUTPUTS_REGISTERED",
                "scientific_evidence_eligible": False,
            },
        )
        evidence_parents = (
            code.sha256,
            data.sha256,
            configuration.sha256,
            evaluator_record.sha256,
            implementation.sha256,
            spec_record.sha256,
            manifest_record.sha256,
            binding.sha256,
            execution_input_binding.sha256,
            plan_record.sha256,
            seed_hashes[1],
            seed_hashes[2],
            ablation.sha256,
        )
        check_records: dict[DiscoveryCheck, ArtifactRecord] = {}
        for check, role, rule in (
            (
                DiscoveryCheck.CONTROL,
                Role.SCIENTIFIC_REVIEWER,
                "candidate_exceeds_baseline_all_seeds",
            ),
            (
                DiscoveryCheck.ROBUSTNESS,
                Role.REPRODUCTION_VERIFIER,
                "not_applicable_deterministic_fixture_no_promotion_gate",
            ),
            (
                DiscoveryCheck.FALSIFICATION,
                Role.ADVERSARIAL_REVIEWER,
                "ablation_reduces_to_baseline",
            ),
        ):
            check_records[check] = self._put_json(
                {
                    "schema_version": "SCIENTIST_ONE_DISCOVERY_CHECK_V1",
                    "check": check.value,
                    "evaluator_sha256": evaluator_record.sha256,
                    "evidence_artifact_sha256s": [
                        seed_hashes[1],
                        seed_hashes[2],
                        ablation.sha256,
                    ],
                    "frozen_run_spec_sha256": spec_record.sha256,
                    "output_manifest_sha256": manifest_record.sha256,
                    "rule": rule,
                    "source_experiment_id": "experiment-checked",
                },
                logical_type=f"discovery_check.{check.value.lower()}",
                role=role,
                parents=evidence_parents,
            )
        registered = RegisteredBranchEvidence(
            source_experiment_id="experiment-checked",
            frozen_run_spec_sha256=spec_record.sha256,
            output_manifest_sha256=manifest_record.sha256,
            execution_plan_binding_sha256=binding.sha256,
            ledger_event_id=ledger_event.event_id,
            seed_output_sha256s=seed_hashes,
            ablation_artifact_sha256s={"remove-signal": ablation.sha256},
            control_artifact_sha256=check_records[DiscoveryCheck.CONTROL].sha256,
            robustness_artifact_sha256=check_records[
                DiscoveryCheck.ROBUSTNESS
            ].sha256,
            falsification_artifact_sha256=check_records[
                DiscoveryCheck.FALSIFICATION
            ].sha256,
        )
        resolver = RegistryDiscoveryEvidenceResolver(
            self.registry,
            evaluator_record.sha256,
            ledger=self.ledger,
        )
        engine = DiscoveryEngine(DiscoveryBudget(), evidence_resolver=resolver)
        branch = engine.submit(proposal)
        return engine, branch, registered

    def test_checked_result_recomputes_and_promotes_with_frozen_receipt(self) -> None:
        engine, branch, registered = self._checked_fixture()
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(checked.status, BranchStatus.SUCCEEDED)
        self.assertEqual(checked.aggregate_metric, "0.75")
        self.assertIsNone(checked.evidence.robustness_passed)  # type: ignore[union-attr]
        self.assertEqual(
            checked.evidence_authority,
            DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED,
        )
        self.assertIsNotNone(checked.evaluation_receipt_sha256)
        assert checked.evaluation_receipt_sha256 is not None
        receipt = self.registry.get_metadata(checked.evaluation_receipt_sha256)
        self.assertEqual(receipt.logical_type, "discovery.checked_result_evaluation")
        self.assertIs(receipt.creator_role, Role.CLAIM_VERIFIER)
        self.assertTrue(receipt.frozen)
        promoted = engine.promote(branch.branch_id)  # type: ignore[attr-defined]
        self.assertEqual(promoted.status, BranchStatus.PROMOTED)
        self.assertIsNotNone(promoted.promotion_receipt_sha256)
        assert promoted.promotion_receipt_sha256 is not None
        promotion = self.registry.get_metadata(promoted.promotion_receipt_sha256)
        self.assertEqual(promotion.logical_type, "discovery.branch_promotion")
        self.assertIn(checked.evaluation_receipt_sha256, promotion.parent_artifacts)
        snapshot_branch = engine.snapshot()["branches"][0]
        self.assertEqual(
            snapshot_branch["evidence_authority"],
            DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED.value,
        )
        self.assertEqual(
            snapshot_branch["evaluation_receipt_sha256"],
            checked.evaluation_receipt_sha256,
        )
        self.assertEqual(
            snapshot_branch["promotion_receipt_sha256"],
            promoted.promotion_receipt_sha256,
        )

    def test_hash_shaped_metric_and_default_true_controls_are_diagnostic_only(self) -> None:
        engine = DiscoveryEngine(DiscoveryBudget())
        branch = engine.submit(_proposal("proposal-forged-diagnostic"))
        result = engine.record_result(
            branch.branch_id,
            BranchEvidence(
                seed_observations=(
                    SeedObservation(1, SeedStatus.SUCCESS, 999.0, _digest("c")),
                    SeedObservation(2, SeedStatus.SUCCESS, 999.0, _digest("d")),
                )
            ),
        )
        self.assertEqual(result.status, BranchStatus.SUCCEEDED)
        self.assertEqual(result.aggregate_metric, "999.0")
        self.assertTrue(result.evidence.control_passed)  # type: ignore[union-attr]
        self.assertEqual(
            result.evidence_authority,
            DiscoveryEvidenceAuthority.DIAGNOSTIC_ONLY,
        )
        self.assertFalse(engine.is_promotion_eligible(branch.branch_id))
        self.assertEqual(engine.promote(branch.branch_id).status, BranchStatus.SUCCEEDED)
        self.assertEqual(
            engine.selection_history[-1].decision,
            SelectionDecision.PROMOTION_REJECTED,
        )

    def test_missing_registry_seed_hash_cannot_authorize_checked_result(self) -> None:
        engine, branch, registered = self._checked_fixture()
        forged = replace(
            registered,
            seed_output_sha256s={
                1: _digest("f"),
                2: registered.seed_output_sha256s[2],
            },
        )
        rejected = engine.record_checked_result(branch.branch_id, forged)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertEqual(
            rejected.evidence_authority,
            DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED,
        )
        assert rejected.evaluation_receipt_sha256 is not None
        receipt = self.registry.get_metadata(rejected.evaluation_receipt_sha256)
        self.assertEqual(receipt.logical_type, "discovery.checked_result_rejection")
        self.assertEqual(receipt.parent_artifacts, ())
        with self.assertRaises(DiscoveryError):
            engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]

    def test_registry_output_with_forged_reported_metric_is_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture(
            reported_metrics=(0.9, 0.75)
        )
        rejected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertIn("CHECKED_RESULT_RESOLUTION_FAILED", rejected.reason_codes)

    def test_hash_consistent_forged_correctness_vector_is_recomputed_from_data(self) -> None:
        engine, branch, registered = self._checked_fixture(
            forge_correctness_vector=True
        )
        rejected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertFalse(engine.is_promotion_eligible(branch.branch_id))

    def test_caller_supplied_always_true_evaluator_cannot_enter_checked_path(self) -> None:
        _, branch, _ = self._checked_fixture()

        class AlwaysTrueEvaluator:
            evaluator_sha256 = branch.proposal.evaluator_sha256  # type: ignore[attr-defined]
            evaluator_implementation_id = "forged-always-true"

            def evaluate_seed(self, **_: object) -> SeedObservation:
                return SeedObservation(1, SeedStatus.SUCCESS, 999.0, _digest("f"))

            def evaluate_ablation(self, **_: object) -> bool:
                return True

            def evaluate_check(self, **_: object) -> bool:
                return True

        with self.assertRaises(ValidationError):
            RegistryDiscoveryEvidenceResolver(  # type: ignore[arg-type]
                self.registry,
                AlwaysTrueEvaluator(),
                ledger=self.ledger,
            )

    def test_checked_controls_are_explicit_and_false_control_blocks_promotion(self) -> None:
        with self.assertRaises(TypeError):
            RegisteredBranchEvidence(  # type: ignore[call-arg]
                source_experiment_id="experiment-checked",
                frozen_run_spec_sha256=_digest("4"),
                output_manifest_sha256=_digest("5"),
                execution_plan_binding_sha256=_digest("6"),
                ledger_event_id="event-checked",
                seed_output_sha256s={1: _digest("1")},
                ablation_artifact_sha256s={},
                robustness_artifact_sha256=_digest("2"),
                falsification_artifact_sha256=_digest("3"),
            )
        engine, branch, registered = self._checked_fixture(control_passed=False)
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(checked.status, BranchStatus.INVALID)
        self.assertIn("CONTROL_FAILED", checked.reason_codes)
        self.assertFalse(engine.is_promotion_eligible(branch.branch_id))
        self.assertEqual(engine.promote(branch.branch_id).status, BranchStatus.INVALID)  # type: ignore[attr-defined]

    def test_public_resolver_recomputes_status_and_aggregate_before_promotion(self) -> None:
        engine, branch, registered = self._checked_fixture(control_passed=False)
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(checked.status, BranchStatus.INVALID)
        forged = replace(
            checked,
            status=BranchStatus.SUCCEEDED,
            reason_codes=(),
            aggregate_metric="999",
        )
        resolver = RegistryDiscoveryEvidenceResolver(
            self.registry,
            branch.proposal.evaluator_sha256,  # type: ignore[arg-type,attr-defined]
            ledger=self.ledger,
        )
        with self.assertRaises(DiscoveryIntegrityError):
            resolver.register_promotion(forged)

    def test_promoted_authority_is_revalidated_before_later_consumption(self) -> None:
        engine, branch, registered = self._checked_fixture()
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertTrue(engine.is_promotion_eligible(branch.branch_id))
        promoted = engine.promote(branch.branch_id)  # type: ignore[attr-defined]
        self.assertEqual(promoted.status, BranchStatus.PROMOTED)
        assert promoted.evaluation_receipt_sha256 is not None
        receipt = self.registry.get_metadata(promoted.evaluation_receipt_sha256)
        (self.root / receipt.path).write_bytes(b"tampered\n")
        with self.assertRaises(DiscoveryIntegrityError):
            engine.get_branch(branch.branch_id)  # type: ignore[attr-defined]
        with self.assertRaises(DiscoveryIntegrityError):
            engine.ranked_candidates()
        with self.assertRaises(DiscoveryIntegrityError):
            engine.snapshot()
        with self.assertRaises(DiscoveryIntegrityError):
            _ = engine.selection_history

    def test_full_proposal_fingerprint_and_direction_are_bound_before_execution(self) -> None:
        engine, branch, registered = self._checked_fixture()
        first = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(first.status, BranchStatus.SUCCEEDED)

        resolver = RegistryDiscoveryEvidenceResolver(
            self.registry,
            branch.proposal.evaluator_sha256,  # type: ignore[arg-type,attr-defined]
            ledger=self.ledger,
        )
        distinct_engine = DiscoveryEngine(
            DiscoveryBudget(), evidence_resolver=resolver
        )
        distinct = distinct_engine.submit(
            replace(
                branch.proposal,  # type: ignore[attr-defined]
                proposal_id="proposal-distinct-method",
                variant_identity="unevaluated-distinct-variant",
            )
        )
        rejected = distinct_engine.record_checked_result(  # type: ignore[attr-defined]
            distinct.branch_id, registered
        )
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertFalse(
            distinct_engine.is_promotion_eligible(distinct.branch_id)
        )

        minimize_engine, minimize_branch, minimize_registered = (
            self._checked_fixture(metric_direction="minimize")
        )
        minimize = minimize_engine.record_checked_result(  # type: ignore[attr-defined]
            minimize_branch.branch_id, minimize_registered
        )
        self.assertEqual(minimize.status, BranchStatus.INVALID)

    def test_nonlocal_backend_custody_is_persistently_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture(
            binding_backend="fake-gpu-cloud"
        )
        rejected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)

    def test_missing_ledger_custody_is_persistently_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture()
        missing_event = replace(registered, ledger_event_id="event-absent")
        rejected = engine.record_checked_result(  # type: ignore[attr-defined]
            branch.branch_id, missing_event
        )
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        assert rejected.evaluation_receipt_sha256 is not None
        receipt = self.registry.get_metadata(rejected.evaluation_receipt_sha256)
        self.assertEqual(receipt.parent_artifacts, ())

    def test_superseded_ledger_custody_is_persistently_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture()
        self.ledger.append_correction(
            registered.ledger_event_id,
            actor_role=Role.EXPERIMENT_RUNNER,
            reason="withdraw stale execution custody",
            corrected_fields={"promotion": "WITHDRAWN"},
        )
        rejected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertIn("CHECKED_RESULT_RESOLUTION_FAILED", rejected.reason_codes)
        assert rejected.evaluation_receipt_sha256 is not None
        receipt = self.registry.get_metadata(rejected.evaluation_receipt_sha256)
        self.assertEqual(receipt.logical_type, "discovery.checked_result_rejection")
        self.assertEqual(receipt.parent_artifacts, ())

    def test_protected_split_is_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture(
            evaluation_split="confirmatory-test"
        )
        protected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(protected.status, BranchStatus.INVALID)

    def test_execution_metadata_cannot_select_same_output_protected_split(self) -> None:
        engine, branch, registered = self._checked_fixture(
            evaluation_split="development",
            execution_split="confirmatory-test",
        )
        rejected = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertIn("CHECKED_RESULT_RESOLUTION_FAILED", rejected.reason_codes)

    def test_unfrozen_ablation_intervention_is_rejected(self) -> None:
        engine, branch, registered = self._checked_fixture(
            ablation_intervention="caller-declared copied baseline"
        )
        intervention = engine.record_checked_result(  # type: ignore[attr-defined]
            branch.branch_id, registered
        )
        self.assertEqual(intervention.status, BranchStatus.INVALID)

    def test_source_snapshot_is_pinned(self) -> None:
        engine, branch, registered = self._checked_fixture()
        source = next(
            record
            for record in self.registry.list_records()
            if record.logical_type == "vnext_source_snapshot"
        )
        (self.root / source.path).write_bytes(b"tampered source inventory\n")
        with self.assertRaises(IntegrityError):
            engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]

    def test_helper_dispatch_is_pinned(self) -> None:
        engine, branch, registered = self._checked_fixture()
        original = RegistryDiscoveryEvidenceResolver._resolve_check
        try:
            RegistryDiscoveryEvidenceResolver._resolve_check = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: True
            )
            with self.assertRaises(DiscoveryIntegrityError):
                engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        finally:
            RegistryDiscoveryEvidenceResolver._resolve_check = original  # type: ignore[method-assign]

    def test_registry_dispatch_and_paired_paths_are_immutably_pinned(self) -> None:
        engine, branch, registered = self._checked_fixture()
        original_get_bytes = ArtifactRegistry.get_bytes
        try:
            ArtifactRegistry.get_bytes = lambda *_args, **_kwargs: b"{}\n"  # type: ignore[method-assign]
            with self.assertRaises(DiscoveryIntegrityError):
                engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        finally:
            ArtifactRegistry.get_bytes = original_get_bytes  # type: ignore[method-assign]

        resolver = engine._evidence_resolver  # type: ignore[attr-defined]
        assert resolver is not None
        original_registry_path = self.registry.base_path
        original_ledger_path = self.ledger.relative_path
        try:
            self.registry.base_path = Path("runs/rebound/registry")
            self.ledger.relative_path = Path("runs/rebound/events.jsonl")
            with self.assertRaises(DiscoveryIntegrityError):
                resolver._verify_resolver_is_pinned()  # type: ignore[attr-defined]
        finally:
            self.registry.base_path = original_registry_path
            self.ledger.relative_path = original_ledger_path

    def test_verified_unpromoted_receipt_is_revalidated(self) -> None:
        engine, branch, registered = self._checked_fixture()
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        assert checked.evaluation_receipt_sha256 is not None
        evaluation = self.registry.get_metadata(checked.evaluation_receipt_sha256)
        (self.root / evaluation.path).write_bytes(b"tampered evaluation\n")
        with self.assertRaises(DiscoveryIntegrityError):
            _ = engine.branches

    def test_promotion_receipt_is_revalidated(self) -> None:
        engine, branch, registered = self._checked_fixture()
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        promoted = engine.promote(branch.branch_id)  # type: ignore[attr-defined]
        assert promoted.promotion_receipt_sha256 is not None
        promotion = self.registry.get_metadata(promoted.promotion_receipt_sha256)
        payload = safe_json_loads(self.registry.get_bytes(promotion.sha256))
        self.assertEqual(payload["decision"], "PROMOTED")
        self.assertTrue(payload["exploration_only"])
        self.assertFalse(payload["scientific_evidence_eligible"])
        (self.root / promotion.path).write_bytes(b"tampered promotion\n")
        with self.assertRaises(DiscoveryIntegrityError):
            engine.get_branch(branch.branch_id)  # type: ignore[attr-defined]

    def test_promotion_reresolution_failure_has_frozen_rejection_receipt(self) -> None:
        engine, branch, registered = self._checked_fixture()
        checked = engine.record_checked_result(branch.branch_id, registered)  # type: ignore[attr-defined]
        self.assertTrue(engine.is_promotion_eligible(branch.branch_id))
        (self.root / self.ledger.relative_path).write_bytes(b"corrupt ledger\n")
        rejected = engine.promote(branch.branch_id)  # type: ignore[attr-defined]
        self.assertEqual(rejected.status, BranchStatus.INVALID)
        self.assertEqual(
            rejected.evidence_authority,
            DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED,
        )
        assert rejected.promotion_receipt_sha256 is not None
        receipt = self.registry.get_metadata(rejected.promotion_receipt_sha256)
        self.assertEqual(
            receipt.logical_type, "discovery.branch_promotion_rejection"
        )
        self.assertEqual(receipt.parent_artifacts, ())
        self.assertEqual(
            engine.get_branch(branch.branch_id).promotion_receipt_sha256,  # type: ignore[attr-defined]
            rejected.promotion_receipt_sha256,
        )


def _spec(
    run_id: str,
    *,
    phase: ExperimentPhase = ExperimentPhase.EXPLORATORY,
    seeds: tuple[int, ...] = (11, 22),
    required_ablations: tuple[str, ...] = (),
    attempt: int = 1,
    retry_of: str | None = None,
    argv: tuple[str, ...] = ("/usr/bin/true",),
    evidence_class: EvidenceClass | None = None,
    metadata: dict[str, object] | None = None,
) -> FrozenRunSpec:
    arguments: dict[str, object] = {
        "run_id": run_id,
        "experiment_id": "experiment-1",
        "hypothesis_id": "hypothesis-1",
        "phase": phase,
        "argv": argv,
        "working_directory": ".",
        "code_sha256": _digest("a"),
        "data_sha256": _digest("b"),
        "configuration_sha256": _digest("c"),
        "evaluator_sha256": _digest("d"),
        "seeds": seeds,
        "comparison_tolerance": 0.01,
        "required_ablations": required_ablations,
        "attempt": attempt,
        "retry_of_run_id": retry_of,
        "maximum_stdout_bytes": 16,
        "maximum_stderr_bytes": 16,
        "metadata": metadata or {},
    }
    if evidence_class is not None:
        arguments["evidence_class"] = evidence_class
    return FrozenRunSpec(**arguments)  # type: ignore[arg-type]


def _write_manifest(
    spec: FrozenRunSpec,
    directory: Path,
    *,
    metrics: tuple[float, ...] = (1.0, 1.1),
    reported_seeds: tuple[int, ...] | None = None,
    completed_ablations: tuple[str, ...] = (),
    fabricated_ablation: str | None = None,
) -> OutputManifest:
    selected_seeds = reported_seeds if reported_seeds is not None else spec.seeds
    artifacts: list[OutputArtifact] = []
    seed_results: list[SeedRunResult] = []
    for index, seed in enumerate(selected_seeds):
        payload = f"seed={seed};metric={metrics[index]}".encode("utf-8")
        path = f"seed-{seed}.json"
        (directory / path).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        artifacts.append(OutputArtifact(path, digest, len(payload), "seed_result"))
        seed_results.append(
            SeedRunResult(seed, SeedRunStatus.SUCCESS, metrics[index], digest)
        )
    ablations: list[AblationResult] = []
    for ablation_id in completed_ablations:
        payload = f"ablation={ablation_id}".encode("utf-8")
        path = f"ablation-{ablation_id}.json"
        (directory / path).write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        artifacts.append(OutputArtifact(path, digest, len(payload), "ablation_result"))
        ablations.append(AblationResult(ablation_id, digest))
    if fabricated_ablation is not None:
        ablations.append(AblationResult(fabricated_ablation, _digest("f")))
    manifest = OutputManifest(
        run_id=spec.run_id,
        spec_sha256=spec.sha256,
        code_sha256=spec.code_sha256,
        data_sha256=spec.data_sha256,
        configuration_sha256=spec.configuration_sha256,
        evaluator_sha256=spec.evaluator_sha256,
        planned_seeds=spec.seeds,
        seed_results=tuple(seed_results),
        artifacts=tuple(artifacts),
        ablations=tuple(ablations),
    )
    (directory / "output-manifest.json").write_bytes(
        canonical_json_bytes(manifest.to_dict()) + b"\n"
    )
    return manifest


class ExperimentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_frozen_run_spec_is_immutable_and_binds_every_scientific_identity(self) -> None:
        self.assertEqual(
            _spec("run-conservative-default").evidence_class,
            EvidenceClass.NON_EVIDENTIARY,
        )
        spec = _spec(
            "run-frozen",
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        )
        self.assertEqual(len(spec.sha256), 64)
        self.assertEqual(len(spec.scientific_binding_sha256), 64)
        with self.assertRaises(FrozenInstanceError):
            spec.run_id = "changed"  # type: ignore[misc]
        with self.assertRaises(ConfirmatoryPolicyError):
            _spec(
                "run-confirmatory-retry",
                phase=ExperimentPhase.CONFIRMATORY,
                attempt=2,
                retry_of="run-confirmatory-original",
            )

        # Attempt identity is deliberately excluded so a clean rerun can use a
        # fresh run ID. Every serialized execution/scientific field is bound.
        self.assertEqual(
            spec.scientific_binding_sha256,
            replace(spec, run_id="run-frozen-clean-rerun").scientific_binding_sha256,
        )
        result_affecting_variants = (
            replace(spec, experiment_id="experiment-2"),
            replace(spec, hypothesis_id="hypothesis-2"),
            replace(spec, phase=ExperimentPhase.CONFIRMATORY),
            replace(spec, argv=("/usr/bin/true", "variant")),
            replace(spec, working_directory="different-directory"),
            replace(spec, code_sha256=_digest("e")),
            replace(spec, data_sha256=_digest("f")),
            replace(spec, configuration_sha256=_digest("1")),
            replace(spec, evaluator_sha256=_digest("2")),
            replace(spec, seeds=(11, 33)),
            replace(spec, comparison_tolerance=0.02),
            replace(spec, timeout_seconds=120.0),
            replace(spec, maximum_stdout_bytes=32),
            replace(spec, maximum_stderr_bytes=32),
            replace(spec, required_ablations=("remove-component",)),
            replace(spec, evidence_class=EvidenceClass.NON_EVIDENTIARY),
            replace(spec, metadata={"candidate_threshold": 0.75}),
        )
        for variant in result_affecting_variants:
            with self.subTest(variant=variant.to_dict()):
                self.assertNotEqual(
                    spec.scientific_binding_sha256,
                    variant.scientific_binding_sha256,
                )

    def test_experiment_class_and_resource_estimate_are_typed_and_bounded(self) -> None:
        self.assertEqual(
            {item.value for item in ExperimentClass},
            {"SMOKE", "PILOT", "EXPLORATORY", "FINAL_LOCAL"},
        )
        estimate = ResourceEstimate(
            expected_scientific_value=8,
            expected_uncertainty_reduction=5,
            cpu_cores=2,
            gpu_count=0,
            ram_bytes=2_000_000_000,
            vram_bytes=0,
            disk_bytes=1_000_000,
            wall_clock_seconds=60,
            monetary_cost=0,
            escalation_reason="bounded local pilot before any GPU escalation",
        )
        self.assertEqual(estimate.to_dict()["cpu_cores"], 2)
        with self.assertRaises(ExperimentError):
            replace(estimate, cpu_cores=0)
        with self.assertRaises(ExperimentError):
            replace(estimate, monetary_cost=-1)

    def test_local_backend_scrubs_environment_bounds_logs_and_collects_manifest(self) -> None:
        observed_environment: dict[str, str] = {}
        observed_directory: list[Path] = []

        def runner(
            spec: FrozenRunSpec,
            directory: Path,
            environment: object,
        ) -> ExecutionResult:
            observed_environment.update(dict(environment))  # type: ignore[arg-type]
            observed_directory.append(directory)
            _write_manifest(spec, directory)
            return ExecutionResult(0, stdout=b"x" * 100, stderr=b"y" * 100)

        os.environ["SCIENTIST_ONE_TEST_SECRET"] = "must-not-cross-boundary"
        try:
            backend = LocalMacBackend(
                self.root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            receipt = backend.submit(
                _spec(
                    "run-local",
                    evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
                ),
                idempotency_key="submit-local",
            )
        finally:
            os.environ.pop("SCIENTIST_ONE_TEST_SECRET", None)
        self.assertEqual(receipt.state, RunState.SUCCEEDED)
        self.assertNotIn("SCIENTIST_ONE_TEST_SECRET", observed_environment)
        self.assertEqual(observed_environment["SCIENTIST_ONE_NETWORK_POLICY"], "DENY")
        self.assertLessEqual((observed_directory[0] / "stdout.log").stat().st_size, 16)
        self.assertLessEqual((observed_directory[0] / "stderr.log").stat().st_size, 16)
        collected = backend.collect(receipt.job_id)
        self.assertFalse(collected.scientific_evidence)
        self.assertFalse(collected.network_used)
        self.assertEqual(collected.validation_status, ValidationStatus.UNTESTED)

    def test_non_evidentiary_local_success_can_be_collected_but_never_promoted(self) -> None:
        def runner(spec: FrozenRunSpec, directory: Path, _: object) -> ExecutionResult:
            _write_manifest(spec, directory)
            return ExecutionResult(0)

        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/true",),
            execution_runner=runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        receipt = backend.submit(
            _spec(
                "run-local-fixture",
                evidence_class=EvidenceClass.NON_EVIDENTIARY,
                metadata={"fixture": True},
            ),
            idempotency_key="submit-local-fixture",
        )
        self.assertEqual(receipt.state, RunState.SUCCEEDED)
        self.assertFalse(receipt.scientific_evidence)
        self.assertFalse(backend.reconcile(receipt.job_id).scientific_evidence)
        self.assertFalse(backend.collect(receipt.job_id).scientific_evidence)

    def test_failed_invalid_and_cancelled_local_runs_are_never_scientific_evidence(self) -> None:
        (self.root / "failed").mkdir()
        failed_backend = LocalMacBackend(
            self.root / "failed",
            allowed_executables=("/usr/bin/true",),
            execution_runner=lambda *_: ExecutionResult(2),
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        failed = failed_backend.submit(
            _spec(
                "run-local-failed",
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            ),
            idempotency_key="submit-local-failed",
        )
        self.assertEqual(failed.state, RunState.FAILED)
        self.assertFalse(failed.scientific_evidence)
        self.assertFalse(failed_backend.reconcile(failed.job_id).scientific_evidence)

        (self.root / "invalid").mkdir()
        invalid_backend = LocalMacBackend(
            self.root / "invalid",
            allowed_executables=("/usr/bin/true",),
            execution_runner=lambda *_: ExecutionResult(0),
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        invalid = invalid_backend.submit(
            _spec(
                "run-local-invalid",
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            ),
            idempotency_key="submit-local-invalid",
        )
        self.assertEqual(invalid.state, RunState.INVALID_OUTPUT)
        self.assertFalse(invalid.scientific_evidence)
        self.assertFalse(invalid_backend.reconcile(invalid.job_id).scientific_evidence)

        started = threading.Event()
        release = threading.Event()

        def blocked_runner(
            spec: FrozenRunSpec,
            directory: Path,
            _: object,
        ) -> ExecutionResult:
            started.set()
            if not release.wait(timeout=5):
                return ExecutionResult(3)
            _write_manifest(spec, directory)
            return ExecutionResult(0)

        (self.root / "cancelled").mkdir()
        cancelled_backend = LocalMacBackend(
            self.root / "cancelled",
            allowed_executables=("/usr/bin/true",),
            execution_runner=blocked_runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        cancelled_spec = _spec(
            "run-local-cancelled",
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        )
        receipts: list[object] = []
        worker = threading.Thread(
            target=lambda: receipts.append(
                cancelled_backend.submit(
                    cancelled_spec,
                    idempotency_key="submit-local-cancelled",
                )
            )
        )
        worker.start()
        self.assertTrue(started.wait(timeout=5))
        cancelled_job_id = f"local-{cancelled_spec.sha256[:20]}-diagnostic"
        cancel_status = cancelled_backend.cancel(cancelled_job_id)
        self.assertEqual(cancel_status.state, RunState.CANCELLED)
        self.assertFalse(cancel_status.scientific_evidence)
        release.set()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(receipts), 1)
        final_status = cancelled_backend.reconcile(cancelled_job_id)
        self.assertEqual(final_status.state, RunState.CANCELLED)
        self.assertFalse(final_status.scientific_evidence)
        with self.assertRaises(ExperimentIntegrityError):
            cancelled_backend.collect(cancelled_job_id)

    def test_local_backend_rejects_shell_and_network_executables(self) -> None:
        backend = LocalMacBackend(
            self.root,
            allowed_executables=("curl", "sh", "/usr/bin/true"),
            execution_runner=lambda *_: ExecutionResult(0),
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        with self.assertRaises(CommandSecurityError):
            backend.submit(
                _spec("run-network", argv=("curl", "https://example.invalid")),
                idempotency_key="network",
            )
        with self.assertRaises(CommandSecurityError):
            backend.submit(
                _spec("run-shell", argv=("sh", "script.sh")),
                idempotency_key="shell",
            )

    def test_selective_seed_output_fails_closed(self) -> None:
        def runner(spec: FrozenRunSpec, directory: Path, _: object) -> ExecutionResult:
            _write_manifest(
                spec,
                directory,
                metrics=(100.0,),
                reported_seeds=(spec.seeds[0],),
            )
            return ExecutionResult(0)

        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/true",),
            execution_runner=runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        receipt = backend.submit(_spec("run-selective"), idempotency_key="selective")
        self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)
        self.assertIn("all planned seeds", backend.reconcile(receipt.job_id).reason or "")
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)

    def test_missing_and_fabricated_ablations_fail_closed(self) -> None:
        for mode in ("missing", "fabricated"):
            with self.subTest(mode=mode):
                root = self.root / mode
                root.mkdir()

                def runner(
                    spec: FrozenRunSpec,
                    directory: Path,
                    _: object,
                    current_mode: str = mode,
                ) -> ExecutionResult:
                    _write_manifest(
                        spec,
                        directory,
                        fabricated_ablation=(
                            "remove-component" if current_mode == "fabricated" else None
                        ),
                    )
                    return ExecutionResult(0)

                backend = LocalMacBackend(
                    root,
                    allowed_executables=("/usr/bin/true",),
                    execution_runner=runner,
                    execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                )
                receipt = backend.submit(
                    _spec(
                        f"run-{mode}",
                        required_ablations=("remove-component",),
                    ),
                    idempotency_key=f"submit-{mode}",
                )
                self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)

    def test_stale_or_altered_output_is_revoked_after_success(self) -> None:
        directories: list[Path] = []

        def runner(spec: FrozenRunSpec, directory: Path, _: object) -> ExecutionResult:
            directories.append(directory)
            _write_manifest(spec, directory)
            return ExecutionResult(0)

        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/true",),
            execution_runner=runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        receipt = backend.submit(_spec("run-altered"), idempotency_key="altered")
        self.assertEqual(receipt.state, RunState.SUCCEEDED)
        backend.collect(receipt.job_id)
        (directories[0] / "seed-11.json").write_bytes(b"altered-after-evaluation")
        status = backend.reconcile(receipt.job_id)
        self.assertEqual(status.state, RunState.INVALID_OUTPUT)
        self.assertIn("STALE_OR_ALTERED_OUTPUT", status.reason or "")
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)

    def test_local_preemption_requires_bound_checkpoint_and_never_auto_retries(self) -> None:
        def runner(spec: FrozenRunSpec, directory: Path, _: object) -> ExecutionResult:
            (directory / "checkpoint.json").write_bytes(
                canonical_json_bytes(
                    {
                        "run_id": spec.run_id,
                        "spec_sha256": spec.sha256,
                        "completed_seeds": [],
                    }
                )
                + b"\n"
            )
            return ExecutionResult(75)

        backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/true",),
            execution_runner=runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
        )
        spec = _spec("run-preempted-local")
        receipt = backend.submit(spec, idempotency_key="preempt-local")
        self.assertEqual(receipt.state, RunState.PREEMPTED)
        self.assertIsNotNone(backend.reconcile(receipt.job_id).checkpoint_sha256)
        self.assertEqual(
            backend.submit(spec, idempotency_key="preempt-local-again").job_id,
            receipt.job_id,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)

    def test_fake_gpu_is_idempotent_preemptible_and_never_evidentiary(self) -> None:
        backend = FakeGPUCloudBackend()
        spec = _spec("run-fake-gpu")
        first = backend.submit(spec, idempotency_key="remote-submit")
        duplicate = backend.submit(spec, idempotency_key="remote-submit")
        alternate_key = backend.submit(spec, idempotency_key="remote-submit-again")
        self.assertEqual(first.job_id, duplicate.job_id)
        self.assertEqual(first.job_id, alternate_key.job_id)
        self.assertEqual(first.validation_status, ValidationStatus.UNTESTED)
        self.assertFalse(first.network_used)
        self.assertFalse(first.scientific_evidence)
        queued = backend.reconcile(first.job_id)
        self.assertIsNone(backend.preemption_checkpoint(first.job_id))
        self.assertEqual(backend.reconcile(first.job_id), queued)

        different = _spec("run-fake-gpu-different")
        with self.assertRaises(SubmissionConflictError):
            backend.submit(different, idempotency_key="remote-submit")

        backend.start(first.job_id)
        status = backend.preempt(first.job_id, checkpoint_token="checkpoint-1")
        self.assertEqual(status.state, RunState.PREEMPTED)
        self.assertEqual(backend.preemption_checkpoint(first.job_id), "checkpoint-1")
        self.assertEqual(backend.preemption_checkpoint(first.job_id), "checkpoint-1")
        self.assertEqual(backend.reconcile(first.job_id), status)
        self.assertEqual(
            backend.submit(spec, idempotency_key="no-automatic-retry").job_id,
            first.job_id,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(first.job_id)

    def test_fake_gpu_completion_remains_non_evidentiary(self) -> None:
        backend = FakeGPUCloudBackend()
        spec = _spec("run-fake-complete")
        receipt = backend.submit(spec, idempotency_key="fake-complete")
        manifest = OutputManifest(
            run_id=spec.run_id,
            spec_sha256=spec.sha256,
            code_sha256=spec.code_sha256,
            data_sha256=spec.data_sha256,
            configuration_sha256=spec.configuration_sha256,
            evaluator_sha256=spec.evaluator_sha256,
            planned_seeds=spec.seeds,
            seed_results=(
                SeedRunResult(11, SeedRunStatus.SUCCESS, 1.0, _digest("1")),
                SeedRunResult(22, SeedRunStatus.SUCCESS, 1.0, _digest("2")),
            ),
            artifacts=(
                OutputArtifact("one.json", _digest("1"), 1, "seed_result"),
                OutputArtifact("two.json", _digest("2"), 1, "seed_result"),
            ),
        )
        backend.complete(receipt.job_id, manifest)
        collected = backend.collect(receipt.job_id)
        self.assertFalse(collected.scientific_evidence)
        self.assertFalse(collected.network_used)
        self.assertEqual(collected.validation_status, ValidationStatus.UNTESTED)

    def test_cancel_is_idempotent_and_cancelled_work_is_not_collectable(self) -> None:
        backend = FakeGPUCloudBackend()
        receipt = backend.submit(_spec("run-cancelled"), idempotency_key="cancelled")
        first = backend.cancel(receipt.job_id)
        second = backend.cancel(receipt.job_id)
        self.assertEqual(first.state, RunState.CANCELLED)
        self.assertEqual(second.state, RunState.CANCELLED)
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)

    def test_clean_rerun_outside_frozen_tolerance_is_not_a_pass(self) -> None:
        expected_spec = _spec(
            "run-expected",
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        )
        observed_spec = _spec(
            "run-observed",
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        )

        def collected(spec: FrozenRunSpec, metrics: tuple[float, float]) -> CollectedRun:
            manifest = OutputManifest(
                run_id=spec.run_id,
                spec_sha256=spec.sha256,
                code_sha256=spec.code_sha256,
                data_sha256=spec.data_sha256,
                configuration_sha256=spec.configuration_sha256,
                evaluator_sha256=spec.evaluator_sha256,
                planned_seeds=spec.seeds,
                seed_results=(
                    SeedRunResult(11, SeedRunStatus.SUCCESS, metrics[0], _digest("1")),
                    SeedRunResult(22, SeedRunStatus.SUCCESS, metrics[1], _digest("2")),
                ),
                artifacts=(
                    OutputArtifact("one.json", _digest("1"), 1, "seed_result"),
                    OutputArtifact("two.json", _digest("2"), 1, "seed_result"),
                ),
            )
            manifest_sha256 = hashlib.sha256(
                canonical_json_bytes(manifest.to_dict())
            ).hexdigest()
            manifest_bytes = canonical_json_bytes(manifest.to_dict())
            return CollectedRun(
                backend_id="local-mac",
                spec=spec,
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                manifest_bytes=manifest_bytes,
                network_used=False,
                # Synthetic DTOs cannot self-authorize scientific evidence;
                # this test exercises the outside-tolerance result first.
                scientific_evidence=False,
                validation_status=ValidationStatus.VALIDATED_LOCAL,
            )

        comparison = compare_clean_rerun(
            collected(expected_spec, (1.0, 1.0)),
            collected(observed_spec, (1.0, 1.2)),
            tolerance=0.01,
        )
        self.assertEqual(comparison.status, ReproductionStatus.OUTSIDE_TOLERANCE)
        self.assertAlmostEqual(comparison.maximum_absolute_difference or 0.0, 0.2)
        self.assertEqual(comparison.compared_seeds, (11, 22))
        with self.assertRaises(ExperimentError):
            compare_clean_rerun(
                collected(expected_spec, (1.0, 1.0)),
                collected(observed_spec, (1.0, 1.0)),
                tolerance=0.02,
            )

    def test_non_evidentiary_clean_rerun_reports_deterministic_comparison_without_pass(self) -> None:
        expected_spec = _spec(
            "run-fixture-expected",
            evidence_class=EvidenceClass.NON_EVIDENTIARY,
            metadata={"fixture": True},
        )
        observed_spec = _spec(
            "run-fixture-observed",
            evidence_class=EvidenceClass.NON_EVIDENTIARY,
            metadata={"fixture": True},
        )

        def collected(spec: FrozenRunSpec) -> CollectedRun:
            manifest = OutputManifest(
                run_id=spec.run_id,
                spec_sha256=spec.sha256,
                code_sha256=spec.code_sha256,
                data_sha256=spec.data_sha256,
                configuration_sha256=spec.configuration_sha256,
                evaluator_sha256=spec.evaluator_sha256,
                planned_seeds=spec.seeds,
                seed_results=(
                    SeedRunResult(11, SeedRunStatus.SUCCESS, 1.0, _digest("1")),
                    SeedRunResult(22, SeedRunStatus.SUCCESS, 1.0, _digest("2")),
                ),
                artifacts=(
                    OutputArtifact("one.json", _digest("1"), 1, "seed_result"),
                    OutputArtifact("two.json", _digest("2"), 1, "seed_result"),
                ),
            )
            manifest_bytes = canonical_json_bytes(manifest.to_dict())
            return CollectedRun(
                backend_id="local-mac",
                spec=spec,
                manifest=manifest,
                manifest_sha256=hashlib.sha256(
                    manifest_bytes
                ).hexdigest(),
                manifest_bytes=manifest_bytes,
                network_used=False,
                scientific_evidence=False,
                validation_status=ValidationStatus.VALIDATED_LOCAL,
            )

        comparison = compare_clean_rerun(collected(expected_spec), collected(observed_spec))
        self.assertEqual(comparison.status, ReproductionStatus.NON_EVIDENTIARY)
        self.assertEqual(comparison.maximum_absolute_difference, 0.0)
        self.assertEqual(comparison.compared_seeds, (11, 22))
        self.assertIn("within the frozen tolerance", comparison.reason)

    def test_confirmatory_retry_and_backend_fallback_fail_closed(self) -> None:
        confirmatory = _spec(
            "run-confirmatory",
            phase=ExperimentPhase.CONFIRMATORY,
        )
        with self.assertRaises(ConfirmatoryPolicyError):
            require_no_backend_fallback(
                confirmatory,
                submitted_backend_id="gpu-cloud-a",
                requested_backend_id="local-mac",
            )
        with self.assertRaises(ConfirmatoryPolicyError):
            validate_explicit_retry(confirmatory, confirmatory)

        original = _spec("run-exploratory-original")
        retry = _spec(
            "run-exploratory-retry",
            attempt=2,
            retry_of=original.run_id,
        )
        validate_explicit_retry(original, retry)
        with self.assertRaises(ExperimentError):
            require_no_backend_fallback(
                original,
                submitted_backend_id="gpu-cloud-a",
                requested_backend_id="local-mac",
            )


if __name__ == "__main__":
    unittest.main()
