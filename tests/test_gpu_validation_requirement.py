"""Prospective operational source tests, never successful execution/science mocks.

Actual public registrars retain the CUDA source/data/config/evaluator and check
the design freeze and compute plan. The contract fixture is structural design
input, not proof of novelty, empirical merit, GPU execution, or publishability.
Progress injections are explicitly inert adverse records, not execution claims.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.cuda_device_timing import (
    CUDA_DEVICE_TIMING_BENCHMARK_BYTES,
    CUDA_DEVICE_TIMING_EVALUATOR_BYTES,
    CUDA_DEVICE_TIMING_METRIC_AGGREGATION,
    CUDA_DEVICE_TIMING_METRIC_DEFINITION,
    CUDA_DEVICE_TIMING_PROFILE_ID,
    CudaDeviceTimingProtocol,
)
from scientist_one.experiments import (
    AcceleratorKind,
    ComputeEscalationBudget,
    ComputeMode,
    ComputeProfile,
    EscalationDecision,
    EvidenceClass,
    ExperimentClass,
    ExperimentPhase,
    FrozenRunSpec,
    ResourceEstimate,
    SchedulerKind,
    ValidationStatus,
    make_gpu_cloud_submission_plan,
    register_compute_escalation_plan_authority,
)
from scientist_one.gates import HumanGatePolicy, HumanGateProfile
from scientist_one import gpu_validation_requirement as owner
from scientist_one.gpu_validation_requirement import (
    GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY,
    GPU_VALIDATION_REQUIREMENT_POLICY_SCHEMA,
    GpuValidationRequirementError,
    GpuValidationRequirementResolution,
    GpuValidationRequirementStatus,
    resolve_gpu_validation_requirement,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    BaselineRegistry,
    BaselineStatus,
    ExperimentPlan,
    ExperimentStage,
    HypothesisRegister,
    MetricDirection,
    MetricScope,
    MetricUnit,
    record_scientific_design_freeze,
    register_evaluation_contract_freeze_gate_receipt,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
)
from scientist_one.security import canonical_json_bytes

from tests.test_scientific_design import make_contract


class GpuValidationRequirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ledger_run_id = "gpu-requirement-ledger"
        self.registry = ArtifactRegistry(self.root, "runs/gpu-requirement-ledger/registry")
        self.ledger = EventLedger(self.root, "runs/gpu-requirement-ledger/events.jsonl")

    def artifact(self, raw, logical_type, role=Role.PROTOCOL_DESIGNER, parents=(),
                 mime_type="application/json", validation_result="PASS"):
        return self.registry.put_bytes(
            raw, logical_type=logical_type,
            origin="prospective GPU requirement test input; no execution claim",
            creator_role=role,
            creation_command=("scientist-one", "test-gpu-requirement-input"),
            parent_artifacts=parents, schema_version="1.0", mime_type=mime_type,
            validation_result=validation_result, frozen=validation_result == "PASS",
        )

    def prepare(self, *, policy=None, omit_policy=False, code=None, evaluator=None,
                configuration=None, data=None, metric_changes=None,
                baseline_status=BaselineStatus.MUST_RUN, baseline_exclusion=None,
                local_changes=None, cloud_changes=None, escalation_local_changes=None,
                escalation_first=False, before_freeze=None):
        protocol = CudaDeviceTimingProtocol("device-ms", "baseline-strong", (7, 11, 19),
                                            4, 64, 128, 1, 3)
        base = make_contract()
        metric = replace(base.primary_metric,
                         metric_id=protocol.metric_id, name="CUDA kernel event duration",
                         definition=CUDA_DEVICE_TIMING_METRIC_DEFINITION,
                         direction=MetricDirection.LOWER_IS_BETTER,
                         unit=MetricUnit.MILLISECONDS, scope=MetricScope.INTERMEDIATE,
                         aggregation=CUDA_DEVICE_TIMING_METRIC_AGGREGATION)
        if metric_changes:
            metric = replace(metric, **metric_changes)
        conditions = replace(base.candidate_conditions, metric_id=metric.metric_id,
                             metric_unit=metric.unit, hardware_class="CUDA device",
                             latency_method="synchronized CUDA Runtime events",
                             hyperparameter_search="two frozen block sizes; no tuning",
                             preprocessing="none", tuning_trials=0)
        baseline = replace(base.baseline_registry.entries[0], conditions=conditions,
                           status=baseline_status, exclusion=baseline_exclusion,
                           expected_metric=None, reported_metric=None, observed_metric=None)
        baselines = (baseline,)
        if baseline_status is not BaselineStatus.MUST_RUN:
            baselines += (replace(baseline, baseline_id="another-mandatory-baseline",
                                  status=BaselineStatus.MUST_RUN),)
        hypothesis = replace(base.hypothesis_register.primary,
                             statement="The frozen two-block CUDA protocol measures device event time.",
                             prediction="All declared per-seed device measurements are retained.",
                             falsification_condition="Any invalid output or missing measurement.")
        contract = replace(base, primary_metric=metric, secondary_metrics=(),
                           candidate_conditions=conditions,
                           hypothesis_register=HypothesisRegister((hypothesis,)),
                           baseline_registry=BaselineRegistry(baselines), ablations=())
        evidence = self.artifact(b'{"structural-design-input":"not-scientific-validation"}\n',
                                 "gpu_requirement_design_input", Role.EVIDENCE_CURATOR)
        contract_record = register_frozen_evaluation_contract(
            self.registry, contract=contract, parent_artifact_sha256s=(evidence.sha256,),
        )
        code_record = self.artifact(
            CUDA_DEVICE_TIMING_BENCHMARK_BYTES if code is None else code,
            "experiment_code", Role.IMPLEMENTER, mime_type="text/x-c++src")
        data_record = self.artifact(
            b"CDT1" + struct.pack("<I8I", 4, 1, 2, 3, 4, 5, 6, 7, 8) if data is None else data,
            "experiment_dataset", Role.EVIDENCE_CURATOR, mime_type="application/octet-stream")
        config_record = self.artifact(
            protocol.canonical_bytes() if configuration is None else configuration,
            "experiment_configuration")
        evaluator_record = self.artifact(
            CUDA_DEVICE_TIMING_EVALUATOR_BYTES if evaluator is None else evaluator,
            "evaluator_implementation", mime_type="text/x-python")
        metadata = {"evaluation_split": "development-v1"}
        if not omit_policy:
            metadata[GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY] = policy if policy is not None else {
                "schema_version": GPU_VALIDATION_REQUIREMENT_POLICY_SCHEMA,
                "profile_id": CUDA_DEVICE_TIMING_PROFILE_ID,
            }
        local = FrozenRunSpec(
            run_id="cuda-local-never-started", experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary", phase=ExperimentPhase.EXPLORATORY,
            argv=protocol.expected_argv(), working_directory=".",
            code_sha256=code_record.sha256, data_sha256=data_record.sha256,
            configuration_sha256=config_record.sha256, evaluator_sha256=evaluator_record.sha256,
            seeds=protocol.seeds, evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            metadata=metadata,
        )
        if local_changes:
            local = replace(local, **local_changes)
        plans = tuple(ExperimentPlan(
            experiment_id=local.experiment_id, hypothesis_id=local.hypothesis_id,
            stage=ExperimentStage.EXPLORATORY, contract_sha256=contract.sha256,
            dataset_split_id="development-v1", seed=seed, evaluator_id=conditions.evaluator,
            uses_protected_resource=False, results_seen_before_plan=False,
        ) for seed in local.seeds)
        plan_records = tuple(register_frozen_experiment_plan(
            self.registry, contract=contract, contract_artifact_sha256=contract_record.sha256,
            plan=plan,
        ) for plan in plans)
        local_record = register_frozen_run_spec(
            self.registry, contract=contract, contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(item.sha256 for item in plan_records), spec=local,
        )
        target_profile = ComputeProfile(
            profile_id="planned-cuda-untested", mode=ComputeMode.GPU_CLOUD,
            accelerator=AcceleratorKind.CUDA, scheduler=SchedulerKind.SLURM,
            experiment_class=ExperimentClass.EXPLORATORY, cpu_cores=2, accelerator_count=1,
            memory_limit_bytes=1024**3, maximum_concurrency=1,
            minimum_batch_size=1, preferred_batch_size=4, maximum_batch_size=16,
            accelerator_memory_limit_bytes=1024**3, disk_limit_bytes=1024**3,
            validation_status=ValidationStatus.UNTESTED, queue_name="unvalidated-research", hourly_cost=1.0,
        )
        estimate = ResourceEstimate(
            expected_scientific_value=2.0, expected_uncertainty_reduction=1.0,
            cpu_cores=2, gpu_count=1, ram_bytes=64 * 1024**2, vram_bytes=8 * 1024**2,
            disk_bytes=8 * 1024**2, wall_clock_seconds=60.0, monetary_cost=0.1,
            escalation_reason="CPU/MPS cannot supply the frozen CUDA-event quantity.",
        )
        cloud = replace(local, run_id="cuda-cloud-not-submitted",
                        compute_profile=target_profile, resource_estimate=estimate)
        if cloud_changes:
            cloud = replace(cloud, **cloud_changes)
        escalation_local = replace(local, **(escalation_local_changes or {}))
        decision = EscalationDecision(
            decision_id="cuda-device-protocol-plan",
            source_profile_sha256=escalation_local.compute_profile.sha256,
            target_profile_sha256=cloud.compute_profile.sha256,
            target_estimate_sha256=cloud.resource_estimate.sha256,
            rationale="The device-specific quantity is outside the admitted local grammar.",
            scientific_equivalence_rationale="The exact retained intended protocol is unchanged.",
            expected_information_gain=1.0, lower_cost_alternatives_exhausted=True,
        )
        budget = ComputeEscalationBudget(
            budget_id="cuda-unspent-budget", target_profile_sha256=cloud.compute_profile.sha256,
            target_estimate_sha256=cloud.resource_estimate.sha256, maximum_monetary_cost=1.0,
        )
        plan = make_gpu_cloud_submission_plan(escalation_local, cloud, decision, budget)

        def register_escalation():
            return register_compute_escalation_plan_authority(
                self.registry, self.ledger, authority_id="cuda-plan-authority",
                run_id=self.ledger_run_id, local_spec=escalation_local, cloud_spec=cloud,
                decision=decision, submission_plan=plan, budget=budget,
                human_gate_policy=HumanGatePolicy(HumanGateProfile.HUMAN_GATES_REQUIRED),
            )

        if escalation_first:
            escalation_record = register_escalation()
        if before_freeze:
            before_freeze(local, local_record, contract_record)
        freeze_arguments = dict(
            run_id=self.ledger_run_id, contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(item.sha256 for item in plan_records),
            frozen_run_spec_artifact_sha256=local_record.sha256,
        )
        record_scientific_design_freeze(self.registry, self.ledger, **freeze_arguments)
        freeze_record = register_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger, receipt_id="cuda-device-freeze", **freeze_arguments,
        )
        if not escalation_first:
            escalation_record = register_escalation()
        return dict(local=local, local_record=local_record, cloud=cloud, contract=contract,
                    contract_record=contract_record, freeze_record=freeze_record,
                    escalation_record=escalation_record, protocol=protocol)

    def resolve(self, inputs, **changes):
        arguments = dict(
            expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=inputs["local"].run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
            compute_escalation_plan_authority_artifact_sha256=inputs["escalation_record"].sha256,
        )
        arguments.update(changes)
        return resolve_gpu_validation_requirement(self.registry, self.ledger, **arguments)

    def inert_progress(self, parents=(), value=None, logical_type="scientific_execution_unknown"):
        return self.artifact(canonical_json_bytes(value or {"inert-adverse-progress": True}) + b"\n",
                             logical_type, Role.EXPERIMENT_RUNNER, parents,
                             validation_result="FAIL")

    def event(self, metadata, *, artifacts=(), event_type="CHECKPOINT", supersedes=None):
        return self.ledger.record(
            run_id=self.ledger_run_id, actor_role=Role.EXPERIMENT_RUNNER,
            state_before=MacroState.PROTOCOL, requested_state_after=MacroState.PROTOCOL,
            artifact_hashes=artifacts, code_version="inert-adverse-selector",
            configuration_hash="a" * 64, dataset_identifiers=(), random_seeds=(),
            evaluator_outputs=(), reason="Inert negative control; no execution asserted.",
            event_type=event_type, supersedes_event_id=supersedes, metadata=metadata,
        )

    def assert_unavailable(self, result, status=GpuValidationRequirementStatus.BLOCKED_LOCAL):
        self.assertIs(result.status, status)
        self.assertIsNone(result.requirement)

    def test_genuine_prospective_owners_establish_only_the_operational_requirement(self):
        inputs = self.prepare()
        before = (self.registry.verify_all(), self.ledger.assert_valid())
        result = self.resolve(inputs)
        self.assertIs(result.status, GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED)
        sources = result.requirement
        self.assertEqual(sources.local_spec, inputs["local"])
        self.assertEqual(sources.cloud_spec, inputs["cloud"])
        self.assertEqual(sources.protocol, inputs["protocol"])
        self.assertEqual(sources.obligation_identity,
                         (inputs["contract_record"].sha256, inputs["contract"].sha256,
                          "hypothesis-primary", "experiment-primary"))
        self.assertEqual(sources.project_definition_sha256, inputs["local"].project_definition_sha256)
        self.assertEqual(sources.input_bytes[0], CUDA_DEVICE_TIMING_BENCHMARK_BYTES)
        self.assertEqual(sources.input_bytes[3], CUDA_DEVICE_TIMING_EVALUATOR_BYTES)
        self.assertFalse(sources.scientific_evidence_eligible)
        self.assertFalse(sources.spending_authorized)
        self.assertIs(sources.external_validation, ValidationStatus.UNTESTED)
        self.assertFalse(sources.escalation.live_gpu_availability_verified)
        self.assertFalse(sources.escalation.gpu_execution_validated)
        self.assertEqual((sources.entry_registry_snapshot, sources.entry_ledger_snapshot), before)
        self.assertEqual((self.registry.verify_all(), self.ledger.assert_valid()), before)
        self.assertEqual(sources.entry_ledger_snapshot.events[sources.freeze_event_index], sources.freeze_event)
        self.assertEqual(sources.entry_ledger_snapshot.events[sources.escalation_event_index], sources.escalation_event)
        self.assertLessEqual(len(sources.source_records), 256)
        with self.assertRaises(FrozenInstanceError):
            sources.local_spec = inputs["cloud"]

    def test_plan_before_design_freeze_is_also_prospective(self):
        inputs = self.prepare(escalation_first=True)
        result = self.resolve(inputs)
        self.assertIs(result.status, GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED)
        self.assertLess(result.requirement.escalation_event_index, result.requirement.freeze_event_index)

    def test_absent_policy_is_not_applicable_not_a_gpu_requirement(self):
        inputs = self.prepare(omit_policy=True)
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.NOT_APPLICABLE)

    def test_closed_policy_rejects_extra_authority_assertion(self):
        inputs = self.prepare(policy={"schema_version": GPU_VALIDATION_REQUIREMENT_POLICY_SCHEMA,
                                      "profile_id": CUDA_DEVICE_TIMING_PROFILE_ID,
                                      "gpu_necessary": True})
        self.assert_unavailable(self.resolve(inputs))

    def test_missing_real_source_and_wrong_run_are_not_success(self):
        inputs = self.prepare()
        for changes in ({"evaluation_contract_freeze_receipt_artifact_sha256": "0" * 64},
                        {"compute_escalation_plan_authority_artifact_sha256": "0" * 64},
                        {"expected_ledger_run_id": "different-ledger"},
                        {"expected_execution_run_id": "different-execution"}):
            with self.subTest(changes=changes):
                self.assert_unavailable(self.resolve(inputs, **changes))

    def test_same_project_does_not_excuse_different_cloud_argv(self):
        inputs = self.prepare(cloud_changes={"argv": ("./cpu-fallback",)})
        self.assertEqual(inputs["local"].project_definition_sha256,
                         inputs["cloud"].project_definition_sha256)
        self.assert_unavailable(self.resolve(inputs))

    def test_same_project_does_not_excuse_different_cloud_workdir(self):
        self.assert_unavailable(self.resolve(self.prepare(cloud_changes={"working_directory": "elsewhere"})))

    def test_escalation_local_wrapper_must_equal_complete_canonical_local_value(self):
        self.assert_unavailable(self.resolve(self.prepare(escalation_local_changes={"run_id": "renamed-local-wrapper"})))

    def test_retained_cpp_and_evaluator_bytes_are_not_caller_prose(self):
        inputs = self.prepare(code=b"// CUDA required, according to the caller.\n")
        self.assert_unavailable(self.resolve(inputs))

    def test_changed_evaluator_is_refused(self):
        self.assert_unavailable(self.resolve(self.prepare(evaluator=CUDA_DEVICE_TIMING_EVALUATOR_BYTES + b"\n")))

    def test_noncanonical_configuration_is_refused(self):
        protocol = CudaDeviceTimingProtocol("device-ms", "baseline-strong", (7, 11, 19), 4, 64, 128, 1, 3)
        self.assert_unavailable(self.resolve(self.prepare(configuration=protocol.canonical_bytes().rstrip())))

    def test_wrong_binary_dataset_header_is_refused(self):
        self.assert_unavailable(self.resolve(self.prepare(data=b"NOPE" + struct.pack("<I8I", 4, *range(8)))))

    def test_intermediate_quantity_cannot_be_end_to_end(self):
        self.assert_unavailable(self.resolve(self.prepare(metric_changes={"scope": MetricScope.END_TO_END})))

    def test_declared_baseline_must_be_mandatory(self):
        self.assert_unavailable(self.resolve(self.prepare(baseline_status=BaselineStatus.SHOULD_RUN)))

    def test_known_preparation_or_failed_output_cannot_be_ignored(self):
        inputs = self.prepare()
        self.inert_progress((inputs["local_record"].sha256,), logical_type="experiment_output.seed_result")
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_equivalent_renamed_profile_attempt_is_not_never_started(self):
        inputs = self.prepare()
        clone = replace(inputs["cloud"], run_id="renamed-attempt", attempt=2,
                        retry_of_run_id="earlier-attempt", hypothesis_id="renamed-hypothesis",
                        experiment_id="renamed-experiment", evidence_class=EvidenceClass.NON_EVIDENTIARY)
        self.assertNotEqual(clone.project_definition_sha256, inputs["local"].project_definition_sha256)
        clone_record = self.artifact(canonical_json_bytes(clone.to_dict()) + b"\n",
                                     "frozen_run_spec", Role.EXPERIMENT_RUNNER)
        self.inert_progress((clone_record.sha256,))
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_same_contract_obligation_catches_different_input_configuration(self):
        inputs = self.prepare()
        clone = replace(inputs["local"], run_id="different-configuration-attempt",
                        configuration_sha256="f" * 64)
        clone_record = self.artifact(canonical_json_bytes(clone.to_dict()) + b"\n",
                                     "frozen_run_spec", Role.EXPERIMENT_RUNNER,
                                     (inputs["contract_record"].sha256,))
        self.inert_progress((clone_record.sha256,))
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def unrelated_spec(self, inputs):
        clone = replace(inputs["local"], run_id="unrelated-run", hypothesis_id="unrelated-hypothesis",
                        experiment_id="unrelated-experiment", configuration_sha256="e" * 64)
        return self.artifact(canonical_json_bytes(clone.to_dict()) + b"\n",
                             "frozen_run_spec", Role.EXPERIMENT_RUNNER)

    def test_unrelated_token_cannot_launder_unknown_progress(self):
        inputs = self.prepare()
        self.unrelated_spec(inputs)
        self.inert_progress(value={"note": "unrelated-run"})
        self.assert_unavailable(self.resolve(inputs))

    def test_extra_unrelated_parent_cannot_launder_unknown_progress(self):
        inputs = self.prepare()
        unrelated = self.unrelated_spec(inputs)
        self.inert_progress((unrelated.sha256,), value={"unknown": "not an owned progress schema"})
        self.assert_unavailable(self.resolve(inputs))

    def test_unrelated_token_cannot_launder_unknown_progress_event(self):
        inputs = self.prepare()
        self.unrelated_spec(inputs)
        self.event({"scientific_execution_unknown": {"note": "unrelated-run"}})
        self.assert_unavailable(self.resolve(inputs))

    def test_partial_preparation_requires_its_full_actual_owner_for_exclusion(self):
        inputs = self.prepare()
        unrelated = self.unrelated_spec(inputs)
        self.inert_progress((unrelated.sha256,),
                            value={"frozen_run_spec_artifact_sha256": unrelated.sha256},
                            logical_type="scientific_execution_preparation")
        self.assert_unavailable(self.resolve(inputs))

    def test_ledger_visibility_by_obligation_cannot_be_ignored(self):
        inputs = self.prepare()
        self.event({"scientific_timeline": {"kind": "RESULT_OBSERVED",
                                            "contract_artifact_sha256": inputs["contract_record"].sha256,
                                            "hypothesis_id": "hypothesis-primary",
                                            "experiment_id": "experiment-primary"}})
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_external_consumption_is_not_a_gpu_capacity_claim(self):
        inputs = self.prepare()
        self.event({"compute_escalation_submission_consumption": {
            "authority_artifact_sha256": inputs["escalation_record"].sha256}})
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.BLOCKED_EXTERNAL)

    def test_correction_cannot_erase_progress(self):
        inputs = self.prepare()
        progress = self.event({"scientific_execution_unknown": {
            "execution_run_id": inputs["local"].run_id}})
        self.event({"explanation": "inert correction"}, event_type="CORRECTION", supersedes=progress.event_id)
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_corrected_design_admission_is_not_current(self):
        inputs = self.prepare()
        freeze_event = self.ledger.assert_valid().events[0]
        self.event({"explanation": "inert correction"}, event_type="CORRECTION", supersedes=freeze_event.event_id)
        self.assert_unavailable(self.resolve(inputs))

    def test_snapshot_change_during_real_owner_replay_fails_closed(self):
        inputs = self.prepare()
        actual = owner.require_frozen_evaluation_contract

        def full_owner_then_append(*args, **kwargs):
            value = actual(*args, **kwargs)
            self.artifact(b'{"concurrent-source-change":true}\n', "inert_unrelated_source")
            return value

        with patch.object(owner, "require_frozen_evaluation_contract", side_effect=full_owner_then_append):
            result = self.resolve(inputs)
        self.assert_unavailable(result)
        self.assertEqual(result.reason_code, "SOURCES_CHANGED_DURING_RESOLUTION")

    def test_source_parent_capacity_is_closed(self):
        records = tuple(self.artifact(f'{{"parent":{index}}}\n'.encode(), "inert_parent") for index in range(256))
        root_record = self.artifact(b'{"closure-root":true}\n', "inert_root",
                                    parents=tuple(record.sha256 for record in records))
        with self.assertRaisesRegex(GpuValidationRequirementError, "256 parents"):
            owner._source_closure(self.registry.verify_all().records, (root_record,))

    def test_native_scalar_entrypoints_reject_hostile_subclasses_before_hooks(self):
        class Hostile(str):
            def __hash__(self):
                raise AssertionError("hostile hashing hook")

        with self.assertRaises(GpuValidationRequirementError):
            resolve_gpu_validation_requirement(
                self.registry, self.ledger, expected_ledger_run_id=Hostile("run"),
                expected_execution_run_id="run", evaluation_contract_freeze_receipt_artifact_sha256="0" * 64,
                compute_escalation_plan_authority_artifact_sha256="1" * 64,
            )
        with self.assertRaises(GpuValidationRequirementError):
            GpuValidationRequirementResolution("REQUIREMENT_ESTABLISHED", "NOT_AUTHORITY")

    def test_ordinary_non_cuda_plan_policy_cannot_create_device_requirement(self):
        inputs = self.prepare(omit_policy=True, code=b"print('ordinary integer CPU work')\n")
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.NOT_APPLICABLE)

    def test_directed_metric_definition_is_exact(self):
        self.assert_unavailable(self.resolve(self.prepare(metric_changes={"definition": "End-to-end system speedup"})))

    def test_no_owner_writes_after_negative_readback(self):
        inputs = self.prepare()
        self.inert_progress(value={"unsupported": "progress without attributable work"})
        before = (self.registry.verify_all(), self.ledger.assert_valid())
        self.assert_unavailable(self.resolve(inputs))
        self.assertEqual((self.registry.verify_all(), self.ledger.assert_valid()), before)

    def test_progress_before_both_admissions_is_still_not_never_started(self):
        def earlier_progress(_local, local_record, _contract_record):
            self.inert_progress((local_record.sha256,))

        inputs = self.prepare(before_freeze=earlier_progress)
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_corrected_escalation_admission_is_not_current(self):
        inputs = self.prepare()
        escalation_event = self.ledger.assert_valid().events[-1]
        self.event({"explanation": "inert escalation correction"},
                   event_type="CORRECTION", supersedes=escalation_event.event_id)
        self.assert_unavailable(self.resolve(inputs))

    def test_unpaired_registry_and_ledger_refuse_before_source_resolution(self):
        inputs = self.prepare()
        other_ledger = EventLedger(self.root, "runs/another-run/events.jsonl")
        result = resolve_gpu_validation_requirement(
            self.registry, other_ledger, expected_ledger_run_id=self.ledger_run_id,
            expected_execution_run_id=inputs["local"].run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
            compute_escalation_plan_authority_artifact_sha256=inputs["escalation_record"].sha256,
        )
        self.assert_unavailable(result)
        self.assertEqual(result.reason_code, "SOURCE_SNAPSHOT_UNAVAILABLE")

    def test_private_locked_entry_is_the_same_full_owner(self):
        inputs = self.prepare()
        public = self.resolve(inputs)
        with owner._project_resource_execution_lock(self.root):
            private = owner._resolve_gpu_validation_requirement(
                self.registry, self.ledger, expected_ledger_run_id=self.ledger_run_id,
                expected_execution_run_id=inputs["local"].run_id,
                evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
                compute_escalation_plan_authority_artifact_sha256=inputs["escalation_record"].sha256,
                project_lock_held=True,
            )
        self.assertEqual(private, public)

    def test_unknown_policy_version_fails_closed(self):
        inputs = self.prepare(policy={"schema_version": "gpu-validation-requirement-policy/v999",
                                      "profile_id": CUDA_DEVICE_TIMING_PROFILE_ID})
        self.assert_unavailable(self.resolve(inputs))

    def test_malformed_known_spec_cannot_hide_execution_scope(self):
        inputs = self.prepare()
        self.artifact(b'{"run_id":"unclassifiable"}\n', "frozen_run_spec", Role.EXPERIMENT_RUNNER)
        self.assert_unavailable(self.resolve(inputs))

    def test_unrelated_artifact_reference_does_not_exclude_unknown_progress_event(self):
        inputs = self.prepare()
        unrelated = self.unrelated_spec(inputs)
        self.event({"scientific_execution_unknown": {"note": "unrelated-run"}},
                   artifacts=(unrelated.sha256,))
        self.assert_unavailable(self.resolve(inputs))

    def test_gpu_return_publication_is_progress_even_without_output_child(self):
        inputs = self.prepare()
        self.artifact(canonical_json_bytes(inputs["cloud"].to_dict()),
                      "gpu_cloud_target_run_spec", Role.EXPERIMENT_RUNNER)
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)

    def test_malformed_timeline_marker_does_not_mean_no_progress(self):
        inputs = self.prepare()
        self.event({"scientific_timeline": None})
        self.assert_unavailable(self.resolve(inputs))

    def test_design_label_does_not_hide_declared_output_visibility(self):
        inputs = self.prepare()
        self.event({"scientific_timeline": {"kind": "DESIGN_FROZEN",
                                            "output_manifest_artifact_sha256": "d" * 64}})
        self.assert_unavailable(self.resolve(inputs))

    def test_unavailable_project_lock_is_explicit_not_authority(self):
        inputs = self.prepare()
        with patch.object(owner, "_project_resource_execution_lock", side_effect=OSError("inert lock failure")):
            result = self.resolve(inputs)
        self.assert_unavailable(result)
        self.assertEqual(result.reason_code, "PROJECT_RESOURCE_LOCK_UNAVAILABLE")

    def test_identical_inputs_with_renamed_contract_and_partial_declared_seeds_are_progress(self):
        inputs = self.prepare()
        different_contract = self.artifact(b'{"inert-renamed-contract":true}\n', "evaluation_contract")
        clone = replace(inputs["local"], run_id="renamed-partial-seed-attempt",
                        hypothesis_id="another-hypothesis", experiment_id="another-experiment",
                        seeds=(7,))
        clone_record = self.artifact(canonical_json_bytes(clone.to_dict()) + b"\n",
                                     "frozen_run_spec", Role.EXPERIMENT_RUNNER,
                                     (different_contract.sha256,))
        self.assertNotEqual(clone.seeds, inputs["local"].seeds)
        self.assertEqual(clone.argv, inputs["local"].argv)
        self.assertTrue(owner._same_work(clone, inputs["local"], different_contract.sha256,
                                        inputs["contract_record"].sha256))
        self.inert_progress((clone_record.sha256,))
        self.assert_unavailable(self.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED)


if __name__ == "__main__":
    unittest.main()
