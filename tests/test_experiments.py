from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.experiments import (
    AcceleratorKind,
    CachePolicy,
    CheckpointPolicy,
    ComputeMode,
    ComputeProfile,
    ComputeEscalationBudget,
    EscalationDecision,
    EvidenceClass,
    ExecutionResult,
    ExperimentClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    FakeGPUCloudBackend,
    FrozenRunSpec,
    GPUCloudCapabilities,
    LocalMacBackend,
    LocalMacExecutionMode,
    NetworkUseStatus,
    OutputArtifact,
    OutputManifest,
    ResourceEstimate,
    ReproductionStatus,
    RunState,
    SchedulerKind,
    ScheduledGPUArtifactBundle,
    ScheduledGPUCloudBackend,
    ScheduledGPURecoveryBlocked,
    ScheduledGPURequest,
    ScheduledGPUStatus,
    SeedRunResult,
    SeedRunStatus,
    StagedArtifact,
    SubmissionConflictError,
    ValidationStatus,
    compare_clean_rerun,
    make_gpu_cloud_submission_plan,
    plan_adaptive_execution,
    register_compute_escalation_plan_authority,
    register_compute_escalation_submission_authorization,
    validate_compute_escalation,
)
from scientist_one.gates import (
    AutonomousDecisionRecord,
    HumanGate,
    HumanGatePolicy,
    HumanGateProfile,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import thaw_json
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def local_profile(
    *,
    accelerator: AcceleratorKind = AcceleratorKind.CPU,
    validation_hash: str | None = None,
) -> ComputeProfile:
    return ComputeProfile(
        profile_id=f"local-{accelerator.value.lower()}-profile",
        mode=ComputeMode.LOCAL_MAC,
        accelerator=accelerator,
        scheduler=SchedulerKind.LOCAL,
        experiment_class=ExperimentClass.PILOT,
        cpu_cores=4,
        accelerator_count=0 if accelerator is AcceleratorKind.CPU else 1,
        memory_limit_bytes=8 * 1024**3,
        maximum_concurrency=4,
        minimum_batch_size=2,
        preferred_batch_size=16,
        maximum_batch_size=32,
        maximum_memory_fraction=0.5,
        supports_checkpointing=True,
        supports_preemption=False,
        validation_status=ValidationStatus.VALIDATED_LOCAL,
        validation_artifact_sha256=validation_hash,
        hourly_cost=0.0,
    )


def gpu_profile(*, count: int = 1, scheduler: SchedulerKind = SchedulerKind.SLURM) -> ComputeProfile:
    return ComputeProfile(
        profile_id=f"gpu-cloud-{count}-{scheduler.value.lower()}",
        mode=ComputeMode.GPU_CLOUD,
        accelerator=AcceleratorKind.CUDA,
        scheduler=scheduler,
        experiment_class=ExperimentClass.EXPLORATORY,
        cpu_cores=8,
        accelerator_count=count,
        memory_limit_bytes=64 * 1024**3,
        maximum_concurrency=8,
        minimum_batch_size=8,
        preferred_batch_size=64,
        maximum_batch_size=256,
        accelerator_memory_limit_bytes=16 * 1024**3 * count,
        disk_limit_bytes=64 * 1024**3,
        supports_checkpointing=True,
        supports_preemption=True,
        validation_status=ValidationStatus.UNTESTED,
        queue_name=("research" if scheduler in {SchedulerKind.SCHEDULED, SchedulerKind.SLURM} else None),
        multi_accelerator_rationale=(
            "the frozen model and batch do not fit one accelerator" if count > 1 else None
        ),
        hourly_cost=3.0 * count,
    )


def local_estimate() -> ResourceEstimate:
    return ResourceEstimate(
        expected_scientific_value=2.0,
        expected_uncertainty_reduction=1.0,
        cpu_cores=4,
        gpu_count=0,
        ram_bytes=4 * 1024**3,
        vram_bytes=0,
        disk_bytes=1024**3,
        wall_clock_seconds=120.0,
        monetary_cost=0.0,
    )


def gpu_estimate(*, count: int = 1) -> ResourceEstimate:
    return ResourceEstimate(
        expected_scientific_value=8.0,
        expected_uncertainty_reduction=4.0,
        cpu_cores=8,
        gpu_count=count,
        ram_bytes=32 * 1024**3,
        vram_bytes=12 * 1024**3 * count,
        disk_bytes=4 * 1024**3,
        wall_clock_seconds=600.0,
        monetary_cost=2.5 * count,
        escalation_reason="local pilot cannot fit the preregistered confirmatory workload",
    )


def spec(
    run_id: str,
    *,
    profile: ComputeProfile | None = None,
    estimate: ResourceEstimate | None = None,
    argv: tuple[str, ...] = ("/usr/bin/true",),
    data_hash: str | None = None,
) -> FrozenRunSpec:
    return FrozenRunSpec(
        run_id=run_id,
        experiment_id="experiment-profile-test",
        hypothesis_id="hypothesis-profile-test",
        phase=ExperimentPhase.EXPLORATORY,
        argv=argv,
        working_directory=".",
        code_sha256=digest("code"),
        data_sha256=data_hash or digest("data"),
        configuration_sha256=digest("configuration"),
        evaluator_sha256=digest("evaluator"),
        seeds=(11, 22, 33, 44),
        timeout_seconds=900.0,
        evidence_class=EvidenceClass.NON_EVIDENTIARY,
        scientific_purpose="discriminate the frozen hypothesis using all planned seeds",
        expected_outputs=("output_manifest", "seed_results"),
        seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
        termination_conditions=("wall_clock_timeout", "all_planned_seeds_reported"),
        compute_profile=profile or local_profile(),
        resource_estimate=estimate or local_estimate(),
        cache_policy=CachePolicy.CONTENT_ADDRESSABLE,
        checkpoint_policy=CheckpointPolicy.PER_SEED,
        bytes_per_sample=32 * 1024**2,
        worker_overhead_bytes=256 * 1024**2,
    )


def escalation_decision(
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision_id: str,
) -> EscalationDecision:
    return EscalationDecision(
        decision_id=decision_id,
        source_profile_sha256=local_spec.compute_profile.sha256,
        target_profile_sha256=cloud_spec.compute_profile.sha256,
        target_estimate_sha256=cloud_spec.resource_estimate.sha256,
        rationale="the bounded local pilot eliminated cheaper candidate configurations",
        scientific_equivalence_rationale=(
            "code data evaluator seeds and expected outputs are unchanged"
        ),
        expected_information_gain=4.0,
        lower_cost_alternatives_exhausted=True,
    )


def submit_planned_gpu(
    backend: FakeGPUCloudBackend,
    cloud_spec: FrozenRunSpec,
    *,
    idempotency_key: str,
):
    local_spec = spec(f"{cloud_spec.run_id}-local-source")
    return backend.submit_planned(
        local_spec,
        cloud_spec,
        escalation_decision(
            local_spec,
            cloud_spec,
            f"decision-{cloud_spec.run_id}",
        ),
        idempotency_key=idempotency_key,
    )


def write_manifest(run_spec: FrozenRunSpec, directory: Path) -> OutputManifest:
    artifacts: list[OutputArtifact] = []
    results: list[SeedRunResult] = []
    for seed in run_spec.seeds:
        payload = canonical_json_bytes({"seed": seed, "metric": seed / 100.0})
        path = f"seed-{seed}.json"
        (directory / path).write_bytes(payload)
        sha = hashlib.sha256(payload).hexdigest()
        artifacts.append(OutputArtifact(path, sha, len(payload), "seed_result"))
        results.append(SeedRunResult(seed, SeedRunStatus.SUCCESS, seed / 100.0, sha))
    manifest = OutputManifest(
        run_id=run_spec.run_id,
        spec_sha256=run_spec.sha256,
        code_sha256=run_spec.code_sha256,
        data_sha256=run_spec.data_sha256,
        configuration_sha256=run_spec.configuration_sha256,
        evaluator_sha256=run_spec.evaluator_sha256,
        planned_seeds=run_spec.seeds,
        seed_results=tuple(results),
        artifacts=tuple(artifacts),
    )
    (directory / "output-manifest.json").write_bytes(
        canonical_json_bytes(manifest.to_dict()) + b"\n"
    )
    return manifest


class StructuredSchedulerFixture:
    provider_name = "STRUCTURED_SCHEDULER_FIXTURE"
    validation_status = ValidationStatus.UNTESTED
    network_used = False
    capabilities = GPUCloudCapabilities(
        cuda=True,
        single_gpu=True,
        multi_gpu=True,
        scheduled_execution=True,
        slurm=True,
        checkpoints=True,
        preemption=True,
        queues=True,
        artifact_return=True,
    )

    def __init__(self) -> None:
        self.submit_calls = 0
        self.requeue_calls: list[tuple[str, str, str]] = []
        self.requeue_attempt_delta = 1
        self.requests: dict[str, ScheduledGPURequest] = {}
        self.statuses: dict[str, ScheduledGPUStatus] = {}
        self.bundles: dict[str, ScheduledGPUArtifactBundle] = {}

    def submit(self, request: ScheduledGPURequest) -> ScheduledGPUStatus:
        self.submit_calls += 1
        provider_job_id = f"slurm-{request.submission_plan.sha256[:16]}"
        self.requests[provider_job_id] = request
        status = ScheduledGPUStatus(
            provider_job_id=provider_job_id,
            state=RunState.QUEUED,
            reason="FIXTURE_QUEUED_UNTESTED",
            queue_position=0,
        )
        self.statuses[provider_job_id] = status
        return status

    def status(self, provider_job_id: str) -> ScheduledGPUStatus:
        return self.statuses[provider_job_id]

    def cancel(self, provider_job_id: str, *, idempotency_key: str) -> ScheduledGPUStatus:
        status = ScheduledGPUStatus(
            provider_job_id=provider_job_id,
            state=RunState.CANCELLED,
            reason=f"FIXTURE_CANCELLED:{idempotency_key}",
        )
        self.statuses[provider_job_id] = status
        return status

    def requeue(
        self,
        provider_job_id: str,
        *,
        checkpoint_token: str,
        idempotency_key: str,
    ) -> ScheduledGPUStatus:
        self.requeue_calls.append(
            (provider_job_id, checkpoint_token, idempotency_key)
        )
        next_attempt = (
            self.statuses[provider_job_id].attempt + self.requeue_attempt_delta
        )
        status = ScheduledGPUStatus(
            provider_job_id=provider_job_id,
            state=RunState.QUEUED,
            reason=f"FIXTURE_REQUEUED:{idempotency_key}",
            checkpoint_token=checkpoint_token,
            queue_position=0,
            attempt=next_attempt,
        )
        self.statuses[provider_job_id] = status
        return status

    def collect(self, provider_job_id: str) -> ScheduledGPUArtifactBundle:
        return self.bundles[provider_job_id]


class ComputeProfileTests(unittest.TestCase):
    def test_mps_requires_validation_artifact_and_gpu_remains_untested(self) -> None:
        with self.assertRaises(ExperimentError):
            local_profile(accelerator=AcceleratorKind.MPS)
        mps = local_profile(
            accelerator=AcceleratorKind.MPS,
            validation_hash=digest("validated-mps-smoke"),
        )
        self.assertEqual(mps.validation_status, ValidationStatus.VALIDATED_LOCAL)
        cloud = gpu_profile(count=2)
        self.assertEqual(cloud.validation_status, ValidationStatus.UNTESTED)
        self.assertEqual(cloud.accelerator, AcceleratorKind.CUDA)
        self.assertEqual(cloud.scheduler, SchedulerKind.SLURM)
        with self.assertRaises(ExperimentError):
            replace(cloud, multi_accelerator_rationale=None)
        with self.assertRaises(ExperimentError):
            replace(cloud, validation_status=ValidationStatus.VALIDATED_LOCAL)
        with self.assertRaises(ExperimentError):
            replace(cloud, accelerator_memory_limit_bytes=0)

    def test_adaptive_plan_respects_memory_concurrency_batch_and_cost(self) -> None:
        profile = local_profile()
        estimate = local_estimate()
        plan = plan_adaptive_execution(
            profile,
            estimate,
            observed_available_memory_bytes=4 * 1024**3,
            pending_tasks=10,
            bytes_per_sample=32 * 1024**2,
            worker_overhead_bytes=256 * 1024**2,
            concurrency_cap=3,
        )
        self.assertEqual(plan.usable_memory_bytes, 2 * 1024**3)
        self.assertEqual(plan.concurrency, 3)
        self.assertGreaterEqual(plan.batch_size, profile.minimum_batch_size)
        self.assertLessEqual(plan.batch_size, profile.preferred_batch_size)
        self.assertEqual(plan.estimated_monetary_cost, 0.0)
        self.assertEqual(len(plan.sha256), 64)
        with self.assertRaises(ExperimentError):
            plan_adaptive_execution(
                profile,
                estimate,
                observed_available_memory_bytes=128 * 1024**2,
                pending_tasks=1,
                bytes_per_sample=64 * 1024**2,
                worker_overhead_bytes=256 * 1024**2,
            )

    def test_run_spec_binds_scientific_and_compute_controls_separately(self) -> None:
        local = spec("run-local-project")
        cloud = spec(
            "run-cloud-project",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
            argv=("/opt/project/remote-runner",),
        )
        self.assertNotEqual(local.sha256, cloud.sha256)
        self.assertNotEqual(local.scientific_binding_sha256, cloud.scientific_binding_sha256)
        self.assertEqual(local.project_definition_sha256, cloud.project_definition_sha256)
        changed = replace(cloud, data_sha256=digest("different-data"))
        self.assertNotEqual(local.project_definition_sha256, changed.project_definition_sha256)
        self.assertEqual(local.to_dict()["scientific_purpose"], local.scientific_purpose)
        self.assertEqual(local.to_dict()["compute_profile"]["mode"], "LOCAL_MAC")

    def test_resource_estimates_cannot_exceed_ram_vram_or_disk_envelopes(self) -> None:
        cloud_profile = gpu_profile()
        with self.assertRaises(ExperimentError):
            spec(
                "run-cloud-vram-overflow",
                profile=cloud_profile,
                estimate=replace(
                    gpu_estimate(),
                    vram_bytes=cloud_profile.accelerator_memory_limit_bytes + 1,
                ),
            )
        local = local_profile()
        with self.assertRaises(ExperimentError):
            spec(
                "run-local-disk-overflow",
                profile=local,
                estimate=replace(local_estimate(), disk_bytes=local.disk_limit_bytes + 1),
            )


class LocalMacControlTests(unittest.TestCase):
    def test_bound_builtin_rejects_unbound_submission_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
            )
            jobs_root = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
            )
            with self.assertRaisesRegex(ExperimentError, "exact code, data"):
                backend.submit(
                    spec("bound-builtin-unbound"),
                    idempotency_key="bound-builtin-unbound",
                )
            self.assertEqual(tuple(jobs_root.iterdir()), ())

    def test_injected_diagnostic_rejects_bindings_and_is_unpromotable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = 0

            def runner(run_spec, job_directory, _environment):
                nonlocal calls
                calls += 1
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            with self.assertRaisesRegex(
                ExperimentError,
                "rejects scientific input bindings",
            ):
                backend.submit(
                    spec("diagnostic-rejects-bindings"),
                    idempotency_key="diagnostic-rejects-bindings",
                    input_artifact_paths={
                        "code": "code.py",
                        "data": "data.json",
                        "configuration": "configuration.json",
                        "evaluator": "evaluator.json",
                    },
                )
            self.assertEqual(calls, 0)
            run_spec = spec("diagnostic-unpromotable")
            receipt = backend.submit(
                run_spec,
                idempotency_key="diagnostic-unpromotable",
            )
            self.assertTrue(receipt.job_id.endswith("-diagnostic"))
            self.assertEqual(receipt.validation_status, ValidationStatus.UNTESTED)
            self.assertIsNone(receipt.execution_input_binding_sha256)
            status = backend.reconcile(receipt.job_id)
            self.assertIn("INJECTED_DIAGNOSTIC", status.reason or "")
            collected = backend.collect(receipt.job_id)
            self.assertEqual(collected.validation_status, ValidationStatus.UNTESTED)
            self.assertIsNone(collected.execution_input_binding_sha256)
            self.assertFalse(collected.scientific_evidence)

    def test_bound_inputs_are_staged_and_consumed_after_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_worker = Path("scripts/vnext_fixture_experiment.py").read_bytes()
            worker = original_worker.replace(
                b"def main() -> int:\n",
                (
                    b"def main() -> int:\n"
                    b"    with open('data.json', 'wb') as hostile_source:\n"
                    b"        hostile_source.write(b'{\\\"rows\\\":[]}\\n')\n"
                ),
                1,
            )
            data = canonical_json_bytes(
                {
                    "schema_version": "SCIENTIST_ONE_VNEXT_FIXTURE_DATASET_V1",
                    "rows": [
                        {"id": "a", "label": 0, "signal": 0.1, "split": "development"},
                        {"id": "b", "label": 1, "signal": 0.9, "split": "development"},
                    ],
                }
            ) + b"\n"
            configuration = canonical_json_bytes(
                {
                    "ablation_interventions": {},
                    "candidate_threshold": 0.5,
                    "dataset_path": "data.json",
                    "evaluation_split": "development",
                    "experiment_class": "SMOKE",
                    "fixture_notice": (
                        "Synthetic integration fixture only; no publishable scientific conclusion."
                    ),
                    "required_ablations": [],
                    "seeds": [11, 22, 33, 44],
                }
            ) + b"\n"
            evaluator = canonical_json_bytes(
                {
                    "aggregation": "arithmetic mean over all declared seeds",
                    "definition": (
                        "correct development subjects divided by all development subjects"
                    ),
                    "fixture_notice": (
                        "Synthetic integration fixture only; no publishable scientific conclusion."
                    ),
                    "metric_id": "subject-accuracy",
                    "unit": "fraction",
                    "version": "accuracy-evaluator-v1",
                }
            ) + b"\n"
            (root / "worker.py").write_bytes(worker)
            (root / "data.json").write_bytes(data)
            (root / "configuration.json").write_bytes(configuration)
            (root / "evaluator.json").write_bytes(evaluator)
            run_spec = replace(
                spec("run-bound-exact-inputs"),
                argv=("/usr/bin/python3", "-I", "-S", "-B", "worker.py"),
                code_sha256=hashlib.sha256(worker).hexdigest(),
                data_sha256=hashlib.sha256(data).hexdigest(),
                configuration_sha256=hashlib.sha256(configuration).hexdigest(),
                evaluator_sha256=hashlib.sha256(evaluator).hexdigest(),
                required_ablations=(),
            )
            backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/python3",),
            )
            real_popen = subprocess.Popen
            replaced_staged_code: list[Path] = []

            def replace_staged_path_before_exec(argv, **kwargs):
                job_parent = (
                    root
                    / ".scientist-one-build"
                    / "experiments"
                    / "local-mac"
                )
                job_root = next(item for item in job_parent.iterdir() if item.is_dir())
                staged_code = job_root / "frozen-input-code.py"
                held_inode_name = job_root / "frozen-input-code.held.py"
                staged_code.rename(held_inode_name)
                staged_code.write_bytes(b"raise SystemExit(91)\n")
                replaced_staged_code.append(staged_code)
                return real_popen(argv, **kwargs)

            with mock.patch(
                "scientist_one.experiments.subprocess.Popen",
                side_effect=replace_staged_path_before_exec,
            ):
                receipt = backend.submit(
                    run_spec,
                    idempotency_key="bound-exact-inputs",
                    input_artifact_paths={
                        "code": "worker.py",
                        "configuration": "configuration.json",
                        "data": "data.json",
                        "evaluator": "evaluator.json",
                    },
                )
            self.assertEqual(
                receipt.state,
                RunState.SUCCEEDED,
                (
                    backend.reconcile(receipt.job_id).reason,
                    (backend._jobs[receipt.job_id].directory / "stderr.log").read_text(),
                ),
            )
            self.assertIsNotNone(receipt.execution_input_binding_sha256)
            self.assertEqual(len(replaced_staged_code), 1)
            self.assertEqual(
                replaced_staged_code[0].read_bytes(),
                b"raise SystemExit(91)\n",
            )
            self.assertEqual((root / "data.json").read_bytes(), b'{"rows":[]}\n')
            collected = backend.collect(receipt.job_id)
            self.assertEqual(
                collected.execution_input_binding_sha256,
                receipt.execution_input_binding_sha256,
            )
            job_root = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
                / receipt.job_id
            )
            self.assertEqual(
                hashlib.sha256((job_root / "frozen-input-data.bin").read_bytes()).hexdigest(),
                run_spec.data_sha256,
            )
            self.assertEqual(
                collected.manifest_bytes,
                (job_root / "output-manifest.json").read_bytes(),
            )
            replaced_staged_code[0].write_bytes(worker)
            recovered_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/python3",),
            )
            recovered = recovered_backend.recover(
                run_spec,
                idempotency_key="bound-exact-inputs-recovery",
            )
            self.assertEqual(recovered.state, RunState.SUCCEEDED)
            self.assertEqual(
                recovered.execution_input_binding_sha256,
                receipt.execution_input_binding_sha256,
            )
            (job_root / "execution-input-binding.json").unlink()
            missing_binding_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/python3",),
            )
            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "complete execution input binding",
            ):
                missing_binding_backend.recover(
                    run_spec,
                    idempotency_key="bound-exact-inputs-missing-binding",
                )

    def test_local_execution_exports_plan_and_content_cache_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed: list[dict[str, str]] = []
            calls = 0

            def runner(run_spec, job_directory, environment):
                nonlocal calls
                calls += 1
                observed.append(dict(environment))
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                observed_available_memory_bytes=4 * 1024**3,
                maximum_concurrency_cap=2,
            )
            run_spec = spec("run-local-controls")
            first = backend.submit(run_spec, idempotency_key="local-controls-one")
            cached = backend.submit(run_spec, idempotency_key="local-controls-two")
            self.assertEqual(first.state, RunState.SUCCEEDED)
            self.assertFalse(first.cache_hit)
            self.assertTrue(cached.cache_hit)
            self.assertEqual(calls, 1)
            self.assertEqual(first.execution_plan_sha256, cached.execution_plan_sha256)
            environment = observed[0]
            self.assertEqual(environment["SCIENTIST_ONE_COMPUTE_MODE"], "LOCAL_MAC")
            self.assertEqual(environment["SCIENTIST_ONE_ACCELERATOR"], "CPU")
            self.assertEqual(environment["SCIENTIST_ONE_CACHE_POLICY"], "CONTENT_ADDRESSABLE")
            self.assertEqual(environment["SCIENTIST_ONE_CHECKPOINT_POLICY"], "PER_SEED")
            self.assertLessEqual(int(environment["SCIENTIST_ONE_CONCURRENCY"]), 2)
            collected = backend.collect(first.job_id)
            self.assertEqual(collected.execution_plan_sha256, first.execution_plan_sha256)
            self.assertEqual(
                set(collected.returned_artifact_sha256s),
                {item.sha256 for item in collected.manifest.artifacts},
            )
            recovered_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=lambda *_: (_ for _ in ()).throw(
                    AssertionError("verified cache recovery must not execute")
                ),
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                observed_available_memory_bytes=4 * 1024**3,
                maximum_concurrency_cap=2,
            )
            recovered = recovered_backend.recover(
                run_spec,
                idempotency_key="local-controls-recovered",
            )
            self.assertEqual(recovered.state, RunState.SUCCEEDED)
            self.assertTrue(recovered.cache_hit)
            self.assertEqual(recovered.execution_plan_sha256, first.execution_plan_sha256)
            self.assertEqual(recovered_backend.collect(recovered.job_id).manifest, collected.manifest)

    def test_explicit_resume_requires_unchanged_bound_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invocations = 0
            resume_markers: list[str] = []

            def runner(run_spec, job_directory, environment):
                nonlocal invocations
                invocations += 1
                resume_markers.append(environment["SCIENTIST_ONE_RESUME_FROM_CHECKPOINT_SHA256"])
                if invocations == 1:
                    (job_directory / "checkpoint.json").write_bytes(
                        canonical_json_bytes(
                            {
                                "run_id": run_spec.run_id,
                                "spec_sha256": run_spec.sha256,
                                "execution_plan_sha256": environment[
                                    "SCIENTIST_ONE_EXECUTION_PLAN_SHA256"
                                ],
                                "completed_seeds": [11],
                            }
                        )
                        + b"\n"
                    )
                    return ExecutionResult(75)
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            submitting_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            run_spec = spec("run-resumable")
            first = submitting_backend.submit(run_spec, idempotency_key="resumable")
            self.assertEqual(first.state, RunState.PREEMPTED)
            recovered_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            recovered = recovered_backend.recover(
                run_spec,
                idempotency_key="resumable-after-restart",
            )
            self.assertEqual(recovered.state, RunState.PREEMPTED)
            resumed = recovered_backend.resume(first.job_id)
            self.assertEqual(resumed.state, RunState.SUCCEEDED)
            self.assertIsNotNone(resumed.resumed_from_checkpoint_sha256)
            self.assertEqual(resume_markers[0], "NONE")
            self.assertEqual(resume_markers[1], resumed.resumed_from_checkpoint_sha256)
            self.assertEqual(
                recovered_backend.collect(first.job_id).manifest.run_id,
                "run-resumable",
            )
            with self.assertRaises(ExperimentError):
                recovered_backend.resume(first.job_id)

    def test_local_backend_rejects_cloud_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=lambda *_: ExecutionResult(1),
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            with self.assertRaises(ExperimentError):
                backend.submit(
                    spec("run-wrong-backend", profile=gpu_profile(), estimate=gpu_estimate()),
                    idempotency_key="wrong-backend",
                )

    def test_cache_disabled_preserves_idempotency_without_content_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            calls = 0

            def runner(run_spec, job_directory, _environment):
                nonlocal calls
                calls += 1
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            run_spec = replace(spec("run-cache-disabled"), cache_policy=CachePolicy.DISABLED)
            first = backend.submit(run_spec, idempotency_key="cache-disabled")
            duplicate = backend.submit(run_spec, idempotency_key="cache-disabled")
            self.assertEqual(first.job_id, duplicate.job_id)
            self.assertFalse(duplicate.cache_hit)
            with self.assertRaises(ExperimentError):
                backend.submit(run_spec, idempotency_key="cache-disabled-alternate")
            self.assertEqual(calls, 1)

    def test_failed_duplicate_is_idempotent_but_not_a_cache_hit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=lambda *_: ExecutionResult(1),
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            run_spec = spec("run-failed-not-cached")
            first = backend.submit(run_spec, idempotency_key="failed-not-cached-one")
            duplicate = backend.submit(
                run_spec,
                idempotency_key="failed-not-cached-two",
            )
            self.assertEqual(first.state, RunState.FAILED)
            self.assertEqual(first.job_id, duplicate.job_id)
            self.assertFalse(duplicate.cache_hit)

    def test_recovery_rejects_a_tampered_persisted_execution_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def runner(run_spec, job_directory, _environment):
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            run_spec = spec("run-tampered-plan")
            submitting_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            receipt = submitting_backend.submit(
                run_spec,
                idempotency_key="tampered-plan-submit",
            )
            plan_path = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
                / receipt.job_id
                / "execution-plan.json"
            )
            plan_path.write_bytes(b"{}\n")
            recovering_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            with self.assertRaises(ExperimentIntegrityError):
                recovering_backend.recover(
                    run_spec,
                    idempotency_key="tampered-plan-recover",
                )

    def test_malformed_manifest_and_checkpoint_become_invalid_output(self) -> None:
        for label, returncode, filename, payload in (
            ("manifest", 0, "output-manifest.json", b'{"unterminated":'),
            ("checkpoint", 75, "checkpoint.json", b'{"unterminated":'),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                def runner(_run_spec, job_directory, _environment):
                    (job_directory / filename).write_bytes(payload)
                    return ExecutionResult(returncode)

                backend = LocalMacBackend(
                    directory,
                    allowed_executables=("/usr/bin/true",),
                    execution_runner=runner,
                    execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                )
                receipt = backend.submit(
                    spec(f"run-malformed-{label}"),
                    idempotency_key=f"malformed-{label}",
                )
                self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)

    def test_checkpoint_recovery_rejects_a_smaller_current_host_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def preempting_runner(run_spec, job_directory, environment):
                (job_directory / "checkpoint.json").write_bytes(
                    canonical_json_bytes(
                        {
                            "run_id": run_spec.run_id,
                            "spec_sha256": run_spec.sha256,
                            "execution_plan_sha256": environment[
                                "SCIENTIST_ONE_EXECUTION_PLAN_SHA256"
                            ],
                        }
                    )
                    + b"\n"
                )
                return ExecutionResult(75)

            run_spec = spec("run-host-envelope-change")
            submitting_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=preempting_runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                observed_available_memory_bytes=4 * 1024**3,
                maximum_concurrency_cap=2,
            )
            receipt = submitting_backend.submit(
                run_spec,
                idempotency_key="host-envelope-submit",
            )
            self.assertEqual(receipt.state, RunState.PREEMPTED)
            smaller_backend = LocalMacBackend(
                root,
                allowed_executables=("/usr/bin/true",),
                execution_runner=preempting_runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                observed_available_memory_bytes=512 * 1024**2,
                maximum_concurrency_cap=1,
            )
            with self.assertRaises(ExperimentIntegrityError):
                smaller_backend.recover(
                    run_spec,
                    idempotency_key="host-envelope-recover",
                )

    def test_unbound_legacy_checkpoint_cannot_resume_or_report_cache_hit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def runner(run_spec, job_directory, _environment):
                (job_directory / "checkpoint.json").write_bytes(
                    canonical_json_bytes(
                        {
                            "run_id": run_spec.run_id,
                            "spec_sha256": run_spec.sha256,
                        }
                    )
                    + b"\n"
                )
                return ExecutionResult(75)

            backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            run_spec = spec("run-legacy-unbound-checkpoint")
            receipt = backend.submit(run_spec, idempotency_key="legacy-checkpoint")
            duplicate = backend.submit(
                run_spec,
                idempotency_key="legacy-checkpoint-duplicate",
            )
            self.assertEqual(receipt.state, RunState.PREEMPTED)
            self.assertFalse(duplicate.cache_hit)
            self.assertIn(
                "LEGACY_UNBOUND_CHECKPOINT",
                backend.reconcile(receipt.job_id).reason or "",
            )
            with self.assertRaises(ExperimentIntegrityError):
                backend.resume(receipt.job_id)

    def test_mps_submission_requires_a_backend_trusted_validation_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            validation_sha256 = digest("validated-mps-smoke")
            run_spec = spec(
                "run-mps-validation",
                profile=local_profile(
                    accelerator=AcceleratorKind.MPS,
                    validation_hash=validation_sha256,
                ),
            )

            def runner(submitted_spec, job_directory, _environment):
                write_manifest(submitted_spec, job_directory)
                return ExecutionResult(0)

            untrusted_backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            with self.assertRaises(ExperimentError):
                untrusted_backend.submit(run_spec, idempotency_key="mps-untrusted")
            trusted_backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                validated_mps_artifact_sha256s=(validation_sha256,),
            )
            receipt = trusted_backend.submit(run_spec, idempotency_key="mps-trusted")
            self.assertEqual(receipt.state, RunState.SUCCEEDED)
            self.assertEqual(receipt.validation_status, ValidationStatus.UNTESTED)
            self.assertFalse(receipt.scientific_evidence)

    def test_caller_evidence_flag_cannot_forge_os_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def runner(run_spec, job_directory, _environment):
                write_manifest(run_spec, job_directory)
                return ExecutionResult(0)

            backend = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=runner,
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            run_spec = replace(
                spec("run-caller-forged-eligibility"),
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            )
            receipt = backend.submit(run_spec, idempotency_key="caller-forged-eligibility")
            self.assertEqual(receipt.state, RunState.SUCCEEDED)
            self.assertFalse(receipt.scientific_evidence)
            self.assertFalse(receipt.network_isolation_attested)
            self.assertEqual(
                receipt.network_use_status,
                NetworkUseStatus.UNKNOWN_UNATTESTED,
            )
            # Even a white-box caller adding a field with the old attestation
            # name cannot cross the evidence boundary: there is no verifier or
            # trusted attestation path in this backend.
            setattr(
                backend._jobs[receipt.job_id],  # type: ignore[attr-defined]
                "os_isolation_attestation_sha256",
                digest("caller-forged-os-isolation-attestation"),
            )
            status = backend.reconcile(receipt.job_id)
            self.assertFalse(status.scientific_evidence)
            self.assertFalse(status.network_isolation_attested)
            self.assertEqual(
                status.network_use_status,
                NetworkUseStatus.UNKNOWN_UNATTESTED,
            )
            self.assertIn("OS_ISOLATION_UNATTESTED", status.reason or "")
            collected = backend.collect(receipt.job_id)
            self.assertFalse(collected.scientific_evidence)
            self.assertFalse(collected.network_isolation_attested)
            self.assertEqual(
                collected.network_use_status,
                NetworkUseStatus.UNKNOWN_UNATTESTED,
            )
            with self.assertRaises(ExperimentError):
                replace(collected, scientific_evidence=True)
            with self.assertRaises(ExperimentError):
                replace(collected, network_isolation_attested=True)
            object.__setattr__(collected, "scientific_evidence", True)
            forged_comparison = compare_clean_rerun(collected, collected)
            self.assertEqual(
                forged_comparison.status,
                ReproductionStatus.NON_EVIDENTIARY,
            )


class GPUCloudBoundaryTests(unittest.TestCase):
    def test_escalation_requires_equivalent_science_and_positive_rationale(self) -> None:
        local = spec("run-escalation-local")
        cloud = spec(
            "run-escalation-cloud",
            profile=gpu_profile(count=2),
            estimate=gpu_estimate(count=2),
            argv=("/opt/project/slurm-entrypoint",),
        )
        decision = escalation_decision(
            local,
            cloud,
            "escalate-after-local-pilot",
        )
        validate_compute_escalation(local, cloud, decision)
        plan = make_gpu_cloud_submission_plan(local, cloud, decision)
        self.assertEqual(plan.scheduler, SchedulerKind.SLURM)
        self.assertEqual(plan.queue_name, "research")
        self.assertEqual(plan.accelerator_count, 2)
        self.assertEqual(plan.external_validation, ValidationStatus.UNTESTED)
        backend = FakeGPUCloudBackend()
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="planned-gpu-escalation",
        )
        self.assertEqual(receipt.execution_plan_sha256, plan.sha256)
        self.assertEqual(receipt.validation_status, ValidationStatus.UNTESTED)
        self.assertFalse(receipt.scientific_evidence)
        changed = replace(cloud, evaluator_sha256=digest("changed-evaluator"))
        with self.assertRaises(ExperimentError):
            validate_compute_escalation(local, changed, decision)
        with self.assertRaises(ExperimentError):
            replace(decision, lower_cost_alternatives_exhausted=False)

    def test_fake_gpu_queue_preemption_requeue_and_artifact_return_are_untested(self) -> None:
        backend = FakeGPUCloudBackend()
        first_spec = spec(
            "run-gpu-one",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        second_spec = spec(
            "run-gpu-two",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        first = submit_planned_gpu(backend, first_spec, idempotency_key="gpu-one")
        second = submit_planned_gpu(backend, second_spec, idempotency_key="gpu-two")
        self.assertEqual(backend.queue_position(first.job_id), 0)
        self.assertEqual(backend.queue_position(second.job_id), 1)
        self.assertEqual(backend.validation_status, ValidationStatus.UNTESTED)
        self.assertFalse(backend.network_used)
        self.assertFalse(backend.scientific_evidence)
        self.assertTrue(backend.capabilities.slurm)
        self.assertTrue(backend.capabilities.artifact_return)

        backend.start(first.job_id)
        backend.preempt(first.job_id, checkpoint_token="opaque-checkpoint-reference")
        self.assertEqual(
            backend.requeue_from_checkpoint(
                first.job_id,
                checkpoint_token="opaque-checkpoint-reference",
            ).state,
            RunState.QUEUED,
        )
        self.assertEqual(backend.queue_position(second.job_id), 0)
        self.assertEqual(backend.queue_position(first.job_id), 1)
        backend.start(first.job_id)
        with tempfile.TemporaryDirectory() as artifact_directory:
            artifact_root = Path(artifact_directory)
            manifest = write_manifest(first_spec, artifact_root)
            returned_payloads = {
                item.sha256: (artifact_root / item.path).read_bytes()
                for item in manifest.artifacts
            }
            backend.complete(
                first.job_id,
                manifest,
                returned_payloads=returned_payloads,
            )
            collected = backend.collect(first.job_id)
            self.assertEqual(
                backend.returned_artifacts(first.job_id),
                tuple(item.sha256 for item in manifest.artifacts),
            )
            self.assertEqual(collected.validation_status, ValidationStatus.UNTESTED)
            self.assertFalse(collected.scientific_evidence)
            self.assertEqual(
                tuple(item.payload for item in backend.staged_artifacts(first.job_id)),
                tuple(returned_payloads[item.sha256] for item in manifest.artifacts),
            )

    def test_checkpoint_token_mismatch_fails_closed(self) -> None:
        backend = FakeGPUCloudBackend()
        run_spec = spec(
            "run-gpu-checkpoint",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        receipt = submit_planned_gpu(
            backend,
            run_spec,
            idempotency_key="gpu-checkpoint",
        )
        backend.start(receipt.job_id)
        backend.preempt(receipt.job_id, checkpoint_token="checkpoint-one")
        with self.assertRaises(ExperimentIntegrityError):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="checkpoint-two",
            )

    def test_gpu_specs_cannot_bypass_planned_escalation(self) -> None:
        backend = FakeGPUCloudBackend()
        cloud_spec = spec(
            "run-gpu-unplanned",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        with self.assertRaises(ExperimentError):
            backend.submit(cloud_spec, idempotency_key="unplanned-gpu")

    def test_planned_gpu_completion_rejects_tampered_returned_bytes(self) -> None:
        backend = FakeGPUCloudBackend()
        run_spec = spec(
            "run-gpu-tampered-return",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        receipt = submit_planned_gpu(
            backend,
            run_spec,
            idempotency_key="gpu-tampered-return",
        )
        backend.start(receipt.job_id)
        with tempfile.TemporaryDirectory() as artifact_directory:
            artifact_root = Path(artifact_directory)
            manifest = write_manifest(run_spec, artifact_root)
            returned_payloads = {
                item.sha256: (artifact_root / item.path).read_bytes()
                for item in manifest.artifacts
            }
            returned_payloads[manifest.artifacts[0].sha256] = b"tampered-return"
            with self.assertRaises(ExperimentIntegrityError):
                backend.complete(
                    receipt.job_id,
                    manifest,
                    returned_payloads=returned_payloads,
                )
        self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.RUNNING)


class ScheduledGPUBackendTests(unittest.TestCase):
    def _authorized_backend(
        self,
        transport: StructuredSchedulerFixture,
        local: FrozenRunSpec,
        cloud: FrozenRunSpec,
        decision: EscalationDecision,
        *,
        root: Path | None = None,
        human_gate_policy: HumanGatePolicy | None = None,
        maximum_total_attempts: int = 3,
    ) -> tuple[ScheduledGPUCloudBackend, ArtifactRegistry, dict[str, object]]:
        if root is None:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
        run_id = f"scheduled-authority-{digest(decision.decision_id)[:20]}"
        registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
        ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
        budget = ComputeEscalationBudget(
            budget_id=f"budget-{digest(decision.decision_id)[:20]}",
            target_profile_sha256=cloud.compute_profile.sha256,
            target_estimate_sha256=cloud.resource_estimate.sha256,
            maximum_monetary_cost=1_000.0,
            maximum_total_attempts=maximum_total_attempts,
            maximum_cumulative_monetary_cost=(
                1_000.0 * maximum_total_attempts
            ),
            maximum_cumulative_wall_clock_seconds=(
                cloud.resource_estimate.wall_clock_seconds
                * maximum_total_attempts
            ),
        )
        plan = make_gpu_cloud_submission_plan(local, cloud, decision, budget)
        gate_policy = human_gate_policy or HumanGatePolicy(
            HumanGateProfile.FULL_AUTONOMOUS
        )
        authority = register_compute_escalation_plan_authority(
            registry,
            ledger,
            authority_id=f"authority-{digest(decision.decision_id)[:20]}",
            run_id=run_id,
            local_spec=local,
            cloud_spec=cloud,
            decision=decision,
            submission_plan=plan,
            budget=budget,
            human_gate_policy=gate_policy,
        )
        gate_decision = AutonomousDecisionRecord(
            decision_id=f"gate-{digest(decision.decision_id)[:20]}",
            gate=HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=authority.sha256,
            alternatives=("SUBMIT", "STOP"),
            evidence_hashes=(authority.sha256,),
            governing_rule="submit only the exact freshly authorized plan",
            uncertainty="external GPU execution remains untested",
            reason="exercise the scheduled transport boundary",
            downstream_consequences=("one scheduled submission may occur",),
        )
        backend = ScheduledGPUCloudBackend(
            transport,
            artifact_registry=registry,
            event_ledger=ledger,
        )
        return backend, registry, {
            "authority_artifact_sha256": authority.sha256,
            "authority_run_id": run_id,
            "autonomous_decision": gate_decision,
        }

    def test_required_and_selective_compute_policy_stop_before_authorization(self) -> None:
        policies = (
            None,
            HumanGatePolicy(
                HumanGateProfile.HUMAN_GATES_SELECTIVE,
                (HumanGate.COMPUTE_ESCALATION,),
            ),
        )
        for index, policy in enumerate(policies):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                transport = StructuredSchedulerFixture()
                local = spec(f"gate-stop-{index}-local")
                cloud = spec(
                    f"gate-stop-{index}-cloud",
                    profile=gpu_profile(),
                    estimate=gpu_estimate(),
                )
                decision = escalation_decision(
                    local,
                    cloud,
                    f"gate-stop-{index}-decision",
                )
                run_id = f"gate-stop-{index}-authority"
                registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
                ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
                budget = ComputeEscalationBudget(
                    budget_id=f"gate-stop-{index}-budget",
                    target_profile_sha256=cloud.compute_profile.sha256,
                    target_estimate_sha256=cloud.resource_estimate.sha256,
                    maximum_monetary_cost=cloud.resource_estimate.monetary_cost or 0.0,
                    maximum_cumulative_wall_clock_seconds=(
                        cloud.resource_estimate.wall_clock_seconds
                    ),
                )
                plan = make_gpu_cloud_submission_plan(
                    local,
                    cloud,
                    decision,
                    budget,
                )
                policy_arguments = (
                    {} if policy is None else {"human_gate_policy": policy}
                )
                authority_record = register_compute_escalation_plan_authority(
                    registry,
                    ledger,
                    authority_id=f"gate-stop-{index}-caller-label",
                    run_id=run_id,
                    local_spec=local,
                    cloud_spec=cloud,
                    decision=decision,
                    submission_plan=plan,
                    budget=budget,
                    **policy_arguments,
                )
                autonomous_decision = AutonomousDecisionRecord(
                    decision_id=f"gate-stop-{index}-autonomous",
                    gate=HumanGate.COMPUTE_ESCALATION,
                    scientific_authority_hash=authority_record.sha256,
                    alternatives=("SUBMIT", "STOP"),
                    evidence_hashes=(authority_record.sha256,),
                    governing_rule="submit only when the frozen policy permits it",
                    uncertainty="remote execution remains untested",
                    reason="exercise the policy stop boundary",
                    downstream_consequences=("no transport before authorization",),
                )
                backend = ScheduledGPUCloudBackend(
                    transport,
                    artifact_registry=registry,
                    event_ledger=ledger,
                )
                records_before = registry.list_records()
                events_before = ledger.events()
                with self.assertRaisesRegex(
                    ExperimentError,
                    "does not authorize",
                ):
                    backend.submit_planned(
                        local,
                        cloud,
                        decision,
                        idempotency_key=f"gate-stop-{index}-submit",
                        authority_artifact_sha256=authority_record.sha256,
                        authority_run_id=run_id,
                        autonomous_decision=autonomous_decision,
                    )
                self.assertEqual(registry.list_records(), records_before)
                self.assertEqual(ledger.events(), events_before)
                self.assertEqual(transport.submit_calls, 0)

    def test_stable_plan_authority_is_unique_and_policy_collision_is_write_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = spec("stable-authority-local")
            cloud = spec(
                "stable-authority-cloud",
                profile=gpu_profile(),
                estimate=gpu_estimate(),
            )
            decision = escalation_decision(
                local,
                cloud,
                "stable-authority-decision",
            )
            run_id = "stable-authority-run"
            registry = ArtifactRegistry(root, f"runs/{run_id}/registry")
            ledger = EventLedger(root, f"runs/{run_id}/events.jsonl")
            budget = ComputeEscalationBudget(
                budget_id="stable-authority-budget",
                target_profile_sha256=cloud.compute_profile.sha256,
                target_estimate_sha256=cloud.resource_estimate.sha256,
                maximum_monetary_cost=2.5,
                maximum_cumulative_wall_clock_seconds=600.0,
            )
            plan = make_gpu_cloud_submission_plan(local, cloud, decision, budget)
            autonomous_policy = HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS)
            first = register_compute_escalation_plan_authority(
                registry,
                ledger,
                authority_id="caller-selected-authority-one",
                run_id=run_id,
                local_spec=local,
                cloud_spec=cloud,
                decision=decision,
                submission_plan=plan,
                budget=budget,
                human_gate_policy=autonomous_policy,
            )
            events_after_first = ledger.events()
            second = register_compute_escalation_plan_authority(
                registry,
                ledger,
                authority_id="caller-selected-authority-two",
                run_id=run_id,
                local_spec=local,
                cloud_spec=cloud,
                decision=decision,
                submission_plan=plan,
                budget=budget,
                human_gate_policy=autonomous_policy,
            )
            self.assertEqual(second, first)
            self.assertEqual(ledger.events(), events_after_first)
            records_before_collision = registry.list_records()
            with self.assertRaisesRegex(ExperimentError, "competing"):
                register_compute_escalation_plan_authority(
                    registry,
                    ledger,
                    authority_id="caller-selected-authority-three",
                    run_id=run_id,
                    local_spec=local,
                    cloud_spec=cloud,
                    decision=decision,
                    submission_plan=plan,
                    budget=budget,
                    human_gate_policy=HumanGatePolicy(
                        HumanGateProfile.HUMAN_GATES_REQUIRED
                    ),
                )
            self.assertEqual(registry.list_records(), records_before_collision)
            self.assertEqual(ledger.events(), events_after_first)

    def test_concurrent_submission_consumes_one_exact_authority_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = spec("concurrent-authority-local")
            cloud = spec(
                "concurrent-authority-cloud",
                profile=gpu_profile(),
                estimate=gpu_estimate(),
            )
            decision = escalation_decision(
                local,
                cloud,
                "concurrent-authority-decision",
            )
            first_transport = StructuredSchedulerFixture()
            first_backend, registry, authority = self._authorized_backend(
                first_transport,
                local,
                cloud,
                decision,
                root=root,
            )
            ledger = first_backend._ledger  # type: ignore[attr-defined]
            assert ledger is not None
            authorization = register_compute_escalation_submission_authorization(
                registry,
                ledger,
                authority_artifact_sha256=authority[
                    "authority_artifact_sha256"
                ],
                authority_run_id=authority["authority_run_id"],
                local_spec=local,
                cloud_spec=cloud,
                decision=decision,
                idempotency_key="concurrent-authority-submit",
                autonomous_decision=authority["autonomous_decision"],
            )
            second_transport = StructuredSchedulerFixture()
            second_backend = ScheduledGPUCloudBackend(
                second_transport,
                artifact_registry=registry,
                event_ledger=ledger,
            )
            submit_arguments = {
                "idempotency_key": "concurrent-authority-submit",
                "authority_artifact_sha256": authority[
                    "authority_artifact_sha256"
                ],
                "authority_run_id": authority["authority_run_id"],
                "submission_authorization_artifact_sha256": authorization.sha256,
            }
            barrier = threading.Barrier(2)
            receipts: list[object] = []
            failures: list[BaseException] = []

            def submit(candidate: ScheduledGPUCloudBackend) -> None:
                try:
                    barrier.wait(timeout=5)
                    receipts.append(
                        candidate.submit_planned(
                            local,
                            cloud,
                            decision,
                            **submit_arguments,
                        )
                    )
                except BaseException as exc:  # assertion inspects exact count
                    failures.append(exc)

            threads = (
                threading.Thread(target=submit, args=(first_backend,)),
                threading.Thread(target=submit, args=(second_backend,)),
            )
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            self.assertEqual(len(receipts), 1)
            self.assertEqual(len(failures), 1)
            self.assertEqual(
                first_transport.submit_calls + second_transport.submit_calls,
                1,
            )
            consumptions = [
                thaw_json(event.metadata)[
                    "compute_escalation_submission_consumption"
                ]
                for event in ledger.events()
                if "compute_escalation_submission_consumption"
                in thaw_json(event.metadata)
            ]
            self.assertEqual(len(consumptions), 1)

    def test_legacy_v1_plan_authority_is_non_executable(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("legacy-v1-authority-local")
        cloud = spec(
            "legacy-v1-authority-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local,
            cloud,
            "legacy-v1-authority-decision",
        )
        backend, registry, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
        )
        current_sha256 = authority["authority_artifact_sha256"]
        current_record = registry.get_metadata(current_sha256)
        legacy_value = dict(safe_json_loads(registry.get_bytes(current_sha256)))
        legacy_value["schema_version"] = (
            "SCIENTIST_ONE_COMPUTE_ESCALATION_PLAN_AUTHORITY_V1"
        )
        legacy_record = registry.put_json(
            legacy_value,
            logical_type=current_record.logical_type,
            origin=current_record.origin,
            creator_role=current_record.creator_role,
            creation_command=current_record.creation_command,
            parent_artifacts=current_record.parent_artifacts,
            schema_version=current_record.schema_version,
            mime_type=current_record.mime_type,
            validation_result=current_record.validation_result,
            frozen=True,
        )
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        events_before = ledger.events()
        with self.assertRaisesRegex(ExperimentError, "audit-only"):
            backend.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="legacy-v1-authority-submit",
                authority_artifact_sha256=legacy_record.sha256,
                authority_run_id=authority["authority_run_id"],
                autonomous_decision=authority["autonomous_decision"],
            )
        self.assertEqual(ledger.events(), events_before)
        self.assertEqual(transport.submit_calls, 0)

    def _requeued_success_case(
        self,
        root: Path,
        label: str,
    ) -> tuple[
        StructuredSchedulerFixture,
        ScheduledGPUCloudBackend,
        FrozenRunSpec,
        object,
        str,
        ScheduledGPUArtifactBundle,
    ]:
        transport = StructuredSchedulerFixture()
        local = spec(f"{label}-local")
        cloud = spec(
            f"{label}-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, f"{label}-decision")
        backend, registry, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
            root=root,
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key=f"{label}-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        checkpoint_token = f"{label}-checkpoint"
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token=checkpoint_token,
        )
        backend.reconcile(receipt.job_id)
        backend.requeue_from_checkpoint(
            receipt.job_id,
            checkpoint_token=checkpoint_token,
        )
        artifact_root = root / f"{label}-return"
        artifact_root.mkdir()
        manifest = write_manifest(cloud, artifact_root)
        staged = tuple(
            StagedArtifact(item, (artifact_root / item.path).read_bytes())
            for item in manifest.artifacts
        )
        bundle = ScheduledGPUArtifactBundle(
            manifest,
            staged,
            manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
            provider_job_id=provider_job_id,
            spec_sha256=cloud.sha256,
            submission_plan_sha256=receipt.execution_plan_sha256,
            attempt=2,
            resumed_checkpoint_sha256=digest(checkpoint_token),
            requeue_history=backend.requeue_lineage(receipt.job_id),
        )
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.SUCCEEDED,
            attempt=2,
        )
        return transport, backend, cloud, receipt, provider_job_id, bundle

    def test_structured_scheduler_lifecycle_and_registry_return_are_untested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = StructuredSchedulerFixture()
            local = spec("scheduled-gpu-local-source")
            cloud = spec(
                "scheduled-gpu-cloud-target",
                profile=gpu_profile(),
                estimate=gpu_estimate(),
            )
            decision = escalation_decision(local, cloud, "scheduled-gpu-decision")
            backend, registry, authority = self._authorized_backend(
                transport,
                local,
                cloud,
                decision,
                root=Path(directory),
            )
            receipt = backend.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="scheduled-gpu-submit",
                **authority,
            )
            duplicate = backend.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="scheduled-gpu-submit",
                **authority,
            )
            self.assertEqual(receipt.job_id, duplicate.job_id)
            self.assertEqual(transport.submit_calls, 1)
            ledger = backend._ledger  # type: ignore[attr-defined]
            assert ledger is not None
            events_before_rejected_replay = ledger.events()
            substituted_authority = dict(authority)
            substituted_authority["autonomous_decision"] = replace(
                authority["autonomous_decision"],
                reason="substituted idempotent replay decision",
            )
            with self.assertRaisesRegex(ExperimentError, "frozen replay"):
                backend.submit_planned(
                    local,
                    cloud,
                    decision,
                    idempotency_key="scheduled-gpu-submit",
                    **substituted_authority,
                )
            with self.assertRaisesRegex(SubmissionConflictError, "another request"):
                backend.submit_planned(
                    local,
                    cloud,
                    decision,
                    idempotency_key="scheduled-gpu-other-request",
                    **authority,
                )
            self.assertEqual(ledger.events(), events_before_rejected_replay)
            self.assertEqual(transport.submit_calls, 1)
            self.assertEqual(receipt.state, RunState.QUEUED)
            self.assertEqual(receipt.validation_status, ValidationStatus.UNTESTED)
            self.assertFalse(receipt.scientific_evidence)
            provider_job_id = next(iter(transport.requests))

            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id,
                RunState.RUNNING,
                reason="FIXTURE_RUNNING_UNTESTED",
            )
            self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.RUNNING)
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id,
                RunState.PREEMPTED,
                reason="FIXTURE_PREEMPTED_UNTESTED",
                checkpoint_token="checkpoint-object-v1",
            )
            self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.PREEMPTED)
            requeued = backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="checkpoint-object-v1",
            )
            self.assertEqual(requeued.state, RunState.QUEUED)
            self.assertEqual(
                backend.requeue_from_checkpoint(
                    receipt.job_id,
                    checkpoint_token="checkpoint-object-v1",
                ).state,
                RunState.QUEUED,
            )

            artifact_root = Path(directory) / "transport-return"
            artifact_root.mkdir()
            manifest = write_manifest(cloud, artifact_root)
            staged = tuple(
                StagedArtifact(item, (artifact_root / item.path).read_bytes())
                for item in manifest.artifacts
            )
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest,
                staged,
                manifest_bytes=(
                    artifact_root / "output-manifest.json"
                ).read_bytes(),
                provider_job_id=provider_job_id,
                spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256,
                attempt=2,
                resumed_checkpoint_sha256=digest("checkpoint-object-v1"),
                requeue_history=backend.requeue_lineage(receipt.job_id),
            )
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id,
                RunState.SUCCEEDED,
                reason="FIXTURE_SUCCEEDED_UNTESTED",
                attempt=2,
            )
            registered = backend.collect_into_registry(
                receipt.job_id,
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            self.assertEqual(
                tuple(item.sha256 for item in registered.artifact_records),
                tuple(item.descriptor.sha256 for item in staged),
            )
            self.assertTrue(registry.verify(registered.manifest_record.sha256))
            self.assertEqual(
                registry.get_bytes(registered.manifest_record.sha256),
                (artifact_root / "output-manifest.json").read_bytes(),
            )
            for record in (
                registered.source_spec_record,
                registered.target_spec_record,
                registered.submission_plan_record,
                registered.escalation_decision_record,
                registered.manifest_record,
                registered.return_receipt_record,
            ):
                self.assertTrue(registry.verify(record.sha256))
            return_receipt = safe_json_loads(
                registry.get_bytes(registered.return_receipt_record.sha256)
            )
            self.assertEqual(return_receipt["external_validation"], "UNTESTED")
            self.assertFalse(return_receipt["scientific_evidence"])
            self.assertFalse(return_receipt["network_isolation_attested"])
            self.assertEqual(
                return_receipt["network_use_status"],
                "UNKNOWN_UNATTESTED",
            )
            self.assertEqual(
                return_receipt["submission_plan_sha256"],
                receipt.execution_plan_sha256,
            )
            self.assertEqual(return_receipt["attempt"], 2)
            self.assertEqual(return_receipt["requeued_from_attempt"], 1)
            self.assertEqual(
                return_receipt["resumed_from_checkpoint_sha256"],
                digest("checkpoint-object-v1"),
            )
            self.assertIsNone(return_receipt["pending_checkpoint_sha256"])
            self.assertEqual(
                return_receipt["requeue_history"],
                [
                    {
                        "source_attempt": 1,
                        "target_attempt": 2,
                        "checkpoint_sha256": digest("checkpoint-object-v1"),
                        "action_idempotency_key": (
                            f"requeue-{digest('checkpoint-object-v1')[:16]}-attempt-2-"
                            f"{digest(provider_job_id)[:8]}"
                        ),
                    }
                ],
            )
            for staged_item, record in zip(staged, registered.artifact_records, strict=True):
                self.assertEqual(registry.get_bytes(record.sha256), staged_item.payload)
                self.assertIn(
                    registered.return_receipt_record.sha256,
                    record.parent_artifacts,
                )
            self.assertEqual(
                registered.external_validation,
                ValidationStatus.UNTESTED,
            )
            self.assertFalse(registered.collected_run.scientific_evidence)

    def test_scheduled_submission_consumes_fresh_authority_once(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-one-shot-local")
        cloud = spec(
            "scheduled-one-shot-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "scheduled-one-shot-decision")
        backend, registry, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-one-shot-submit",
            **authority,
        )
        self.assertEqual(receipt.state, RunState.QUEUED)
        self.assertEqual(transport.submit_calls, 1)
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        events = ledger.events()
        consumption = next(
            thaw_json(event.metadata)["compute_escalation_submission_consumption"]
            for event in reversed(events)
            if "compute_escalation_submission_consumption" in thaw_json(event.metadata)
        )
        self.assertEqual(
            consumption["idempotency_key"],
            "scheduled-one-shot-submit",
        )
        self.assertEqual(consumption["cloud_spec_sha256"], cloud.sha256)
        self.assertEqual(consumption["action_type"], "SUBMIT")
        self.assertEqual(consumption["source_attempt"], 0)
        self.assertEqual(consumption["target_attempt"], 1)
        self.assertIsNone(consumption["provider_job_id"])
        self.assertIsNone(consumption["checkpoint_sha256"])
        self.assertEqual(consumption["cumulative_monetary_cost"], 2.5)
        self.assertEqual(consumption["cumulative_wall_clock_seconds"], 600.0)
        authority_value = safe_json_loads(
            registry.get_bytes(authority["authority_artifact_sha256"])
        )
        self.assertEqual(
            consumption["human_gate_policy_artifact_sha256"],
            authority_value["human_gate_policy_artifact_sha256"],
        )
        self.assertEqual(
            consumption["human_gate_policy_sha256"],
            authority_value["human_gate_policy_sha256"],
        )
        self.assertEqual(
            consumption["authority_key_sha256"],
            authority_value["authority_key_sha256"],
        )
        self.assertEqual(
            consumption["submission_plan_sha256"],
            receipt.execution_plan_sha256,
        )
        consumption_event = next(
            event
            for event in reversed(events)
            if "compute_escalation_submission_consumption" in thaw_json(event.metadata)
        )
        self.assertEqual(
            consumption_event.prior_event_hash,
            consumption["authority_ledger_event_hash"],
        )

        second_transport = StructuredSchedulerFixture()
        second = ScheduledGPUCloudBackend(
            second_transport,
            artifact_registry=backend._registry,  # type: ignore[attr-defined]
            event_ledger=ledger,
        )
        with self.assertRaisesRegex(
            ExperimentError,
            "fresh ledger head|already consumed|another request",
        ):
            second.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="scheduled-one-shot-reuse",
                **authority,
            )
        self.assertEqual(second_transport.submit_calls, 0)

    def test_scheduled_submission_without_authority_never_reaches_transport(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-missing-authority-local")
        cloud = spec(
            "scheduled-missing-authority-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        with self.assertRaisesRegex(ExperimentError, "v2 compute authority"):
            ScheduledGPUCloudBackend(transport).submit_planned(
                local,
                cloud,
                escalation_decision(
                    local,
                    cloud,
                    "scheduled-missing-authority-decision",
                ),
                idempotency_key="scheduled-missing-authority-submit",
            )
        self.assertEqual(transport.submit_calls, 0)

    def test_scheduled_submission_blocks_ambiguous_consumed_transport_window(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("submit-crash-window-local")
        cloud = spec(
            "submit-crash-window-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "submit-crash-window-decision")
        backend, _, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
        )
        original_submit = transport.submit
        fail_once = True

        def interrupted_submit(request: ScheduledGPURequest) -> ScheduledGPUStatus:
            nonlocal fail_once
            if fail_once:
                fail_once = False
                raise RuntimeError("fixture interruption before provider submit")
            return original_submit(request)

        transport.submit = interrupted_submit  # type: ignore[method-assign]
        arguments = {
            "idempotency_key": "submit-crash-window-request",
            **authority,
        }
        with self.assertRaisesRegex(RuntimeError, "interruption"):
            backend.submit_planned(local, cloud, decision, **arguments)
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        events_after_interruption = ledger.events()
        consumptions = [
            thaw_json(event.metadata)["compute_escalation_submission_consumption"]
            for event in events_after_interruption
            if "compute_escalation_submission_consumption"
            in thaw_json(event.metadata)
        ]
        self.assertEqual(len(consumptions), 1)
        self.assertEqual(transport.submit_calls, 0)

        with self.assertRaises(ScheduledGPURecoveryBlocked):
            backend.submit_planned(local, cloud, decision, **arguments)
        self.assertEqual(transport.submit_calls, 0)
        self.assertGreaterEqual(len(ledger.events()), len(events_after_interruption))

    def test_scheduled_submission_rejects_caller_forged_gate_authorization(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-forged-gate-local")
        cloud = spec(
            "scheduled-forged-gate-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local,
            cloud,
            "scheduled-forged-gate-decision",
        )
        backend, _, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
        )
        with self.assertRaises(TypeError):
            backend.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="scheduled-forged-gate-submit",
                authority_artifact_sha256=authority[
                    "authority_artifact_sha256"
                ],
                authority_run_id=authority["authority_run_id"],
                gate_authorization=object(),
            )
        self.assertEqual(transport.submit_calls, 0)

    def test_structured_scheduler_requeue_binds_checkpoint_and_attempt(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-repeat-preemption-local")
        cloud = spec(
            "scheduled-repeat-preemption-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local,
            cloud,
            "scheduled-repeat-preemption-decision",
        )
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-repeat-preemption-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.RUNNING,
            attempt=1,
        )
        backend.reconcile(receipt.job_id)
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="reused-provider-checkpoint-token",
            attempt=1,
        )
        backend.reconcile(receipt.job_id)
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="substituted-checkpoint-token",
            attempt=1,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.reconcile(receipt.job_id)
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.QUEUED,
            checkpoint_token="reused-provider-checkpoint-token",
            attempt=1,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.reconcile(receipt.job_id)
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="reused-provider-checkpoint-token",
            attempt=1,
        )
        job = backend._jobs[receipt.job_id]  # type: ignore[attr-defined]
        job.provider_job_id = "substituted-provider-job"
        with self.assertRaisesRegex(
            ExperimentIntegrityError,
            "provider job identity was substituted",
        ):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="reused-provider-checkpoint-token",
            )
        self.assertEqual(transport.requeue_calls, [])
        job.provider_job_id = provider_job_id
        first = backend.requeue_from_checkpoint(
            receipt.job_id,
            checkpoint_token="reused-provider-checkpoint-token",
        )
        self.assertEqual(first.state, RunState.QUEUED)
        self.assertIsNone(backend.preemption_checkpoint(receipt.job_id))
        self.assertIn("attempt-2", transport.requeue_calls[-1][2])
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        first_consumption = next(
            thaw_json(event.metadata)["compute_escalation_submission_consumption"]
            for event in reversed(ledger.events())
            if "compute_escalation_submission_consumption" in thaw_json(event.metadata)
        )
        self.assertEqual(first_consumption["action_type"], "REQUEUE")
        self.assertEqual(first_consumption["provider_job_id"], provider_job_id)
        self.assertEqual(
            first_consumption["checkpoint_sha256"],
            digest("reused-provider-checkpoint-token"),
        )
        self.assertEqual(first_consumption["source_attempt"], 1)
        self.assertEqual(first_consumption["target_attempt"], 2)
        self.assertEqual(first_consumption["cumulative_monetary_cost"], 5.0)
        self.assertEqual(
            first_consumption["cumulative_wall_clock_seconds"],
            1_200.0,
        )
        self.assertEqual(
            first_consumption["action_idempotency_key"],
            transport.requeue_calls[-1][2],
        )
        events_after_first_requeue = ledger.events()
        self.assertEqual(
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="reused-provider-checkpoint-token",
            ),
            first,
        )
        self.assertEqual(len(transport.requeue_calls), 1)
        self.assertEqual(ledger.events(), events_after_first_requeue)

        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.RUNNING,
            attempt=2,
        )
        backend.reconcile(receipt.job_id)
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="reused-provider-checkpoint-token",
            attempt=2,
        )
        backend.reconcile(receipt.job_id)
        second = backend.requeue_from_checkpoint(
            receipt.job_id,
            checkpoint_token="reused-provider-checkpoint-token",
        )
        self.assertEqual(second.state, RunState.QUEUED)
        self.assertIn("attempt-3", transport.requeue_calls[-1][2])
        self.assertEqual(len(transport.requeue_calls), 2)
        lineage = backend.requeue_lineage(receipt.job_id)
        self.assertEqual(
            tuple((item.source_attempt, item.target_attempt) for item in lineage),
            ((1, 2), (2, 3)),
        )
        self.assertEqual(
            tuple(item.checkpoint_sha256 for item in lineage),
            (digest("reused-provider-checkpoint-token"),) * 2,
        )

        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.RUNNING,
            attempt=2,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.reconcile(receipt.job_id)

    def test_structured_scheduler_requeue_requires_next_attempt(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-static-attempt-local")
        cloud = spec(
            "scheduled-static-attempt-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local, cloud, "scheduled-static-attempt-decision"
        )
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-static-attempt-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="static-attempt-checkpoint",
        )
        backend.reconcile(receipt.job_id)
        transport.requeue_attempt_delta = 0
        with self.assertRaises(ExperimentIntegrityError):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="static-attempt-checkpoint",
            )

    def test_requeue_blocks_ambiguous_consumed_transport_window(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("requeue-crash-window-local")
        cloud = spec(
            "requeue-crash-window-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "requeue-crash-window-decision")
        backend, _, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="requeue-crash-window-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        checkpoint_token = "requeue-crash-window-checkpoint"
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token=checkpoint_token,
        )
        backend.reconcile(receipt.job_id)
        original_requeue = transport.requeue
        fail_once = True

        def interrupted_requeue(
            remote_job_id: str,
            *,
            checkpoint_token: str,
            idempotency_key: str,
        ) -> ScheduledGPUStatus:
            nonlocal fail_once
            if fail_once:
                fail_once = False
                raise RuntimeError("fixture interruption before provider requeue")
            return original_requeue(
                remote_job_id,
                checkpoint_token=checkpoint_token,
                idempotency_key=idempotency_key,
            )

        transport.requeue = interrupted_requeue  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "interruption"):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token=checkpoint_token,
            )
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        events_after_interruption = ledger.events()
        self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.PREEMPTED)
        self.assertEqual(transport.requeue_calls, [])

        with self.assertRaises(ScheduledGPURecoveryBlocked):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token=checkpoint_token,
            )
        self.assertEqual(len(transport.requeue_calls), 0)
        self.assertGreaterEqual(len(ledger.events()), len(events_after_interruption))

    def test_requeue_stops_before_transport_when_attempt_budget_is_exhausted(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("attempt-budget-local")
        cloud = spec(
            "attempt-budget-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "attempt-budget-decision")
        backend, _, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
            maximum_total_attempts=1,
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="attempt-budget-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="attempt-budget-checkpoint",
        )
        backend.reconcile(receipt.job_id)
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        events_before = ledger.events()
        with self.assertRaisesRegex(ExperimentError, "attempt.*ceiling"):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="attempt-budget-checkpoint",
            )
        self.assertEqual(transport.requeue_calls, [])
        self.assertEqual(ledger.events(), events_before)

    def test_corrected_attempt_consumption_revokes_requeue_before_transport(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("corrected-consumption-local")
        cloud = spec(
            "corrected-consumption-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local,
            cloud,
            "corrected-consumption-decision",
        )
        backend, _, authority = self._authorized_backend(
            transport,
            local,
            cloud,
            decision,
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="corrected-consumption-submit",
            **authority,
        )
        ledger = backend._ledger  # type: ignore[attr-defined]
        assert ledger is not None
        consumption_event = next(
            event
            for event in reversed(ledger.events())
            if "compute_escalation_submission_consumption" in thaw_json(event.metadata)
        )
        ledger.append_correction(
            consumption_event.event_id,
            actor_role=Role.CLAIM_VERIFIER,
            reason="revoke the attempt-specific consumption fixture",
            corrected_fields={"status": "REVOKED"},
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.PREEMPTED,
            checkpoint_token="corrected-consumption-checkpoint",
        )
        with self.assertRaises(ScheduledGPURecoveryBlocked):
            backend.reconcile(receipt.job_id)
        events_before = ledger.events()
        with self.assertRaises(ScheduledGPURecoveryBlocked):
            backend.requeue_from_checkpoint(
                receipt.job_id,
                checkpoint_token="corrected-consumption-checkpoint",
            )
        self.assertEqual(transport.requeue_calls, [])
        self.assertEqual(ledger.events(), events_before)

    def test_structured_scheduler_snapshots_network_use_per_job(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-network-snapshot-local")
        cloud = spec(
            "scheduled-network-snapshot-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "scheduled-network-snapshot-decision")
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-network-snapshot-submit",
            **authority,
        )
        self.assertFalse(receipt.network_used)
        transport.network_used = True
        duplicate = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-network-snapshot-submit",
            **authority,
        )
        self.assertFalse(duplicate.network_used)

        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.RUNNING,
        )
        self.assertTrue(backend.reconcile(receipt.job_id).network_used)
        self.assertEqual(
            backend.reconcile(receipt.job_id).network_use_status,
            NetworkUseStatus.USED,
        )
        transport.network_used = False
        self.assertTrue(backend.reconcile(receipt.job_id).network_used)

    def test_structured_scheduler_rejects_unplanned_and_invalid_identity(self) -> None:
        transport = StructuredSchedulerFixture()
        cloud = spec(
            "scheduled-gpu-hostile",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        local = spec("scheduled-gpu-hostile-local")
        decision = escalation_decision(local, cloud, "scheduled-hostile-decision")
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        with self.assertRaises(ExperimentError):
            backend.submit(cloud, idempotency_key="scheduled-unplanned")
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-hostile-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            "different-provider-job",
            RunState.RUNNING,
        )
        with self.assertRaises(ExperimentIntegrityError):
            backend.reconcile(receipt.job_id)

    def test_structured_scheduler_cancel_is_idempotent(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-cancel-local")
        cloud = spec(
            "scheduled-cancel-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(local, cloud, "scheduled-cancel-decision")
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-cancel-submit",
            **authority,
        )
        first = backend.cancel(receipt.job_id)
        second = backend.cancel(receipt.job_id)
        self.assertEqual(first.state, RunState.CANCELLED)
        self.assertEqual(second, first)

    def test_structured_scheduler_invalid_bundle_fails_closed(self) -> None:
        transport = StructuredSchedulerFixture()
        local = spec("scheduled-invalid-bundle-local")
        cloud = spec(
            "scheduled-invalid-bundle-cloud",
            profile=gpu_profile(),
            estimate=gpu_estimate(),
        )
        decision = escalation_decision(
            local, cloud, "scheduled-invalid-bundle-decision"
        )
        backend, _, authority = self._authorized_backend(
            transport, local, cloud, decision
        )
        receipt = backend.submit_planned(
            local,
            cloud,
            decision,
            idempotency_key="scheduled-invalid-bundle-submit",
            **authority,
        )
        provider_job_id = next(iter(transport.requests))
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.SUCCEEDED,
        )
        transport.bundles[provider_job_id] = {}  # type: ignore[assignment]
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)
        self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.INVALID_OUTPUT)

    def test_structured_scheduler_bundle_binds_exact_job_plan_attempt_and_lineage(self) -> None:
        cases = (
            "cross-job",
            "wrong-spec",
            "wrong-plan",
            "stale-attempt",
            "missing-checkpoint",
            "wrong-checkpoint",
            "missing-lineage",
            "wrong-lineage",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (
                    transport,
                    backend,
                    cloud,
                    receipt,
                    provider_job_id,
                    bundle,
                ) = self._requeued_success_case(root, f"bundle-{case}")
                if case == "cross-job":
                    hostile = replace(bundle, provider_job_id="different-provider-job")
                elif case == "wrong-spec":
                    other_cloud = spec(
                        f"bundle-{case}-substituted-cloud",
                        profile=gpu_profile(),
                        estimate=gpu_estimate(),
                    )
                    other_root = root / "substituted-return"
                    other_root.mkdir()
                    other_manifest = write_manifest(other_cloud, other_root)
                    other_staged = tuple(
                        StagedArtifact(item, (other_root / item.path).read_bytes())
                        for item in other_manifest.artifacts
                    )
                    hostile = replace(
                        bundle,
                        manifest=other_manifest,
                        artifacts=other_staged,
                        manifest_bytes=(
                            other_root / "output-manifest.json"
                        ).read_bytes(),
                        spec_sha256=other_cloud.sha256,
                    )
                elif case == "wrong-plan":
                    hostile = replace(
                        bundle,
                        submission_plan_sha256=digest("substituted-submission-plan"),
                    )
                elif case == "stale-attempt":
                    hostile = replace(
                        bundle,
                        attempt=1,
                        resumed_checkpoint_sha256=None,
                        requeue_history=(),
                    )
                elif case == "missing-checkpoint":
                    hostile = replace(bundle, resumed_checkpoint_sha256=None)
                elif case == "wrong-checkpoint":
                    hostile = replace(
                        bundle,
                        resumed_checkpoint_sha256=digest("substituted-checkpoint"),
                    )
                elif case == "missing-lineage":
                    hostile = replace(bundle, requeue_history=())
                else:
                    hostile = replace(
                        bundle,
                        requeue_history=(
                            replace(
                                bundle.requeue_history[0],
                                checkpoint_sha256=digest("substituted-lineage-checkpoint"),
                            ),
                        ),
                    )
                transport.bundles[provider_job_id] = hostile

                with self.assertRaisesRegex(
                    ExperimentIntegrityError,
                    "scheduled GPU artifact return is invalid",
                ):
                    backend.collect(receipt.job_id)
                self.assertEqual(
                    backend.reconcile(receipt.job_id).state,
                    RunState.INVALID_OUTPUT,
                )

    def test_structured_scheduler_registry_return_rejects_every_non_runner_role(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = StructuredSchedulerFixture()
            local = spec("scheduled-gpu-role-local")
            cloud = spec(
                "scheduled-gpu-role-cloud",
                profile=gpu_profile(),
                estimate=gpu_estimate(),
            )
            decision = escalation_decision(
                local, cloud, "scheduled-gpu-role-decision"
            )
            backend, registry, authority = self._authorized_backend(
                transport,
                local,
                cloud,
                decision,
                root=Path(directory),
            )
            receipt = backend.submit_planned(
                local,
                cloud,
                decision,
                idempotency_key="scheduled-gpu-role-submit",
                **authority,
            )
            records_before = registry.list_records()

            for role in Role:
                if role is Role.EXPERIMENT_RUNNER:
                    continue
                with self.subTest(role=role.value), self.assertRaisesRegex(
                    ExperimentError,
                    "backend-owned experiment-runner role",
                ):
                    backend.collect_into_registry(
                        receipt.job_id,
                        creator_role=role,
                    )
            self.assertEqual(registry.list_records(), records_before)


if __name__ == "__main__":
    unittest.main()
