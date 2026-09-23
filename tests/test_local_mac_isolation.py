from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.experiments import (
    AcceleratorKind,
    CachePolicy,
    CheckpointPolicy,
    ComputeMode,
    ComputeProfile,
    EvidenceClass,
    ExecutionResult,
    ExperimentClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    FrozenRunSpec,
    LocalMacBackend,
    LocalMacExecutionMode,
    LocalMacIsolationMode,
    ResourceEstimate,
    RunState,
    SchedulerKind,
    ValidationStatus,
)
from scientist_one.security import safe_json_loads


def _profile() -> ComputeProfile:
    return ComputeProfile(
        profile_id="local-seatbelt-test",
        mode=ComputeMode.LOCAL_MAC,
        accelerator=AcceleratorKind.CPU,
        scheduler=SchedulerKind.LOCAL,
        experiment_class=ExperimentClass.PILOT,
        cpu_cores=1,
        accelerator_count=0,
        memory_limit_bytes=8 * 1024**3,
        maximum_concurrency=1,
        minimum_batch_size=1,
        preferred_batch_size=1,
        maximum_batch_size=1,
        disk_limit_bytes=128 * 1024**2,
        maximum_memory_fraction=0.8,
        supports_checkpointing=False,
        supports_preemption=False,
        validation_status=ValidationStatus.VALIDATED_LOCAL,
        hourly_cost=0.0,
    )


def _spec(
    script: Path,
    *,
    data: Path,
    configuration: Path,
    evaluator: Path,
) -> FrozenRunSpec:
    runtime_root = Path(sys.base_prefix).resolve(strict=True)
    direct_interpreter = (
        runtime_root / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    )
    if not direct_interpreter.is_file():
        direct_interpreter = Path(sys.executable).resolve(strict=True)
    return FrozenRunSpec(
        run_id="run-local-seatbelt-integration",
        experiment_id="experiment-local-seatbelt",
        hypothesis_id="hypothesis-local-seatbelt",
        phase=ExperimentPhase.EXPLORATORY,
        argv=(str(direct_interpreter), "-I", "-S", "-B", script.name),
        working_directory=".",
        code_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        data_sha256=hashlib.sha256(data.read_bytes()).hexdigest(),
        configuration_sha256=hashlib.sha256(
            configuration.read_bytes()
        ).hexdigest(),
        evaluator_sha256=hashlib.sha256(evaluator.read_bytes()).hexdigest(),
        seeds=(7,),
        timeout_seconds=30.0,
        evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        scientific_purpose="verify the opt-in technical isolation launch boundary",
        expected_outputs=("output_manifest", "seed_results"),
        seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
        termination_conditions=("wall_clock_timeout", "all_planned_seeds_reported"),
        compute_profile=_profile(),
        resource_estimate=ResourceEstimate(
            expected_scientific_value=1.0,
            expected_uncertainty_reduction=1.0,
            cpu_cores=1,
            gpu_count=0,
            ram_bytes=512 * 1024**2,
            vram_bytes=0,
            disk_bytes=64 * 1024**2,
            wall_clock_seconds=20.0,
            monetary_cost=0.0,
        ),
        cache_policy=CachePolicy.CONTENT_ADDRESSABLE,
        checkpoint_policy=CheckpointPolicy.DISABLED,
        bytes_per_sample=1024,
        worker_overhead_bytes=64 * 1024**2,
    )


_WORKER = r'''import errno
import hashlib
import json
import os
import socket


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


job = os.environ["SCIENTIST_ONE_JOB_DIR"]
with open(os.path.join(job, "frozen-run-spec.json"), "rb") as handle:
    spec = json.load(handle)
denials = {}
candidate_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    candidate_socket.bind(("127.0.0.1", 0))
except OSError as exc:
    if exc.errno not in {errno.EPERM, errno.EACCES}:
        raise
    denials["loopback_bind_errno"] = exc.errno
else:
    raise RuntimeError("Seatbelt unexpectedly allowed loopback bind")
finally:
    candidate_socket.close()

forbidden_path = os.path.join(os.getcwd(), "seatbelt-forbidden-write.txt")
try:
    with open(forbidden_path, "xb") as handle:
        handle.write(b"forbidden\n")
except OSError as exc:
    if exc.errno not in {errno.EPERM, errno.EACCES}:
        raise
    denials["outside_job_write_errno"] = exc.errno
else:
    raise RuntimeError("Seatbelt unexpectedly allowed an out-of-job write")

payload = canonical({"metric": 0.7, "seatbelt_denials": denials, "seed": 7})
artifact_path = os.path.join(job, "seed-7.json")
with open(artifact_path, "wb") as handle:
    handle.write(payload)
artifact_sha256 = hashlib.sha256(payload).hexdigest()
manifest = {
    "schema_version": "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
    "run_id": spec["run_id"],
    "spec_sha256": os.environ["SCIENTIST_ONE_SPEC_SHA256"],
    "code_sha256": spec["code_sha256"],
    "data_sha256": spec["data_sha256"],
    "configuration_sha256": spec["configuration_sha256"],
    "evaluator_sha256": spec["evaluator_sha256"],
    "planned_seeds": [7],
    "seed_results": [{
        "seed": 7,
        "status": "SUCCESS",
        "metric": 0.7,
        "artifact_sha256": artifact_sha256,
        "reason": None,
    }],
    "artifacts": [{
        "path": "seed-7.json",
        "sha256": artifact_sha256,
        "size": len(payload),
        "logical_type": "seed_result",
    }],
    "ablations": [],
}
with open(os.environ["SCIENTIST_ONE_OUTPUT_MANIFEST"], "wb") as handle:
    handle.write(canonical(manifest) + b"\n")
'''


def _seatbelt_probe_succeeds() -> bool:
    if not LocalMacBackend.isolation_available():
        return False
    try:
        result = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1) (allow default) (deny network*)",
                "/usr/bin/true",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class LocalMacIsolationUnitTests(unittest.TestCase):
    def test_disabled_is_default_and_required_rejects_injected_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ExperimentError, "diagnostic mode"):
                LocalMacBackend(
                    directory,
                    allowed_executables=("/usr/bin/true",),
                    execution_runner=lambda *_: ExecutionResult(1),
                )
            disabled = LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                execution_runner=lambda *_: ExecutionResult(1),
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            self.assertEqual(disabled.isolation_mode, LocalMacIsolationMode.DISABLED)
            with self.assertRaises(ExperimentError):
                LocalMacBackend(
                    directory,
                    allowed_executables=("/usr/bin/true",),
                    execution_runner=lambda *_: ExecutionResult(1),
                    isolation_mode=LocalMacIsolationMode.REQUIRED,
                )

    def test_required_mode_fails_closed_when_host_boundary_is_unavailable(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(LocalMacBackend, "isolation_available", return_value=False),
            self.assertRaises(ExperimentError),
        ):
            LocalMacBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                isolation_mode=LocalMacIsolationMode.REQUIRED,
            )

    def test_required_mode_rejects_subclass_runner_substitution(self) -> None:
        class SubstitutedBackend(LocalMacBackend):
            def _run_subprocess(self, *_):  # type: ignore[no-untyped-def]
                return ExecutionResult(0)

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(LocalMacBackend, "isolation_available", return_value=True),
            self.assertRaises(ExperimentIntegrityError),
        ):
            SubstitutedBackend(
                directory,
                allowed_executables=("/usr/bin/true",),
                isolation_mode=LocalMacIsolationMode.REQUIRED,
            )


@unittest.skipUnless(
    os.environ.get("SCIENTIST_ONE_RUN_MACOS_SEATBELT_INTEGRATION") == "1",
    "set SCIENTIST_ONE_RUN_MACOS_SEATBELT_INTEGRATION=1 for the real host probe",
)
class LocalMacIsolationIntegrationTests(unittest.TestCase):
    def test_exact_launch_evidence_recovery_and_tamper_failure(self) -> None:
        if sys.platform != "darwin" or not _seatbelt_probe_succeeds():
            self.skipTest("macOS Seatbelt is not actually available in this execution context")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "isolated_worker.py"
            script.write_text(_WORKER, encoding="utf-8")
            data = root / "data.json"
            configuration = root / "configuration.json"
            evaluator = root / "evaluator.json"
            data.write_bytes(b'{"fixture":"seatbelt-data"}\n')
            configuration.write_bytes(b'{"fixture":"seatbelt-configuration"}\n')
            evaluator.write_bytes(b'{"fixture":"seatbelt-evaluator"}\n')
            input_artifact_paths = {
                "code": script.name,
                "data": data.name,
                "configuration": configuration.name,
                "evaluator": evaluator.name,
            }
            run_spec = _spec(
                script,
                data=data,
                configuration=configuration,
                evaluator=evaluator,
            )
            direct_interpreter = run_spec.argv[0]
            disabled_backend = LocalMacBackend(
                root,
                allowed_executables=(direct_interpreter,),
                execution_runner=lambda *_: ExecutionResult(1),
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            )
            disabled_receipt = disabled_backend.submit(
                run_spec,
                idempotency_key="unsandboxed-same-spec",
            )
            backend = LocalMacBackend(
                root,
                allowed_executables=(direct_interpreter,),
                isolation_mode=LocalMacIsolationMode.REQUIRED,
                observed_available_memory_bytes=2 * 1024**3,
            )
            receipt = backend.submit(
                run_spec,
                idempotency_key="seatbelt-submit",
                input_artifact_paths=input_artifact_paths,
            )
            self.assertNotEqual(receipt.job_id, disabled_receipt.job_id)
            self.assertTrue(receipt.job_id.endswith("-isolated"))
            status = backend.reconcile(receipt.job_id)
            stderr_path = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
                / receipt.job_id
                / "stderr.log"
            )
            stderr = (
                stderr_path.read_text(encoding="utf-8", errors="replace")
                if stderr_path.exists()
                else ""
            )
            self.assertEqual(
                receipt.state,
                RunState.SUCCEEDED,
                msg=f"status={status.reason!r}; stderr={stderr!r}",
            )
            self.assertFalse(receipt.scientific_evidence)
            self.assertFalse(receipt.network_isolation_attested)
            self.assertFalse((root / "seatbelt-forbidden-write.txt").exists())

            job_directory = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
                / receipt.job_id
            )
            evidence_path = job_directory / "local-isolation-launch-1.json"
            evidence = safe_json_loads(evidence_path.read_bytes())
            seed_payload = safe_json_loads((job_directory / "seed-7.json").read_bytes())
            self.assertIn(
                seed_payload["seatbelt_denials"]["loopback_bind_errno"],
                {errno.EPERM, errno.EACCES},
            )
            self.assertIn(
                seed_payload["seatbelt_denials"]["outside_job_write_errno"],
                {errno.EPERM, errno.EACCES},
            )
            self.assertEqual(evidence["isolation_mode"], "REQUIRED")
            self.assertEqual(evidence["spec_sha256"], run_spec.sha256)
            self.assertEqual(
                evidence["execution_plan_sha256"],
                receipt.execution_plan_sha256,
            )
            self.assertEqual(
                evidence["compute_profile_sha256"],
                run_spec.compute_profile.sha256,
            )
            self.assertEqual(evidence["target_executable_path"], direct_interpreter)
            self.assertEqual(evidence["launch_argv"][0], "/usr/bin/sandbox-exec")
            self.assertEqual(evidence["launch_argv"][1], "-p")
            self.assertEqual(evidence["launch_argv"][3], "--")
            self.assertEqual(
                hashlib.sha256(
                    evidence["launch_argv"][2].encode("utf-8")
                ).hexdigest(),
                evidence["sandbox_profile_sha256"],
            )
            self.assertEqual(
                evidence["sandbox_profile_consumption"],
                "INLINE_EXACT_BYTES",
            )
            self.assertNotIn("-f", evidence["launch_argv"][:4])
            self.assertTrue(
                evidence["boundary_claims"]["network_denied_by_seatbelt"]
            )
            self.assertTrue(
                evidence["boundary_claims"]["writes_confined_to_job_directory"]
            )
            self.assertFalse(
                evidence["boundary_claims"]["filesystem_read_isolation"]
            )
            self.assertFalse(
                evidence["boundary_claims"]["os_resource_limits_enforced"]
            )
            self.assertFalse(evidence["scientific_evidence"])
            self.assertFalse(evidence["network_isolation_attested"])

            recovered_backend = LocalMacBackend(
                root,
                allowed_executables=(direct_interpreter,),
                isolation_mode=LocalMacIsolationMode.REQUIRED,
                observed_available_memory_bytes=2 * 1024**3,
            )
            recovered = recovered_backend.recover(
                run_spec,
                idempotency_key="seatbelt-recover",
            )
            self.assertEqual(recovered.state, RunState.SUCCEEDED)
            self.assertFalse(recovered.scientific_evidence)
            self.assertFalse(recovered.network_isolation_attested)

            evidence["boundary_claims"]["filesystem_read_isolation"] = True
            evidence_path.write_text(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            tamper_backend = LocalMacBackend(
                root,
                allowed_executables=(direct_interpreter,),
                isolation_mode=LocalMacIsolationMode.REQUIRED,
                observed_available_memory_bytes=2 * 1024**3,
            )
            with self.assertRaises(ExperimentIntegrityError):
                tamper_backend.recover(
                    run_spec,
                    idempotency_key="seatbelt-tampered",
                )


if __name__ == "__main__":
    unittest.main()
