from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import errno
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from scientist_one.errors import PathSecurityError, ValidationError
from scientist_one.experiments import (
    AcceleratorKind,
    CheckpointPolicy,
    EvidenceClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    LocalMacBackend,
    LocalMacExecutionMode,
    RunState,
    SeedRunStatus,
    SubmissionConflictError,
)
from scientist_one.local_terminal_observation import (
    LOCAL_TERMINAL_CAPTURE_METADATA_KEY,
    LOCAL_TERMINAL_CAPTURE_PROFILE,
    LOCAL_TERMINAL_MAX_FILE_BYTES,
    LOCAL_TERMINAL_MAX_FILES,
    LOCAL_TERMINAL_MAX_JSON_BYTES,
    LOCAL_TERMINAL_MAX_SOURCE_BYTES,
    LOCAL_TERMINAL_MAX_TOTAL_BYTES,
    LOCAL_TERMINAL_WORST_CASE_JSON_BYTES,
    LocalTerminalFile,
    LocalTerminalObservation,
    validate_terminal_capture_limits,
)
from scientist_one.security import canonical_json_bytes
from tests.test_experiments import local_estimate, local_profile, spec


# Real isolated Python child fixtures; no injected execution or source-owner
# success receipt. The deliberately bad cases are operational fixture evidence.
WORKER = """import hashlib, json, os, sys, time
job_fd = int(os.environ["SCIENTIST_ONE_JOB_DIR_FD"])
def read(name):
    fd = os.open(name, os.O_RDONLY, dir_fd=job_fd)
    with os.fdopen(fd, "rb") as stream:
        return stream.read()
def write(name, payload):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=job_fd)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
spec = json.loads(read("frozen-run-spec.json"))
for kind in ("DATA", "CONFIGURATION", "EVALUATOR"):
    os.read(int(os.environ["SCIENTIST_ONE_INPUT_" + kind + "_FD"]), 4096)
MODE = __MODE__
print("actual child stdout", flush=True)
print("actual child stderr", file=sys.stderr, flush=True)
if MODE == "timeout":
    time.sleep(10)
if MODE == "slow":
    time.sleep(0.6)
if MODE == "empty-failure":
    sys.exit(9)
if MODE == "large-logs":
    print("x" * 512, flush=True)
    print("y" * 512, file=sys.stderr, flush=True)
if MODE == "malformed":
    write("output-manifest.json", b"{not-json\\n")
    sys.exit(0)
payload = b"actual delivered metric fixture bytes\\n"
if MODE in ("capture-capacity", "total-capacity"):
    payload = b"x" * (__MAX_FILE__ - 1)
digest = hashlib.sha256(payload).hexdigest()
write("metrics.bin", payload)
manifest = {
    "schema_version": "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
    "run_id": spec["run_id"],
    "spec_sha256": os.environ["SCIENTIST_ONE_SPEC_SHA256"],
    **{key:spec[key] for key in ("code_sha256", "data_sha256", "configuration_sha256", "evaluator_sha256")},
    "planned_seeds": spec["seeds"],
    "seed_results": [{"seed":seed, "status":status, "metric":metric,
        "artifact_sha256":digest, "reason": "observed adverse fixture" if status in ("FAILED", "INVALID") else None}
        for seed,status,metric in zip(spec["seeds"], ("SUCCESS", "NEGATIVE", "NULL", "FAILED", "INVALID"), (1., 0., 0., 9., 10.))],
    "artifacts": [{"path":"metrics.bin", "sha256":digest, "size":len(payload), "logical_type":"seed_metrics"}],
    "ablations":[],
}
if MODE == "total-capacity":
    second_payload = b"y" * (__MAX_FILE__ - 1)
    write("second.bin", second_payload)
    manifest["artifacts"].append({"path":"second.bin", "sha256":hashlib.sha256(second_payload).hexdigest(), "size":len(second_payload), "logical_type":"seed_metrics"})
if MODE == "unsafe":
    os.unlink("metrics.bin", dir_fd=job_fd)
    os.symlink("/etc/passwd", "metrics.bin", dir_fd=job_fd)
if MODE == "oversize":
    fd = os.open("metrics.bin", os.O_WRONLY, dir_fd=job_fd)
    os.ftruncate(fd, __MAX_FILE__ + 1)
    os.close(fd)
if MODE == "unavailable":
    os.chmod("metrics.bin", 0, dir_fd=job_fd)
if MODE == "oversize-manifest":
    write("output-manifest.json", b"{}")
    fd = os.open("output-manifest.json", os.O_WRONLY, dir_fd=job_fd)
    os.ftruncate(fd, __MAX_FILE__ + 1)
    os.close(fd)
    sys.exit(0)
if MODE == "bad-seed":
    manifest["seed_results"].pop()
if MODE == "nul-path":
    manifest["artifacts"][0]["path"] = "bad" + chr(0) + "name"
if MODE == "surrogate-path":
    manifest["artifacts"][0]["path"] = "bad" + chr(0xD800) + "name"
if MODE in ("nested-output", "unavailable-parent"):
    os.mkdir("blocked", dir_fd=job_fd)
    os.rename("metrics.bin", "blocked/metrics.bin", src_dir_fd=job_fd, dst_dir_fd=job_fd)
    manifest["artifacts"][0]["path"] = "blocked/metrics.bin"
    if MODE == "unavailable-parent":
        os.chmod("blocked", 0, dir_fd=job_fd)
if MODE == "unsafe-parent":
    os.symlink("/outside/inert", "blocked", dir_fd=job_fd)
    manifest["artifacts"][0]["path"] = "blocked/metrics.bin"
write("output-manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\\n")
if MODE == "manifest-failure":
    sys.exit(7)
"""


class LocalTerminalObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def backend(self, **kwargs):
        return LocalMacBackend(
            self.root, allowed_executables=("/usr/bin/python3",), **kwargs
        )

    def fixture(self, mode="success", *, name="terminal-run", timeout=3.0):
        worker = (
            WORKER.replace("__MODE__", repr(mode))
            .replace("__MAX_FILE__", str(LOCAL_TERMINAL_MAX_FILE_BYTES))
            .encode()
        )
        payloads = {
            "code": worker,
            "data": b"data\n",
            "configuration": b"config\n",
            "evaluator": b"evaluator\n",
        }
        paths = {
            kind: f"{name}-{kind}.py" if kind == "code" else f"{name}-{kind}.bin"
            for kind in payloads
        }
        for kind, path in paths.items():
            (self.root / path).write_bytes(payloads[kind])
        run_spec = replace(
            spec(name),
            argv=("/usr/bin/python3", "-I", "-S", "-B", paths["code"]),
            seeds=(11, 22, 33, 44, 55),
            required_ablations=(),
            timeout_seconds=timeout,
            resource_estimate=replace(local_estimate(), wall_clock_seconds=timeout),
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=128,
            checkpoint_policy=CheckpointPolicy.DISABLED,
            metadata={
                LOCAL_TERMINAL_CAPTURE_METADATA_KEY: dict(
                    LOCAL_TERMINAL_CAPTURE_PROFILE
                )
            },
            **{
                f"{kind}_sha256": hashlib.sha256(payload).hexdigest()
                for kind, payload in payloads.items()
            },
        )
        return run_spec, paths

    def run_fixture(self, mode="success", **kwargs):
        run_spec, paths = self.fixture(mode, **kwargs)
        backend = self.backend()
        receipt = backend.submit(
            run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
        )
        return (
            backend,
            run_spec,
            paths,
            receipt,
            backend.collect_terminal_observation(receipt.job_id),
        )

    def test_success_keeps_all_five_statuses_and_adverse_numeric_metrics(self):
        backend, run_spec, paths, receipt, observation = self.run_fixture()
        self.assertEqual(observation.state, "SUCCEEDED")
        self.assertEqual(
            (observation.invocation_count, observation.proven_popen_launch_count),
            (1, 1),
        )
        self.assertEqual(observation.returncode, 0)
        self.assertFalse(observation.scientific_evidence)
        self.assertFalse(observation.independent_execution_attested)
        self.assertFalse(observation.network_isolation_attested)
        self.assertEqual(observation.network_use_status, "UNKNOWN_UNATTESTED")
        collected = backend.collect(receipt.job_id)
        self.assertEqual(
            tuple(item.status for item in collected.manifest.seed_results),
            tuple(SeedRunStatus),
        )
        self.assertEqual(
            tuple(item.metric for item in collected.manifest.seed_results),
            (1.0, 0.0, 0.0, 9.0, 10.0),
        )
        with self.assertRaises(FrozenInstanceError):
            observation.reason = "CHANGED"
        with mock.patch(
            "scientist_one.experiments.subprocess.Popen",
            side_effect=AssertionError("replay must not dispatch"),
        ):
            self.assertEqual(
                self.backend().recover_terminal_observation(
                    run_spec, idempotency_key="fresh-key"
                ),
                observation,
            )
            self.assertEqual(
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                ).job_id,
                receipt.job_id,
            )
        self.assertEqual(
            LocalTerminalObservation.from_bytes(observation.payload), observation
        )

    def test_nonzero_without_output_preserves_absence_not_per_seed_failures(self):
        backend, run_spec, _, receipt, observation = self.run_fixture("empty-failure")
        self.assertEqual(
            (observation.state, observation.reason, observation.returncode),
            ("FAILED", "PROCESS_EXIT:9", 9),
        )
        self.assertIsNone(observation.accepted_manifest_sha256)
        manifest = next(item for item in observation.files if item.role == "manifest")
        self.assertEqual(manifest.status, "MISSING")
        self.assertIsNone(manifest.payload)
        self.assertEqual(observation.delivery_inventory_status, "UNRESOLVED_MANIFEST")
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect(receipt.job_id)
        self.assertEqual(
            self.backend().recover(run_spec, idempotency_key="fresh-key").state,
            RunState.FAILED,
        )

    def test_valid_looking_manifest_after_nonzero_is_never_promoted_on_recovery(self):
        _, run_spec, _, _, observation = self.run_fixture("manifest-failure")
        self.assertEqual((observation.state, observation.returncode), ("FAILED", 7))
        self.assertIsNone(observation.accepted_manifest_sha256)
        self.assertTrue(
            any(item.role == "output" and item.payload for item in observation.files)
        )
        fresh = self.backend()
        self.assertEqual(
            fresh.recover_terminal_observation(run_spec, idempotency_key="fresh-key"),
            observation,
        )
        self.assertEqual(
            fresh.recover(run_spec, idempotency_key="fresh-key").state, RunState.FAILED
        )

    def test_malformed_manifest_retains_raw_bytes_without_normalizing(self):
        _, run_spec, _, _, observation = self.run_fixture("malformed")
        self.assertEqual(observation.state, "INVALID_OUTPUT")
        self.assertEqual(
            next(item.payload for item in observation.files if item.role == "manifest"),
            b"{not-json\n",
        )
        self.assertIsNone(observation.accepted_manifest_sha256)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_incomplete_seed_manifest_remains_invalid_with_raw_declared_rows(self):
        _, _, _, _, observation = self.run_fixture("bad-seed")
        self.assertEqual(observation.state, "INVALID_OUTPUT")
        self.assertIsNone(observation.accepted_manifest_sha256)

    def test_real_timeout_retains_bounded_logs_and_actual_launch(self):
        _, run_spec, _, _, observation = self.run_fixture("timeout", timeout=0.75)
        self.assertEqual(
            (observation.state, observation.reason), ("FAILED", "WALL_CLOCK_TIMEOUT")
        )
        self.assertTrue(observation.timed_out)
        self.assertEqual(observation.proven_popen_launch_count, 1)
        self.assertTrue(observation.log_capture_complete)
        self.assertIn(
            b"actual child stdout",
            next(
                item.payload for item in observation.files if item.path == "stdout.log"
            ),
        )
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_unsafe_and_oversized_raw_outputs_are_retained_as_uncaptured(self):
        for mode, status in (("unsafe", "UNSAFE"), ("oversize", "OVER_LIMIT")):
            with self.subTest(mode=mode):
                _, run_spec, _, _, observation = self.run_fixture(
                    mode, name=f"run-{mode}"
                )
                output = next(
                    item for item in observation.files if item.role == "output"
                )
                self.assertEqual(output.status, status)
                self.assertIsNone(output.payload)
                self.assertEqual(observation.state, "INVALID_OUTPUT")
                self.assertEqual(
                    self.backend().recover_terminal_observation(
                        run_spec, idempotency_key=f"recover-{mode}"
                    ),
                    observation,
                )

    def test_actual_queue_timeout_is_zero_invocations_and_zero_launches(self):
        backend = self.backend(queue_timeout_seconds=0.08)
        first, first_paths = self.fixture("slow", name="first-run")
        second, second_paths = self.fixture("success", name="second-run")
        outcomes = []
        thread = threading.Thread(
            target=lambda: outcomes.append(
                backend.submit(
                    first, idempotency_key="first-key", input_artifact_paths=first_paths
                )
            )
        )
        thread.start()
        self.addCleanup(thread.join)
        self.wait_for_launch(first)
        receipt = backend.submit(
            second, idempotency_key="second-key", input_artifact_paths=second_paths
        )
        observation = backend.collect_terminal_observation(receipt.job_id)
        self.assertEqual(
            (observation.state, observation.reason), ("FAILED", "LOCAL_QUEUE_TIMEOUT")
        )
        self.assertEqual(
            (observation.invocation_count, observation.proven_popen_launch_count),
            (0, 0),
        )
        self.assertIsNone(observation.returncode)
        self.assertFalse(observation.log_capture_complete)
        thread.join(timeout=5)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                second, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_unavailable_output_keeps_partial_observation(self):
        _, run_spec, _, _, observation = self.run_fixture("unavailable")
        output = next(item for item in observation.files if item.role == "output")
        self.assertEqual(output.status, "UNAVAILABLE")
        self.assertIsNone(output.payload)
        self.assertEqual(observation.state, "INVALID_OUTPUT")
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_oversized_raw_manifest_keeps_identity_without_reading_it(self):
        _, run_spec, _, _, observation = self.run_fixture("oversize-manifest")
        manifest = next(item for item in observation.files if item.role == "manifest")
        self.assertEqual(manifest.status, "OVER_LIMIT")
        self.assertIsNone(manifest.payload)
        self.assertEqual(observation.delivery_inventory_status, "UNRESOLVED_MANIFEST")
        self.assertEqual(observation.state, "INVALID_OUTPUT")
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_post_constructor_runner_replacement_refuses_capture(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        backend._execution_runner = lambda *_: None
        with self.assertRaises(ExperimentIntegrityError):
            backend.submit(
                run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
            )
        self.assertFalse(
            (
                self.root
                / ".scientist-one-build/experiments/local-mac"
                / f"local-{run_spec.sha256[:20]}"
            ).exists()
        )

    def test_job_directory_replacement_refuses_fresh_recovery(self):
        backend, run_spec, _, receipt, _ = self.run_fixture()
        job_root = (
            self.root / ".scientist-one-build/experiments/local-mac" / receipt.job_id
        )
        previous = job_root.with_name(job_root.name + "-previous")
        job_root.rename(previous)
        job_root.mkdir()
        for path in previous.iterdir():
            if path.is_file():
                (job_root / path.name).write_bytes(path.read_bytes())
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect_terminal_observation(receipt.job_id)
        with self.assertRaises(ExperimentIntegrityError):
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            )

    def test_real_logs_are_truncated_with_truthful_flags(self):
        _, _, _, _, observation = self.run_fixture("large-logs")
        self.assertTrue(observation.stdout_truncated)
        self.assertTrue(observation.stderr_truncated)
        self.assertTrue(observation.log_capture_complete)
        self.assertEqual(
            tuple(
                len(item.payload) for item in observation.files if item.role == "log"
            ),
            (128, 128),
        )

    def test_partial_log_callback_failure_cannot_become_success(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        original_capture = LocalMacBackend._capture_terminal_pipe

        class PartialPipe:
            def __init__(self, pipe):
                self.pipe = pipe
                self.read_count = 0

            def read(self, size):
                self.read_count += 1
                if self.read_count > 1:
                    raise OSError("SECRET drain exception")
                return self.pipe.read(min(size, 6))

            def close(self):
                self.pipe.close()

        def fail_drain(pipe, maximum, captured, prefix):
            original_capture(PartialPipe(pipe), maximum, captured, prefix)

        with mock.patch.object(
            LocalMacBackend, "_capture_terminal_pipe", side_effect=fail_drain
        ):
            receipt = backend.submit(
                run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
            )
        observation = backend.collect_terminal_observation(receipt.job_id)
        self.assertEqual(observation.state, "FAILED")
        self.assertEqual(observation.reason, "LOG_CAPTURE_EXCEPTION")
        self.assertEqual(observation.stdout_capture_status, "INCOMPLETE")
        self.assertFalse(observation.log_capture_complete)
        self.assertIsNone(observation.stdout_truncated)
        self.assertIsNone(observation.accepted_manifest_sha256)
        self.assertEqual(
            next(
                item.payload for item in observation.files if item.path == "stdout.log"
            ),
            b"actual",
        )
        self.assertNotIn(b"SECRET", observation.payload)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_environment_exception_before_invocation_is_recorded(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        with mock.patch.object(
            backend,
            "_scrubbed_environment",
            side_effect=OSError("SECRET environment exception"),
        ):
            with self.assertRaises(OSError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        observation = backend.collect_terminal_observation(
            f"local-{run_spec.sha256[:20]}"
        )
        self.assertEqual(
            (observation.invocation_count, observation.proven_popen_launch_count),
            (0, 0),
        )
        self.assertEqual(observation.stdout_capture_status, "UNAVAILABLE")
        self.assertEqual(observation.reason, "EXECUTION_EXCEPTION")
        self.assertNotIn(b"SECRET", observation.payload)

    def test_no_terminal_publication_after_source_changes_during_capture(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        original_capture = backend._capture_and_validate_manifest

        def replace_source(job, *, first_capture):
            original_capture(job, first_capture=first_capture)
            path = job.directory / "execution-plan.json"
            path.write_bytes(path.read_bytes() + b" ")

        with mock.patch.object(
            backend, "_capture_and_validate_manifest", side_effect=replace_source
        ):
            with self.assertRaises(ExperimentIntegrityError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        job_root = (
            self.root
            / ".scientist-one-build/experiments/local-mac"
            / f"local-{run_spec.sha256[:20]}"
        )
        self.assertFalse((job_root / "terminal-observation.json").exists())
        with self.assertRaises(ExperimentIntegrityError):
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            )

    def test_log_write_failure_leaves_no_successful_terminal_marker(self):
        from scientist_one import experiments

        real_write = experiments.atomic_write_bytes
        for target in ("stdout.log", "stderr.log"):
            with self.subTest(target=target):
                run_spec, paths = self.fixture(name=f"fail-{target.replace('.', '-')}")
                backend = self.backend()

                def fail_log(root, path, payload, **kwargs):
                    if str(path).endswith(target):
                        raise OSError("simulated log write failure")
                    return real_write(root, path, payload, **kwargs)

                with mock.patch(
                    "scientist_one.experiments.atomic_write_bytes", side_effect=fail_log
                ):
                    with self.assertRaises(OSError):
                        backend.submit(
                            run_spec,
                            idempotency_key="terminal-key",
                            input_artifact_paths=paths,
                        )
                job_root = (
                    self.root
                    / ".scientist-one-build/experiments/local-mac"
                    / f"local-{run_spec.sha256[:20]}"
                )
                self.assertFalse((job_root / "terminal-observation.json").exists())
                with self.assertRaises(ExperimentIntegrityError):
                    self.backend().recover(run_spec, idempotency_key="fresh-key")

    def test_invalid_unicode_paths_preserve_raw_manifest_without_filesystem_access(
        self,
    ):
        for mode, invalid_path in (
            ("nul-path", "bad\x00name"),
            ("surrogate-path", "bad\ud800name"),
        ):
            with self.subTest(mode=mode):
                backend, run_spec, _, receipt, observation = self.run_fixture(
                    mode, name=mode
                )
                self.assertEqual(observation.state, "INVALID_OUTPUT")
                self.assertEqual(observation.returncode, 0)
                self.assertEqual(observation.proven_popen_launch_count, 1)
                self.assertIsNone(observation.accepted_manifest_sha256)
                job_root = (
                    self.root
                    / ".scientist-one-build/experiments/local-mac"
                    / receipt.job_id
                )
                manifest = next(
                    item for item in observation.files if item.role == "manifest"
                )
                self.assertEqual(
                    manifest.payload, (job_root / "output-manifest.json").read_bytes()
                )
                outputs = tuple(
                    item for item in observation.files if item.role == "output"
                )
                if mode == "nul-path":
                    self.assertEqual(
                        tuple((item.path, item.status) for item in outputs),
                        ((invalid_path, "UNSAFE"),),
                    )
                else:
                    self.assertEqual(outputs, ())
                    self.assertEqual(
                        observation.delivery_inventory_status, "UNRESOLVED_MANIFEST"
                    )
                self.assertEqual(
                    LocalTerminalObservation.from_bytes(observation.payload),
                    observation,
                )
                real_stat = os.stat

                def reject_invalid_path(path, *args, **kwargs):
                    if path == invalid_path:
                        self.fail(
                            "inadmissible path must never reach a filesystem call"
                        )
                    return real_stat(path, *args, **kwargs)

                with mock.patch(
                    "scientist_one.experiments.os.stat", side_effect=reject_invalid_path
                ):
                    self.assertEqual(
                        backend.collect_terminal_observation(receipt.job_id),
                        observation,
                    )
                    self.assertEqual(
                        self.backend().recover_terminal_observation(
                            run_spec, idempotency_key="fresh-key"
                        ),
                        observation,
                    )

    def test_output_read_io_errors_retain_partial_capture_and_exact_replay(self):
        for error_number, expected_status in (
            (errno.EIO, "ERROR"),
            (errno.EACCES, "UNAVAILABLE"),
        ):
            with self.subTest(error_number=error_number):
                run_spec, paths = self.fixture(name=f"read-error-{error_number}")
                backend = self.backend()
                job_root = (
                    self.root
                    / ".scientist-one-build/experiments/local-mac"
                    / f"local-{run_spec.sha256[:20]}"
                )
                target = job_root / "metrics.bin"
                real_stat, real_pread = os.stat, os.pread

                def fail_output_read(descriptor, *args):
                    try:
                        target_metadata = real_stat(target)
                    except FileNotFoundError:
                        return real_pread(descriptor, *args)
                    held = os.fstat(descriptor)
                    if (held.st_dev, held.st_ino) == (
                        target_metadata.st_dev,
                        target_metadata.st_ino,
                    ):
                        raise OSError(error_number, "adverse read fixture")
                    return real_pread(descriptor, *args)

                with mock.patch(
                    "scientist_one.experiments.os.pread", side_effect=fail_output_read
                ):
                    receipt = backend.submit(
                        run_spec,
                        idempotency_key="terminal-key",
                        input_artifact_paths=paths,
                    )
                    observation = backend.collect_terminal_observation(receipt.job_id)
                    output = next(
                        item for item in observation.files if item.role == "output"
                    )
                    self.assertEqual(output.status, expected_status)
                    self.assertIsNotNone(output.identity)
                    self.assertIsNone(output.payload)
                    self.assertEqual(
                        (observation.state, observation.returncode),
                        ("INVALID_OUTPUT", 0),
                    )
                    self.assertEqual(observation.proven_popen_launch_count, 1)
                    self.assertEqual(
                        self.backend().recover_terminal_observation(
                            run_spec, idempotency_key="fresh-key"
                        ),
                        observation,
                    )
                with self.assertRaises(ExperimentIntegrityError):
                    backend.collect_terminal_observation(receipt.job_id)

    def test_parent_directory_io_errors_are_not_mislabeled_unsafe(self):
        for mode, expected_status in (
            ("unavailable-parent", "UNAVAILABLE"),
            ("nested-output", "ERROR"),
            ("unsafe-parent", "UNSAFE"),
        ):
            with self.subTest(mode=mode):
                run_spec, paths = self.fixture(mode, name=mode)
                backend = self.backend()
                real_open = os.open

                def fail_parent_open(path, *args, **kwargs):
                    if mode == "nested-output" and path == "blocked":
                        raise OSError(errno.EIO, "adverse parent-open fixture")
                    return real_open(path, *args, **kwargs)

                with mock.patch(
                    "scientist_one.experiments.os.open", side_effect=fail_parent_open
                ):
                    receipt = backend.submit(
                        run_spec,
                        idempotency_key="terminal-key",
                        input_artifact_paths=paths,
                    )
                    observation = backend.collect_terminal_observation(receipt.job_id)
                    self.assertEqual(observation.returncode, 0)
                    self.assertEqual(observation.state, "INVALID_OUTPUT")
                    self.assertEqual(
                        next(
                            item.status
                            for item in observation.files
                            if item.role == "output"
                        ),
                        expected_status,
                    )
                    self.assertEqual(
                        self.backend().recover_terminal_observation(
                            run_spec, idempotency_key="fresh-key"
                        ),
                        observation,
                    )

    def test_finished_early_publication_failure_never_reports_running(self):
        from scientist_one import experiments

        real_write = experiments.atomic_write_bytes
        for target in ("stdout.log", "stderr.log", "terminal-observation.json"):
            with self.subTest(target=target):
                run_spec, paths = self.fixture(
                    name=f"finished-{target.replace('.', '-')}"
                )
                backend = self.backend()

                def fail_publication(root, path, payload, **kwargs):
                    if str(path).endswith(target):
                        raise OSError("adverse publication fixture")
                    return real_write(root, path, payload, **kwargs)

                with mock.patch(
                    "scientist_one.experiments.atomic_write_bytes",
                    side_effect=fail_publication,
                ):
                    with self.assertRaises(OSError):
                        backend.submit(
                            run_spec,
                            idempotency_key="terminal-key",
                            input_artifact_paths=paths,
                        )
                job_id = f"local-{run_spec.sha256[:20]}"
                # Inspect actual backend completion, never invent a receipt.
                self.assertEqual(backend._jobs[job_id].terminal_result.returncode, 0)
                self.assertTrue(backend._jobs[job_id].terminal_finished.is_set())
                self.assertNotIn(job_id, backend._active_processes)
                with self.assertRaises(ExperimentIntegrityError):
                    backend.reconcile(job_id)
                with self.assertRaises(ExperimentIntegrityError):
                    backend.collect_terminal_observation(job_id)
                with self.assertRaises(ExperimentIntegrityError):
                    backend.submit(
                        run_spec,
                        idempotency_key="terminal-key",
                        input_artifact_paths=paths,
                    )

    def test_admitted_near_file_capacity_can_publish_with_shared_codec(self):
        from scientist_one.security import DEFAULT_MAX_JSON_BYTES

        _, run_spec, _, _, observation = self.run_fixture("capture-capacity")
        self.assertEqual((observation.state, observation.returncode), ("SUCCEEDED", 0))
        self.assertEqual(
            len(
                next(
                    item.payload for item in observation.files if item.role == "output"
                )
            ),
            LOCAL_TERMINAL_MAX_FILE_BYTES - 1,
        )
        self.assertLessEqual(len(observation.payload), DEFAULT_MAX_JSON_BYTES)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_output_read_error_does_not_hide_same_byte_inode_replacement(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        job_root = (
            self.root
            / ".scientist-one-build/experiments/local-mac"
            / f"local-{run_spec.sha256[:20]}"
        )
        target = job_root / "metrics.bin"
        real_stat, real_pread = os.stat, os.pread
        replaced = False

        def replace_during_read(descriptor, *args):
            nonlocal replaced
            try:
                target_metadata = real_stat(target)
            except FileNotFoundError:
                return real_pread(descriptor, *args)
            held = os.fstat(descriptor)
            if not replaced and (held.st_dev, held.st_ino) == (
                target_metadata.st_dev,
                target_metadata.st_ino,
            ):
                raw = target.read_bytes()
                target.rename(target.with_suffix(".previous"))
                target.write_bytes(raw)
                replaced = True
                raise OSError(errno.EIO, "read failure during inode replacement")
            return real_pread(descriptor, *args)

        with mock.patch(
            "scientist_one.experiments.os.pread", side_effect=replace_during_read
        ):
            with self.assertRaises(ExperimentIntegrityError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        self.assertTrue(replaced)
        self.assertEqual(backend._jobs[job_root.name].terminal_result.returncode, 0)
        self.assertFalse((job_root / "terminal-observation.json").exists())
        with self.assertRaises(ExperimentIntegrityError):
            backend.reconcile(job_root.name)
        with self.assertRaises(ExperimentIntegrityError):
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            )

    def test_total_capacity_keeps_over_limit_output_identity_without_bytes(self):
        _, run_spec, _, _, observation = self.run_fixture("total-capacity")
        self.assertEqual(observation.state, "INVALID_OUTPUT")
        self.assertEqual(observation.returncode, 0)
        outputs = tuple(item for item in observation.files if item.role == "output")
        self.assertEqual(
            tuple(item.status for item in outputs), ("CAPTURED", "OVER_LIMIT")
        )
        self.assertIsNone(outputs[1].payload)
        self.assertEqual(outputs[1].identity[4], LOCAL_TERMINAL_MAX_FILE_BYTES - 1)
        self.assertLessEqual(
            sum(len(item.payload or b"") for item in observation.files),
            LOCAL_TERMINAL_MAX_TOTAL_BYTES,
        )
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_source_budget_refuses_before_dispatch(self):
        run_spec, paths = self.fixture()
        data = b"d" * LOCAL_TERMINAL_MAX_SOURCE_BYTES
        (self.root / paths["data"]).write_bytes(data)
        run_spec = replace(run_spec, data_sha256=hashlib.sha256(data).hexdigest())
        backend = self.backend()
        with mock.patch(
            "scientist_one.experiments.subprocess.Popen",
            side_effect=AssertionError("capacity refusal must precede dispatch"),
        ):
            with self.assertRaises(ExperimentError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        self.assertFalse(
            (
                self.root
                / ".scientist-one-build/experiments/local-mac"
                / f"local-{run_spec.sha256[:20]}"
            ).exists()
        )

    def test_codec_worst_case_metadata_and_encoding_fit_reserved_envelope(self):
        validate_terminal_capture_limits()
        self.assertLessEqual(
            LOCAL_TERMINAL_WORST_CASE_JSON_BYTES, LOCAL_TERMINAL_MAX_JSON_BYTES
        )
        _, _, _, _, original = self.run_fixture()
        # Codec stress values only: deliberately not native backend files or
        # scientific evidence. No collect/recover call accepts this DTO.
        large_identity_integer = -(2**4096 - 1)
        files = []
        for index in range(LOCAL_TERMINAL_MAX_FILES):
            label = str(index)
            path = label + "\x01" * (1024 - len(label))
            payload = (
                bytes([65 + index]) * LOCAL_TERMINAL_MAX_FILE_BYTES
                if index < 2
                else None
            )
            identity = (
                (large_identity_integer,) * 4
                + ((len(payload) if payload is not None else large_identity_integer),)
                + (large_identity_integer,) * 2
            )
            files.append(
                LocalTerminalFile(
                    "output",
                    path,
                    "CAPTURED" if payload is not None else "OVER_LIMIT",
                    identity,
                    payload,
                )
            )
        stress = replace(
            original,
            state="INVALID_OUTPUT",
            reason="OUTPUT_INVALID",
            accepted_manifest_sha256=None,
            files=tuple(files),
        )
        self.assertLessEqual(len(stress.payload), LOCAL_TERMINAL_WORST_CASE_JSON_BYTES)
        self.assertEqual(LocalTerminalObservation.from_bytes(stress.payload), stress)

    def wait_for_launch(self, run_spec):
        directory = (
            self.root
            / ".scientist-one-build/experiments/local-mac"
            / f"local-{run_spec.sha256[:20]}"
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (directory / "terminal-dispatch-intent.json").exists():
                time.sleep(0.03)
                return directory
            time.sleep(0.005)
        self.fail("real child did not reach dispatch")

    def test_actual_running_cancellation_captures_before_return(self):
        run_spec, paths = self.fixture("timeout")
        backend = self.backend()
        outcomes = []
        thread = threading.Thread(
            target=lambda: outcomes.append(
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
            )
        )
        thread.start()
        self.addCleanup(thread.join)
        self.wait_for_launch(run_spec)
        job_id = f"local-{run_spec.sha256[:20]}"
        status = backend.cancel(job_id)
        self.assertEqual(status.state, RunState.CANCELLED)
        observation = backend.collect_terminal_observation(job_id)
        self.assertEqual(observation.state, "CANCELLED")
        self.assertEqual(observation.proven_popen_launch_count, 1)
        self.assertIsNotNone(observation.returncode)
        thread.join(timeout=5)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_popen_exception_is_one_invocation_but_no_proven_launch(self):
        run_spec, paths = self.fixture()
        backend = self.backend()
        with mock.patch(
            "scientist_one.experiments.subprocess.Popen",
            side_effect=OSError("SECRET must not enter reason"),
        ):
            with self.assertRaises(OSError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        observation = backend.collect_terminal_observation(
            f"local-{run_spec.sha256[:20]}"
        )
        self.assertEqual(
            (observation.invocation_count, observation.proven_popen_launch_count),
            (1, 0),
        )
        self.assertEqual(observation.reason, "EXECUTION_EXCEPTION")
        self.assertEqual(observation.launch_observation, "UNKNOWN_AFTER_INVOCATION")
        self.assertNotIn(b"SECRET", observation.payload)
        self.assertEqual(
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            ),
            observation,
        )

    def test_commit_failure_prefix_is_unresolved_and_cannot_redispatch(self):
        run_spec, paths = self.fixture("manifest-failure")
        backend = self.backend()
        from scientist_one import experiments

        real_write = experiments.atomic_write_bytes

        def fail_terminal(root, path, payload, **kwargs):
            if str(path).endswith("terminal-observation.json"):
                raise OSError("simulated publication failure")
            return real_write(root, path, payload, **kwargs)

        with mock.patch(
            "scientist_one.experiments.atomic_write_bytes", side_effect=fail_terminal
        ):
            with self.assertRaises(OSError):
                backend.submit(
                    run_spec, idempotency_key="terminal-key", input_artifact_paths=paths
                )
        with mock.patch(
            "scientist_one.experiments.subprocess.Popen",
            side_effect=AssertionError("must not redispatch"),
        ):
            with self.assertRaises(ExperimentIntegrityError):
                backend.collect_terminal_observation(f"local-{run_spec.sha256[:20]}")
            with self.assertRaises(ExperimentIntegrityError):
                self.backend().recover(run_spec, idempotency_key="fresh-key")
            with self.assertRaises(SubmissionConflictError):
                self.backend().submit(
                    run_spec, idempotency_key="fresh-key", input_artifact_paths=paths
                )

    def test_raw_manifest_and_terminal_record_substitution_refuse_replay(self):
        for target in (
            "output-manifest.json",
            "metrics.bin",
            "execution-plan.json",
            "execution-mode.json",
            "execution-input-binding.json",
            "frozen-input-code.py",
            "stdout.log",
            "terminal-observation.json",
        ):
            with self.subTest(target=target):
                backend, run_spec, _, receipt, _ = self.run_fixture(
                    name=f"substitute-{target.replace('.', '-')}"
                )
                path = (
                    self.root
                    / ".scientist-one-build/experiments/local-mac"
                    / receipt.job_id
                    / target
                )
                path.chmod(0o600)
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaises(
                    (ExperimentIntegrityError, ValidationError, PathSecurityError)
                ):
                    backend.collect_terminal_observation(receipt.job_id)
                with self.assertRaises(
                    (ExperimentIntegrityError, ValidationError, PathSecurityError)
                ):
                    self.backend().recover_terminal_observation(
                        run_spec, idempotency_key="fresh-key"
                    )

    def test_equal_bytes_replacement_and_hardlink_refuse_replay(self):
        backend, run_spec, _, receipt, _ = self.run_fixture()
        path = (
            self.root
            / ".scientist-one-build/experiments/local-mac"
            / receipt.job_id
            / "metrics.bin"
        )
        original = path.read_bytes()
        path.unlink()
        path.write_bytes(original)
        with self.assertRaises(ExperimentIntegrityError):
            backend.collect_terminal_observation(receipt.job_id)
        os.link(path, path.with_suffix(".hardlink"))
        with self.assertRaises(ExperimentIntegrityError):
            self.backend().recover_terminal_observation(
                run_spec, idempotency_key="fresh-key"
            )

    def test_marker_and_scope_refuse_before_dispatch(self):
        run_spec, paths = self.fixture()
        variants = (
            replace(
                run_spec,
                metadata={
                    LOCAL_TERMINAL_CAPTURE_METADATA_KEY: {
                        **LOCAL_TERMINAL_CAPTURE_PROFILE,
                        "extra": True,
                    }
                },
            ),
            replace(run_spec, evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE),
            replace(run_spec, phase=ExperimentPhase.CONFIRMATORY),
            replace(run_spec, checkpoint_policy=CheckpointPolicy.PER_SEED),
            replace(run_spec, metadata={**run_spec.metadata, "resume_from": "old"}),
            replace(
                run_spec,
                compute_profile=local_profile(
                    accelerator=AcceleratorKind.MPS, validation_hash="a" * 64
                ),
            ),
        )
        with mock.patch(
            "scientist_one.experiments.subprocess.Popen",
            side_effect=AssertionError("unsupported must not dispatch"),
        ):
            for variant in variants:
                with (
                    self.subTest(variant=variant.sha256),
                    self.assertRaises(ExperimentError),
                ):
                    self.backend().submit(
                        variant, idempotency_key="bad-key", input_artifact_paths=paths
                    )
            diagnostic = self.backend(
                execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
                execution_runner=lambda *_: None,
            )
            with self.assertRaises(ExperimentError):
                diagnostic.submit(
                    run_spec, idempotency_key="bad-key", input_artifact_paths=paths
                )

    def test_resume_and_unmarked_capture_are_not_enabled(self):
        backend, _, _, receipt, _ = self.run_fixture()
        with self.assertRaises(ExperimentError):
            backend.resume(receipt.job_id)
        unmarked, _ = self.fixture(name="unmarked-run")
        with self.assertRaises(ExperimentError):
            backend.recover_terminal_observation(
                replace(unmarked, metadata={}), idempotency_key="bad-key"
            )

    def test_codec_rejects_unknown_fields_and_boolean_counts(self):
        _, _, _, _, observation = self.run_fixture()
        for update in (
            {"unknown": True},
            {"invocation_count": True},
            {"scientific_evidence": True},
            {"accepted_manifest_sha256": None},
        ):
            with self.assertRaises(ValidationError):
                LocalTerminalObservation.from_bytes(
                    canonical_json_bytes({**observation.to_dict(), **update}) + b"\n"
                )


if __name__ == "__main__":
    unittest.main()
