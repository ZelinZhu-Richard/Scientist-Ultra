from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scientist_one.experiments import (
    ExecutionResult,
    ExperimentIntegrityError,
    FakeGPUCloudBackend,
    LocalMacBackend,
    LocalMacExecutionMode,
    OutputArtifact,
    OutputManifest,
    RunState,
    ScheduledGPUArtifactBundle,
    ScheduledGPUStatus,
    SeedRunStatus,
    StagedArtifact,
    _validate_manifest_bindings,
)
from scientist_one.security import canonical_json_bytes
from tests import test_experiments as experiment_tests


class ExpectedOutputCompletionTests(unittest.TestCase):
    """Portable completion checks for the frozen minimum output interface."""

    @staticmethod
    def _write_manifest(directory: Path, manifest: OutputManifest) -> None:
        (directory / "output-manifest.json").write_bytes(
            canonical_json_bytes(manifest.to_dict()) + b"\n"
        )

    def _append_output(
        self,
        directory: Path,
        manifest: OutputManifest,
        *,
        path: str,
        logical_type: str,
        payload: bytes,
        write_payload: bool = True,
    ) -> OutputManifest:
        if write_payload:
            (directory / path).write_bytes(payload)
        descriptor = OutputArtifact(
            path,
            hashlib.sha256(payload).hexdigest(),
            len(payload),
            logical_type,
        )
        updated = replace(manifest, artifacts=(*manifest.artifacts, descriptor))
        self._write_manifest(directory, updated)
        return updated

    @staticmethod
    def _diagnostic_backend(root: Path, runner) -> LocalMacBackend:
        return LocalMacBackend(
            root,
            allowed_executables=("/usr/bin/true",),
            execution_runner=runner,
            execution_mode=LocalMacExecutionMode.INJECTED_DIAGNOSTIC,
            observed_available_memory_bytes=4 * 1024**3,
        )

    @staticmethod
    def _scheduled_completion_fixture(root: Path, label: str):
        local = replace(
            experiment_tests.spec(f"{label}-local"),
            expected_outputs=("output_manifest", "seed_results", "analysis_report"),
        )
        cloud = replace(
            experiment_tests.spec(
                f"{label}-cloud",
                profile=experiment_tests.gpu_profile(),
                estimate=experiment_tests.gpu_estimate(),
            ),
            expected_outputs=("output_manifest", "seed_results", "analysis_report"),
        )
        decision = experiment_tests.escalation_decision(
            local,
            cloud,
            f"{label}-decision",
        )
        transport = experiment_tests.StructuredSchedulerFixture()
        fixture_case = experiment_tests.ScheduledGPUBackendTests("run")
        backend, _registry, authority = fixture_case._authorized_backend(
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
        transport.statuses[provider_job_id] = ScheduledGPUStatus(
            provider_job_id,
            RunState.SUCCEEDED,
        )
        return transport, backend, cloud, receipt, provider_job_id

    def test_local_submit_and_collect_refuse_absent_custom_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = replace(
                experiment_tests.spec("expected-output-local-missing"),
                expected_outputs=(
                    "output_manifest",
                    "seed_results",
                    "analysis_report",
                ),
            )

            def runner(spec, job_directory, environment):
                experiment_tests.write_manifest(spec, job_directory)
                return ExecutionResult(0)

            backend = self._diagnostic_backend(Path(directory), runner)
            receipt = backend.submit(run_spec, idempotency_key="local-missing-output")

            self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)
            self.assertIn(
                "frozen expected output type",
                backend.reconcile(receipt.job_id).reason or "",
            )
            with self.assertRaises(ExperimentIntegrityError):
                backend.collect(receipt.job_id)

    def test_local_present_custom_output_is_accepted_but_non_evidentiary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = replace(
                experiment_tests.spec("expected-output-local-present"),
                expected_outputs=(
                    "output_manifest",
                    "seed_results",
                    "analysis_report",
                ),
            )

            def runner(spec, job_directory, environment):
                manifest = experiment_tests.write_manifest(spec, job_directory)
                self._append_output(
                    job_directory,
                    manifest,
                    path="analysis-report.json",
                    logical_type="analysis_report",
                    payload=b'{"result":"fixture"}\n',
                )
                return ExecutionResult(0)

            backend = self._diagnostic_backend(Path(directory), runner)
            receipt = backend.submit(run_spec, idempotency_key="local-present-output")
            collected = backend.collect(receipt.job_id)

            self.assertEqual(receipt.state, RunState.SUCCEEDED)
            self.assertFalse(collected.scientific_evidence)
            self.assertIn(
                "INJECTED_DIAGNOSTIC_UNTESTED_UNPROMOTABLE",
                backend.reconcile(receipt.job_id).reason or "",
            )
            self.assertIn(
                "analysis_report",
                {item.logical_type for item in collected.manifest.artifacts},
            )

    def test_local_permits_additional_undeclared_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = experiment_tests.spec("expected-output-local-additional")

            def runner(spec, job_directory, environment):
                manifest = experiment_tests.write_manifest(spec, job_directory)
                self._append_output(
                    job_directory,
                    manifest,
                    path="diagnostic.json",
                    logical_type="diagnostic_payload",
                    payload=b'{"kind":"additional"}\n',
                )
                return ExecutionResult(0)

            backend = self._diagnostic_backend(Path(directory), runner)
            receipt = backend.submit(run_spec, idempotency_key="local-additional-output")

            self.assertEqual(receipt.state, RunState.SUCCEEDED)
            self.assertIn(
                "diagnostic_payload",
                {item.logical_type for item in backend.collect(receipt.job_id).manifest.artifacts},
            )

    def test_shared_validation_preserves_seed_result_and_seed_results_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base_spec = experiment_tests.spec("expected-output-seed-aliases")

            for expected_alias in ("seed_result", "seed_results"):
                with self.subTest(expected_alias=expected_alias):
                    run_spec = replace(
                        base_spec,
                        expected_outputs=("output_manifest", expected_alias),
                    )
                    manifest = experiment_tests.write_manifest(run_spec, Path(directory))
                    _validate_manifest_bindings(
                        run_spec,
                        manifest,
                    )

    def test_shared_validation_refuses_absent_custom_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base_spec = experiment_tests.spec("expected-output-shared-missing")
            run_spec = replace(
                base_spec,
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )
            manifest = experiment_tests.write_manifest(run_spec, Path(directory))

            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "frozen expected output type",
            ):
                _validate_manifest_bindings(run_spec, manifest)

    def test_filename_cannot_substitute_for_expected_logical_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_spec = experiment_tests.spec("expected-output-filename-substitute")
            run_spec = replace(
                base_spec,
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )
            manifest = experiment_tests.write_manifest(run_spec, root)
            mismatched = self._append_output(
                root,
                manifest,
                path="analysis-report.json",
                logical_type="unrelated_payload",
                payload=b'{"result":"wrong-type"}\n',
            )

            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "frozen expected output type",
            ):
                _validate_manifest_bindings(run_spec, mismatched)

    def test_local_refuses_expected_artifact_descriptor_without_its_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = replace(
                experiment_tests.spec("expected-output-missing-file"),
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )

            def runner(spec, job_directory, environment):
                manifest = experiment_tests.write_manifest(spec, job_directory)
                self._append_output(
                    job_directory,
                    manifest,
                    path="analysis-report.json",
                    logical_type="analysis_report",
                    payload=b"declared-but-not-written",
                    write_payload=False,
                )
                return ExecutionResult(0)

            backend = self._diagnostic_backend(Path(directory), runner)
            receipt = backend.submit(run_spec, idempotency_key="local-missing-artifact")

            self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)
            with self.assertRaises(ExperimentIntegrityError):
                backend.collect(receipt.job_id)

    def test_local_refuses_altered_expected_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = replace(
                experiment_tests.spec("expected-output-altered-artifact"),
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )

            def runner(spec, job_directory, environment):
                manifest = experiment_tests.write_manifest(spec, job_directory)
                self._append_output(
                    job_directory,
                    manifest,
                    path="analysis-report.json",
                    logical_type="analysis_report",
                    payload=b'{"result":"verified"}\n',
                )
                (job_directory / "analysis-report.json").write_bytes(
                    b'{"result":"altered"}\n'
                )
                return ExecutionResult(0)

            backend = self._diagnostic_backend(Path(directory), runner)
            receipt = backend.submit(run_spec, idempotency_key="local-altered-artifact")

            self.assertEqual(receipt.state, RunState.INVALID_OUTPUT)
            with self.assertRaises(ExperimentIntegrityError):
                backend.collect(receipt.job_id)

    def test_shared_validation_preserves_negative_and_null_seed_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = experiment_tests.spec("expected-output-null-negative")
            manifest = experiment_tests.write_manifest(run_spec, Path(directory))
            results = list(manifest.seed_results)
            results[0] = replace(results[0], status=SeedRunStatus.NEGATIVE)
            results[1] = replace(results[1], status=SeedRunStatus.NULL)
            completed = replace(manifest, seed_results=tuple(results))

            _validate_manifest_bindings(run_spec, completed)
            self.assertEqual(completed.seed_results[0].status, SeedRunStatus.NEGATIVE)
            self.assertEqual(completed.seed_results[1].status, SeedRunStatus.NULL)

    def test_fake_gpu_completion_refuses_absent_custom_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_spec = replace(
                experiment_tests.spec("expected-output-fake-missing"),
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )
            backend = FakeGPUCloudBackend()
            receipt = backend.submit(run_spec, idempotency_key="fake-missing-output")
            backend.start(receipt.job_id)
            manifest = experiment_tests.write_manifest(run_spec, Path(directory))

            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "frozen expected output type",
            ):
                backend.complete(receipt.job_id, manifest)
            self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.RUNNING)

    def test_fake_gpu_completion_accepts_present_custom_output_non_evidentiary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_spec = replace(
                experiment_tests.spec("expected-output-fake-present"),
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )
            backend = FakeGPUCloudBackend()
            receipt = backend.submit(run_spec, idempotency_key="fake-present-output")
            backend.start(receipt.job_id)
            manifest = experiment_tests.write_manifest(run_spec, root)
            completed = self._append_output(
                root,
                manifest,
                path="analysis-report.json",
                logical_type="analysis_report",
                payload=b'{"result":"fixture"}\n',
            )
            returned_payloads = {
                item.sha256: (root / item.path).read_bytes()
                for item in completed.artifacts
            }

            status = backend.complete(
                receipt.job_id,
                completed,
                returned_payloads=returned_payloads,
            )
            collected = backend.collect(receipt.job_id)

            self.assertEqual(status.state, RunState.SUCCEEDED)
            self.assertFalse(collected.scientific_evidence)
            self.assertEqual(
                collected.returned_artifact_sha256s,
                tuple(item.sha256 for item in completed.artifacts),
            )

    def test_scheduled_gpu_completion_refuses_absent_custom_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, cloud, receipt, provider_job_id = (
                self._scheduled_completion_fixture(root, "expected-output-scheduled-missing")
            )
            artifact_root = root / "scheduled-missing-return"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest=manifest,
                artifacts=tuple(
                    StagedArtifact(item, (artifact_root / item.path).read_bytes())
                    for item in manifest.artifacts
                ),
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id,
                spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256,
                attempt=1,
                resumed_checkpoint_sha256=None,
                requeue_history=(),
            )

            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "scheduled GPU artifact return is invalid",
            ):
                backend.collect(receipt.job_id)
            self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.INVALID_OUTPUT)

    def test_scheduled_gpu_completion_accepts_present_custom_output_non_evidentiary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, cloud, receipt, provider_job_id = (
                self._scheduled_completion_fixture(root, "expected-output-scheduled-present")
            )
            artifact_root = root / "scheduled-present-return"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            completed = self._append_output(
                artifact_root,
                manifest,
                path="analysis-report.json",
                logical_type="analysis_report",
                payload=b'{"result":"fixture"}\n',
            )
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest=completed,
                artifacts=tuple(
                    StagedArtifact(item, (artifact_root / item.path).read_bytes())
                    for item in completed.artifacts
                ),
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id,
                spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256,
                attempt=1,
                resumed_checkpoint_sha256=None,
                requeue_history=(),
            )

            collected = backend.collect(receipt.job_id)

            self.assertFalse(collected.scientific_evidence)
            self.assertIn(
                "analysis_report",
                {item.logical_type for item in collected.manifest.artifacts},
            )

    def test_legacy_incomplete_cache_recovery_and_collect_refuse_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_spec = replace(
                experiment_tests.spec("expected-output-legacy-cache"),
                expected_outputs=("output_manifest", "seed_results", "analysis_report"),
            )

            def legacy_runner(spec, job_directory, environment):
                experiment_tests.write_manifest(spec, job_directory)
                return ExecutionResult(0)

            legacy_backend = self._diagnostic_backend(root, legacy_runner)
            with mock.patch(
                "scientist_one.experiments._missing_expected_output_types",
                return_value=(),
            ):
                legacy_receipt = legacy_backend.submit(
                    run_spec,
                    idempotency_key="legacy-incomplete-cache",
                )
            self.assertEqual(legacy_receipt.state, RunState.SUCCEEDED)
            legacy_directory = (
                root
                / ".scientist-one-build"
                / "experiments"
                / "local-mac"
                / legacy_receipt.job_id
            )
            frozen_spec_bytes = (legacy_directory / "frozen-run-spec.json").read_bytes()
            manifest_bytes = (legacy_directory / "output-manifest.json").read_bytes()
            artifact_bytes = {
                f"seed-{seed}.json": (legacy_directory / f"seed-{seed}.json").read_bytes()
                for seed in run_spec.seeds
            }

            def assert_legacy_cache_bytes_unchanged() -> None:
                self.assertEqual(
                    (legacy_directory / "frozen-run-spec.json").read_bytes(),
                    frozen_spec_bytes,
                )
                self.assertEqual(
                    (legacy_directory / "output-manifest.json").read_bytes(),
                    manifest_bytes,
                )
                self.assertEqual(
                    {
                        path: (legacy_directory / path).read_bytes()
                        for path in artifact_bytes
                    },
                    artifact_bytes,
                )

            valid_spec = experiment_tests.spec("expected-output-legacy-valid-cache")
            valid_receipt = legacy_backend.submit(
                valid_spec,
                idempotency_key="legacy-valid-cache",
            )
            self.assertEqual(valid_receipt.state, RunState.SUCCEEDED)

            recovery_runner_calls = 0

            def recovery_runner(spec, job_directory, environment):
                nonlocal recovery_runner_calls
                recovery_runner_calls += 1
                raise AssertionError("cache recovery must not execute a replacement run")

            recovered_backend = self._diagnostic_backend(root, recovery_runner)
            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "frozen expected output type",
            ):
                recovered_backend.recover(
                    run_spec,
                    idempotency_key="legacy-cache-refused",
                )
            assert_legacy_cache_bytes_unchanged()

            # This narrow fixture bypass models only the formerly admitted cache.
            with mock.patch(
                "scientist_one.experiments._missing_expected_output_types",
                return_value=(),
            ):
                recovered = recovered_backend.recover(
                    run_spec,
                    idempotency_key="legacy-cache-collect-refused",
                )
            self.assertEqual(recovered.state, RunState.SUCCEEDED)
            with self.assertRaises(ExperimentIntegrityError):
                recovered_backend.collect(recovered.job_id)
            assert_legacy_cache_bytes_unchanged()

            valid_recovered = recovered_backend.recover(
                valid_spec,
                idempotency_key="legacy-valid-cache-recovered",
            )
            self.assertEqual(valid_recovered.state, RunState.SUCCEEDED)
            self.assertEqual(
                recovered_backend.collect(valid_recovered.job_id).manifest.run_id,
                valid_spec.run_id,
            )
            self.assertEqual(recovery_runner_calls, 0)
