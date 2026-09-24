"""Synthetic, offline byte-contract checks; no Colab CLI or GPU is invoked."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import unittest

from scientist_one.colab_preparation import ColabInputPreparation, inspect_colab_output
from scientist_one.errors import ValidationError
from scientist_one.experiments import (
    EvidenceClass,
    ExperimentError,
    ExperimentIntegrityError,
    ExperimentPhase,
    GPUCloudSubmissionPlan,
    OutputArtifact,
    OutputManifest,
    ScheduledGPURequest,
    SchedulerKind,
    SeedRunResult,
    SeedRunStatus,
    ValidationStatus,
)
from scientist_one.security import canonical_json_bytes
from tests.test_experiments import gpu_estimate, gpu_profile, spec


WORKER = b"# synthetic bytes, never executed\n"
CONFIG = b'{"engineering_example":true}\n'
DATA = b"synthetic input\n"
COMMIT = "1" * 40  # Deliberately not an actual reviewed source identity.


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def request_for(run_spec=None):
    if run_spec is None:
        run_spec = replace(
            spec(
                "colab-offline",
                profile=replace(
                    gpu_profile(scheduler=SchedulerKind.DIRECT_REMOTE),
                    supports_preemption=False,
                ),
                estimate=gpu_estimate(),
            ),
            code_sha256=digest(WORKER),
            configuration_sha256=digest(CONFIG),
            data_sha256=digest(DATA),
        )
    plan = GPUCloudSubmissionPlan(
        spec_sha256=run_spec.sha256,
        project_definition_sha256=run_spec.project_definition_sha256,
        compute_profile_sha256=run_spec.compute_profile.sha256,
        escalation_decision_sha256="2" * 64,
        scheduler=run_spec.compute_profile.scheduler,
        queue_name=run_spec.compute_profile.queue_name,
        accelerator_count=run_spec.compute_profile.accelerator_count,
        checkpoint_policy=run_spec.checkpoint_policy,
    )
    return ScheduledGPURequest(run_spec, plan, "offline-only")


def example_output(request):
    payloads = {f"seed-{seed}.json": str(seed).encode() for seed in request.spec.seeds}
    artifacts = tuple(
        OutputArtifact(path, digest(raw), len(raw), "seed_results")
        for path, raw in payloads.items()
    )
    outcomes = (SeedRunStatus.SUCCESS, SeedRunStatus.NEGATIVE, SeedRunStatus.NULL, SeedRunStatus.FAILED)
    results = tuple(
        SeedRunResult(
            seed, outcome, None if outcome is SeedRunStatus.FAILED else 0.0,
            artifact.sha256, "synthetic infrastructure failure" if outcome is SeedRunStatus.FAILED else None,
        )
        for seed, outcome, artifact in zip(request.spec.seeds, outcomes, artifacts)
    )
    run_spec = request.spec
    manifest = OutputManifest(
        run_spec.run_id, run_spec.sha256, run_spec.code_sha256, run_spec.data_sha256,
        run_spec.configuration_sha256, run_spec.evaluator_sha256,
        run_spec.seeds, results, artifacts,
    )
    return manifest, payloads


class ColabPreparationTests(unittest.TestCase):
    def setUp(self):
        self.request = request_for()

    def prepare(self, **changes):
        values = dict(request=self.request, source_commit=COMMIT, worker_bytes=WORKER,
                      configuration_bytes=CONFIG, data_bytes=DATA)
        values.update(changes)
        return ColabInputPreparation(**values)

    def inspect(self, manifest=None, payloads=None, **changes):
        original, original_payloads = example_output(self.request)
        values = dict(request=self.request, manifest_bytes=canonical_json_bytes(
            (manifest or original).to_dict()),
            payloads=original_payloads if payloads is None else payloads,
            provider_job_id="synthetic-job-not-a-real-runtime")
        values.update(changes)
        return inspect_colab_output(**values)

    def test_input_identity_is_deterministic_and_not_source_review_or_authority(self):
        before = self.request.to_dict()
        prepared = self.prepare()
        report = prepared.to_dict()
        self.assertEqual(report["classification"], "OFFLINE_PREPARATION_NOT_EXECUTION_AUTHORITY")
        self.assertEqual(report["source_commit_verification"], "CALLER_SUPPLIED_NOT_VERIFIED")
        self.assertFalse(report["scientific_evidence"])
        self.assertEqual(report["external_validation"], "UNTESTED")
        self.assertEqual(report["request_sha256"], digest(canonical_json_bytes(before)))
        self.assertEqual(report["inputs"], [
            {"role": name, "size": len(raw), "sha256": digest(raw)}
            for name, raw in (("worker.py", WORKER), ("configuration.bin", CONFIG), ("data.bin", DATA))
        ])
        self.assertEqual(prepared.sha256, self.prepare().sha256)
        self.assertEqual(before, self.request.to_dict())
        self.assertNotIn(DATA.decode(), repr(prepared))
        self.assertNotIn("compute_units", report)  # Existing money is never relabeled CU.

    def test_complete_commit_required_but_not_authenticated(self):
        for value in ("main", "1" * 39, "A" * 40, "1" * 41, "../main", True, None):
            with self.subTest(value=value), self.assertRaises(ExperimentError):
                self.prepare(source_commit=value)
        self.assertNotEqual(self.prepare().sha256, self.prepare(source_commit="2" * 40).sha256)

    def test_each_input_hash_is_bound_and_mutable_bytes_are_refused(self):
        for field in ("worker_bytes", "configuration_bytes", "data_bytes"):
            with self.subTest(field=field), self.assertRaises(ExperimentIntegrityError):
                self.prepare(**{field: b"changed"})
            for wrong in (b"", bytearray(DATA), "text", None):
                with self.subTest(field=field, wrong=type(wrong)), self.assertRaises(ExperimentError):
                    self.prepare(**{field: wrong})

    def test_preparation_and_returned_metadata_do_not_mutate_request(self):
        prepared = self.prepare()
        before = prepared.to_dict()
        with self.assertRaises(FrozenInstanceError):
            prepared.source_commit = "2" * 40
        report = prepared.to_dict()
        report["inputs"][0]["sha256"] = "0" * 64
        self.assertEqual(prepared.to_dict(), before)

    def test_unsupported_scheduler_and_multiple_gpus_are_not_advertised(self):
        for profile, estimate in (
            (gpu_profile(), gpu_estimate()),
            (gpu_profile(count=2, scheduler=SchedulerKind.DIRECT_REMOTE), gpu_estimate(count=2)),
        ):
            request = request_for(replace(self.request.spec, compute_profile=profile, resource_estimate=estimate))
            with self.assertRaises(ExperimentError):
                self.prepare(request=request)

    def test_confirmation_and_retries_cannot_enter_first_profile(self):
        for changed in (
            replace(self.request.spec, phase=ExperimentPhase.CONFIRMATORY),
            replace(self.request.spec, attempt=2, retry_of_run_id="old-run"),
        ):
            request = request_for(changed)
            with self.assertRaises(ExperimentError):
                self.prepare(request=request)
            with self.assertRaises(ExperimentError):
                inspect_colab_output(request, manifest_bytes=b"{}", payloads={}, provider_job_id="not-run")

    def test_scientific_evidence_class_is_not_enabled_by_preparation(self):
        for evidence_class in EvidenceClass:
            if evidence_class is not EvidenceClass.NON_EVIDENTIARY:
                with self.subTest(evidence_class=evidence_class), self.assertRaises(ExperimentError):
                    self.prepare(request=request_for(replace(self.request.spec, evidence_class=evidence_class)))

    def test_plan_projection_mismatch_is_refused_without_changing_old_schema(self):
        for field in ("project_definition_sha256", "compute_profile_sha256"):
            request = replace(self.request, submission_plan=replace(self.request.submission_plan, **{field: "f" * 64}))
            with self.subTest(field=field), self.assertRaises(ExperimentIntegrityError):
                self.prepare(request=request)

    def test_all_outcomes_and_exact_raw_manifest_are_retained_not_promoted(self):
        manifest, payloads = example_output(self.request)
        raw = canonical_json_bytes(manifest.to_dict()) + b"\n"
        bundle = self.inspect(manifest_bytes=raw)
        self.assertEqual(bundle.manifest_bytes, raw)
        self.assertEqual(bundle.manifest, manifest)
        self.assertEqual(bundle.external_validation, ValidationStatus.UNTESTED)
        self.assertEqual(bundle.submission_plan_sha256, self.request.submission_plan.sha256)
        self.assertEqual(bundle.attempt, 1)
        self.assertIsNone(bundle.resumed_checkpoint_sha256)
        self.assertEqual(bundle.requeue_history, ())
        self.assertEqual({item.descriptor.path: item.payload for item in bundle.artifacts}, payloads)
        self.assertEqual(tuple(item.status for item in bundle.manifest.seed_results),
                         (SeedRunStatus.SUCCESS, SeedRunStatus.NEGATIVE, SeedRunStatus.NULL, SeedRunStatus.FAILED))

    def test_missing_extra_or_corrupted_payload_does_not_form_bundle(self):
        _, payloads = example_output(self.request)
        cases = ({}, {**payloads, "unplanned.json": b"x"}, {**payloads, "seed-11.json": b"wrong"})
        for changed in cases:
            with self.subTest(keys=tuple(changed)), self.assertRaises(ExperimentIntegrityError):
                self.inspect(payloads=changed)

    def test_each_frozen_manifest_identity_is_rechecked(self):
        manifest, _ = example_output(self.request)
        for field in ("spec_sha256", "code_sha256", "data_sha256", "configuration_sha256", "evaluator_sha256"):
            with self.subTest(field=field), self.assertRaises(ExperimentIntegrityError):
                self.inspect(replace(manifest, **{field: "e" * 64}))
        with self.assertRaises(ExperimentIntegrityError):
            self.inspect(replace(manifest, run_id="different-run"))

    def test_missing_or_duplicate_seed_outcomes_refuse_incomplete_return(self):
        manifest, _ = example_output(self.request)
        for results in (manifest.seed_results[:-1], manifest.seed_results[:-1] + (manifest.seed_results[0],)):
            with self.assertRaises(ExperimentIntegrityError):
                self.inspect(replace(manifest, seed_results=results))

    def test_duplicate_artifact_paths_refuse_even_with_distinct_hashes(self):
        manifest, _ = example_output(self.request)
        artifacts = list(manifest.artifacts)
        artifacts[1] = replace(artifacts[1], path=artifacts[0].path)
        with self.assertRaises(ExperimentIntegrityError):
            self.inspect(replace(manifest, artifacts=tuple(artifacts)))

    def test_original_expected_outputs_and_ablation_rules_remain_in_force(self):
        manifest, _ = example_output(self.request)
        request = request_for(replace(self.request.spec, required_ablations=("missing-ablation",)))
        changed = replace(manifest, spec_sha256=request.spec.sha256)
        with self.assertRaises(ExperimentIntegrityError):
            self.inspect(changed, request=request)
        request = request_for(replace(
            self.request.spec,
            expected_outputs=(*self.request.spec.expected_outputs, "predictions"),
        ))
        changed = replace(manifest, spec_sha256=request.spec.sha256)
        with self.assertRaises(ExperimentIntegrityError):
            self.inspect(changed, request=request)
        # Supplying the additional required type is sufficient for the minimum
        # output interface, not proof of scientific correctness or execution.
        present = replace(changed, artifacts=(
            replace(changed.artifacts[0], logical_type="predictions"),
            *changed.artifacts[1:],
        ))
        self.assertEqual(self.inspect(present, request=request).manifest, present)

    def test_malformed_json_duplicate_keys_and_unknown_schema_are_not_results(self):
        for raw in (b"{", b'{"schema_version":1,"schema_version":2}', b"[]", b"{}", b"NaN"):
            with self.subTest(raw=raw), self.assertRaises((ExperimentError, ValidationError)):
                self.inspect(manifest_bytes=raw)
        manifest, _ = example_output(self.request)
        value = manifest.to_dict()
        value["authority"] = "PASS"
        with self.assertRaises(ExperimentError):
            self.inspect(manifest_bytes=canonical_json_bytes(value))


if __name__ == "__main__":
    unittest.main()
