"""Focused custody tests for locally persisted adaptive execution plans."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.experiments import (
    ExperimentPhase,
    FrozenRunSpec,
    LocalMacBackend,
)
from scientist_one.ledger import EventLedger
from scientist_one.orchestrator import (
    OrchestrationError,
    _validate_vnext_adaptive_plan_binding,
)
from scientist_one.research_os import (
    _DesignArtifacts,
    _FoundationBundle,
    _promote_collected_run,
    _register_static_file,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


_BOUND_CHILD = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import stat

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def held(fd):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("bound input is not a private regular file")
    data = os.pread(fd, before.st_size, 0)
    after = os.fstat(fd)
    if len(data) != before.st_size or (before.st_dev, before.st_ino,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns):
        raise RuntimeError("bound input changed while read")
    return data

def env_fd(name):
    value = os.environ.get(name)
    if value is None or not value.isdigit():
        raise RuntimeError("missing bound descriptor")
    return int(value)

def write_new(directory_fd, name, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

job_fd = env_fd("SCIENTIST_ONE_JOB_DIR_FD")
spec_bytes = held(os.open("frozen-run-spec.json", os.O_RDONLY | os.O_NOFOLLOW,
                          dir_fd=job_fd))
spec = json.loads(spec_bytes.decode("utf-8"))
if spec_bytes != canonical(spec) + b"\n":
    raise RuntimeError("frozen spec is not canonical")
if hashlib.sha256(canonical(spec)).hexdigest() != os.environ["SCIENTIST_ONE_SPEC_SHA256"]:
    raise RuntimeError("frozen spec hash mismatch")
for kind in ("CODE", "DATA", "CONFIGURATION", "EVALUATOR"):
    held(env_fd("SCIENTIST_ONE_INPUT_" + kind + "_FD"))
seed = spec["seeds"][0]
payload = canonical({"metric": 0.25, "run_id": spec["run_id"], "seed": seed}) + b"\n"
digest = hashlib.sha256(payload).hexdigest()
write_new(job_fd, "seed-result.json", payload)
manifest = {
    "schema_version": "SCIENTIST_ONE_OUTPUT_MANIFEST_V1",
    "run_id": spec["run_id"],
    "spec_sha256": os.environ["SCIENTIST_ONE_SPEC_SHA256"],
    "code_sha256": spec["code_sha256"],
    "data_sha256": spec["data_sha256"],
    "configuration_sha256": spec["configuration_sha256"],
    "evaluator_sha256": spec["evaluator_sha256"],
    "planned_seeds": spec["seeds"],
    "seed_results": [{"seed": seed, "status": "SUCCESS", "metric": 0.25,
                       "artifact_sha256": digest, "reason": None}],
    "artifacts": [{"path": "seed-result.json", "sha256": digest,
                    "size": len(payload), "logical_type": "seed_result"}],
    "ablations": [],
}
write_new(job_fd, "output-manifest.json", canonical(manifest) + b"\n")
'''


class ResearchOSExecutionPlanCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="scientist-one-plan-custody-"
        )
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root)
        self.ledger = EventLedger(self.root, "runs/custody/events.jsonl")
        records = list(self._record(f"foundation-{index}") for index in range(8))
        fixture = self.root / "fixtures" / "plan-custody-worker.py"
        fixture.parent.mkdir()
        fixture.write_text(_BOUND_CHILD, encoding="utf-8")
        records[1] = self.registry.register_file(
            "fixtures/plan-custody-worker.py",
            logical_type="foundation-1",
            origin="focused custody Python execution fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "execution-plan-custody"),
            schema_version="1.0",
            mime_type="text/x-python",
            validation_result="PASS",
            frozen=True,
        )
        records = tuple(records)
        self.foundations = _FoundationBundle(*records)
        designs = tuple(self._record(f"design-{index}") for index in range(4))
        self.design = _DesignArtifacts(*designs)
        self.backend = LocalMacBackend(
            self.root,
            allowed_executables=("/usr/bin/python3",),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(self, identity: str) -> ArtifactRecord:
        return self.registry.put_json(
            {"identity": identity},
            logical_type=identity,
            origin=f"focused custody fixture {identity}",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("test", "execution-plan-custody"),
            validation_result="PASS",
            frozen=True,
        )

    def _spec(self, run_id: str) -> FrozenRunSpec:
        return FrozenRunSpec(
            run_id=run_id,
            experiment_id="experiment-plan-custody",
            hypothesis_id="hypothesis-plan-custody",
            phase=ExperimentPhase.EXPLORATORY,
            argv=(
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "fixtures/plan-custody-worker.py",
            ),
            working_directory=".",
            code_sha256=self.foundations.experiment_code.sha256,
            data_sha256=self.foundations.dataset.sha256,
            configuration_sha256=self.foundations.configuration.sha256,
            evaluator_sha256=self.foundations.evaluator.sha256,
            seeds=(7,),
        )

    def _submit_collect(self, run_id: str):
        submission = self.backend.submit(
            self._spec(run_id),
            idempotency_key=f"submit-{run_id}",
            input_artifact_paths={
                "code": "fixtures/plan-custody-worker.py",
                "data": self.foundations.dataset.path,
                "configuration": self.foundations.configuration.path,
                "evaluator": self.foundations.evaluator.path,
            },
        )
        return submission, self.backend.collect(submission.job_id)

    def test_plan_bytes_deduplicate_while_each_run_gets_an_exact_binding(self) -> None:
        first_submission, first_collected = self._submit_collect("custody-first")
        first_relative = (
            ".scientist-one-build/experiments/local-mac/"
            f"{first_submission.job_id}"
        )
        pre_registered_spec = _register_static_file(
            self.registry,
            f"{first_relative}/frozen-run-spec.json",
            logical_type="autonomous_implementation.frozen_run_spec",
            creator_role=Role.IMPLEMENTER,
            mime_type="application/json",
            parents=(self.foundations.configuration.sha256,),
        )
        first = _promote_collected_run(
            self.registry,
            self.ledger,
            global_run_id="custody-global",
            backend=self.backend,
            submission=first_submission,
            collected=first_collected,
            foundations=self.foundations,
            design_artifacts=self.design,
            registered_spec_artifact=pre_registered_spec,
        )
        self.assertEqual(first.frozen_spec, pre_registered_spec)

        second_submission, second_collected = self._submit_collect("custody-second")
        second = _promote_collected_run(
            self.registry,
            self.ledger,
            global_run_id="custody-global",
            backend=self.backend,
            submission=second_submission,
            collected=second_collected,
            foundations=self.foundations,
            design_artifacts=self.design,
        )

        self.assertEqual(first.execution_plan, second.execution_plan)
        self.assertNotEqual(
            first.execution_plan_binding.sha256,
            second.execution_plan_binding.sha256,
        )
        records = self.registry.verify_all(raise_on_error=True).records
        self.assertEqual(
            sum(record.logical_type == "adaptive_execution_plan" for record in records),
            1,
        )
        self.assertEqual(
            sum(
                record.logical_type == "adaptive_execution_plan_binding"
                for record in records
            ),
            2,
        )
        events = self.ledger.validate(raise_on_error=True).events
        for captured, submission, collected in (
            (first, first_submission, first_collected),
            (second, second_submission, second_collected),
        ):
            binding = json.loads(
                self.registry.get_bytes(captured.execution_plan_binding.sha256)
            )
            self.assertTrue(binding["agreement"])
            self.assertEqual(binding["run_id"], collected.spec.run_id)
            self.assertEqual(binding["job_id"], submission.job_id)
            self.assertEqual(binding["spec_sha256"], collected.spec.sha256)
            self.assertEqual(
                binding["submission_spec_sha256"], collected.spec.sha256
            )
            self.assertEqual(
                binding["collected_spec_sha256"], collected.spec.sha256
            )
            self.assertEqual(
                binding["submission_backend_id"], self.backend.backend_id
            )
            self.assertEqual(
                binding["collected_backend_id"], self.backend.backend_id
            )
            self.assertEqual(
                binding["execution_plan_sha256"],
                submission.execution_plan_sha256,
            )
            self.assertEqual(
                binding["collected_execution_plan_sha256"],
                collected.execution_plan_sha256,
            )
            self.assertEqual(
                captured.execution_plan_binding.parent_artifacts,
                (
                    captured.execution_plan.sha256,
                    captured.execution_input_binding.sha256,
                    captured.frozen_spec.sha256,
                ),
            )
            self.assertEqual(
                binding["execution_input_binding_sha256"],
                captured.execution_input_binding.sha256,
            )
            self.assertEqual(
                binding["execution_input_binding_artifact_sha256"],
                captured.execution_input_binding.sha256,
            )
            self.assertIn(captured.execution_plan.sha256, captured.all_hashes)
            self.assertIn(
                captured.execution_plan_binding.sha256,
                captured.all_hashes,
            )
            event = next(item for item in events if item.event_id == captured.ledger_event_id)
            self.assertTrue(set(captured.all_hashes).issubset(event.artifact_hashes))

    def test_tampered_or_rebound_plan_fails_before_registry_promotion(self) -> None:
        submission, collected = self._submit_collect("custody-tamper")
        plan_path = (
            self.root
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
        with self.assertRaisesRegex(
            RuntimeError,
            "persisted backend execution plan differs from submission or collection",
        ):
            _promote_collected_run(
                self.registry,
                self.ledger,
                global_run_id="custody-global",
                backend=self.backend,
                submission=submission,
                collected=collected,
                foundations=self.foundations,
                design_artifacts=self.design,
            )

        rebound_submission, rebound_collected = self._submit_collect(
            "custody-rebound"
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "persisted backend execution plan differs from submission or collection",
        ):
            _promote_collected_run(
                self.registry,
                self.ledger,
                global_run_id="custody-global",
                backend=self.backend,
                submission=rebound_submission,
                collected=replace(
                    rebound_collected,
                    execution_plan_sha256="0" * 64,
                ),
                foundations=self.foundations,
                design_artifacts=self.design,
            )

    def test_vnext_verifier_requires_the_exact_canonical_plan_binding(self) -> None:
        run_id = "custody-vnext-verifier"
        submission = self.backend.submit(
            self._spec(run_id),
            idempotency_key=run_id,
            input_artifact_paths={
                "code": "fixtures/plan-custody-worker.py",
                "data": self.foundations.dataset.path,
                "configuration": self.foundations.configuration.path,
                "evaluator": self.foundations.evaluator.path,
            },
        )
        collected = self.backend.collect(submission.job_id)
        captured = _promote_collected_run(
            self.registry,
            self.ledger,
            global_run_id="custody-global",
            backend=self.backend,
            submission=submission,
            collected=collected,
            foundations=self.foundations,
            design_artifacts=self.design,
        )
        encoded = self.registry.get_bytes(captured.execution_plan_binding.sha256)
        binding = json.loads(encoded)

        def validate(
            value: dict[str, object],
            raw: bytes,
            *,
            parents: tuple[str, ...] | None = None,
            returned_artifacts: tuple[str, ...] | None = None,
        ) -> None:
            _validate_vnext_adaptive_plan_binding(
                value,
                encoded=raw,
                parent_artifacts=(
                    captured.execution_plan_binding.parent_artifacts
                    if parents is None
                    else parents
                ),
                run_id=run_id,
                spec_artifact_sha256=captured.frozen_spec.sha256,
                spec_sha256=collected.spec.sha256,
                execution_plan_artifact_sha256=captured.execution_plan.sha256,
                execution_plan_sha256=str(collected.execution_plan_sha256),
                registry=self.registry,
                execution_input_binding_artifact_sha256=(
                    captured.execution_input_binding.sha256
                ),
                frozen_spec=collected.spec,
                manifest_artifact_sha256=captured.output_manifest.sha256,
                returned_artifact_sha256s=(
                    collected.returned_artifact_sha256s
                    if returned_artifacts is None
                    else returned_artifacts
                ),
            )

        validate(binding, encoded)

        missing = dict(binding)
        missing.pop("collected_manifest_sha256")
        with self.assertRaisesRegex(
            OrchestrationError, "missing or unknown fields"
        ):
            validate(missing, canonical_json_bytes(missing) + b"\n")

        unknown = dict(binding)
        unknown["caller_asserted_pass"] = True
        with self.assertRaisesRegex(
            OrchestrationError, "missing or unknown fields"
        ):
            validate(unknown, canonical_json_bytes(unknown) + b"\n")

        reversed_fields = dict(reversed(tuple(binding.items())))
        noncanonical = (
            json.dumps(reversed_fields, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        self.assertNotEqual(noncanonical, encoded)
        with self.assertRaisesRegex(OrchestrationError, "not canonical JSON"):
            validate(binding, noncanonical)

        substituted = dict(binding)
        substituted["submission_idempotency_key"] = "substituted-run"
        with self.assertRaisesRegex(OrchestrationError, "custody binding is invalid"):
            validate(substituted, canonical_json_bytes(substituted) + b"\n")

        spliced = dict(binding)
        spliced["submission_execution_input_binding_sha256"] = "0" * 64
        with self.assertRaisesRegex(OrchestrationError, "custody binding is invalid"):
            validate(spliced, canonical_json_bytes(spliced) + b"\n")

        tampered_input = dict(binding)
        tampered_input["execution_input_binding_artifact_sha256"] = "f" * 64
        with self.assertRaisesRegex(OrchestrationError, "custody binding is invalid"):
            validate(tampered_input, canonical_json_bytes(tampered_input) + b"\n")

        expected_output_order = (
            *collected.returned_artifact_sha256s,
            "f" * 64,
        )
        reordered_outputs = dict(binding)
        reordered_outputs["collected_returned_artifact_sha256s"] = list(
            reversed(expected_output_order)
        )
        with self.assertRaisesRegex(OrchestrationError, "custody binding is invalid"):
            validate(
                reordered_outputs,
                canonical_json_bytes(reordered_outputs) + b"\n",
                returned_artifacts=expected_output_order,
            )

        with self.assertRaisesRegex(OrchestrationError, "parent order is invalid"):
            validate(
                binding,
                encoded,
                parents=tuple(
                    reversed(captured.execution_plan_binding.parent_artifacts)
                ),
            )


if __name__ == "__main__":
    unittest.main()
