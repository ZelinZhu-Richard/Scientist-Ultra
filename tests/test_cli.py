"""CLI/orchestration integration checks; standard library and offline only."""

from __future__ import annotations

import ast
import base64
import contextlib
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import uuid
from unittest import mock

# Direct imports in this module are an explicitly marked test capability.  A
# production process cannot obtain this marker from the verified launcher.
sys._scientist_one_test_runner = True  # type: ignore[attr-defined]

from scientist_one.cli import _dispatch, build_parser, main
from scientist_one.artifacts import ArtifactRegistry, artifact_record_hash
from scientist_one.evaluators import Decision, Evaluation, EvaluatorClass
from scientist_one.holdout import SimulatedHoldoutCustody
from scientist_one.orchestrator import OrchestrationError, ScientistOneOrchestrator
from scientist_one.packaging import (
    PackagingError,
    _assert_gateway_trust_root_not_serialized,
    _contains_forbidden_boundary_text,
    _ledger_evaluator_projection,
    _publish_immutable,
    _validate_custody_snapshot,
    _validate_resource_authority_projection,
    _zip_bytes,
    package_run,
)
from scientist_one.ledger import EventLedger
from scientist_one.reproduction import (
    ARCHITECTURE_CONTROL_REPLAY_SCOPE,
    ARCHITECTURE_CONTROL_REPLAY_STATUS,
    ReproductionError,
    _atomic_write,
    _canonical_json,
    _mean,
    _require_replay_source_classification,
    reproduce_run,
    verify_frozen_architecture_control_reproduction,
    verify_frozen_reproduction,
)
from scientist_one.recovery import RecoveryReport, ResumeAction
from scientist_one.resources import ResourceAction, ResourceController
from scientist_one.roles import Role


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_RESOURCE_EVALUATE = ResourceController.evaluate


class _CliFixtureOwner:
    """Test-only returned-ID ownership, not controller or scientific authority."""

    def __init__(self, root: Path, *, run_only: bool = False):
        if type(root) is not type(Path()) or type(run_only) is not bool:
            raise AssertionError("fixture root/profile type is invalid")
        self.root = root
        self.run_only = run_only
        self._run_ids = []
        self._packages = {}
        self.cleanup_incomplete = False
        self._require_root()
        self._directory(root / "runs")
        self._directory(root / ".scientist-one-build")
        archive = root / ".scientist-one-build" / "test-runs"
        if not self._present(archive):
            archive.mkdir()
        self._directory(archive)

    @staticmethod
    def _safe_id(value):
        return type(value) is str and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value
        ) is not None

    @staticmethod
    def _present(path):
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _directory(path):
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise AssertionError("unsafe fixture directory")

    @staticmethod
    def _file(path):
        if not stat.S_ISREG(path.lstat().st_mode):
            raise AssertionError("unsafe fixture file")

    @classmethod
    def _absent(cls, path):
        if cls._present(path):
            raise AssertionError("fixture destination/reserved subtree conflict")

    def _require_root(self):
        if not self.root.is_absolute() or self.root.resolve(strict=True) != self.root:
            raise AssertionError("fixture root is not canonical")
        self._directory(self.root)

    def _record_return(self, result):
        run_id = result.get("run_id") if type(result) is dict else None
        if not self._safe_id(run_id):
            raise AssertionError("unsafe returned run ID")
        if run_id in self._run_ids:
            raise AssertionError("duplicate returned run ID")
        self._run_ids.append(run_id)

    def start(self, controller, *args, **kwargs):
        # No interception: a partial start that raises exposes no owned ID.
        result = controller.start(*args, **kwargs)
        self._record_return(result)
        return result

    def demo(self, controller, **kwargs):
        # Genuine demo remains one call, including its original internal start.
        result = controller.demo(**kwargs)
        self._record_return(result)
        self.record_package(result["run_id"], result.get("package"))
        return result

    def record_package(self, run_id, package):
        if not self._safe_id(run_id) or run_id not in self._run_ids:
            raise AssertionError("package run is not fixture-owned")
        if package is None:
            return
        if self.run_only or type(package) is not dict or package.get("run_id") != run_id:
            raise AssertionError("package ownership/profile mismatch")
        if run_id in self._packages:
            raise AssertionError("package already recorded")
        records = []
        for path_key, hash_key, suffix in (
            ("archive_path", "archive_sha256", ".zip"),
            ("envelope_path", "envelope_sha256", ".final-envelope.json"),
        ):
            digest = package.get(hash_key)
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise AssertionError("invalid package identity hash")
            expected = "artifacts/release_candidates/" + run_id + "-" + digest[:20] + suffix
            path = package.get(path_key)
            if type(path) is not str or path != expected:
                raise AssertionError("noncanonical package identity path")
            records.append((path, digest))
        # Immutable copied identity metadata; this does not verify current bytes.
        self._packages[run_id] = tuple(records)

    def _diagnose_cleanup(self):
        self.cleanup_incomplete = True
        try:
            # Fixed bounded metadata, no payload/exception serialization.
            sys.stderr.write("CLI_FIXTURE_CLEANUP_INCOMPLETE reason=ARCHIVE_FAILED\n")
            sys.stderr.flush()
        except Exception:
            return

    def archive(self):
        if not self._run_ids:
            return
        try:
            self._archive()
        except Exception:
            self._diagnose_cleanup()
            # Preserve earlier actual moves and the actual failure; never retry.
            raise

    def _archive(self):
        self._require_root()
        root = self.root
        build = root / ".scientist-one-build"
        runs = root / "runs"
        archive = build / "test-runs"
        parents = [root, build, runs, archive]
        if not self.run_only:
            parents += [build / "custody", build / "resource-authority"]
        if self._packages:
            parents += [root / "artifacts", root / "artifacts" / "release_candidates"]
        for parent in parents:
            self._directory(parent)
        ids = tuple(self._run_ids)
        if any(not self._safe_id(value) for value in ids) or len(set(ids)) != len(ids):
            raise AssertionError("unsafe or duplicate fixture ownership")
        if any(value not in ids for value in self._packages):
            raise AssertionError("package ownership lost")
        plans = []
        # Preflight the complete fixed target set before any move.
        for run_id in ids:
            source, destination = runs / run_id, archive / run_id
            self._directory(source)
            self._absent(destination)
            ancillary = []
            packages = []
            if not self.run_only:
                self._absent(source / "external-authority")
                self._absent(source / "release-candidates")
                for path, name, kind in (
                    (build / "custody" / (run_id + ".jsonl"), "custody.jsonl", "file"),
                    (build / "resource-authority" / run_id, "resource", "dir"),
                ):
                    present = self._present(path)
                    if present:
                        (self._file if kind == "file" else self._directory)(path)
                    ancillary.append((path, name, kind, present))
                for relative, digest in self._packages.get(run_id, ()):
                    path = root / relative
                    self._file(path)
                    packages.append((path, path.name, digest))
            elif self._packages:
                raise AssertionError("run-only fixture cannot own packages")
            plans.append((source, destination, tuple(ancillary), tuple(packages)))
        for source, destination, ancillary, packages in plans:
            self._require_root()
            for parent in parents:
                self._directory(parent)
            self._directory(source)
            self._absent(destination)
            if not self.run_only:
                self._absent(source / "external-authority")
                self._absent(source / "release-candidates")
            os.replace(source, destination)
            self._directory(destination)
            if self.run_only:
                continue
            external = destination / "external-authority"
            release = destination / "release-candidates"
            self._absent(external)
            self._absent(release)
            if any(present for _, _, _, present in ancillary):
                external.mkdir()
            if packages:
                release.mkdir()
            for path, name, kind, present in ancillary:
                self._require_root()
                for parent in (*parents, destination):
                    self._directory(parent)
                if self._present(path) != present:
                    raise AssertionError("authority presence changed after preflight")
                if not present:
                    continue
                (self._file if kind == "file" else self._directory)(path)
                self._directory(external)
                target = external / name
                self._absent(target)
                os.replace(path, target)
            for path, name, _digest in packages:
                self._require_root()
                for parent in (*parents, destination, release):
                    self._directory(parent)
                self._file(path)
                target = release / name
                self._absent(target)
                os.replace(path, target)
        # Checkpoints, rollback archives and unknown partial outputs stay put.


@contextlib.contextmanager
def _captured_evidence_dispatch():
    """Provide the exact captured-runner contract in a normal focused test."""

    import scientist_one.orchestrator as orchestration_module

    if "_scientist_one_captured_evidence_capability" in sys.__dict__:
        yield
        return
    paths = (PROJECT_ROOT / "scripts" / "scientist_one_cli.py",) + tuple(
        sorted((PROJECT_ROOT / "src" / "scientist_one").glob("*.py"))
    )
    entries = []
    for path in paths:
        data = path.read_bytes()
        info = os.stat(path, follow_symlinks=False)
        entries.append(
            (
                path.relative_to(PROJECT_ROOT).as_posix(),
                hashlib.sha256(data).hexdigest(),
                len(data),
                info.st_dev,
                info.st_ino,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        )
    entries.sort(key=lambda entry: entry[0])
    module_path = Path(orchestration_module.__file__)
    module_data = module_path.read_bytes()
    record = types.SimpleNamespace(
        path=module_path,
        identity=os.stat(module_path, follow_symlinks=False),
        sha256=hashlib.sha256(module_data).hexdigest(),
    )
    loader_type = type(
        "_CapturedSourceLoader", (), {"__module__": "__main__"}
    )
    loader = loader_type()
    loader.tree = types.SimpleNamespace(
        root=PROJECT_ROOT,
        root_identity=os.stat(PROJECT_ROOT, follow_symlinks=False),
        records={"scientist_one.orchestrator": record},
    )
    loader.executed = {"scientist_one.orchestrator": record.sha256}
    with mock.patch.object(
        orchestration_module, "__loader__", loader
    ), mock.patch.object(
        orchestration_module.__spec__, "loader", loader
    ), mock.patch.object(
        sys, "meta_path", [loader, *sys.meta_path]
    ), mock.patch.dict(
        sys.__dict__,
        {
            "_scientist_one_captured_evidence_capability": loader,
            "_scientist_one_captured_source_attestation": (
                "SCIENTIST_ONE_CAPTURED_SOURCE_V1",
                tuple(entries),
            ),
            "_scientist_one_test_runner": True,
        },
        clear=False,
    ):
        yield


@contextlib.contextmanager
def _without_sys_attribute(name: str):
    """Temporarily remove one runner-owned marker and restore its exact value."""

    missing = object()
    original = sys.__dict__.pop(name, missing)
    try:
        yield
    finally:
        if original is not missing:
            sys.__dict__[name] = original


class ParserTests(unittest.TestCase):
    def test_required_command_surface_parses(self) -> None:
        parser = build_parser()
        cases = (
            (["preflight"], "preflight"),
            (["calibrate"], "calibrate"),
            (["start"], "start"),
            (["start", "--brief", "RESEARCH_BRIEF.md"], "start"),
            (["demo"], "demo"),
            (["research-os-fixture"], "research-os-fixture"),
            (
                ["research-os-fixture", "--run-id", "fixture-run"],
                "research-os-fixture",
            ),
            (
                [
                    "research-os-fixture",
                    "--run-id",
                    "fixture-restart",
                    "--restart-from",
                    "fixture-abandoned",
                ],
                "research-os-fixture",
            ),
            (["status"], "status"),
            (["status", "run-1"], "status"),
            (["resume", "run-1"], "resume"),
            (["verify", "run-1"], "verify"),
            (["reproduce", "run-1"], "reproduce"),
            (["package", "run-1"], "package"),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(parser.parse_args(arguments).command, expected)

    def test_research_os_restart_dispatch_binds_exact_command_context(
        self,
    ) -> None:
        parser = build_parser()
        arguments = parser.parse_args(
            [
                "research-os-fixture",
                "--run-id",
                "fixture-restart",
                "--restart-from",
                "fixture-abandoned",
            ]
        )
        orchestrator = mock.Mock()
        orchestrator.research_os_fixture.return_value = {"status": "PASS"}
        result = _dispatch(orchestrator, arguments)
        self.assertEqual(result, {"status": "PASS"})
        orchestrator.set_command_context.assert_called_once_with(
            [
                "python3",
                "-I",
                "-S",
                "-B",
                "scripts/scientist_one_cli.py",
                "research-os-fixture",
                "--run-id",
                "fixture-restart",
                "--restart-from",
                "fixture-abandoned",
            ]
        )
        orchestrator.research_os_fixture.assert_called_once_with(
            "fixture-restart",
            restart_from_run_id="fixture-abandoned",
        )

        missing_run = parser.parse_args(
            ["research-os-fixture", "--restart-from", "fixture-abandoned"]
        )
        with self.assertRaisesRegex(
            ValueError,
            "--restart-from requires",
        ):
            _dispatch(orchestrator, missing_run)

    def test_lifecycle_commands_require_run_id(self) -> None:
        parser = build_parser()
        for command in ("resume", "verify", "reproduce", "package"):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                parser.parse_args([command])

    def test_legacy_module_entrypoint_fails_before_state_mutation(self) -> None:
        state = PROJECT_ROOT / "state" / "PREFLIGHT_RESULT.json"
        before = state.read_bytes() if state.exists() else None
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-B", "-m", "scientist_one", "preflight"],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["error_type"], "UnsafeStartupError")
        self.assertEqual(state.read_bytes() if state.exists() else None, before)

    def test_sys_executable_subprocesses_disable_bytecode_writes(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        commands: list[tuple[int, ast.List | ast.Tuple]] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in {"run", "Popen"}
                and node.args
                and isinstance(node.args[0], (ast.List, ast.Tuple))
                and node.args[0].elts
            ):
                continue
            executable = node.args[0].elts[0]
            if (
                isinstance(executable, ast.Attribute)
                and isinstance(executable.value, ast.Name)
                and executable.value.id == "sys"
                and executable.attr == "executable"
            ):
                commands.append((node.lineno, node.args[0]))

        self.assertTrue(commands, "expected direct sys.executable subprocesses")
        for line, command in commands:
            flags = {
                element.value
                for element in command.elts
                if isinstance(element, ast.Constant)
                and isinstance(element.value, str)
            }
            self.assertIn(
                "-B",
                flags,
                f"test Python subprocess at line {line} may mutate captured source",
            )

    def test_captured_root_capability_fails_closed_outside_test_runner(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with _without_sys_attribute(
            "_scientist_one_captured_evidence_capability"
        ), mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), mock.patch.object(
            sys, "_scientist_one_test_runner", False, create=True
        ), mock.patch.object(
            orchestration_module, "__loader__", object()
        ), self.assertRaisesRegex(
            OrchestrationError, "captured dispatch capability is invalid"
        ):
            orchestration_module._captured_project_root()

    def test_evidence_markers_without_exact_loader_fail_closed(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with mock.patch.dict(
            sys.__dict__,
            {
                "_scientist_one_captured_evidence_capability": object(),
                "_scientist_one_captured_source_attestation": (
                    "SCIENTIST_ONE_CAPTURED_SOURCE_V1",
                    (),
                ),
                "_scientist_one_test_runner": True,
            },
            clear=False,
        ), self.assertRaisesRegex(
            OrchestrationError, "captured dispatch capability is invalid"
        ):
            orchestration_module._source_inventory(PROJECT_ROOT)

    def test_raw_attestation_without_verified_dispatch_fails_closed(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with _without_sys_attribute(
            "_scientist_one_captured_evidence_capability"
        ), mock.patch.dict(
            sys.__dict__,
            {
                "_scientist_one_captured_source_attestation": (
                    "SCIENTIST_ONE_CAPTURED_SOURCE_V1",
                    (),
                ),
                "_scientist_one_test_runner": True,
            },
            clear=False,
        ), self.assertRaisesRegex(
            OrchestrationError, "outside verified dispatch"
        ):
            orchestration_module._source_inventory(PROJECT_ROOT)

    def test_captured_audit_dispatch_accepts_exact_loader_without_test_marker(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with _captured_evidence_dispatch(), _without_sys_attribute(
            "_scientist_one_test_runner"
        ):
            inventory = orchestration_module._source_inventory(PROJECT_ROOT)
            captured = orchestration_module._captured_project_root()
        self.assertEqual(inventory["kind"], "FROZEN_SOURCE_INVENTORY")
        self.assertIsNotNone(captured)
        self.assertEqual(captured[0], PROJECT_ROOT)


class PackagingResourceAuthorityProjectionTests(unittest.TestCase):
    @staticmethod
    def _authority(
        *records: tuple[str, str]
    ) -> tuple[dict[str, bytes], list[dict[str, object]]]:
        authority: dict[str, bytes] = {}
        descriptors: list[dict[str, object]] = []
        prior: str | None = None
        for sequence, (logical_type, state_sha256) in enumerate(records):
            data = json.dumps(
                {
                    "logical_type": logical_type,
                    "state_sha256": state_sha256,
                    "prior_authority_sha256": prior,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            digest = hashlib.sha256(data).hexdigest()
            authority[f"{sequence:04d}-{digest}.json"] = data
            descriptors.append(
                {
                    "sequence": sequence,
                    "logical_type": logical_type,
                    "state_sha256": state_sha256,
                    "authority_sha256": digest,
                    "prior_authority_sha256": prior,
                }
            )
            prior = digest
        return authority, descriptors

    @staticmethod
    def _event(
        descriptor: dict[str, object],
        *,
        event_type: str,
        state: str = "CONFIRM",
        state_before: str | None = None,
        logical_type: str | None = None,
        artifact_sha256: str | None = None,
        evidence_class: str | None = None,
        execution_kind: str | None = None,
    ) -> object:
        metadata: dict[str, object] = {
            "artifact_types": [
                logical_type or str(descriptor["logical_type"])
            ],
            "resource_authority_checkpoint": descriptor,
        }
        if evidence_class is not None:
            metadata["evidence_class"] = evidence_class
        if execution_kind is not None:
            metadata["execution_kind"] = execution_kind
        return types.SimpleNamespace(
            metadata=metadata,
            artifact_hashes=(
                artifact_sha256 or str(descriptor["state_sha256"]),
            ),
            event_type=event_type,
            state_before=types.SimpleNamespace(value=state_before or state),
            requested_state_after=types.SimpleNamespace(value=state),
        )

    def test_confirmatory_started_accepts_one_exact_charge_reference(self) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(descriptors[0], event_type="CHECKPOINT")
        started = self._event(
            descriptors[0], event_type="CONFIRMATORY_STARTED"
        )
        _validate_resource_authority_projection((charge, started), authority)

    def test_architecture_control_start_accepts_one_exact_charge_reference(
        self,
    ) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(
            descriptors[0], event_type="CHECKPOINT", state="CANDIDATE"
        )
        started = self._event(
            descriptors[0],
            event_type="CHECKPOINT",
            state="CANDIDATE",
            evidence_class="ARCHITECTURE_CONTROL",
            execution_kind="SIMULATED_ARCHITECTURE_CONTROL_STARTED",
        )
        _validate_resource_authority_projection((charge, started), authority)

    def test_architecture_control_charge_reference_rejects_marker_and_replay(
        self,
    ) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(descriptors[0], event_type="CHECKPOINT")
        valid = self._event(
            descriptors[0],
            event_type="CHECKPOINT",
            evidence_class="ARCHITECTURE_CONTROL",
            execution_kind="SIMULATED_ARCHITECTURE_CONTROL_STARTED",
        )
        candidates = (
            self._event(
                descriptors[0],
                event_type="CHECKPOINT",
                execution_kind="SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            ),
            self._event(
                descriptors[0],
                event_type="CHECKPOINT",
                evidence_class="ARCHITECTURE_CONTROL",
                execution_kind="SIMULATED_ARCHITECTURE_CONTROL_COMPLETED",
            ),
            self._event(
                descriptors[0],
                event_type="CONFIRMATORY_STARTED",
                evidence_class="ARCHITECTURE_CONTROL",
                execution_kind="SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            ),
            self._event(
                descriptors[0],
                event_type="CHECKPOINT",
                state="CANDIDATE",
                state_before="CONFIRM",
                evidence_class="ARCHITECTURE_CONTROL",
                execution_kind="SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            ),
        )
        for index, candidate in enumerate(candidates):
            with self.subTest(case=index), self.assertRaises(PackagingError):
                _validate_resource_authority_projection(
                    (charge, candidate), authority
                )
        with self.assertRaises(PackagingError):
            _validate_resource_authority_projection(
                (charge, valid, valid), authority
            )

    def test_confirmatory_started_rejects_second_charge_reference(self) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(descriptors[0], event_type="CHECKPOINT")
        first = self._event(descriptors[0], event_type="CONFIRMATORY_STARTED")
        second = self._event(descriptors[0], event_type="CONFIRMATORY_STARTED")
        with self.assertRaises(PackagingError):
            _validate_resource_authority_projection(
                (charge, first, second), authority
            )

    def test_charge_reference_rejects_wrong_event_or_state(self) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(descriptors[0], event_type="CHECKPOINT")
        for label, event in (
            (
                "event",
                self._event(descriptors[0], event_type="CHECKPOINT"),
            ),
            (
                "state",
                self._event(
                    descriptors[0],
                    event_type="CONFIRMATORY_STARTED",
                    state="PILOT",
                ),
            ),
        ):
            with self.subTest(label=label), self.assertRaises(PackagingError):
                _validate_resource_authority_projection((charge, event), authority)

    def test_charge_reference_rejects_altered_binding_hash_or_order(self) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        charge = self._event(descriptors[0], event_type="CHECKPOINT")
        altered = dict(descriptors[0])
        altered["authority_sha256"] = "f" * 64
        candidates = (
            self._event(altered, event_type="CONFIRMATORY_STARTED"),
            self._event(
                descriptors[0],
                event_type="CONFIRMATORY_STARTED",
                artifact_sha256="b" * 64,
            ),
            self._event(
                descriptors[0],
                event_type="CONFIRMATORY_STARTED",
                logical_type="resource_runtime_confirmatory_completion",
            ),
        )
        for index, event in enumerate(candidates):
            with self.subTest(case=index), self.assertRaises(PackagingError):
                _validate_resource_authority_projection((charge, event), authority)

        ordered_authority, ordered = self._authority(
            ("resource_runtime_pilot_completion", "b" * 64),
            ("resource_runtime_confirmatory_charge", "a" * 64),
        )
        with self.assertRaises(PackagingError):
            _validate_resource_authority_projection(
                (self._event(ordered[1], event_type="CHECKPOINT"),),
                ordered_authority,
            )

    def test_confirmatory_started_cannot_replace_charge_checkpoint(self) -> None:
        authority, descriptors = self._authority(
            ("resource_runtime_confirmatory_charge", "a" * 64)
        )
        started = self._event(
            descriptors[0], event_type="CONFIRMATORY_STARTED"
        )
        with self.assertRaises(PackagingError):
            _validate_resource_authority_projection((started,), authority)


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)
        self._fixture_owner = _CliFixtureOwner(PROJECT_ROOT)
        self.addCleanup(self._fixture_owner.archive)

    def test_unsafe_recovery_actions_dominate_status_without_resume_command(self) -> None:
        manifest = {
            "run_id": "status-recovery",
            "current_state": "CALIBRATE",
            "terminal_state": None,
            "outcome": "IN_PROGRESS",
            "mode": "synthetic_demo",
            "artifacts": {},
            "event_count": 1,
        }
        for action in (
            ResumeAction.STOP_SECURITY,
            ResumeAction.STOP_SCIENTIFIC_INVALIDITY,
            ResumeAction.NEW_STUDY_REQUIRED,
        ):
            report = RecoveryReport(
                action=action,
                reasons=("validated recovery refusal",),
                ledger_valid=False,
                ledger_event_count=1,
                ledger_head_hash=None,
                artifacts_valid=True,
                artifact_issues=(),
                quarantined=(),
                checkpoint=None,
                derived_state="CALIBRATE",
                confirmatory_touched=False,
                confirmatory_completed=False,
            )
            with self.subTest(action=action.value), mock.patch.object(
                self.orchestrator,
                "_fixture_operation_receipt",
                return_value=None,
            ), mock.patch.object(
                self.orchestrator, "load_manifest", return_value=dict(manifest)
            ), mock.patch.object(
                self.orchestrator, "_assert_no_newer_external_checkpoint"
            ), mock.patch.object(
                self.orchestrator, "_recovery_report", return_value=report
            ):
                status = self.orchestrator.status("status-recovery")
            self.assertEqual(status["status"], action.value)
            self.assertEqual(status["outcome"], action.value)
            self.assertFalse(status["resumable"])
            self.assertNotIn("safe_resume_command", status)

    def test_resume_never_reenters_a_persisted_terminal_stop(self) -> None:
        for action in (
            ResumeAction.STOP_SECURITY,
            ResumeAction.STOP_SCIENTIFIC_INVALIDITY,
        ):
            terminal_state = action.value
            manifest = {
                "run_id": "persisted-stop",
                "current_state": terminal_state,
                "terminal_state": terminal_state,
                "outcome": terminal_state,
                "mode": "synthetic_demo",
                "artifacts": {},
            }
            report = RecoveryReport(
                action=action,
                reasons=(f"PERSISTED_TERMINAL_STATE:{terminal_state}",),
                ledger_valid=True,
                ledger_event_count=2,
                ledger_head_hash="a" * 64,
                artifacts_valid=True,
                artifact_issues=(),
                quarantined=(),
                checkpoint=None,
                derived_state=terminal_state,
                confirmatory_touched=True,
                confirmatory_completed=True,
            )
            expected = {
                "status": terminal_state,
                "resumable": False,
            }
            with self.subTest(action=action.value), mock.patch.object(
                self.orchestrator, "load_manifest", return_value=manifest
            ), mock.patch.object(
                self.orchestrator, "_recovery_report", return_value=report
            ), mock.patch.object(
                self.orchestrator, "status", return_value=expected
            ) as status, mock.patch.object(
                self.orchestrator, "_resource_controller"
            ) as resource_controller, mock.patch.object(
                self.orchestrator, "_queue_terminal"
            ) as queue_terminal:
                result = self.orchestrator.resume("persisted-stop")
            self.assertEqual(result, expected)
            status.assert_called_once_with("persisted-stop")
            resource_controller.assert_not_called()
            queue_terminal.assert_not_called()

    def test_v1_transition_authority_is_inspectable_but_never_resumed(self) -> None:
        manifest = {
            "run_id": "legacy-v1",
            "current_state": "CHARTER",
            "terminal_state": None,
            "mode": "synthetic_demo",
            "artifacts": {},
        }
        report = RecoveryReport(
            action=ResumeAction.STOP_SECURITY,
            reasons=(
                "ledger validation failed: INVALID_LEGACY_TRANSITION_AUTHORITY:"
                "invalid transition receipt schema",
            ),
            ledger_valid=False,
            ledger_event_count=2,
            ledger_head_hash="a" * 64,
            artifacts_valid=True,
            artifact_issues=(),
            quarantined=(),
            checkpoint=None,
            derived_state="CHARTER",
            confirmatory_touched=False,
            confirmatory_completed=False,
        )
        with mock.patch.object(
            self.orchestrator, "load_manifest", return_value=manifest
        ), mock.patch.object(
            self.orchestrator, "_recovery_report", return_value=report
        ), mock.patch.object(
            self.orchestrator, "_queue_terminal"
        ) as queue_terminal:
            result = self.orchestrator.resume("legacy-v1")
        queue_terminal.assert_not_called()
        self.assertEqual(result["authority_channel"], "LEGACY_V1_AUTHORITY_REFUSAL")
        self.assertEqual(result["current_state"], "CHARTER")
        self.assertFalse(result["persisted"])
        self.assertFalse(result["resumable"])

    def test_root_is_bound_to_current_bootstrapped_workspace(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            fake = Path(temporary) / "ScientistOne"
            (fake / "state").mkdir(parents=True)
            (fake / "state" / "APP_SESSION_BOOTSTRAP.json").write_text(
                json.dumps(
                    {
                        "app_session_bootstrap": "PASS",
                        "canonical_project_root": str(fake.resolve()),
                    }
                )
            )
            with self.assertRaises(OrchestrationError):
                ScientistOneOrchestrator(fake)

    def test_commands_reject_same_name_root_replacement_before_state_io(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            parent = Path(temporary)
            admitted = parent / "ScientistOne"
            displaced = parent / "ScientistOne-displaced"
            admitted.mkdir()
            identity = os.stat(admitted, follow_symlinks=False)
            orchestrator = object.__new__(ScientistOneOrchestrator)
            orchestrator.root = admitted.resolve(strict=True)
            orchestrator._root_identity = (identity.st_dev, identity.st_ino)
            orchestrator._command_thread_lock = threading.RLock()
            orchestrator._command_guard_state = threading.local()
            os.replace(admitted, displaced)
            admitted.mkdir()

            with mock.patch.object(
                orchestrator,
                "load_manifest",
                side_effect=AssertionError("replacement root state must not be read"),
            ) as state_read:
                for command in (
                    orchestrator.status,
                    orchestrator.verify,
                    orchestrator.reproduce,
                    orchestrator.package,
                    orchestrator.advance_once,
                ):
                    with self.subTest(command=command.__name__), self.assertRaisesRegex(
                        OrchestrationError,
                        "project resource namespace identity changed",
                    ):
                        command("run-root-replacement")
            state_read.assert_not_called()

    def test_commands_reject_symlink_to_displaced_root_before_state_io(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            parent = Path(temporary)
            admitted = parent / "ScientistOne"
            displaced = parent / "ScientistOne-displaced"
            admitted.mkdir()
            identity = os.stat(admitted, follow_symlinks=False)
            orchestrator = object.__new__(ScientistOneOrchestrator)
            orchestrator.root = admitted.resolve(strict=True)
            orchestrator._root_identity = (identity.st_dev, identity.st_ino)
            orchestrator._command_thread_lock = threading.RLock()
            orchestrator._command_guard_state = threading.local()
            os.replace(admitted, displaced)
            admitted.symlink_to(displaced.name, target_is_directory=True)

            with mock.patch.object(
                orchestrator,
                "load_manifest",
                side_effect=AssertionError("symlinked root state must not be read"),
            ) as state_read, self.assertRaisesRegex(
                OrchestrationError,
                "project resource namespace identity changed",
            ):
                orchestrator.status("run-root-symlink-replacement")
            state_read.assert_not_called()

    def test_command_root_guard_does_not_share_reentrancy_between_threads(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        second_finished = threading.Event()
        errors: list[BaseException] = []

        def first_thread() -> None:
            try:
                with self.orchestrator._command_root_guard():
                    entered.set()
                    if not release.wait(5):
                        raise AssertionError("timed out waiting to release root guard")
            except BaseException as exc:
                errors.append(exc)

        def second_thread() -> None:
            try:
                self.orchestrator.status("missing-threaded-run")
            except OrchestrationError:
                pass
            except BaseException as exc:
                errors.append(exc)
            finally:
                second_finished.set()

        first = threading.Thread(target=first_thread)
        second = threading.Thread(target=second_thread)
        first.start()
        self.assertTrue(entered.wait(5))
        with mock.patch.object(
            self.orchestrator,
            "load_manifest",
            side_effect=OrchestrationError("expected post-lock sentinel"),
        ) as state_read, mock.patch.object(
            self.orchestrator,
            "_fixture_operation_receipt",
            return_value=None,
        ):
            second.start()
            self.assertFalse(second_finished.wait(0.2))
            state_read.assert_not_called()
            release.set()
            self.assertTrue(second_finished.wait(5))
            state_read.assert_called_once_with("missing-threaded-run")
        first.join(5)
        second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])

    def test_project_local_import_shadow_is_rejected_before_run_start(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            shadow = Path(temporary) / "json.py"
            shadow.write_text("SHADOW = True\n")
            module = types.ModuleType("json_shadow_probe")
            module.__file__ = str(shadow)
            with mock.patch.dict(
                "sys.modules", {"json_shadow_probe": module}, clear=False
            ), self.assertRaises(OrchestrationError):
                self._fixture_owner.start(self.orchestrator)

    def test_path_traversal_run_id_is_rejected(self) -> None:
        with self.assertRaises(OrchestrationError):
            self.orchestrator.status("../outside")

    def test_brief_outside_root_is_rejected(self) -> None:
        with self.assertRaises(OrchestrationError):
            self._fixture_owner.start(self.orchestrator, "/tmp/not-project-evidence.md")

    def test_start_without_brief_is_synthetic_and_resumable(self) -> None:
        result = self._fixture_owner.start(self.orchestrator)
        self.assertEqual(result["mode"], "synthetic_demo")
        self.assertEqual(result["current_state"], "CALIBRATE")
        self.assertTrue(result["resumable"])
        manifest = self.orchestrator.load_manifest(result["run_id"])
        self.assertEqual(manifest["external_integrations_used"], [])
        self.assertNotIn("E4", json.dumps(manifest["evaluator_decisions"]))

    def test_captured_evidence_dispatch_binds_source_inventory_and_start(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with _captured_evidence_dispatch():
            inventory = orchestration_module._source_inventory(PROJECT_ROOT)
            captured = orchestration_module._captured_project_root()
            self.assertIsNotNone(captured)
            self.assertEqual(captured[0], PROJECT_ROOT)
            orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)
            started = self._fixture_owner.start(orchestrator)
            manifest = orchestrator.load_manifest(started["run_id"])
            frozen = orchestrator._json_artifact_payload(
                manifest, "frozen_source_inventory"
            )
        self.assertEqual(frozen, inventory)

    def test_production_and_evidence_dispatch_authority_is_rejected(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with _captured_evidence_dispatch(), mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), self.assertRaisesRegex(
            OrchestrationError, "captured dispatch authority is ambiguous"
        ):
            orchestration_module._captured_project_root()

    @unittest.skipUnless(
        hasattr(__import__("scientist_one.calibration", fromlist=["run_calibration"]), "_calibration_report_sha256"),
        "calibration owner is repairing a concurrent helper regression",
    )
    def test_small_end_to_end_demo_reproduces_and_packages(self) -> None:
        protected_live_inputs = (
            PROJECT_ROOT / "configs" / "resource_limits.json",
            PROJECT_ROOT / "scripts" / "scientist_one_cli.py",
            *sorted((PROJECT_ROOT / "src" / "scientist_one").glob("*.py")),
        )

        def live_input_identity(path: Path) -> tuple[int, int, int, int, int, str]:
            info = os.stat(path, follow_symlinks=False)
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

        live_input_identities = {
            path: live_input_identity(path) for path in protected_live_inputs
        }
        with mock.patch.object(
            ResourceController, "evaluate", autospec=True
        ) as evaluate:
            evaluate.side_effect = lambda controller, *args, **kwargs: replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )
            result = self._fixture_owner.demo(self.orchestrator)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["terminal_state"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(result["outcome"], "COMPLETE_DEMO_ONLY")
        self.assertEqual(result["reproduction"]["absolute_difference"], 0.0)
        self.assertEqual(
            result["reproduction"]["status"],
            ARCHITECTURE_CONTROL_REPLAY_STATUS,
        )
        self.assertTrue(result["package"]["e4_required"])
        self.assertTrue(result["package"]["envelope_sha256"])
        run_id = result["run_id"]
        verified = self.orchestrator.verify(run_id)
        self.assertEqual(verified["status"], "PASS")
        self.assertEqual(self.orchestrator.resume(run_id)["event_count"], result["event_count"])
        manifest = self.orchestrator.load_manifest(run_id)
        self.assertEqual(
            manifest["r_checks"],
            {
                "R0": "PASS",
                "R1": "PASS",
                "R2": "PASS",
                "R3": "UNTESTED",
                "R4": "PASS",
                "R5": "PASS",
                "R6": "PASS",
                "R7": "UNTESTED",
            },
        )
        self.assertNotIn("E4", json.dumps(manifest["evaluator_decisions"]))
        self.assertTrue(manifest["artifacts"]["release_candidate"]["registry_record_hash"])
        self.assertEqual(manifest["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(manifest["resource_runtime_state"]["confirmatory_used"], 4)
        self.assertEqual(self.orchestrator.reproduce(run_id), manifest["reproduction"])
        verified_replay = verify_frozen_architecture_control_reproduction(
            PROJECT_ROOT,
            run_id,
            manifest["reproduction"],
        )
        self.assertEqual(
            verified_replay.status,
            ARCHITECTURE_CONTROL_REPLAY_STATUS,
        )
        # Reuse this real frozen replay to exercise the R7 adapter.  A matching
        # local synthetic replay is still not independent scientific evidence.
        from scientist_one.evaluators import (
            AuthorityScope,
            AuthorityStatus,
            RCheck,
            _derive_status,
            _fixture_scope,
        )

        replay_registry = self.orchestrator._registry(run_id)
        replay_record = replay_registry.get_metadata(
            manifest["artifacts"]["reproduction_report"]["sha256"]
        )
        replay_payload = self.orchestrator._json_artifact_payload(
            manifest, "reproduction_report"
        )
        replay_scope = _fixture_scope((replay_record,), (replay_payload,))
        self.assertIs(replay_scope, AuthorityScope.SYSTEM_FIXTURE)
        r7_status, r7_reason, r7_checks = _derive_status(
            replay_registry,
            EventLedger(PROJECT_ROOT, f"runs/{run_id}/events.jsonl"),
            run_id, RCheck.R7, EvaluatorClass.E3,
            (replay_record,), (replay_payload,), replay_scope,
        )
        self.assertIs(r7_status, AuthorityStatus.UNTESTED)
        self.assertEqual(
            r7_reason, "ARCHITECTURE_CONTROL_REPRODUCTION_NON_EVIDENTIARY"
        )
        self.assertIn(("frozen_reproduction_replay", "PASS"), r7_checks)
        with self.assertRaises(ReproductionError):
            verify_frozen_reproduction(
                PROJECT_ROOT,
                run_id,
                manifest["reproduction"],
            )
        with self.assertRaises(ReproductionError):
            reproduce_run(PROJECT_ROOT, run_id, timestamp=manifest["created_at"])
        replay_manifest = json.loads(
            (PROJECT_ROOT / manifest["reproduction"]["manifest_path"]).read_text()
        )
        replay_result = json.loads(
            (PROJECT_ROOT / manifest["reproduction"]["result_path"]).read_text()
        )
        for packet in (replay_manifest, replay_result):
            self.assertEqual(
                packet["replay_scope"], ARCHITECTURE_CONTROL_REPLAY_SCOPE
            )
            self.assertEqual(packet["evidence_class"], "ARCHITECTURE_CONTROL")
            self.assertIs(packet["scientific_evidence"], False)
            self.assertIs(packet["independent_confirmation"], False)
            self.assertIs(packet["publication_eligible"], False)
        custody = self.orchestrator._json_artifact_payload(manifest, "custody_record")
        protocol = self.orchestrator._json_artifact_payload(
            manifest, "frozen_protocol"
        )["protocol"]
        self.assertEqual(custody["study_id"], protocol["study_id"])
        self.assertEqual(custody["study_version"], protocol["study_version"])
        self.assertRegex(custody["journal_identity_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            custody["pre_unblinding_interpretation_hash"],
            manifest["artifacts"]["blind_interpretation"]["sha256"],
        )
        self.assertEqual(len(manifest["artifacts"]["claim_graph"]["parent_artifacts"]), 24)
        code_evidence = self.orchestrator._json_artifact_payload(
            manifest, "claim_evidence.code"
        )
        self.assertEqual(
            set(manifest["artifacts"]["claim_evidence.code"]["parent_artifacts"]),
            {
                manifest["artifacts"]["frozen_source_inventory"]["sha256"],
                manifest["artifacts"]["frozen_configuration_inventory"]["sha256"],
            },
        )
        self.assertEqual(
            code_evidence["source_inventory_sha256"],
            manifest["artifacts"]["frozen_source_inventory"]["sha256"],
        )
        run_directory = PROJECT_ROOT / "runs" / run_id
        events = [
            json.loads(line)
            for line in (run_directory / "events.jsonl").read_text().splitlines()
        ]
        started_index = next(
            index for index, event in enumerate(events)
            if event["event_type"] == "CHECKPOINT"
            and event["metadata"].get("execution_kind")
            == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
        )
        completed_index = next(
            index for index, event in enumerate(events)
            if event["event_type"] == "CHECKPOINT"
            and event["metadata"].get("execution_kind")
            == "SIMULATED_ARCHITECTURE_CONTROL_COMPLETED"
        )
        self.assertFalse(
            any(
                event["event_type"]
                in {"CONFIRMATORY_STARTED", "CONFIRMATORY_COMPLETED"}
                for event in events
            )
        )
        candidate_index = next(
            index for index, event in enumerate(events)
            if event["state_before"] == "CANDIDATE"
            and event["requested_state_after"] == "CONFIRM"
        )
        self.assertLess(candidate_index, started_index)
        self.assertLess(started_index, completed_index)
        custody_checkpoint = next(
            event
            for event in events
            if event["event_type"] == "CHECKPOINT"
            and event["actor_role"] == "holdout_custodian"
        )
        self.assertLess(events.index(custody_checkpoint), started_index)
        self.assertEqual(
            custody_checkpoint["metadata"]["fresh_custody"]["artifact_sha256"],
            manifest["artifacts"]["fresh_custody_receipt"]["sha256"],
        )
        original_manifest = json.loads(json.dumps(manifest))
        tampered = json.loads(json.dumps(manifest))
        tampered["artifacts"]["machine_results"] = dict(
            tampered["artifacts"]["frozen_protocol"]
        )
        self.orchestrator._save_manifest(tampered)
        with self.assertRaises((ReproductionError, OrchestrationError)):
            self.orchestrator.reproduce(run_id)
        tampered = json.loads(json.dumps(original_manifest))
        tampered["reproduction"]["result_path"] = tampered["reproduction"]["manifest_path"]
        self.orchestrator._save_manifest(tampered)
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)
        tampered = json.loads(json.dumps(original_manifest))
        tampered["package"]["archive_sha256"] = "0" * 64
        self.orchestrator._save_manifest(tampered)
        with self.assertRaises((PackagingError, OrchestrationError)):
            self.orchestrator.package(run_id)
        self.orchestrator._save_manifest(original_manifest)
        receipt_name = "claim_support_receipt.limitation"
        receipt_record = original_manifest["artifacts"][receipt_name]
        metadata_path = PROJECT_ROOT / receipt_record["registry_metadata_path"]
        metadata_bytes = metadata_path.read_bytes()
        forged_metadata = json.loads(metadata_bytes)
        forged_metadata["origin"] = "forged same-content provenance"
        forged_metadata["record_hash"] = artifact_record_hash(
            {
                key: value
                for key, value in forged_metadata.items()
                if key != "record_hash"
            }
        )
        metadata_path.write_text(
            json.dumps(forged_metadata, sort_keys=True, separators=(",", ":"))
        )
        forged_manifest = json.loads(json.dumps(original_manifest))
        forged_manifest["artifacts"][receipt_name]["origin"] = forged_metadata["origin"]
        forged_manifest["artifacts"][receipt_name]["registry_record_hash"] = (
            forged_metadata["record_hash"]
        )
        self.orchestrator._save_manifest(forged_manifest)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)
        metadata_path.write_bytes(metadata_bytes)
        self.orchestrator._save_manifest(original_manifest)
        for field, replacement in (
            ("outcome", "RELEASED"),
            ("novelty", "NOVELTY_VERIFIED"),
            ("completed_transitions", []),
        ):
            with self.subTest(final_projection_field=field):
                mutated = json.loads(json.dumps(original_manifest))
                mutated[field] = replacement
                self.orchestrator._save_manifest(mutated)
                with self.assertRaises(PackagingError):
                    package_run(PROJECT_ROOT, run_id)
        mutated = json.loads(json.dumps(original_manifest))
        mutated["r_checks"]["R7"] = "FAIL"
        self.orchestrator._save_manifest(mutated)
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)
        mutated = json.loads(json.dumps(original_manifest))
        mutated["evaluator_decisions"]["E2:AUDIT"]["decision"] = "FAIL"
        self.orchestrator._save_manifest(mutated)
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)
        for label, field, replacement in (
            ("fingerprint", "request_fingerprint", "0" * 64),
            ("replayed", "replayed", True),
            ("generated", "generated_artifact_types", []),
        ):
            with self.subTest(final_receipt=label):
                mutated = json.loads(json.dumps(original_manifest))
                mutated["typed_transition_receipts"][-1][field] = replacement
                self.orchestrator._save_manifest(mutated)
                with self.assertRaises(PackagingError):
                    package_run(PROJECT_ROOT, run_id)
        mutated = json.loads(json.dumps(original_manifest))
        mutated["typed_transition_receipts"][0]["transition_request"][
            "reason"
        ] = "drifted historical transition request"
        self.orchestrator._save_manifest(mutated)
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)
        self.orchestrator._save_manifest(original_manifest)
        for inventory_name, inventory_kind, live_inventory_helper in (
            (
                "frozen_source_inventory",
                "FROZEN_SOURCE_INVENTORY",
                "scientist_one.orchestrator._source_inventory",
            ),
            (
                "frozen_configuration_inventory",
                "FROZEN_CONFIGURATION_INVENTORY",
                "scientist_one.orchestrator._configuration_inventory",
            ),
        ):
            with self.subTest(live_inventory=inventory_name), mock.patch(
                live_inventory_helper,
                return_value={"kind": f"SIMULATED_{inventory_kind}_DRIFT"},
            ) as observed_inventory:
                self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
            observed_inventory.assert_called()

            def reject_selected_inventory(
                _root: Path,
                payload: object,
                *,
                selected_kind: str = inventory_kind,
            ) -> bool:
                return not (
                    isinstance(payload, dict)
                    and payload.get("kind") == selected_kind
                )

            with self.subTest(package_inventory=inventory_name), mock.patch(
                "scientist_one.packaging._inventory_matches_live",
                side_effect=reject_selected_inventory,
            ) as packaging_inventory:
                with self.assertRaises(PackagingError):
                    package_run(PROJECT_ROOT, run_id)
            self.assertIn(
                inventory_kind,
                [
                    call.args[1].get("kind")
                    for call in packaging_inventory.call_args_list
                    if len(call.args) > 1 and isinstance(call.args[1], dict)
                ],
            )
        envelope = json.loads(
            (PROJECT_ROOT / original_manifest["package"]["envelope_path"]).read_text()
        )
        self.assertEqual(
            envelope["final_ledger_head_hash"], original_manifest["ledger_head_hash"]
        )
        self.assertEqual(
            len(envelope["ledger_events"]), original_manifest["event_count"]
        )
        self.assertEqual(
            envelope["release_candidate_record"]["record_hash"],
            original_manifest["artifacts"]["release_candidate"][
                "registry_record_hash"
            ],
        )
        interrupted_finalization = json.loads(json.dumps(original_manifest))
        interrupted_finalization["package"]["envelope_path"] = None
        interrupted_finalization["package"]["envelope_sha256"] = None
        self.orchestrator._save_manifest(interrupted_finalization)
        with self.assertRaisesRegex(
            OrchestrationError, "final review packet or envelope is not verified"
        ):
            self.orchestrator.status(run_id)
        resumed = self.orchestrator.resume(run_id)
        self.assertEqual(resumed["terminal_state"], "READY_FOR_HUMAN_REVIEW")
        resumed_manifest = self.orchestrator.load_manifest(run_id)
        self.assertEqual(
            resumed_manifest["package"]["envelope_sha256"],
            original_manifest["package"]["envelope_sha256"],
        )
        for path in run_directory.rglob("*"):
            if not path.is_file() or path.suffix not in {".json", ".jsonl"}:
                continue
            with self.subTest(evidence_path=path.relative_to(PROJECT_ROOT)):
                self.assertNotIn("/opt/", path.read_text(encoding="utf-8"))
                self.assertNotIn("/usr/", path.read_text(encoding="utf-8"))
        self.assertEqual(
            {path: live_input_identity(path) for path in protected_live_inputs},
            live_input_identities,
            "the authoritative end-to-end test changed captured source/configuration identity",
        )

    def test_custody_authority_projection_rejects_exact_tamper_classes(self) -> None:
        with mock.patch.object(
            ResourceController, "evaluate", autospec=True
        ) as evaluate:
            evaluate.side_effect = lambda controller, *args, **kwargs: replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )
            result = self._fixture_owner.demo(self.orchestrator)
        run_id = result["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        custody_record = self.orchestrator._json_artifact_payload(
            manifest, "custody_record"
        )
        protocol_record = self.orchestrator._json_artifact_payload(
            manifest, "frozen_protocol"
        )
        registry = ArtifactRegistry(
            PROJECT_ROOT, Path("runs") / run_id / "registry"
        )
        ledger = EventLedger(
            PROJECT_ROOT, Path("runs") / run_id / "events.jsonl"
        ).validate()
        self.assertTrue(ledger.valid)
        journal_path = (
            Path(".scientist-one-build") / "custody" / f"{run_id}.jsonl"
        )
        provider = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=PROJECT_ROOT,
            journal_path=journal_path,
        )

        def validate(
            candidate: dict[str, object],
            artifact_records: dict[str, object] | None = None,
            live_snapshot=None,
        ) -> bytes:
            return _validate_custody_snapshot(
                candidate,
                protocol_record,
                manifest["artifacts"]["frozen_source_inventory"]["sha256"],
                manifest["artifacts"]["frozen_configuration_inventory"][
                    "sha256"
                ],
                manifest["protocol_hash"],
                manifest["code_fingerprint"],
                manifest["configuration_sha256"],
                provider,
                live if live_snapshot is None else live_snapshot,
                journal_path.as_posix(),
                artifact_records=(
                    artifact_records
                    if artifact_records is not None
                    else manifest["artifacts"]
                ),
                registry=registry,
                events=ledger.events,
            )

        with provider.admission_guard(
            expected_journal_head_hash=custody_record["journal_head_hash"],
            expected_journal_identity_sha256=custody_record[
                "journal_identity_sha256"
            ],
        ) as live:
            self.assertTrue(validate(dict(custody_record)))
            expected_reasons = (
                "simulated architecture-control release is non-evidentiary",
            )
            self.assertEqual(live.status.violation_reasons, expected_reasons)

            for label, reasons in (
                ("empty-status-reasons", ()),
                ("different-status-reason", ("different derived reason",)),
                ("extra-status-reason", expected_reasons + ("unexpected",)),
            ):
                tampered_live = replace(
                    live,
                    status=replace(live.status, violation_reasons=reasons),
                )
                with self.subTest(tamper=label), self.assertRaises(PackagingError):
                    validate(dict(custody_record), live_snapshot=tampered_live)

            omitted = dict(custody_record)
            omitted.pop("fresh_custody_receipt_sha256")
            substituted = dict(custody_record)
            substituted["fresh_custody_receipt_sha256"] = manifest[
                "artifacts"
            ]["blind_interpretation"]["sha256"]
            wrong_event = dict(custody_record)
            wrong_event["confirmatory_started_event_id"] = custody_record[
                "resource_charge_ledger_event_id"
            ]
            invalid_units = dict(custody_record)
            invalid_units["confirmatory_validity_units"] = 0
            for label, candidate in (
                ("omission", omitted),
                ("substitution", substituted),
                ("wrong-event", wrong_event),
                ("unit", invalid_units),
            ):
                with self.subTest(tamper=label), self.assertRaises(PackagingError):
                    validate(candidate)

            reordered = json.loads(json.dumps(manifest["artifacts"]))
            parents = reordered["custody_record"]["parent_artifacts"]
            parents[1], parents[2] = parents[2], parents[1]
            with self.subTest(tamper="parent-order"), self.assertRaises(
                PackagingError
            ):
                validate(dict(custody_record), reordered)

        self.assertEqual(provider.status.violation_reasons, expected_reasons)

    def test_preflight_pause_refuses_work_with_typed_terminal_evidence(self) -> None:
        started = self._fixture_owner.start(self.orchestrator)
        run_id = started["run_id"]
        while self.orchestrator.status(run_id)["current_state"] != "PREFLIGHT":
            self.orchestrator.advance_once(run_id)
        real_preflight = self.orchestrator.preflight()
        paused = dict(real_preflight)
        paused["status"] = "PAUSE"
        paused["resource_decision"] = dict(real_preflight["resource_decision"])
        paused["resource_decision"].update(
            {"action": "PAUSE", "accept_new_work": False, "stop_budget": False}
        )
        with mock.patch.object(self.orchestrator, "preflight", return_value=paused):
            result = self.orchestrator.advance_once(run_id)
        self.assertEqual(result["terminal_state"], "STOP_BUDGET")
        manifest = self.orchestrator.load_manifest(run_id)
        self.assertIn("terminal_report", manifest["artifacts"])
        self.assertEqual(
            manifest["evaluator_decisions"]["E0:PREFLIGHT->STOP_BUDGET"][
                "decision"
            ],
            "PASS",
        )
        self.assertNotIn("hypothesis_set", manifest["artifacts"])
        ledger = (PROJECT_ROOT / "runs" / run_id / "events.jsonl").read_text()
        self.assertIn(manifest["artifacts"]["terminal_report"]["sha256"], ledger)

    def test_preflight_cross_stage_configuration_mismatch_stops_security(self) -> None:
        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        while self.orchestrator.status(run_id)["current_state"] != "PREFLIGHT":
            self.orchestrator.advance_once(run_id)
        payload = self.orchestrator.preflight()
        payload["configuration_inventory_aggregate_sha256"] = "0" * 64
        with mock.patch.object(self.orchestrator, "preflight", return_value=payload):
            stopped = self.orchestrator.advance_once(run_id)
        self.assertEqual(stopped["terminal_state"], "STOP_SECURITY")

    def test_repeated_worker_crash_and_stall_refuse_work_with_checkpointed_stop(self) -> None:
        for reason in ("REPEATED_WORKER_CRASHES", "WORK_STALLED"):
            with self.subTest(reason=reason):
                started = self._fixture_owner.start(self.orchestrator)
                run_id = started["run_id"]
                while self.orchestrator.status(run_id)["current_state"] != "PREFLIGHT":
                    self.orchestrator.advance_once(run_id)
                real_preflight = self.orchestrator.preflight()
                paused = json.loads(json.dumps(real_preflight))
                paused["status"] = "PAUSE"
                paused["resource_decision"].update(
                    {
                        "action": "PAUSE",
                        "reasons": [reason],
                        "checkpoint_required": True,
                        "accept_new_work": False,
                        "stop_budget": False,
                    }
                )
                with mock.patch.object(
                    self.orchestrator, "preflight", return_value=paused
                ):
                    result = self.orchestrator.advance_once(run_id)
                self.assertEqual(result["terminal_state"], "STOP_BUDGET")
                manifest = self.orchestrator.load_manifest(run_id)
                report = self.orchestrator._json_artifact_payload(
                    manifest, "terminal_report"
                )
                self.assertEqual(
                    report["evidence"]["resource_decision"]["reasons"], [reason]
                )
                self.assertEqual(self.orchestrator.verify(run_id)["status"], "PASS")

    def test_typed_null_reversal_and_unstable_outcomes_stop_before_write(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )

        for scenario, expected in (
            ("null", "NEGATIVE_RESULT"),
            ("reversal", "INCONCLUSIVE"),
            ("unstable", "INCONCLUSIVE"),
        ):
            with self.subTest(scenario=scenario), mock.patch.object(
                ResourceController, "evaluate", autospec=True, side_effect=continue_decision
            ):
                result = self._fixture_owner.demo(self.orchestrator, synthetic_scenario=scenario)
            self.assertEqual(result["terminal_state"], expected)
            manifest = self.orchestrator.load_manifest(result["run_id"])
            self.assertIn("terminal_report", manifest["artifacts"])
            self.assertNotIn("claim_graph", manifest["artifacts"])
            self.assertIsNone(manifest["package"])
            verification = self.orchestrator.verify(result["run_id"])
            self.assertEqual(verification["status"], "PASS", verification)
            if scenario == "null":
                original = json.loads(json.dumps(manifest))
                tampered = json.loads(json.dumps(manifest))
                tampered["terminal_state"] = None
                tampered["outcome"] = "IN_PROGRESS"
                self.orchestrator._save_manifest(tampered)
                self.assertEqual(
                    self.orchestrator.verify(result["run_id"])["status"], "FAIL"
                )
                with self.assertRaises(OrchestrationError):
                    self.orchestrator.status(result["run_id"])
                self.orchestrator._save_manifest(original)

    def test_resource_runtime_rollback_and_erasure_are_rejected(self) -> None:
        started = self._fixture_owner.start(self.orchestrator)
        run_id = started["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        original = json.loads(json.dumps(manifest))
        manifest["resource_runtime_state"]["exploratory_used"] = 1
        self.orchestrator._save_manifest(manifest)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        erased = json.loads(json.dumps(original))
        erased.pop("resource_runtime_state")
        erased.pop("resource_runtime_artifact")
        erased["artifacts"].pop("resource_runtime_initial")
        self.orchestrator._save_manifest(erased)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        self.orchestrator._save_manifest(original)

    def test_resource_transaction_rejects_stale_waiter_before_operation(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        current = self.orchestrator.load_manifest(run_id)
        stale_waiter = json.loads(json.dumps(current))
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            self.assertEqual(
                self.orchestrator._run_with_resources(
                    current,
                    experiment_id=f"{run_id}:first-waiter",
                    validity_stage="PILOT",
                    validity_units=2,
                    operation=lambda: "completed",
                ),
                "completed",
            )
            stale_operation = mock.Mock(
                side_effect=AssertionError("stale waiter must not execute")
            )
            with self.assertRaisesRegex(
                OrchestrationError,
                "resource transaction caller projection is stale",
            ):
                self.orchestrator._run_with_resources(
                    stale_waiter,
                    experiment_id=f"{run_id}:stale-waiter",
                    validity_stage="PILOT",
                    validity_units=2,
                    operation=stale_operation,
                )
        stale_operation.assert_not_called()

    def test_nested_resource_transaction_is_rejected_before_inner_charge(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        used_before = manifest["resource_runtime_state"]["exploratory_used"]
        inner_operation = mock.Mock(
            side_effect=AssertionError("nested resource work must not execute")
        )

        def nested_attempt() -> None:
            self.orchestrator._run_with_resources(
                manifest,
                experiment_id=f"{run_id}:nested-inner",
                validity_stage="PILOT",
                validity_units=2,
                operation=inner_operation,
            )

        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ), self.assertRaisesRegex(
            OrchestrationError, "nested resource transactions are prohibited"
        ):
            self.orchestrator._run_with_resources(
                manifest,
                experiment_id=f"{run_id}:nested-outer",
                validity_stage="PILOT",
                validity_units=2,
                operation=nested_attempt,
            )
        inner_operation.assert_not_called()
        charged = self.orchestrator.load_manifest(run_id)
        self.assertEqual(
            charged["resource_runtime_state"]["exploratory_used"],
            used_before + 2,
        )
        self.assertEqual(
            charged["resource_runtime_artifact"],
            "resource_runtime_pilot_charge",
        )

    def test_resource_transaction_requires_external_checkpoint_authority(self) -> None:
        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        checkpoint = (
            PROJECT_ROOT / ".scientist-one-build" / "checkpoints" / run_id
        )
        preserved = (
            PROJECT_ROOT
            / ".scientist-one-build"
            / "tmp"
            / f"checkpoint-authority-{uuid.uuid4().hex}"
        )
        operation = mock.Mock(
            side_effect=AssertionError("work without checkpoint authority must not run")
        )
        for replacement in ("absent", "symlink"):
            with self.subTest(replacement=replacement):
                os.replace(checkpoint, preserved)
                try:
                    if replacement == "symlink":
                        checkpoint.symlink_to(preserved, target_is_directory=True)
                    with self.assertRaisesRegex(
                        OrchestrationError,
                        "external checkpoint authority is unavailable or unsafe",
                    ):
                        self.orchestrator._run_with_resources(
                            manifest,
                            experiment_id=(
                                f"{run_id}:{replacement}-checkpoint-authority"
                            ),
                            validity_stage="PILOT",
                            validity_units=2,
                            operation=operation,
                        )
                finally:
                    if checkpoint.is_symlink():
                        checkpoint.unlink()
                    os.replace(preserved, checkpoint)
        operation.assert_not_called()

    def test_resource_charge_survives_crash_and_stale_retry_cannot_refund(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(),
                checkpoint_required=False,
                accept_new_work=True,
                stop_budget=False,
                backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        manifest = self.orchestrator.load_manifest(run_id)
        before_crash = json.loads(json.dumps(manifest))
        used_before = manifest["resource_runtime_state"]["exploratory_used"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ), self.assertRaisesRegex(RuntimeError, "simulated worker crash"):
            self.orchestrator._run_with_resources(
                manifest,
                experiment_id=f"{run_id}:crashing-worker",
                validity_stage="PILOT",
                validity_units=2,
                operation=lambda: (_ for _ in ()).throw(
                    RuntimeError("simulated worker crash")
                ),
            )

        charged = self.orchestrator.load_manifest(run_id)
        self.assertEqual(
            charged["resource_runtime_state"]["exploratory_used"],
            used_before + 2,
        )
        self.assertEqual(
            charged["resource_runtime_artifact"],
            "resource_runtime_pilot_charge",
        )
        # This is an injected Python exception in a generic CALIBRATE call,
        # not an observed OS crash or the source-owned CANDIDATE failure witness.
        # Negative PILOT routing may precede the stale-caller diagnostic.
        def retained_identity():
            rows = []
            for relative in (
                Path("runs") / run_id,
                Path(".scientist-one-build/resource-authority") / run_id,
                Path(".scientist-one-build/checkpoints") / run_id,
                Path(".scientist-one-build/custody") / f"{run_id}.jsonl",
            ):
                target = PROJECT_ROOT / relative
                if not target.exists() and not target.is_symlink():
                    rows.append((relative.as_posix(), "ABSENT"))
                    continue
                paths = [target]
                if target.is_dir() and not target.is_symlink():
                    paths += sorted(target.rglob("*"))
                for path in paths:
                    info = path.lstat()
                    payload = (
                        os.readlink(path) if stat.S_ISLNK(info.st_mode)
                        else path.read_bytes() if stat.S_ISREG(info.st_mode)
                        else None
                    )
                    rows.append((
                        path.relative_to(PROJECT_ROOT).as_posix(), info.st_mode,
                        info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns, payload,
                    ))
            return tuple(rows)

        charged_projection = json.loads(json.dumps(charged))
        before_retry = retained_identity()
        for label, projection in (("stale", before_crash), ("fresh", charged)):
            retry = mock.Mock(side_effect=AssertionError("refused retry must not execute"))
            original_projection = json.loads(json.dumps(projection))
            with self.subTest(projection=label), mock.patch.object(
                ResourceController, "acquire",
                side_effect=AssertionError("refused retry must not acquire"),
            ) as acquire, mock.patch.object(
                self.orchestrator, "_run_with_resources_locked",
                side_effect=AssertionError("refused retry must not schedule work"),
            ) as scheduled:
                with self.assertRaises(OrchestrationError):
                    self.orchestrator._run_with_resources(
                        projection,
                        experiment_id=f"{run_id}:{label}-retry",
                        validity_stage="PILOT",
                        validity_units=2,
                        operation=retry,
                    )
            retry.assert_not_called()
            acquire.assert_not_called()
            scheduled.assert_not_called()
            self.assertEqual(projection, original_projection)
            self.assertEqual(retained_identity(), before_retry)
            after_retry = self.orchestrator.load_manifest(run_id)
            self.assertEqual(after_retry, charged_projection)
            self.assertEqual(
                after_retry["resource_runtime_state"]["exploratory_used"],
                used_before + 2,
            )
            self.assertEqual(
                after_retry["resource_runtime_state"]["confirmatory_used"],
                before_crash["resource_runtime_state"]["confirmatory_used"],
            )
            self.assertEqual(
                after_retry["resource_runtime_state"]["worker_crashes"],
                before_crash["resource_runtime_state"]["worker_crashes"],
            )
            self.assertEqual(
                after_retry["resource_runtime_artifact"], "resource_runtime_pilot_charge"
            )
            self.assertNotIn("resource_runtime_pilot_completion", after_retry["artifacts"])
            self.assertNotIn("resource_runtime_pilot_failure", after_retry["artifacts"])

    def test_code_drift_before_confirm_becomes_typed_security_stop(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )
        started = self._fixture_owner.start(self.orchestrator)
        run_id = started["run_id"]
        with mock.patch.object(ResourceController, "evaluate", autospec=True, side_effect=continue_decision):
            while self.orchestrator.status(run_id)["current_state"] != "CONFIRM":
                self.orchestrator.advance_once(run_id)
            with mock.patch(
                "scientist_one.orchestrator._source_inventory",
                return_value={
                    "schema_version": "1.0",
                    "kind": "FROZEN_SOURCE_INVENTORY",
                    "entries": [{"path": "src/scientist_one/drift.py", "sha256": "0" * 64, "size": 1}],
                    "aggregate_sha256": "0" * 64,
                },
            ):
                result = self.orchestrator.advance_once(run_id)
        self.assertEqual(result["terminal_state"], "STOP_SECURITY")
        manifest = self.orchestrator.load_manifest(run_id)
        self.assertIn("terminal_report", manifest["artifacts"])

    def test_code_drift_before_candidate_and_after_confirm_are_typed_stops(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        drift = {
            "schema_version": "1.0",
            "kind": "FROZEN_SOURCE_INVENTORY",
            "entries": [
                {
                    "path": "src/scientist_one/drift.py",
                    "sha256": "0" * 64,
                    "size": 1,
                }
            ],
            "aggregate_sha256": "0" * 64,
        }
        for stage in ("CANDIDATE", "CLAIMS"):
            with self.subTest(stage=stage), mock.patch.object(
                ResourceController,
                "evaluate",
                autospec=True,
                side_effect=continue_decision,
            ):
                run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
                while self.orchestrator.status(run_id)["current_state"] != stage:
                    self.orchestrator.advance_once(run_id)
                with mock.patch(
                    "scientist_one.orchestrator._source_inventory",
                    return_value=drift,
                ):
                    stopped = self.orchestrator.advance_once(run_id)
            self.assertEqual(stopped["terminal_state"], "STOP_SECURITY")
            verification = self.orchestrator.verify(run_id)
            self.assertEqual(verification["status"], "PASS", verification)
            stopped_manifest = self.orchestrator.load_manifest(run_id)
            terminal_report = self.orchestrator._json_artifact_payload(
                stopped_manifest, "terminal_report"
            )
            self.assertIn(
                terminal_report["evidence"].get("stage"),
                {stage, None},
            )

    def test_whole_run_directory_rollback_cannot_repeat_confirmatory_work(self) -> None:
        """A newer external checkpoint yields a typed, non-persisted refusal."""

        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "CANDIDATE":
                self.orchestrator.advance_once(run_id)
            snapshot = (
                PROJECT_ROOT
                / ".scientist-one-build"
                / "tmp"
                / f"rollback-snapshot-{uuid.uuid4().hex}"
            )
            shutil.copytree(PROJECT_ROOT / "runs" / run_id, snapshot)
            while self.orchestrator.status(run_id)["current_state"] != "RELEASE":
                self.orchestrator.advance_once(run_id)
        original_verification = self.orchestrator.verify(run_id)
        self.assertEqual(
            original_verification["status"], "PASS", original_verification
        )
        custody_path = (
            PROJECT_ROOT / ".scientist-one-build" / "custody" / f"{run_id}.jsonl"
        )
        resource_path = (
            PROJECT_ROOT
            / ".scientist-one-build"
            / "resource-authority"
            / run_id
        )
        custody_bytes = custody_path.read_bytes()
        resource_bytes = {
            path.name: path.read_bytes() for path in sorted(resource_path.iterdir())
        }
        completed = PROJECT_ROOT / "runs" / run_id
        preserved = (
            PROJECT_ROOT
            / ".scientist-one-build"
            / "test-runs"
            / f"{run_id}-completed-before-rollback"
        )
        os.replace(completed, preserved)
        os.replace(snapshot, completed)
        with mock.patch.object(
            self.orchestrator,
            "_run_with_resources",
            side_effect=AssertionError("rollback must not schedule resource work"),
        ) as resource_work, mock.patch.object(
            SimulatedHoldoutCustody,
            "_run_confirmatory_locked",
            side_effect=AssertionError("rollback must not reveal the holdout"),
        ) as confirmatory_work:
            stopped = self.orchestrator.resume(run_id)
        resource_work.assert_not_called()
        confirmatory_work.assert_not_called()
        self.assertEqual(stopped["terminal_state"], "STOP_SECURITY")
        self.assertEqual(stopped["status"], "STOP_SECURITY")
        self.assertFalse(stopped["persisted"])
        self.assertEqual(
            stopped["authority_channel"],
            "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL",
        )
        self.assertEqual(custody_path.read_bytes(), custody_bytes)
        self.assertEqual(
            {path.name: path.read_bytes() for path in sorted(resource_path.iterdir())},
            resource_bytes,
        )
        custody = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=PROJECT_ROOT,
            journal_path=Path(".scientist-one-build/custody") / f"{run_id}.jsonl",
        )
        self.assertEqual(custody.status.authorized_access_count, 1)
        latest_authority = json.loads(resource_bytes[sorted(resource_bytes)[-1]])
        self.assertEqual(latest_authority["state"]["exploratory_used"], 2)
        self.assertEqual(latest_authority["state"]["confirmatory_used"], 4)
        verification = self.orchestrator.verify(run_id)
        self.assertEqual(verification["status"], "FAIL", verification)
        with self.assertRaises(OrchestrationError):
            self.orchestrator.status(run_id)

    def test_external_resource_middle_history_rewrite_is_rejected(self) -> None:
        """The final authority head cannot hide a rewritten prior checkpoint."""

        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "RELEASE":
                self.orchestrator.advance_once(run_id)
        original_verification = self.orchestrator.verify(run_id)
        self.assertEqual(
            original_verification["status"], "PASS", original_verification
        )
        authority = (
            PROJECT_ROOT
            / ".scientist-one-build"
            / "resource-authority"
            / run_id
        )
        files = sorted(authority.iterdir())
        self.assertEqual(len(files), 5)
        values = [json.loads(path.read_bytes()) for path in files]
        # Rebuild a syntactically valid hash chain from sequence 1 onward while
        # preserving the authoritative final runtime state and logical names.
        values[1]["state"]["checkpoint_elapsed_seconds"] = 0.125
        prior_digest = files[0].name.split("-", 1)[1].removesuffix(".json")
        replacements: list[tuple[Path, Path, bytes]] = []
        for index in range(1, len(values)):
            values[index]["prior_authority_sha256"] = prior_digest
            state_bytes = json.dumps(
                values[index]["state"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8") + b"\n"
            values[index]["state_sha256"] = hashlib.sha256(state_bytes).hexdigest()
            data = json.dumps(
                values[index],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8") + b"\n"
            digest = hashlib.sha256(data).hexdigest()
            target = authority / f"{index:04d}-{digest}.json"
            replacements.append((files[index], target, data))
            prior_digest = digest
        for old, target, data in replacements:
            old.unlink()
            target.write_bytes(data)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        with self.assertRaises(OrchestrationError):
            self.orchestrator.status(run_id)
        with self.assertRaises(PackagingError):
            package_run(PROJECT_ROOT, run_id)

    def test_external_checkpoint_refuses_combined_per_run_rollback(self) -> None:
        """A stale run+resource projection cannot hide a newer checkpoint."""

        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        run_path = PROJECT_ROOT / "runs" / run_id
        resource_path = (
            PROJECT_ROOT / ".scientist-one-build" / "resource-authority" / run_id
        )
        snapshot_root = (
            PROJECT_ROOT
            / ".scientist-one-build"
            / "tmp"
            / f"combined-rollback-{uuid.uuid4().hex}"
        )
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "CANDIDATE":
                self.orchestrator.advance_once(run_id)
            shutil.copytree(run_path, snapshot_root / "run")
            shutil.copytree(resource_path, snapshot_root / "resource")
            while self.orchestrator.status(run_id)["current_state"] != "CLAIMS":
                self.orchestrator.advance_once(run_id)
        custody_path = (
            PROJECT_ROOT / ".scientist-one-build" / "custody" / f"{run_id}.jsonl"
        )
        preserved = (
            PROJECT_ROOT / ".scientist-one-build" / "test-runs" / f"{run_id}-combined-complete"
        )
        preserved.mkdir()
        os.replace(run_path, preserved / "run")
        os.replace(resource_path, preserved / "resource")
        os.replace(custody_path, preserved / "custody.jsonl")
        os.replace(snapshot_root / "run", run_path)
        os.replace(snapshot_root / "resource", resource_path)
        with mock.patch.object(
            self.orchestrator,
            "_run_with_resources",
            side_effect=AssertionError("stale projection must not execute work"),
        ) as resource_work, mock.patch.object(
            SimulatedHoldoutCustody,
            "_run_confirmatory_locked",
            side_effect=AssertionError("stale projection must not reveal"),
        ) as reveal_work:
            stopped = self.orchestrator.resume(run_id)
        resource_work.assert_not_called()
        reveal_work.assert_not_called()
        self.assertEqual(stopped["status"], "STOP_SECURITY")
        self.assertEqual(stopped["terminal_state"], "STOP_SECURITY")
        self.assertFalse(stopped["persisted"])
        self.assertEqual(
            stopped["authority_channel"],
            "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL",
        )
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        with self.assertRaises(OrchestrationError):
            self.orchestrator.status(run_id)
        with self.assertRaises(OrchestrationError):
            self.orchestrator.reproduce(run_id)
        with self.assertRaises(OrchestrationError):
            self.orchestrator.package(run_id)

    def test_mutable_scenario_and_fake_terminal_are_rejected(self) -> None:
        run_id = self._fixture_owner.start(self.orchestrator, synthetic_scenario="positive")["run_id"]
        original = self.orchestrator.load_manifest(run_id)
        tampered = json.loads(json.dumps(original))
        tampered["synthetic_scenario"] = "null"
        self.orchestrator._save_manifest(tampered)
        self.assertEqual(self.orchestrator.verify(run_id)["status"], "FAIL")
        fake_terminal = json.loads(json.dumps(original))
        fake_terminal["terminal_state"] = "READY_FOR_HUMAN_REVIEW"
        fake_terminal["outcome"] = "COMPLETE_DEMO_ONLY"
        self.orchestrator._save_manifest(fake_terminal)
        with self.assertRaises(OrchestrationError):
            self.orchestrator.status(run_id)
        self.orchestrator._save_manifest(original)

    def test_package_snapshots_custody_bytes_inside_the_provider_guard(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "RELEASE":
                self.orchestrator.advance_once(run_id)
            import scientist_one.packaging as packaging_module

            original_guard = packaging_module.SimulatedHoldoutCustody.admission_guard
            original_read = packaging_module._confined_bytes
            inside_guard = [False]
            custody_reads = [0]

            @contextlib.contextmanager
            def guarded(instance, *args, **kwargs):
                with original_guard(instance, *args, **kwargs) as snapshot:
                    inside_guard[0] = True
                    try:
                        yield snapshot
                    finally:
                        inside_guard[0] = False

            def observed_read(root, raw, **kwargs):
                if Path(raw).name == "custody.jsonl":
                    custody_reads[0] += 1
                    self.fail("packaging must consume provider-held journal bytes")
                return original_read(root, raw, **kwargs)

            with mock.patch.object(
                packaging_module.SimulatedHoldoutCustody,
                "admission_guard",
                guarded,
            ), mock.patch.object(
                packaging_module,
                "_confined_bytes",
                side_effect=observed_read,
            ):
                terminal = self.orchestrator.advance_once(run_id)
        self.assertEqual(terminal["terminal_state"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(custody_reads, [0])
        self._fixture_owner.record_package(
            run_id, self.orchestrator.load_manifest(run_id)["package"]
        )

    def test_pre_release_mutable_semantic_projection_is_rejected(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "RELEASE":
                self.orchestrator.advance_once(run_id)
        original = self.orchestrator.load_manifest(run_id)
        mutations = (
            ("completed", lambda value: value.__setitem__("completed_transitions", [])),
            (
                "typed_receipt",
                lambda value: value["typed_transition_receipts"].__setitem__(
                    0, dict(value["typed_transition_receipts"][-1])
                ),
            ),
            (
                "typed_receipt_fingerprint",
                lambda value: value["typed_transition_receipts"][0].__setitem__(
                    "request_fingerprint", "0" * 64
                ),
            ),
            (
                "typed_receipt_replayed",
                lambda value: value["typed_transition_receipts"][0].__setitem__(
                    "replayed", True
                ),
            ),
            (
                "evaluator",
                lambda value: value["evaluator_decisions"]["E0:CALIBRATE"].__setitem__(
                    "decision", "FAIL"
                ),
            ),
            (
                "resource",
                lambda value: value["resource_runtime_state"].__setitem__(
                    "exploratory_used", 0
                ),
            ),
            (
                "contract",
                lambda value: value["transition_contracts"]["CALIBRATE"].__setitem__(
                    "destination", "RELEASE"
                ),
            ),
            (
                "protocol_hash",
                lambda value: value.__setitem__("protocol_hash", "0" * 64),
            ),
            (
                "code_fingerprint",
                lambda value: value.__setitem__("code_fingerprint", "0" * 64),
            ),
            (
                "configuration_sha256",
                lambda value: value.__setitem__("configuration_sha256", "0" * 64),
            ),
            (
                "artifact_origin",
                lambda value: value["artifacts"]["frozen_protocol"].__setitem__(
                    "origin", "mutable forged provenance"
                ),
            ),
            (
                "artifact_unknown_field",
                lambda value: value["artifacts"]["frozen_protocol"].__setitem__(
                    "unexpected", True
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(original))
                mutate(candidate)
                self.orchestrator._save_manifest(candidate)
                with self.assertRaises(PackagingError):
                    package_run(PROJECT_ROOT, run_id)
        self.orchestrator._save_manifest(original)

    def test_generated_output_path_substitution_is_rejected_before_freeze(self) -> None:
        """A writer-returned pathname cannot substitute bytes for the pure render."""

        import scientist_one.orchestrator as orchestration_module

        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )

        run_id = self._fixture_owner.start(self.orchestrator)["run_id"]
        with mock.patch.object(
            ResourceController,
            "evaluate",
            autospec=True,
            side_effect=continue_decision,
        ):
            while self.orchestrator.status(run_id)["current_state"] != "CLAIMS":
                self.orchestrator.advance_once(run_id)
        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            substituted = Path(temporary) / "substituted.csv"
            substituted.write_bytes(b"task,decision,effect_size\nforged,PASS,999\n")
            with mock.patch.object(
                orchestration_module,
                "write_results_table",
                return_value=substituted,
            ), self.assertRaisesRegex(
                OrchestrationError, "in-memory deterministic rendering"
            ):
                self.orchestrator.advance_once(run_id)
        manifest = self.orchestrator.load_manifest(run_id)
        self.assertNotIn("results_table", manifest["artifacts"])
        self.assertEqual(manifest["current_state"], "CLAIMS")

    def test_claim_support_receipt_corruption_blocks_write(self) -> None:
        def continue_decision(controller, *args, **kwargs):
            return replace(
                ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                action=ResourceAction.CONTINUE,
                reasons=(), checkpoint_required=False, accept_new_work=True,
                stop_budget=False, backoff_seconds=0.0,
            )
        started = self._fixture_owner.start(self.orchestrator)
        run_id = started["run_id"]
        with mock.patch.object(ResourceController, "evaluate", autospec=True, side_effect=continue_decision):
            while self.orchestrator.status(run_id)["current_state"] != "WRITE":
                self.orchestrator.advance_once(run_id)
        manifest = self.orchestrator.load_manifest(run_id)
        claim_graph = self.orchestrator._json_artifact_payload(manifest, "claim_graph")
        self.assertEqual(len(claim_graph["graph"]["evidence"]), 12)
        self.assertEqual(len(claim_graph["writer_view"]), 1)
        parents = manifest["artifacts"]["claim_graph"]["parent_artifacts"]
        self.assertEqual(len(parents), 24)
        receipt = manifest["artifacts"]["claim_support_receipt.limitation"]
        object_path = PROJECT_ROOT / receipt["registry_path"]
        original_bytes = object_path.read_bytes()
        object_path.write_bytes(b"{}\n")
        with self.assertRaises(OrchestrationError):
            self.orchestrator.advance_once(run_id)
        object_path.write_bytes(original_bytes)
        self.assertEqual(self.orchestrator.status(run_id)["current_state"], "WRITE")

    def test_cli_error_is_machine_readable(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), mock.patch(
            "scientist_one.orchestrator._captured_project_root",
            return_value=None,
        ), contextlib.redirect_stdout(output):
            status = main(["status", "../bad"])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "ERROR")

    def test_cli_preflight_exit_status_reflects_admission(self) -> None:
        output = io.StringIO()
        with mock.patch(
            "scientist_one.orchestrator.ScientistOneOrchestrator.preflight",
            return_value={"status": "PASS"},
        ), mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), mock.patch(
            "scientist_one.orchestrator._captured_project_root",
            return_value=None,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["preflight"]), 0)
        output = io.StringIO()
        with mock.patch(
            "scientist_one.orchestrator.ScientistOneOrchestrator.preflight",
            return_value={"status": "PAUSE"},
        ), mock.patch.object(
            sys, "_scientist_one_isolated_launcher", True, create=True
        ), mock.patch(
            "scientist_one.orchestrator._captured_project_root",
            return_value=None,
        ), contextlib.redirect_stdout(output):
            self.assertEqual(main(["preflight"]), 1)


class ImmutablePublishSecurityTests(unittest.TestCase):
    def test_project_resource_execution_is_serialized_across_processes(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            boundary = Path(temporary)
            first = boundary / "first-acquired"
            second = boundary / "second-acquired"
            release = boundary / "release-first"
            program = (
                "import pathlib,sys,time\n"
                "root=pathlib.Path(sys.argv[1]); marker=pathlib.Path(sys.argv[2]); "
                "release=pathlib.Path(sys.argv[3]) if sys.argv[3] != '-' else None\n"
                "sys.path.insert(0,str(root/'src')); "
                "sys._scientist_one_test_runner=True\n"
                "from scientist_one.orchestrator import _project_resource_execution_lock\n"
                "with _project_resource_execution_lock(root):\n"
                " marker.write_text('acquired',encoding='utf-8')\n"
                " while release is not None and not release.exists(): time.sleep(0.01)\n"
            )
            first_process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    program,
                    str(PROJECT_ROOT),
                    str(first),
                    str(release),
                ],
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 10
            while not first.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(first.exists(), first_process.stderr.read() if first_process.poll() else "")
            second_process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    program,
                    str(PROJECT_ROOT),
                    str(second),
                    "-",
                ],
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.25)
            self.assertIsNone(second_process.poll())
            self.assertFalse(second.exists())
            release.write_text("release", encoding="utf-8")
            first_output, first_error = first_process.communicate(timeout=10)
            second_output, second_error = second_process.communicate(timeout=10)
            self.assertEqual(first_process.returncode, 0, first_output + first_error)
            self.assertEqual(second_process.returncode, 0, second_output + second_error)
            self.assertTrue(second.exists())

    def test_project_resource_lock_rejects_namespace_replacement(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            parent = Path(temporary)
            root = parent / "ScientistOne"
            moved = parent / "ScientistOne-held"
            root.mkdir()
            with self.assertRaises(OrchestrationError):
                with orchestration_module._project_resource_execution_lock(root):
                    os.rename(root, moved)
                    root.mkdir()
            self.assertTrue(root.is_dir())
            self.assertTrue(moved.is_dir())

    def test_ledger_evaluator_projection_rejects_orphan_key(self) -> None:
        event = types.SimpleNamespace(
            metadata={"evaluator_keys": ["E0:AUDIT"]},
            evaluator_outputs=(),
            state_before=types.SimpleNamespace(value="AUDIT"),
            requested_state_after=types.SimpleNamespace(value="RELEASE"),
        )
        with self.assertRaises(PackagingError):
            _ledger_evaluator_projection((event,))

    def test_ledger_evaluator_projection_rejects_noncanonical_receipts(self) -> None:
        evaluation = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            (),
            "typed E0:AUDIT contract passed",
        )
        receipt = {
            "evaluator_class": "E0",
            "authority": Role.ORCHESTRATOR.value,
            "decision": "PASS",
            "critical_objection": False,
            "artifact_hashes": [],
            "evaluation_sha256": evaluation.sha256,
            "frozen_context_sha256": "0" * 64,
            "producer_role": None,
            "reason": "typed E0:AUDIT contract passed",
            "r_checks": [],
            "logically_separated": True,
            "human_independence_claimed": False,
        }
        cases = (
            ("arrow", "E0:AUDIT->RELEASE", dict(receipt)),
            (
                "missing",
                "E0:AUDIT",
                {key: value for key, value in receipt.items() if key != "frozen_context_sha256"},
            ),
            ("extra", "E0:AUDIT", {**receipt, "unexpected": True}),
        )
        for label, key, output in cases:
            with self.subTest(label=label):
                event = types.SimpleNamespace(
                    metadata={"evaluator_keys": [key]},
                    evaluator_outputs=(output,),
                    event_type="TRANSITION",
                    state_before=types.SimpleNamespace(value="AUDIT"),
                    requested_state_after=types.SimpleNamespace(value="RELEASE"),
                )
                with self.assertRaises(PackagingError):
                    _ledger_evaluator_projection((event,))

    def test_ledger_evaluator_projection_rejects_same_state_receipt(self) -> None:
        evaluation = Evaluation(
            EvaluatorClass.E1,
            Role.STATISTICIAN,
            Decision.ADVISORY,
            (),
            "unauthorized same-state advisory",
        )
        receipt = {
            "evaluator_class": "E1",
            "authority": Role.STATISTICIAN.value,
            "decision": "ADVISORY",
            "critical_objection": False,
            "artifact_hashes": [],
            "evaluation_sha256": evaluation.sha256,
            "frozen_context_sha256": "0" * 64,
            "producer_role": None,
            "reason": "unauthorized same-state advisory",
            "r_checks": [],
            "logically_separated": True,
            "human_independence_claimed": False,
        }
        event = types.SimpleNamespace(
            metadata={"evaluator_keys": ["E1:CONFIRM"]},
            evaluator_outputs=(receipt,),
            event_type="CONFIRMATORY_COMPLETED",
            state_before=types.SimpleNamespace(value="CONFIRM"),
            requested_state_after=types.SimpleNamespace(value="CONFIRM"),
        )
        with self.assertRaises(PackagingError):
            _ledger_evaluator_projection((event,))
        advisory = Evaluation(
            EvaluatorClass.E1,
            Role.STATISTICIAN,
            Decision.ADVISORY,
            (),
            "typed E1:AUDIT advisory",
        )
        advisory_receipt = {
            "evaluator_class": "E1",
            "authority": Role.STATISTICIAN.value,
            "decision": "ADVISORY",
            "critical_objection": False,
            "artifact_hashes": [],
            "evaluation_sha256": advisory.sha256,
            "frozen_context_sha256": "0" * 64,
            "producer_role": None,
            "reason": "typed E1:AUDIT advisory",
            "r_checks": [],
            "logically_separated": True,
            "human_independence_claimed": False,
        }
        event = types.SimpleNamespace(
            metadata={"evaluator_keys": ["E1:AUDIT"]},
            evaluator_outputs=(advisory_receipt,),
            event_type="TRANSITION",
            state_before=types.SimpleNamespace(value="AUDIT"),
            requested_state_after=types.SimpleNamespace(value="RELEASE"),
        )
        with self.assertRaises(PackagingError):
            _ledger_evaluator_projection((event,))

    def test_review_packet_secret_patterns_are_rejected(self) -> None:
        for payload in (
            b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
            b"token = " + b"ghp_" + b"abcdefghijklmnopqrstuvwxyzABCDEF",
            b"aws=" + b"AK" + b"IAABCDEFGHIJKLMNOP",
            b"pass" + b"word: abcdefghijklmnop",
        ):
            with self.subTest(payload=payload[:12]):
                self.assertTrue(_contains_forbidden_boundary_text(payload))

    def test_gateway_trust_root_is_rejected_from_package_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
        ) as temporary:
            root = Path(temporary)
            registry = ArtifactRegistry(root, "runs/run-key-secrecy/registry")
            key_name = "." + "gateway-execution-" + "authority.key"
            key_material = bytes(range(32))
            key_path = root / registry.base_path / key_name
            key_path.write_bytes(key_material)
            key_path.chmod(0o600)

            _assert_gateway_trust_root_not_serialized(
                registry,
                {"RELEASE_CANDIDATE.json": b'{"safe":true}\n'},
            )
            cases = (
                ({f"registry/{key_name}": b""}, "member path"),
                (
                    {
                        "FINAL_RELEASE_ENVELOPE.json": (
                            f'{{"key_path":"runs/x/registry/{key_name}"}}\n'
                        ).encode("utf-8")
                    },
                    "serialized path",
                ),
                (
                    {"evidence/runtime.bin": b"prefix" + key_material + b"suffix"},
                    "raw key material",
                ),
                (
                    {
                        "FINAL_RELEASE_ENVELOPE.json": (
                            b'{"encoded_key":"'
                            + key_material.hex().encode("ascii")
                            + b'"}\n'
                        )
                    },
                    "hex-encoded key material",
                ),
                (
                    {
                        "FINAL_RELEASE_ENVELOPE.json": (
                            b'{"encoded_key":"'
                            + base64.b64encode(key_material)
                            + b'"}\n'
                        )
                    },
                    "base64-encoded key material",
                ),
            )
            for members, label in cases:
                with self.subTest(label=label), self.assertRaises(PackagingError):
                    _assert_gateway_trust_root_not_serialized(registry, members)

    def test_snapshot_boundary_scan_rejects_binary_secret_and_external_path(self) -> None:
        binary_secret = (
            b"\xff\n" + b"gh" + b"p_" + b"abcdefghijklmnopqrstuvwxyzABCDEF"
        )
        self.assertTrue(
            _contains_forbidden_boundary_text(binary_secret, source_member=True)
        )
        self.assertTrue(
            _contains_forbidden_boundary_text(
                b"fixture reads /etc/shadow", source_member=True
            )
        )
        self.assertTrue(
            _contains_forbidden_boundary_text(
                b"# scratch=/tmp/private-study-name", source_member=True
            )
        )
        self.assertFalse(
            _contains_forbidden_boundary_text(
                b'executable = Path("/usr/bin/vm_stat")', source_member=True
            )
        )
        for trusted_reference in (
            b'PATH = "/usr/bin:/bin"',
            b'executable = "/usr/bin/python3"',
            b'endpoint = "/v1/responses"',
            b'fixture_route = "/research-os-fixture/pmc"',
        ):
            with self.subTest(trusted_reference=trusted_reference):
                self.assertFalse(
                    _contains_forbidden_boundary_text(
                        trusted_reference, source_member=True
                    )
                )
        self.assertTrue(
            _contains_forbidden_boundary_text(
                b'executable = "/usr/bin/python3-unreviewed"',
                source_member=True,
            )
        )
        self.assertFalse(
            _contains_forbidden_boundary_text(
                b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'
            )
        )
        self.assertTrue(
            _contains_forbidden_boundary_text(
                b'path = f"{base}/tmp/private-study-name"', source_member=True
            )
        )

    def test_source_inventory_entry_caps_fail_before_retention(self) -> None:
        import scientist_one.orchestrator as orchestration_module

        with mock.patch.object(
            orchestration_module, "MAX_INVENTORY_ENTRIES", 0
        ), self.assertRaises(OrchestrationError):
            orchestration_module._source_inventory(PROJECT_ROOT)

    def test_package_aggregate_size_is_bounded_before_archive_growth(self) -> None:
        with mock.patch("scientist_one.packaging.MAX_PACKAGE_INPUT_BYTES", 4):
            with self.assertRaises(PackagingError):
                _zip_bytes({"a": b"123", "b": b"456"})

    def test_package_run_aggregate_bound_is_enforced_before_object_read(self) -> None:
        orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)
        fixture_owner = _CliFixtureOwner(PROJECT_ROOT, run_only=True)
        run_id = fixture_owner.start(orchestrator)["run_id"]
        try:
            def continue_decision(controller, *args, **kwargs):
                return replace(
                    ORIGINAL_RESOURCE_EVALUATE(controller, *args, **kwargs),
                    action=ResourceAction.CONTINUE,
                    reasons=(), checkpoint_required=False, accept_new_work=True,
                    stop_budget=False, backoff_seconds=0.0,
                )

            with mock.patch.object(
                ResourceController,
                "evaluate",
                autospec=True,
                side_effect=continue_decision,
            ):
                while orchestrator.status(run_id)["current_state"] != "RELEASE":
                    orchestrator.advance_once(run_id)
            manifest = orchestrator.load_manifest(run_id)
            # Two members per registered artifact plus the seven fixed packet
            # members excludes the independently duplicated source snapshots.
            incomplete_member_cap = 2 * len(manifest["artifacts"]) + 7
            with mock.patch(
                "scientist_one.packaging.MAX_PACKAGE_FILES", incomplete_member_cap
            ), mock.patch(
                "scientist_one.packaging.ArtifactRegistry.verify_all"
            ) as verify_all, self.assertRaises(PackagingError):
                package_run(PROJECT_ROOT, run_id)
            verify_all.assert_not_called()
        finally:
            fixture_owner.archive()

    def test_reproduction_numeric_and_serialization_boundaries_fail_closed(self) -> None:
        with self.assertRaises(ReproductionError):
            _mean([10**400], "huge")
        with self.assertRaises(ReproductionError):
            _mean([float("inf")], "nonfinite")
        with self.assertRaises(ReproductionError):
            _canonical_json({"value": float("nan")})

    def test_architecture_control_replay_classification_is_exact(self) -> None:
        source = {
            "evidence_class": "ARCHITECTURE_CONTROL",
            "scientific_evidence": False,
        }
        custody = {
            "kind": "SIMULATED_HOLDOUT_CUSTODY",
            "custody_independence": "SIMULATED_NON_INDEPENDENT",
            "evidence_class": "ARCHITECTURE_CONTROL",
            "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            "scientific_evidence": False,
            "confirmatory_claims_valid": False,
            "genuine_independence_claimed": False,
            "authorized_access_count": 1,
        }
        _require_replay_source_classification(
            source,
            custody,
            expected_evidence_class="ARCHITECTURE_CONTROL",
        )
        _require_replay_source_classification(
            {"evidence_class": "SYNTHETIC_CONFIRMATORY_FIXTURE"},
            {},
            expected_evidence_class="SYNTHETIC_CONFIRMATORY_FIXTURE",
        )
        for field, replacement in (
            ("evidence_class", "SYNTHETIC_CONFIRMATORY_FIXTURE"),
            ("scientific_evidence", True),
            ("confirmatory_claims_valid", True),
            ("genuine_independence_claimed", True),
            ("execution_kind", "SIMULATED_ARCHITECTURE_CONTROL_COMPLETED"),
            ("authorized_access_count", 2),
        ):
            with self.subTest(field=field):
                bad_source = dict(source)
                bad_custody = dict(custody)
                if field in bad_source:
                    bad_source[field] = replacement
                else:
                    bad_custody[field] = replacement
                with self.assertRaises(ReproductionError):
                    _require_replay_source_classification(
                        bad_source,
                        bad_custody,
                        expected_evidence_class="ARCHITECTURE_CONTROL",
                    )
        with self.assertRaises(ReproductionError):
            _require_replay_source_classification(
                source,
                custody,
                expected_evidence_class="SYNTHETIC_CONFIRMATORY_FIXTURE",
            )

    def test_reproduction_target_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / ".scientist-one-build/tmp") as temporary:
            root = Path(temporary)
            destination = root / "out" / "result.json"
            destination.parent.mkdir()
            outside = root / "outside.json"
            outside.write_bytes(b"unchanged")
            destination.symlink_to(outside)
            with self.assertRaises(ReproductionError):
                _atomic_write(root, destination, b"new")
            self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_reproduction_partial_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / ".scientist-one-build/tmp") as temporary:
            root = Path(temporary)
            destination = root / "out" / "result.json"
            destination.parent.mkdir()
            data = b"new"
            import hashlib

            outside = root / "outside.json"
            outside.write_bytes(b"unchanged")
            with mock.patch("scientist_one.reproduction.os.urandom", return_value=b"\x00" * 8):
                partial = destination.parent / f".{destination.name}.{hashlib.sha256(data).hexdigest()[:16]}.{'00' * 8}.partial"
                partial.symlink_to(outside)
                with self.assertRaises((ReproductionError, FileExistsError)):
                    _atomic_write(root, destination, data)
            self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_package_target_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / ".scientist-one-build/tmp") as temporary:
            root = Path(temporary)
            destination = root / "out" / "candidate.zip"
            destination.parent.mkdir()
            outside = root / "outside.zip"
            outside.write_bytes(b"unchanged")
            destination.symlink_to(outside)
            with self.assertRaises(PackagingError):
                _publish_immutable(root, destination, b"archive")
            self.assertEqual(outside.read_bytes(), b"unchanged")


if __name__ == "__main__":
    unittest.main()
