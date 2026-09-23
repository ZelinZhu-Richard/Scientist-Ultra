from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one import artifacts as artifacts_module
from scientist_one.calibration import run_calibration
from scientist_one.errors import (
    ArtifactCollisionError,
    ArtifactCorruptionError,
    ArtifactError,
    FrozenArtifactError,
    IdempotencyConflictError,
    IncompleteTransitionError,
    InvalidTransitionError,
    LedgerCorruptionError,
    LedgerError,
    PathSecurityError,
    UnauthorizedTransitionError,
    ValidationError,
)
from scientist_one.evaluators import Decision, Evaluation, EvaluatorClass
from scientist_one.ledger import EventLedger, LedgerEvent, event_hash
from scientist_one import ledger as ledger_module
from scientist_one.models import ArtifactRef, MacroState, TerminalState, TransitionRequest
from scientist_one.recovery import RecoveryManager, ResumeAction
from scientist_one.roles import Role, transition_role_context_sha256
from scientist_one.security import canonical_json_bytes
from scientist_one.state_machine import (
    MACRO_SEQUENCE,
    StateController,
    TransitionContract,
    TransitionResult,
    evaluation_gate_id,
    legacy_evaluation_receipt,
    macro_transition_contracts,
)


BUILD_TMP = Path(__file__).resolve().parents[1] / ".scientist-one-build" / "tmp"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON = "/opt/anaconda3/bin/python3"
CONFIG_HASH = "c" * 64


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _wait_for_path(path: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while not path.exists() and time.monotonic() < deadline:
        if process.poll() is not None:
            output, error = process.communicate()
            raise AssertionError(output + error)
        time.sleep(0.01)
    if not path.exists():
        process.terminate()
        output, error = process.communicate(timeout=5)
        raise AssertionError("subprocess marker was not created\n" + output + error)


class ProjectTempCase(unittest.TestCase):
    def setUp(self) -> None:
        BUILD_TMP.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=BUILD_TMP)
        self.sandbox = Path(self.temporary.name)
        self.root = self.sandbox / "project"
        self.outside = self.sandbox / "outside"
        self.root.mkdir()
        self.outside.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()


class StateMachineTests(ProjectTempCase):
    def setUp(self) -> None:
        super().setUp()
        self.registry = ArtifactRegistry(self.root)
        bootstrap = {
            "app_session_bootstrap": "PASS",
            "bootstrap_checks": [
                {"check": "workspace", "result": "PASS"},
                {"check": "network_disabled", "result": "PASS"},
            ],
        }
        self.bootstrap = self.registry.put_json(
            bootstrap,
            logical_type="bootstrap_receipt",
            origin="test fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        self.calibration = self.registry.put_json(
            run_calibration().to_dict(),
            logical_type="calibration_report",
            origin="deterministic local calibration",
            creator_role=Role.ORCHESTRATOR,
        )

    def request(
        self,
        *,
        idempotency_key: str = "calibrate-charter-1",
        reason: str = "mandatory deterministic calibration passed",
        evaluations: tuple[Evaluation, ...] | None = None,
        artifacts: tuple[ArtifactRef, ...] | None = None,
        requester: Role = Role.ORCHESTRATOR,
        approver: Role = Role.SCIENTIFIC_REVIEWER,
    ) -> TransitionRequest:
        refs = artifacts or (self.bootstrap.to_ref(), self.calibration.to_ref())
        if evaluations is None:
            hashes = tuple(item.sha256 for item in refs)
            gate_id = evaluation_gate_id(
                EvaluatorClass.E0,
                MacroState.CALIBRATE,
                MacroState.CHARTER,
            )
            evaluations = (
                Evaluation(
                    EvaluatorClass.E0,
                    Role.ORCHESTRATOR,
                    Decision.PASS,
                    hashes,
                    "schema, hashes, and canonical calibration verified",
                    run_id="run-1",
                    gate_id=gate_id,
                    frozen_context_sha256=transition_role_context_sha256(
                        Role.ORCHESTRATOR,
                        "run-1",
                        hashes,
                        gate_id,
                    ),
                ),
            )
        return TransitionRequest(
            run_id="run-1",
            from_state=MacroState.CALIBRATE,
            to_state=MacroState.CHARTER,
            requester=requester,
            approver=approver,
            artifacts=refs,
            evaluations=evaluations,
            idempotency_key=idempotency_key,
            reason=reason,
        )

    def test_exact_macro_state_sequence_and_terminal_states(self) -> None:
        self.assertEqual(
            tuple(item.value for item in MACRO_SEQUENCE),
            (
                "CALIBRATE", "CHARTER", "GROUND", "PROTOCOL", "PREFLIGHT",
                "IDEATE", "DISCOVER", "CANDIDATE", "CONFIRM", "CLAIMS",
                "WRITE", "AUDIT", "RELEASE",
            ),
        )
        self.assertNotIn("RELEASED", {item.value for item in TerminalState})
        self.assertEqual(len(TerminalState), 7)

    def test_canonical_contracts_match_live_cli_artifacts_and_review_gates(self) -> None:
        contracts = {item.source: item for item in macro_transition_contracts()}
        expected = {
            MacroState.CALIBRATE: {"bootstrap_receipt", "calibration_report"},
            MacroState.CHARTER: {"research_charter"},
            MacroState.GROUND: {"evidence_inventory"},
            MacroState.PROTOCOL: {"frozen_protocol"},
            MacroState.PREFLIGHT: {"preflight_report"},
            MacroState.IDEATE: {"hypothesis_set"},
            MacroState.DISCOVER: {"workflow_benchmark"},
            MacroState.CANDIDATE: {"pilot_report", "midrun_review", "blind_interpretation"},
            MacroState.CONFIRM: {"custody_record", "machine_results"},
            MacroState.CLAIMS: {"claim_graph"},
            MacroState.WRITE: {"results_table", "results_figure", "demo_paper"},
            MacroState.AUDIT: {
                "audit_report", "reproduction_report", "e2_review", "e3_review", "readiness_report"
            },
            MacroState.RELEASE: {"release_candidate"},
        }
        self.assertEqual(set(contracts), set(MacroState))
        for state, artifact_types in expected.items():
            self.assertEqual(contracts[state].required_artifact_types, artifact_types)
            serialized = contracts[state].to_dict()
            self.assertEqual(set(serialized["required_artifacts"]), artifact_types)
            self.assertEqual(serialized["source"], state.value)
        self.assertEqual(
            contracts[MacroState.CANDIDATE].required_evaluators,
            {EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3},
        )
        self.assertEqual(
            contracts[MacroState.AUDIT].required_evaluators,
            {EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3},
        )

    def test_valid_transition_and_exact_replay_are_idempotent(self) -> None:
        controller = StateController(artifact_registry=self.registry)
        request = self.request()
        first = controller.transition(request)
        second = controller.transition(request)
        self.assertEqual(controller.current_state, MacroState.CHARTER)
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.request_fingerprint, second.request_fingerprint)

        resumed = StateController(
            MacroState.CHARTER,
            artifact_registry=self.registry,
            prior_receipts=(first,),
        )
        replayed_after_restart = resumed.transition(request)
        self.assertTrue(replayed_after_restart.replayed)
        self.assertEqual(replayed_after_restart.request_fingerprint, first.request_fingerprint)

    def test_same_idempotency_key_with_different_evidence_is_rejected(self) -> None:
        controller = StateController(artifact_registry=self.registry)
        controller.transition(self.request())
        with self.assertRaises(IdempotencyConflictError):
            controller.transition(self.request(reason="different free-form rationale"))

    def test_context_omission_and_exact_request_fingerprint_drift_fail_closed(self) -> None:
        unbound = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            (self.bootstrap.sha256, self.calibration.sha256),
            "unbound authority",
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(
                self.request(evaluations=(unbound,))
            )

        hashes = (self.bootstrap.sha256, self.calibration.sha256)
        for bound_run, bound_gate in (
            ("other-run", "E0:CALIBRATE"),
            ("run-1", "E0:CHARTER"),
        ):
            with self.subTest(run_id=bound_run, gate_id=bound_gate):
                mismatched = Evaluation(
                    EvaluatorClass.E0,
                    Role.ORCHESTRATOR,
                    Decision.PASS,
                    hashes,
                    "authority bound to the wrong context",
                    run_id=bound_run,
                    gate_id=bound_gate,
                    frozen_context_sha256=transition_role_context_sha256(
                        Role.ORCHESTRATOR,
                        bound_run,
                        hashes,
                        bound_gate,
                    ),
                )
                with self.assertRaises(IncompleteTransitionError):
                    StateController(artifact_registry=self.registry).transition(
                        self.request(evaluations=(mismatched,))
                    )

        receipt = StateController(artifact_registry=self.registry).transition(
            self.request()
        ).to_dict()
        receipt["transition_request"]["reason"] = "fingerprint drift"
        with self.assertRaises(ValueError):
            TransitionResult.from_dict(receipt)

    def test_direct_recovery_replays_full_prefix_against_exact_registry(self) -> None:
        request = self.request(idempotency_key="run-1:CALIBRATE:CHARTER")
        receipt = StateController(artifact_registry=self.registry).transition(
            request
        )
        ledger = EventLedger(self.root, "runs/run-1/events.jsonl")
        ledger.record(
            run_id="run-1",
            event_id="event-0001",
            timestamp="2026-01-01T00:00:00Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CALIBRATE,
            artifact_hashes=(),
            code_version="test-code",
            configuration_hash=CONFIG_HASH,
            reason="canonical initialization",
            event_type="CHECKPOINT",
            metadata={"initialization": True},
        )
        ledger.record(
            run_id="run-1",
            event_id="event-0002",
            timestamp="2026-01-01T00:00:01Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CHARTER,
            artifact_hashes=request.artifact_hashes,
            code_version="test-code",
            configuration_hash=CONFIG_HASH,
            evaluator_outputs=tuple(
                legacy_evaluation_receipt(item) for item in request.evaluations
            ),
            reason="typed transition",
            metadata={
                "artifact_types": [
                    item.logical_type for item in request.artifacts
                ],
                "evaluator_keys": ["E0:CALIBRATE"],
                "transition_receipt": receipt.to_dict(),
            },
        )
        empty_registry = ArtifactRegistry(self.root, "empty-registry")

        report = RecoveryManager(self.root).recover(
            ledger_path="runs/run-1/events.jsonl",
            artifact_registry=empty_registry,
        )
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.resumable)
        self.assertTrue(
            any(
                reason.startswith("LEGACY_TRANSITION_REPLAY_FAILED:")
                for reason in report.reasons
            ),
            report.reasons,
        )
        cross_registry = ArtifactRegistry(self.root, "cross-registry")
        cross_registry.put_bytes(
            self.registry.get_bytes(self.bootstrap.sha256),
            logical_type="calibration_report",
            origin="cross-artifact recovery fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        cross_registry.put_bytes(
            self.registry.get_bytes(self.calibration.sha256),
            logical_type="bootstrap_receipt",
            origin="cross-artifact recovery fixture",
            creator_role=Role.ORCHESTRATOR,
        )
        crossed = RecoveryManager(self.root).recover(
            ledger_path="runs/run-1/events.jsonl",
            artifact_registry=cross_registry,
        )
        self.assertEqual(crossed.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(crossed.resumable)
        self.assertTrue(
            any(
                reason.startswith("LEGACY_TRANSITION_REPLAY_FAILED:")
                for reason in crossed.reasons
            ),
            crossed.reasons,
        )
        accepted = RecoveryManager(self.root).recover(
            ledger_path="runs/run-1/events.jsonl",
            artifact_registry=self.registry,
        )
        self.assertEqual(accepted.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertTrue(accepted.resumable)
        self.assertEqual(accepted.derived_state, "CHARTER")

    def test_duplicate_required_artifact_type_is_ambiguous_and_rejected(self) -> None:
        artifacts = (
            self.bootstrap.to_ref(),
            self.bootstrap.to_ref(),
            self.calibration.to_ref(),
        )
        evaluation = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            tuple(item.sha256 for item in artifacts),
            "ambiguous duplicate evidence",
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(
                self.request(artifacts=artifacts, evaluations=(evaluation,))
            )

    def test_multiple_transition_receipts_restore_a_contiguous_idempotent_history(self) -> None:
        first_contract = TransitionContract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            frozenset(),
            frozenset(),
            frozenset({Role.ORCHESTRATOR}),
            frozenset({Role.SCIENTIFIC_REVIEWER}),
            frozenset(),
            frozenset({TerminalState.STOP_SECURITY}),
        )
        second_contract = TransitionContract(
            MacroState.CHARTER,
            MacroState.GROUND,
            frozenset(),
            frozenset(),
            frozenset({Role.ORCHESTRATOR}),
            frozenset({Role.SCIENTIFIC_REVIEWER}),
            frozenset(),
            frozenset({TerminalState.STOP_SECURITY}),
        )
        first_request = TransitionRequest(
            "run-resume", MacroState.CALIBRATE, MacroState.CHARTER,
            Role.ORCHESTRATOR, Role.SCIENTIFIC_REVIEWER, (), (),
            "resume-edge-1", "first typed edge",
        )
        second_request = TransitionRequest(
            "run-resume", MacroState.CHARTER, MacroState.GROUND,
            Role.ORCHESTRATOR, Role.SCIENTIFIC_REVIEWER, (), (),
            "resume-edge-2", "second typed edge",
        )
        controller = StateController(contracts=(first_contract, second_contract))
        first = controller.transition(first_request)
        second = controller.transition(second_request)
        resumed = StateController(
            MacroState.GROUND,
            contracts=(first_contract, second_contract),
            prior_receipts=(first.to_dict(), second.to_dict()),
        )
        self.assertTrue(resumed.transition(first_request).replayed)
        self.assertTrue(resumed.transition(second_request).replayed)

    def test_invalid_skip_backward_and_terminal_exit_are_rejected(self) -> None:
        controller = StateController(artifact_registry=self.registry)
        skipped = TransitionRequest(
            "run-1", MacroState.CALIBRATE, MacroState.GROUND,
            Role.ORCHESTRATOR, Role.SCIENTIFIC_REVIEWER,
            (self.bootstrap.to_ref(), self.calibration.to_ref()),
            (), "skip-1", "free text is not authority",
        )
        with self.assertRaises(InvalidTransitionError):
            controller.transition(skipped)
        terminal = StateController(TerminalState.STOP_SECURITY, artifact_verifier=lambda _: True)
        with self.assertRaises(InvalidTransitionError):
            terminal.transition(self.request())

    def test_unauthorized_requester_and_self_approval_rejected(self) -> None:
        controller = StateController(artifact_registry=self.registry)
        with self.assertRaises(UnauthorizedTransitionError):
            controller.transition(self.request(requester=Role.IMPLEMENTER))
        custom = TransitionContract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            frozenset(),
            frozenset(),
            frozenset({Role.ORCHESTRATOR}),
            frozenset({Role.ORCHESTRATOR}),
            frozenset(),
            frozenset({TerminalState.STOP_SECURITY}),
        )
        self_approval = TransitionRequest(
            "run-1", MacroState.CALIBRATE, MacroState.CHARTER,
            Role.ORCHESTRATOR, Role.ORCHESTRATOR, (), (),
            "self-approve-1", "attempted self approval",
        )
        with self.assertRaises(UnauthorizedTransitionError):
            StateController(contracts=(custom,), artifact_verifier=lambda _: True).transition(self_approval)

    def test_incomplete_unbound_and_noncanonical_calibration_fail_closed(self) -> None:
        without_registry = StateController()
        with self.assertRaises(IncompleteTransitionError):
            without_registry.transition(self.request())
        missing = self.request(artifacts=(self.bootstrap.to_ref(),))
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(missing)
        forged_record = self.registry.put_json(
            {"passed": True, "mandatory_passed": True},
            logical_type="calibration_report",
            origin="forged summary",
            creator_role=Role.ORCHESTRATOR,
        )
        forged = self.request(artifacts=(self.bootstrap.to_ref(), forged_record.to_ref()))
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(forged)
        with mock.patch(
            "scientist_one.calibration.assert_calibrated",
            side_effect=RuntimeError("mandatory calibration failed"),
        ):
            with self.assertRaises(IncompleteTransitionError):
                StateController(artifact_registry=self.registry).transition(self.request())

    def test_evaluator_must_pass_bind_every_artifact_and_have_no_objection(self) -> None:
        wrong = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            ("f" * 64,),
            "not bound to evidence",
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(
                self.request(evaluations=(wrong,))
            )
        hashes = (self.bootstrap.sha256, self.calibration.sha256)
        objection = Evaluation(
            EvaluatorClass.E2,
            Role.SCIENTIFIC_REVIEWER,
            Decision.FAIL,
            hashes,
            "critical scientific defect",
            critical_objection=True,
            producer_role=Role.ORCHESTRATOR,
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(artifact_registry=self.registry).transition(
                self.request(evaluations=(
                    Evaluation(EvaluatorClass.E0, Role.ORCHESTRATOR, Decision.PASS, hashes, "valid"),
                    objection,
                ))
            )

    def test_e4_cannot_be_constructed_or_used_as_autonomous_approver(self) -> None:
        with self.assertRaises(ValueError):
            Evaluation(
                EvaluatorClass.E4,
                Role.HUMAN_RELEASE,
                Decision.PASS,
                (),
                "forged human release",
            )
        with self.assertRaises(UnauthorizedTransitionError):
            StateController(artifact_registry=self.registry).transition(
                self.request(approver=Role.HUMAN_RELEASE)
            )

    def test_negative_result_is_an_honest_terminal_transition(self) -> None:
        refs = (
            ArtifactRef("1" * 64, "machine_results"),
            ArtifactRef("2" * 64, "terminal_report"),
        )
        hashes = tuple(item.sha256 for item in refs)
        e0_gate = evaluation_gate_id(
            EvaluatorClass.E0,
            MacroState.CONFIRM,
            TerminalState.NEGATIVE_RESULT,
        )
        e2_gate = evaluation_gate_id(
            EvaluatorClass.E2,
            MacroState.CONFIRM,
            TerminalState.NEGATIVE_RESULT,
        )
        evaluations = (
            Evaluation(
                EvaluatorClass.E0,
                Role.ORCHESTRATOR,
                Decision.PASS,
                hashes,
                "validated",
                run_id="run-negative",
                gate_id=e0_gate,
                frozen_context_sha256=transition_role_context_sha256(
                    Role.ORCHESTRATOR,
                    "run-negative",
                    hashes,
                    e0_gate,
                ),
            ),
            Evaluation(
                EvaluatorClass.E2,
                Role.SCIENTIFIC_REVIEWER,
                Decision.PASS,
                hashes,
                "negative result is supported",
                producer_role=Role.EXPERIMENT_RUNNER,
                run_id="run-negative",
                gate_id=e2_gate,
                frozen_context_sha256=transition_role_context_sha256(
                    Role.SCIENTIFIC_REVIEWER,
                    "run-negative",
                    hashes,
                    e2_gate,
                    producer_role=Role.EXPERIMENT_RUNNER,
                ),
            ),
        )
        controller = StateController(MacroState.CONFIRM, artifact_verifier=lambda _: True)
        result = controller.transition(TransitionRequest(
            "run-negative", MacroState.CONFIRM, TerminalState.NEGATIVE_RESULT,
            Role.ORCHESTRATOR, Role.SCIENTIFIC_REVIEWER,
            refs, evaluations, "negative-terminal-1", "primary result is negative",
        ))
        self.assertEqual(result.current_state, TerminalState.NEGATIVE_RESULT)
        self.assertTrue(controller.terminal)


class LedgerTests(ProjectTempCase):
    def setUp(self) -> None:
        super().setUp()
        self.ledger = EventLedger(self.root, "runs/run-1/events.jsonl")
        self._head_state = MacroState.CALIBRATE

    def record(self, event_id: str, *, reason: str = "validated transition") -> LedgerEvent:
        state_before = self._head_state
        destinations = {
            MacroState.CALIBRATE: MacroState.CHARTER,
            MacroState.CHARTER: MacroState.GROUND,
            MacroState.GROUND: MacroState.PROTOCOL,
        }
        event = self.ledger.record(
            run_id="run-1",
            event_id=event_id,
            timestamp=f"2026-08-12T12:00:0{event_id[-1]}Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=state_before,
            requested_state_after=destinations.get(state_before, state_before),
            artifact_hashes=("a" * 64,),
            code_version="working-tree:fixture",
            configuration_hash=CONFIG_HASH,
            dataset_identifiers=("fixture-v1",),
            random_seeds=(7,),
            evaluator_outputs=(),
            reason=reason,
        )
        self._head_state = event.requested_state_after
        return event

    def test_subprocesses_share_the_stable_ledger_namespace_lock(self) -> None:
        acquired = self.sandbox / "ledger-acquired"
        release = self.sandbox / "ledger-release"
        second = self.sandbox / "ledger-second"
        program = (
            "import pathlib,sys\n"
            "sys.path.insert(0,sys.argv.pop(1))\n"
            "from scientist_one.ledger import EventLedger\n"
            "root=pathlib.Path(sys.argv[1]); acquired=pathlib.Path(sys.argv[2]); "
            "release=pathlib.Path(sys.argv[3])\n"
            "ledger=EventLedger(root,'runs/run-1/events.jsonl')\n"
            "guard=ledger._open_lock()\n"
            "try:\n"
            " acquired.write_text('acquired',encoding='utf-8')\n"
            " while not release.exists(): pass\n"
            "finally:\n"
            " ledger._unlock(guard)\n"
        )
        first = subprocess.Popen(
            [
                PYTHON, "-I", "-S", "-B", "-c", program,
                str(PROJECT_ROOT / "src"), str(self.root), str(acquired), str(release),
            ],
            cwd=PROJECT_ROOT,
            env=_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_path(acquired, first)
        second_program = (
            "import pathlib,sys\n"
            "sys.path.insert(0,sys.argv.pop(1))\n"
            "from scientist_one.ledger import EventLedger\n"
            "ledger=EventLedger(pathlib.Path(sys.argv[1]),'runs/run-1/events.jsonl')\n"
            "guard=ledger._open_lock()\n"
            "try: pathlib.Path(sys.argv[2]).write_text('acquired',encoding='utf-8')\n"
            "finally: ledger._unlock(guard)\n"
        )
        rival = subprocess.Popen(
            [
                PYTHON, "-I", "-S", "-B", "-c", second_program,
                str(PROJECT_ROOT / "src"), str(self.root), str(second),
            ],
            cwd=PROJECT_ROOT,
            env=_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        self.assertIsNone(rival.poll())
        self.assertFalse(second.exists())
        release.write_text("release", encoding="utf-8")
        first_output, first_error = first.communicate(timeout=10)
        rival_output, rival_error = rival.communicate(timeout=10)
        self.assertEqual(first.returncode, 0, first_output + first_error)
        self.assertEqual(rival.returncode, 0, rival_output + rival_error)
        self.assertTrue(second.exists())

    def test_ledger_namespace_replace_restore_is_rejected(self) -> None:
        self.record("event-1")
        original_bytes = self.ledger.path.read_bytes()
        moved = self.root / "runs" / "run-1-authentic"
        replacement = self.root / "runs" / "run-1"
        guard = self.ledger._open_lock()
        os.rename(replacement, moved)
        replacement.mkdir()
        (replacement / "events.jsonl").write_bytes(original_bytes)
        os.rename(replacement, self.root / "runs" / "run-1-replacement")
        os.rename(moved, replacement)
        with self.assertRaises(LedgerError):
            self.ledger._unlock(guard)
        self.assertEqual(self.ledger.path.read_bytes(), original_bytes)
        self.assertEqual(self.ledger.validate(raise_on_error=True).event_count, 1)

    def test_append_only_hash_chain_and_exact_schema_validate(self) -> None:
        first = self.record("event-1")
        second = self.record("event-2")
        result = self.ledger.validate(raise_on_error=True)
        self.assertEqual(result.event_count, 2)
        self.assertEqual(second.prior_event_hash, first.event_hash)
        self.assertEqual(result.head_hash, second.event_hash)
        lines = self.ledger.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["event_hash"], event_hash(parsed))

    def test_append_rejects_same_length_valid_prefix_rewrite_before_write(
        self,
    ) -> None:
        first = self.record("event-1")
        original = self.ledger.path.read_bytes()
        rewritten = first.to_dict()
        rewritten["reason"] = "rewritten transition"
        rewritten["event_hash"] = event_hash(
            {
                key: value
                for key, value in rewritten.items()
                if key != "event_hash"
            }
        )
        alternate = canonical_json_bytes(rewritten) + b"\n"
        self.assertEqual(len(alternate), len(original))
        original_verify = self.ledger._verify_ledger_fd
        calls = 0

        def rewrite_after_identity_check(guard, descriptor):
            nonlocal calls
            original_verify(guard, descriptor)
            calls += 1
            if calls == 1:
                self.ledger.path.write_bytes(alternate)

        with mock.patch.object(
            self.ledger,
            "_verify_ledger_fd",
            side_effect=rewrite_after_identity_check,
        ):
            with self.assertRaisesRegex(LedgerError, "ledger bytes changed"):
                self.record("event-2")
        self.assertEqual(self.ledger.path.read_bytes(), alternate)
        self.assertTrue(self.ledger.validate(raise_on_error=True).valid)

    def test_append_rejects_same_length_post_write_event_rewrite(self) -> None:
        self.record("event-1")
        original_verify = self.ledger._verify_ledger_fd
        calls = 0

        def rewrite_after_append_identity_check(guard, descriptor):
            nonlocal calls
            original_verify(guard, descriptor)
            calls += 1
            if calls == 2:
                lines = self.ledger.path.read_bytes().splitlines()
                rewritten = json.loads(lines[-1])
                rewritten["reason"] = "rewritten transition"
                rewritten["event_hash"] = event_hash(
                    {
                        key: value
                        for key, value in rewritten.items()
                        if key != "event_hash"
                    }
                )
                alternate = b"\n".join(
                    (*lines[:-1], canonical_json_bytes(rewritten))
                ) + b"\n"
                self.assertEqual(
                    len(alternate),
                    self.ledger.path.stat().st_size,
                )
                self.ledger.path.write_bytes(alternate)

        with mock.patch.object(
            self.ledger,
            "_verify_ledger_fd",
            side_effect=rewrite_after_append_identity_check,
        ):
            with self.assertRaisesRegex(LedgerError, "append bytes"):
                self.record("event-2")
        self.assertEqual(
            self.ledger.validate(raise_on_error=True).event_count,
            2,
        )

    def test_append_rejects_rewrite_after_final_reread_before_os_write(
        self,
    ) -> None:
        first = self.record("event-1")
        original = self.ledger.path.read_bytes()
        rewritten = first.to_dict()
        rewritten["reason"] = "rewritten transition"
        rewritten["event_hash"] = event_hash(
            {
                key: value
                for key, value in rewritten.items()
                if key != "event_hash"
            }
        )
        alternate = canonical_json_bytes(rewritten) + b"\n"
        self.assertEqual(len(alternate), len(original))
        original_write = ledger_module.os.write
        injected = False

        def rewrite_at_write(descriptor, data):
            nonlocal injected
            if not injected:
                injected = True
                self.ledger.path.write_bytes(alternate)
            return original_write(descriptor, data)

        with mock.patch.object(
            ledger_module.os,
            "write",
            side_effect=rewrite_at_write,
        ):
            with self.assertRaisesRegex(LedgerError, "append bytes"):
                self.record("event-2")
        self.assertTrue(injected)
        self.assertFalse(self.ledger.validate().valid)

    def test_mid_ledger_corruption_is_detected_and_blocks_append(self) -> None:
        self.record("event-1")
        value = json.loads(self.ledger.path.read_text(encoding="utf-8"))
        value["reason"] = "tampered"
        self.ledger.path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        self.assertFalse(self.ledger.validate().valid)
        with self.assertRaises(LedgerCorruptionError):
            self.record("event-2")

    def test_oversized_ledger_fails_closed_before_materialization(self) -> None:
        with mock.patch.object(ledger_module, "MAX_LEDGER_BYTES", 128):
            self.ledger.path.write_bytes(b"x" * 129)
            result = self.ledger.validate()
            self.assertFalse(result.valid)
            self.assertEqual(result.error, "LEDGER_READ_OR_SIZE_LIMIT_FAILED")
            with self.assertRaises(LedgerCorruptionError):
                self.ledger.validate(raise_on_error=True)

    def test_event_count_limit_fails_closed(self) -> None:
        first = LedgerEvent.create(
            run_id="run-1",
            event_id="event-limit-1",
            timestamp="2026-08-12T12:00:00Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CHARTER,
            artifact_hashes=("a" * 64,),
            code_version="fixture",
            configuration_hash=CONFIG_HASH,
            reason="bounded event one",
            prior_event_hash=None,
        )
        second = LedgerEvent.create(
            run_id="run-1",
            event_id="event-limit-2",
            timestamp="2026-08-12T12:00:01Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CHARTER,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=("b" * 64,),
            code_version="fixture",
            configuration_hash=CONFIG_HASH,
            reason="bounded event two",
            prior_event_hash=first.event_hash,
        )
        data = (
            canonical_json_bytes(first.to_dict())
            + b"\n"
            + canonical_json_bytes(second.to_dict())
            + b"\n"
        )
        with mock.patch.object(ledger_module, "MAX_LEDGER_EVENTS", 1):
            result = EventLedger._validate_bytes(data)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "LEDGER_EVENT_LIMIT_EXCEEDED")

    def test_append_refuses_event_limit_without_changing_bytes_or_head(self) -> None:
        first = self.record("event-1")
        before = self.ledger.path.read_bytes()
        with mock.patch.object(ledger_module, "MAX_LEDGER_EVENTS", 1):
            with self.assertRaises(LedgerError):
                self.record("event-2")
        self.assertEqual(self.ledger.path.read_bytes(), before)
        self.assertEqual(self.ledger.validate(raise_on_error=True).head_hash, first.event_hash)

    def test_append_refuses_byte_limit_without_changing_bytes_or_head(self) -> None:
        first = self.record("event-1")
        before = self.ledger.path.read_bytes()
        with mock.patch.object(
            ledger_module, "MAX_LEDGER_BYTES", len(before) + 1
        ):
            with self.assertRaises(LedgerError):
                self.record("event-2")
        self.assertEqual(self.ledger.path.read_bytes(), before)
        self.assertEqual(self.ledger.validate(raise_on_error=True).head_hash, first.event_hash)

    def test_torn_final_append_is_detected_quarantined_and_prefix_restored(self) -> None:
        self.record("event-1")
        with self.ledger.path.open("ab") as handle:
            handle.write(b'{"event_id":"partial"')
        result = self.ledger.validate()
        self.assertFalse(result.valid)
        self.assertTrue(result.recoverable_truncated_tail)
        quarantine = self.ledger.recover_truncated_tail()
        self.assertTrue(quarantine.is_file())
        self.assertEqual(self.ledger.validate(raise_on_error=True).event_count, 1)

    def test_truncated_first_event_is_fatal_not_silently_reset(self) -> None:
        self.ledger.path.write_bytes(b'{"event_id":"partial"')
        result = self.ledger.validate()
        self.assertFalse(result.valid)
        self.assertFalse(result.recoverable_truncated_tail)
        with self.assertRaises(LedgerError):
            self.ledger.recover_truncated_tail()
        self.assertEqual(self.ledger.path.read_bytes(), b'{"event_id":"partial"')

    def test_event_metadata_is_defensively_frozen_before_hashing(self) -> None:
        metadata = {"nested": ["original"]}
        event = LedgerEvent.create(
            run_id="run-1", event_id="event-frozen", timestamp="2026-08-12T12:00:00Z",
            actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CHARTER, artifact_hashes=("a" * 64,),
            code_version="fixture", configuration_hash=CONFIG_HASH,
            metadata=metadata, reason="immutable metadata", prior_event_hash=None,
        )
        metadata["nested"].append("mutated")
        self.assertEqual(event.to_dict()["metadata"], {"nested": ["original"]})
        with self.assertRaises(TypeError):
            event.metadata["replacement"] = True  # type: ignore[index]
        self.ledger.append(event)
        self.assertTrue(self.ledger.validate().valid)

    def test_correction_appends_and_references_superseded_event(self) -> None:
        original = self.record("event-1")
        self.record("event-2")
        original_prefix = self.ledger.path.read_bytes()
        correction = self.ledger.append_correction(
            original.event_id,
            event_id="correction-1",
            timestamp="2026-08-12T12:00:02Z",
            actor_role=Role.ORCHESTRATOR,
            reason="correct a descriptive label without editing history",
            corrected_fields={"dataset_label": "fixture-v2"},
        )
        self.assertEqual(correction.event_type, "CORRECTION")
        self.assertEqual(correction.supersedes_event_id, original.event_id)
        self.assertEqual(correction.state_before, MacroState.GROUND)
        self.assertEqual(correction.requested_state_after, MacroState.GROUND)
        self.assertTrue(self.ledger.path.read_bytes().startswith(original_prefix))
        self.assertEqual(self.ledger.validate(raise_on_error=True).event_count, 3)
        with self.assertRaises(LedgerError):
            self.ledger.append_correction(
                "missing-event",
                actor_role=Role.ORCHESTRATOR,
                reason="invalid correction",
                corrected_fields={"x": 1},
            )

    def test_nonsemantic_state_change_and_stale_head_append_are_zero_write_rejections(self) -> None:
        with self.assertRaises(ValidationError):
            LedgerEvent.create(
                run_id="run-1",
                event_id="state-changing-checkpoint",
                timestamp="2026-08-12T12:00:00Z",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CHARTER,
                artifact_hashes=(),
                code_version="fixture",
                configuration_hash=CONFIG_HASH,
                reason="checkpoint cannot change state",
                prior_event_hash=None,
                event_type="CHECKPOINT",
            )

        first = self.record("event-1")
        original = self.ledger.path.read_bytes()
        stale = LedgerEvent.create(
            run_id="run-1",
            event_id="stale-state",
            timestamp="2026-08-12T12:00:02Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="fixture",
            configuration_hash=CONFIG_HASH,
            reason="stale state head",
            prior_event_hash=first.event_hash,
        )
        with self.assertRaisesRegex(LedgerError, "current ledger head"):
            self.ledger.append(stale)
        self.assertEqual(self.ledger.path.read_bytes(), original)

    def test_duplicate_event_id_and_wrong_prior_hash_rejected(self) -> None:
        self.record("event-1")
        with self.assertRaises(LedgerError):
            self.record("event-1")
        forged = LedgerEvent.create(
            run_id="run-1",
            event_id="event-2",
            timestamp="2026-08-12T12:00:02Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CHARTER,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=("b" * 64,),
            code_version="working-tree:fixture",
            configuration_hash=CONFIG_HASH,
            reason="wrong chain head",
            prior_event_hash="f" * 64,
        )
        with self.assertRaises(LedgerError):
            self.ledger.append(forged)

    def test_boolean_seed_and_nonfinite_metadata_rejected(self) -> None:
        with self.assertRaises(ValueError):
            LedgerEvent.create(
                run_id="run-1", event_id="event-bool", timestamp="2026-08-12T12:00:00Z",
                actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CHARTER, artifact_hashes=("a" * 64,),
                code_version="fixture", configuration_hash=CONFIG_HASH,
                random_seeds=(True,), reason="invalid seed", prior_event_hash=None,
            )
        with self.assertRaises(ValueError):
            LedgerEvent.create(
                run_id="run-1", event_id="event-nan", timestamp="2026-08-12T12:00:00Z",
                actor_role=Role.ORCHESTRATOR, state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CHARTER, artifact_hashes=("a" * 64,),
                code_version="fixture", configuration_hash=CONFIG_HASH,
                metadata={"value": float("nan")}, reason="invalid JSON", prior_event_hash=None,
            )


class ArtifactRegistryTests(ProjectTempCase):
    def setUp(self) -> None:
        super().setUp()
        self.registry = ArtifactRegistry(self.root)

    def store(self, content: bytes = b"evidence"):
        return self.registry.put_bytes(
            content,
            logical_type="result_artifact",
            origin="deterministic fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("python", "-m", "scientist_one"),
        )

    def test_content_address_metadata_and_manifest_interoperate(self) -> None:
        record = self.store()
        self.assertEqual(record.sha256, hashlib.sha256(b"evidence").hexdigest())
        self.assertEqual(record.size, len(b"evidence"))
        self.assertTrue(record.frozen)
        self.assertEqual(self.registry.get_bytes(record.sha256), b"evidence")
        self.assertTrue(self.registry.verify(record.sha256))
        manifest_record = record.to_dict()
        for key in ("path", "sha256", "size", "frozen", "origin", "creator_role"):
            self.assertIn(key, manifest_record)
        self.assertEqual(self.registry.manifest()["result_artifact"]["path"], record.path)

    def test_frozen_metadata_is_immutable_and_registration_is_idempotent(self) -> None:
        first = self.store()
        second = self.store()
        self.assertEqual(first, second)
        with self.assertRaises(FrozenArtifactError):
            self.registry.put_bytes(
                b"evidence",
                logical_type="different_type",
                origin="different origin",
                creator_role=Role.IMPLEMENTER,
            )

    def test_blob_and_metadata_corruption_are_detected_on_every_read(self) -> None:
        record = self.store()
        blob = self.root / record.path
        blob.write_bytes(b"tampered")
        self.assertFalse(self.registry.verify(record.sha256))
        with self.assertRaises(ArtifactCorruptionError):
            self.registry.get_bytes(record.sha256)

        clean_root = self.sandbox / "clean-project"
        clean_root.mkdir()
        registry = ArtifactRegistry(clean_root)
        clean = registry.put_bytes(
            b"clean",
            logical_type="result_artifact",
            origin="fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        metadata = clean_root / clean.metadata_path
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["origin"] = "tampered"
        metadata.write_text(json.dumps(value), encoding="utf-8")
        self.assertFalse(registry.verify(clean.sha256))
        with self.assertRaises(ArtifactCorruptionError):
            registry.get_metadata(clean.sha256)

    def test_registry_object_size_limit_fails_before_unbounded_read(self) -> None:
        record = self.store(b"bounded-object")
        with mock.patch.object(artifacts_module, "MAX_ARTIFACT_OBJECT_BYTES", 4):
            self.assertFalse(self.registry.verify(record.sha256))
            with self.assertRaises(ArtifactCorruptionError):
                self.registry.get_bytes(record.sha256)
            with self.assertRaises(ArtifactError):
                self.store(b"oversized")

    def test_registry_entry_count_limit_fails_closed(self) -> None:
        first = self.store(b"one")
        self.registry.put_bytes(
            b"two",
            logical_type="secondary_result",
            origin="deterministic fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        with mock.patch.object(artifacts_module, "MAX_REGISTRY_RECORDS", 1):
            result = self.registry.verify_all()
        self.assertFalse(result.valid)
        self.assertTrue(any("count exceeds" in item for item in result.errors))
        self.assertTrue(first.sha256)

    def test_registry_scan_streams_and_rejects_before_retaining_cap_plus_one(self) -> None:
        self.store(b"one")
        with mock.patch.object(artifacts_module, "MAX_REGISTRY_SCAN_ENTRIES", 2):
            self.assertTrue(self.registry.verify_all().valid)

        class NamedEntry:
            name = "missing"

        class SentinelEntry:
            @property
            def name(self) -> str:
                raise AssertionError("cap-plus-one entry name must not be retained")

        class GuardedScandir:
            def __init__(self) -> None:
                self._entries = iter((NamedEntry(), SentinelEntry()))
                self.closed = False

            def __enter__(self) -> "GuardedScandir":
                return self

            def __exit__(self, *args: object) -> None:
                self.closed = True

            def __iter__(self) -> "GuardedScandir":
                return self

            def __next__(self) -> object:
                return next(self._entries)

        scans: list[GuardedScandir] = []

        def guarded_scandir(_directory_fd: int) -> GuardedScandir:
            scan = GuardedScandir()
            scans.append(scan)
            return scan

        with (
            mock.patch.object(artifacts_module, "MAX_REGISTRY_SCAN_ENTRIES", 1),
            mock.patch.object(
                artifacts_module.os,
                "listdir",
                side_effect=AssertionError("registry scan must not materialize listdir"),
            ),
            mock.patch.object(
                artifacts_module.os, "scandir", side_effect=guarded_scandir
            ),
        ):
            result = self.registry.verify_all()
        self.assertFalse(result.valid)
        self.assertTrue(any("count exceeds" in item for item in result.errors))
        self.assertTrue(scans)
        self.assertTrue(all(scan.closed for scan in scans))

    def test_registry_write_limit_rejects_before_object_or_metadata_publish(self) -> None:
        first = self.store(b"one")
        before_objects = {
            path.relative_to(self.root)
            for path in (self.root / "artifacts/registry/objects").rglob("*")
            if path.is_file()
        }
        before_metadata = {
            path.relative_to(self.root)
            for path in (self.root / "artifacts/registry/metadata").rglob("*")
            if path.is_file()
        }
        with mock.patch.object(artifacts_module, "MAX_REGISTRY_RECORDS", 1):
            with self.assertRaises(ArtifactError):
                self.store(b"two")
        after_objects = {
            path.relative_to(self.root)
            for path in (self.root / "artifacts/registry/objects").rglob("*")
            if path.is_file()
        }
        after_metadata = {
            path.relative_to(self.root)
            for path in (self.root / "artifacts/registry/metadata").rglob("*")
            if path.is_file()
        }
        self.assertEqual(after_objects, before_objects)
        self.assertEqual(after_metadata, before_metadata)
        self.assertEqual(self.registry.verify_all(raise_on_error=True).count, 1)
        self.assertTrue(self.registry.verify(first.sha256))

    def test_provenance_depth_and_work_are_iterative_and_bounded(self) -> None:
        chain = [self.store(b"root")]
        for index in range(4):
            chain.append(
                self.registry.put_bytes(
                    f"child-{index}".encode(),
                    logical_type=f"chain_{index}",
                    origin="bounded provenance fixture",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    parent_artifacts=(chain[-1].sha256,),
                )
            )
        with mock.patch.object(artifacts_module, "MAX_PROVENANCE_DEPTH", 2):
            self.assertFalse(self.registry.verify(chain[-1].sha256))
            self.assertFalse(self.registry.verify_all().valid)
        with mock.patch.object(artifacts_module, "MAX_PROVENANCE_EDGES", 2):
            self.assertFalse(self.registry.verify(chain[-1].sha256))
            self.assertFalse(self.registry.verify_all().valid)

    def test_parent_count_limit_is_enforced_by_artifact_schema(self) -> None:
        parents = tuple("%064x" % index for index in range(1, 4))
        with mock.patch.object(artifacts_module, "MAX_ARTIFACT_PARENTS", 2):
            with self.assertRaises(ValidationError):
                artifacts_module.ArtifactRecord(
                    sha256="f" * 64,
                    path="objects/ff/" + "f" * 64,
                    relative_path="objects/ff/" + "f" * 64,
                    metadata_path="metadata/ff/" + "f" * 64 + ".json",
                    logical_type="bounded_parents",
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    size=1,
                    origin="fixture",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "internal"),
                    parent_artifacts=parents,
                    validation_result="PASS",
                    frozen=True,
                    created_at="2026-08-12T12:00:00Z",
                )

    def test_subprocesses_share_the_stable_registry_namespace_lock(self) -> None:
        acquired = self.sandbox / "registry-acquired"
        release = self.sandbox / "registry-release"
        second = self.sandbox / "registry-second"
        program = (
            "import pathlib,sys\n"
            "sys.path.insert(0,sys.argv.pop(1))\n"
            "from scientist_one.artifacts import ArtifactRegistry\n"
            "root=pathlib.Path(sys.argv[1]); acquired=pathlib.Path(sys.argv[2]); "
            "release=pathlib.Path(sys.argv[3])\n"
            "registry=ArtifactRegistry(root)\n"
            "guard=registry._open_mutation_lock()\n"
            "try:\n"
            " acquired.write_text('acquired',encoding='utf-8')\n"
            " while not release.exists(): pass\n"
            "finally:\n"
            " registry._unlock_mutation(guard)\n"
        )
        first = subprocess.Popen(
            [
                PYTHON, "-I", "-S", "-B", "-c", program,
                str(PROJECT_ROOT / "src"), str(self.root), str(acquired), str(release),
            ],
            cwd=PROJECT_ROOT,
            env=_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_path(acquired, first)
        second_program = (
            "import pathlib,sys\n"
            "sys.path.insert(0,sys.argv.pop(1))\n"
            "from scientist_one.artifacts import ArtifactRegistry\n"
            "registry=ArtifactRegistry(pathlib.Path(sys.argv[1]))\n"
            "guard=registry._open_mutation_lock()\n"
            "try: pathlib.Path(sys.argv[2]).write_text('acquired',encoding='utf-8')\n"
            "finally: registry._unlock_mutation(guard)\n"
        )
        rival = subprocess.Popen(
            [
                PYTHON, "-I", "-S", "-B", "-c", second_program,
                str(PROJECT_ROOT / "src"), str(self.root), str(second),
            ],
            cwd=PROJECT_ROOT,
            env=_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        self.assertIsNone(rival.poll())
        self.assertFalse(second.exists())
        release.write_text("release", encoding="utf-8")
        first_output, first_error = first.communicate(timeout=10)
        rival_output, rival_error = rival.communicate(timeout=10)
        self.assertEqual(first.returncode, 0, first_output + first_error)
        self.assertEqual(rival.returncode, 0, rival_output + rival_error)
        self.assertTrue(second.exists())

    def test_registry_namespace_replace_restore_is_rejected(self) -> None:
        moved = self.root / "artifacts" / "registry-authentic"
        replacement = self.root / "artifacts" / "registry"
        guard = self.registry._open_mutation_lock()
        os.rename(replacement, moved)
        ArtifactRegistry(self.root)
        os.rename(replacement, self.root / "artifacts" / "registry-replacement")
        os.rename(moved, replacement)
        with self.assertRaises(ArtifactError):
            self.registry._unlock_mutation(guard)
        self.assertEqual(self.registry.verify_all(raise_on_error=True).count, 0)

    def test_registry_publication_rejects_replacement_before_any_child_write(self) -> None:
        moved = self.root / "artifacts" / "registry-authentic"
        replacement = self.root / "artifacts" / "registry"
        replacement_registry: ArtifactRegistry | None = None
        original_publish = self.registry._publish_immutable
        swapped = False

        def replace_then_publish(guard, relative, data):
            nonlocal replacement_registry, swapped
            if not swapped:
                swapped = True
                os.rename(replacement, moved)
                replacement_registry = ArtifactRegistry(self.root)
            return original_publish(guard, relative, data)

        with mock.patch.object(
            self.registry, "_publish_immutable", side_effect=replace_then_publish
        ):
            with self.assertRaises(ArtifactError):
                self.store(b"held-namespace-only")
        assert replacement_registry is not None
        self.assertEqual(
            replacement_registry.verify_all(raise_on_error=True).count, 0
        )
        digest = hashlib.sha256(b"held-namespace-only").hexdigest()
        self.assertFalse(
            (moved / "objects" / digest[:2] / digest).exists()
        )
        self.assertFalse(
            (
                replacement / "objects" / digest[:2] / digest
            ).exists()
        )

    def test_registry_rejects_objects_swap_restored_between_publish_stages(
        self,
    ) -> None:
        objects = self.root / "artifacts" / "registry" / "objects"
        held = self.root / "artifacts" / "registry" / "objects-held"
        discarded = self.root / "objects-replacement"
        original_publish = self.registry._publish_immutable
        publications = 0

        def swap_after_object_publish(guard, relative, data):
            nonlocal publications
            result = original_publish(guard, relative, data)
            publications += 1
            if publications == 1:
                objects.rename(held)
                objects.mkdir()
                objects.rename(discarded)
                held.rename(objects)
            return result

        with mock.patch.object(
            self.registry,
            "_publish_immutable",
            side_effect=swap_after_object_publish,
        ):
            with self.assertRaisesRegex(ArtifactError, "namespace changed"):
                self.store(b"objects-generation-race")

    def test_registry_rejects_digest_directory_swap_restored_mid_operation(
        self,
    ) -> None:
        content = b"digest-generation-race"
        digest = hashlib.sha256(content).hexdigest()
        objects = self.root / "artifacts" / "registry" / "objects"
        prefix = objects / digest[:2]
        held = objects / f"{digest[:2]}-held"
        discarded = self.root / "digest-prefix-replacement"
        original_publish = self.registry._publish_immutable
        publications = 0

        def swap_after_object_publish(guard, relative, data):
            nonlocal publications
            result = original_publish(guard, relative, data)
            publications += 1
            if publications == 1:
                prefix.rename(held)
                prefix.mkdir()
                prefix.rename(discarded)
                held.rename(prefix)
            return result

        with mock.patch.object(
            self.registry,
            "_publish_immutable",
            side_effect=swap_after_object_publish,
        ):
            with self.assertRaisesRegex(ArtifactError, "namespace changed"):
                self.store(content)

    def test_registry_rejects_unexpected_base_child_during_prefix_creation(
        self,
    ) -> None:
        content = b"unexpected-base-delta"
        digest = hashlib.sha256(content).hexdigest()
        original_finish = self.registry._finish_registry_directory_mutation
        injected = False

        def inject_unrelated_child(guard, snapshot, **delta):
            nonlocal injected
            if (
                not injected
                and snapshot.key == ("objects",)
                and any(name == digest[:2] for name, _identity in delta.get("added", ()))
            ):
                injected = True
                os.mkdir(
                    "unrelated-child",
                    dir_fd=guard.directory_fds[("objects",)],
                )
            return original_finish(guard, snapshot, **delta)

        with mock.patch.object(
            self.registry,
            "_finish_registry_directory_mutation",
            side_effect=inject_unrelated_child,
        ):
            with self.assertRaisesRegex(ArtifactError, "namespace changed|exact admitted"):
                self.store(content)
        self.assertTrue(injected)

    def test_registry_rejects_unexpected_digest_entry_during_publish(
        self,
    ) -> None:
        content = b"unexpected-digest-delta"
        digest = hashlib.sha256(content).hexdigest()
        original_finish = self.registry._finish_registry_directory_mutation
        injected = False

        def inject_unrelated_entry(guard, snapshot, **delta):
            nonlocal injected
            if not injected and snapshot.key == ("objects", digest[:2]):
                injected = True
                descriptor = os.open(
                    "unrelated-entry",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=guard.directory_fds[snapshot.key],
                )
                os.close(descriptor)
            return original_finish(guard, snapshot, **delta)

        with mock.patch.object(
            self.registry,
            "_finish_registry_directory_mutation",
            side_effect=inject_unrelated_entry,
        ):
            with self.assertRaisesRegex(ArtifactError, "namespace changed|exact admitted"):
                self.store(content)
        self.assertTrue(injected)

    def test_preexisting_digest_collision_and_symlink_escape_fail_closed(self) -> None:
        content = b"expected"
        digest = hashlib.sha256(content).hexdigest()
        object_path = self.root / "artifacts" / "registry" / "objects" / digest[:2] / digest
        object_path.parent.mkdir(parents=True, exist_ok=True)
        object_path.write_bytes(b"different")
        with self.assertRaises(ArtifactCollisionError):
            self.store(content)

        other_root = self.sandbox / "symlink-project"
        other_root.mkdir()
        registry = ArtifactRegistry(other_root)
        link_digest = hashlib.sha256(b"linked").hexdigest()
        outside = self.outside / "blob"
        outside.write_bytes(b"outside")
        object_parent = other_root / "artifacts" / "registry" / "objects" / link_digest[:2]
        object_parent.mkdir()
        (object_parent / link_digest).symlink_to(outside)
        with self.assertRaises(ArtifactCollisionError):
            registry.put_bytes(
                b"linked",
                logical_type="result_artifact",
                origin="fixture",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_parent_provenance_requires_existing_valid_artifact(self) -> None:
        with self.assertRaises(ArtifactError):
            self.registry.put_bytes(
                b"child",
                logical_type="child_artifact",
                origin="fixture",
                creator_role=Role.IMPLEMENTER,
                parent_artifacts=("f" * 64,),
            )
        parent = self.store(b"parent")
        child = self.registry.put_bytes(
            b"child",
            logical_type="child_artifact",
            origin="fixture",
            creator_role=Role.IMPLEMENTER,
            parent_artifacts=(parent.sha256,),
        )
        self.assertEqual(child.parent_artifacts, (parent.sha256,))
        (self.root / parent.path).write_bytes(b"corrupt-parent")
        self.assertFalse(self.registry.verify(child.sha256))

    def test_file_ingestion_rejects_symlink_and_hard_link_inputs(self) -> None:
        source = self.root / "source"
        source.write_bytes(b"source")
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaises(PathSecurityError):
            self.registry.register_file(
                link,
                logical_type="source_artifact",
                creator_role=Role.EVIDENCE_CURATOR,
            )
        alias = self.root / "alias"
        os.link(source, alias)
        with self.assertRaises(PathSecurityError):
            self.registry.register_file(
                source,
                logical_type="source_artifact",
                creator_role=Role.EVIDENCE_CURATOR,
            )

    def test_registry_detects_orphan_and_quarantines_partial_regular_file(self) -> None:
        partial = self.root / "artifacts" / "registry" / "objects" / "orphan.partial"
        partial.write_bytes(b"incomplete")
        result = self.registry.verify_all()
        self.assertFalse(result.valid)
        moved = self.registry.quarantine_incomplete()
        self.assertEqual(len(moved), 1)
        self.assertEqual(partial.read_bytes(), b"incomplete")
        self.assertTrue((self.root / moved[0]).is_file())
        self.assertTrue((self.root / f"{moved[0]}.metadata.json").is_file())
        self.assertEqual(self.registry.quarantine_incomplete(), ())
        self.assertTrue(self.registry.verify_all().valid)

    def test_logical_quarantine_cannot_hide_a_nonpartial_registry_orphan(self) -> None:
        registry_root = self.root / "artifacts" / "registry"
        source_relative = Path("objects") / "forged-orphan"
        source = registry_root / source_relative
        source.write_bytes(b"orphan content")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        source_key = hashlib.sha256(source_relative.as_posix().encode("utf-8")).hexdigest()
        quarantine = registry_root / "quarantine"
        quarantine.mkdir()
        copy_name = (
            f"{source_key[:16]}-{digest[:16]}-{source.name}.quarantine"
        )
        copy_relative = Path("quarantine") / copy_name
        (registry_root / copy_relative).write_bytes(source.read_bytes())
        sidecar = registry_root / f"{copy_relative.as_posix()}.metadata.json"
        sidecar.write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": "scientist-one-logical-quarantine/v1",
                    "original_relative_path": source_relative.as_posix(),
                    "quarantine_relative_path": copy_relative.as_posix(),
                    "reason": "INCOMPLETE_WRITE",
                    "size_bytes": source.stat().st_size,
                    "sha256": digest,
                }
            )
        )

        result = self.registry.verify_all()
        self.assertFalse(result.valid)
        self.assertIn("artifact logical quarantine is invalid", result.errors)

    def test_logical_quarantine_revalidates_in_place_source_overwrite(self) -> None:
        partial = self.root / "artifacts" / "registry" / "objects" / "racy.tmp"
        partial.write_bytes(b"original partial")
        self.registry.quarantine_incomplete()
        real_walk = self.registry._walk_regular
        overwritten = False

        def overwrite_after_tombstone_validation(guard, relative):
            nonlocal overwritten
            if relative == self.registry.metadata_path and not overwritten:
                overwritten = True
                partial.write_bytes(b"replacement bytes")
            return real_walk(guard, relative)

        with mock.patch.object(
            self.registry,
            "_walk_regular",
            side_effect=overwrite_after_tombstone_validation,
        ):
            result = self.registry.verify_all()
        self.assertTrue(overwritten)
        self.assertFalse(result.valid)
        self.assertIn(
            "artifact logical quarantine changed during validation",
            result.errors,
        )
        self.assertEqual(partial.read_bytes(), b"replacement bytes")

    def test_logical_quarantine_never_removes_a_replacement_inode(self) -> None:
        partial = self.root / "artifacts" / "registry" / "objects" / "racy.partial"
        partial.write_bytes(b"original partial")
        replacement = partial.with_name("replacement")
        replacement.write_bytes(b"replacement inode")
        real_publish = self.registry._publish_immutable
        replaced = False

        def replace_after_copy(guard, relative, data):
            nonlocal replaced
            result = real_publish(guard, relative, data)
            if relative.name.endswith(".quarantine") and not replaced:
                replaced = True
                os.replace(replacement, partial)
            return result

        with mock.patch.object(
            self.registry, "_publish_immutable", side_effect=replace_after_copy
        ):
            with self.assertRaises(ArtifactError):
                self.registry.quarantine_incomplete()
        self.assertTrue(replaced)
        self.assertEqual(partial.read_bytes(), b"replacement inode")

    def test_manifest_rejects_ambiguous_duplicate_logical_type(self) -> None:
        self.store(b"version-one")
        self.store(b"version-two")
        with self.assertRaises(ArtifactCollisionError):
            self.registry.manifest()


if __name__ == "__main__":
    unittest.main()
