"""Semantic reconstruction of frozen state, ledger, and artifact guarantees.

This is a reconstruction, not the missing historical test source.  It targets
the recovered frozen kernel APIs and uses only deterministic, synthetic
TemporaryDirectory projects.  The captured launcher supplies the frozen
``scientist_one`` package; this module deliberately imports no sibling tests,
does not touch the real project state, and does not exercise workflow/native
runtime boundaries.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scientist_one import artifacts as artifacts_module
from scientist_one import ledger as ledger_module
from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
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
    UnauthorizedTransitionError,
    ValidationError,
)
from scientist_one.evaluators import Decision, Evaluation, EvaluatorClass
from scientist_one.ledger import EventLedger, LedgerEvent, event_hash
from scientist_one.models import ArtifactRef, MacroState, TerminalState, TransitionRequest
from scientist_one.roles import Role, make_role_bundle
from scientist_one.security import canonical_json_bytes
from scientist_one.state_machine import (
    MACRO_SEQUENCE,
    StateController,
    TransitionContract,
    macro_transition_contracts,
)


CONFIGURATION_HASH = "c" * 64


class FrozenKernelFixtures(unittest.TestCase):
    """Small helpers shared by the semantic reconstruction cases."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name) / "project"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def registry(self) -> ArtifactRegistry:
        return ArtifactRegistry(self.root)

    def put(
        self,
        registry: ArtifactRegistry,
        content: bytes = b"synthetic evidence",
        *,
        logical_type: str = "evidence",
        creator_role: Role = Role.EXPERIMENT_RUNNER,
        parent_artifacts: tuple[str, ...] = (),
    ):
        return registry.put_bytes(
            content,
            logical_type=logical_type,
            origin="semantic reconstruction fixture",
            creator_role=creator_role,
            creation_command=("python", "-m", "synthetic_fixture"),
            parent_artifacts=parent_artifacts,
        )

    @staticmethod
    def contract(
        source: MacroState,
        destination: MacroState | TerminalState,
        *,
        artifacts: tuple[str, ...] = (),
        evaluators: tuple[EvaluatorClass, ...] = (),
        approvers: tuple[Role, ...] = (Role.SCIENTIFIC_REVIEWER,),
    ) -> TransitionContract:
        return TransitionContract(
            source=source,
            destination=destination,
            required_artifact_types=frozenset(artifacts),
            required_evaluators=frozenset(evaluators),
            allowed_requesters=frozenset({Role.ORCHESTRATOR}),
            allowed_approvers=frozenset(approvers),
            generated_artifact_types=frozenset(),
            failure_states=frozenset({TerminalState.STOP_SECURITY}),
        )

    @staticmethod
    def request(
        *,
        run_id: str,
        source: MacroState,
        destination: MacroState | TerminalState,
        refs: tuple[ArtifactRef, ...] = (),
        evaluations: tuple[Evaluation, ...] = (),
        key: str = "edge-1",
        requester: Role = Role.ORCHESTRATOR,
        approver: Role = Role.SCIENTIFIC_REVIEWER,
        reason: str = "synthetic typed transition",
        metadata: dict[str, object] | None = None,
    ) -> TransitionRequest:
        return TransitionRequest(
            run_id=run_id,
            from_state=source,
            to_state=destination,
            requester=requester,
            approver=approver,
            artifacts=refs,
            evaluations=evaluations,
            idempotency_key=key,
            reason=reason,
            metadata=metadata or {},
        )

    @staticmethod
    def passing_e0(refs: tuple[ArtifactRef, ...]) -> Evaluation:
        return Evaluation(
            evaluator_class=EvaluatorClass.E0,
            actor_role=Role.ORCHESTRATOR,
            decision=Decision.PASS,
            artifact_hashes=tuple(item.sha256 for item in refs),
            reason="deterministic fixture checks passed",
        )

    def ledger(self, path: str = "state/events.jsonl") -> EventLedger:
        return EventLedger(self.root, path)

    @staticmethod
    def append_fixture(
        ledger: EventLedger,
        event_id: str,
        *,
        run_id: str = "run-1",
        reason: str = "synthetic ledger event",
        state_before: MacroState = MacroState.CALIBRATE,
        requested_state_after: MacroState = MacroState.CHARTER,
        artifact_hashes: tuple[str, ...] = ("a" * 64,),
    ) -> LedgerEvent:
        suffix = event_id.rsplit("-", 1)[-1]
        timestamp = f"2026-09-19T12:00:{int(suffix):02d}Z"
        return ledger.record(
            run_id=run_id,
            event_id=event_id,
            timestamp=timestamp,
            actor_role=Role.ORCHESTRATOR,
            state_before=state_before,
            requested_state_after=requested_state_after,
            artifact_hashes=artifact_hashes,
            code_version="semantic-reconstruction",
            configuration_hash=CONFIGURATION_HASH,
            dataset_identifiers=("synthetic-v1",),
            random_seeds=(7,),
            reason=reason,
        )


class StateReconstructionTests(FrozenKernelFixtures):
    def test_macro_chain_is_forward_only_and_has_no_released_terminal(self) -> None:
        self.assertEqual(
            tuple(item.value for item in MACRO_SEQUENCE),
            (
                "CALIBRATE",
                "CHARTER",
                "GROUND",
                "PROTOCOL",
                "PREFLIGHT",
                "IDEATE",
                "DISCOVER",
                "CANDIDATE",
                "CONFIRM",
                "CLAIMS",
                "WRITE",
                "AUDIT",
                "RELEASE",
            ),
        )
        transitions = macro_transition_contracts()
        self.assertEqual(tuple(item.source for item in transitions), MACRO_SEQUENCE)
        self.assertEqual(transitions[-1].destination, TerminalState.READY_FOR_HUMAN_REVIEW)
        self.assertNotIn("RELEASED", {item.value for item in TerminalState})

    def test_contract_rejects_advisory_e1_e4_and_self_loop_authority(self) -> None:
        base = dict(
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            required_artifact_types=frozenset(),
            required_evaluators=frozenset({EvaluatorClass.E1}),
            allowed_requesters=frozenset({Role.ORCHESTRATOR}),
            allowed_approvers=frozenset({Role.SCIENTIFIC_REVIEWER}),
            generated_artifact_types=frozenset(),
            failure_states=frozenset({TerminalState.STOP_SECURITY}),
        )
        with self.assertRaises(ValueError):
            TransitionContract(**base)
        base["required_evaluators"] = frozenset({EvaluatorClass.E4})
        with self.assertRaises(ValueError):
            TransitionContract(**base)
        base["required_evaluators"] = frozenset()
        base["source"] = MacroState.CHARTER
        base["destination"] = MacroState.CHARTER
        with self.assertRaises(ValueError):
            TransitionContract(**base)

    def test_valid_transition_exact_replay_and_resumed_receipt_are_idempotent(self) -> None:
        registry = self.registry()
        first_record = self.put(registry, b"first", logical_type="first_evidence")
        second_record = self.put(registry, b"second", logical_type="second_evidence")
        refs = (first_record.to_ref(), second_record.to_ref())
        contract = self.contract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            artifacts=("first_evidence", "second_evidence"),
            evaluators=(EvaluatorClass.E0,),
        )
        request = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=refs,
            evaluations=(self.passing_e0(refs),),
        )
        controller = StateController(contracts=(contract,), artifact_registry=registry)
        first = controller.transition(request)
        second = controller.transition(request)
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.request_fingerprint, second.request_fingerprint)
        resumed = StateController(
            MacroState.CHARTER,
            contracts=(contract,),
            artifact_registry=registry,
            prior_receipts=(first.to_dict(),),
        )
        self.assertTrue(resumed.transition(request).replayed)

    def test_reusing_idempotency_key_for_different_request_is_rejected(self) -> None:
        contract = self.contract(MacroState.CALIBRATE, MacroState.CHARTER)
        controller = StateController(contracts=(contract,))
        first = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            key="same-key",
        )
        controller.transition(first)
        changed = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            key="same-key",
            reason="different request body",
        )
        with self.assertRaises(IdempotencyConflictError):
            controller.transition(changed)

    def test_skip_backward_and_terminal_exit_are_rejected(self) -> None:
        controller = StateController(contracts=(self.contract(MacroState.CALIBRATE, MacroState.CHARTER),))
        skipped = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.GROUND,
        )
        with self.assertRaises(InvalidTransitionError):
            controller.transition(skipped)
        terminal = StateController(TerminalState.STOP_SECURITY, contracts=())
        with self.assertRaises(InvalidTransitionError):
            terminal.transition(skipped)

    def test_requester_approver_and_human_release_authority_are_separate(self) -> None:
        contract = self.contract(MacroState.CALIBRATE, MacroState.CHARTER)
        unauthorized = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            requester=Role.IMPLEMENTER,
        )
        with self.assertRaises(UnauthorizedTransitionError):
            StateController(contracts=(contract,)).transition(unauthorized)
        self_approval_contract = self.contract(MacroState.CALIBRATE, MacroState.CHARTER, approvers=(Role.ORCHESTRATOR,))
        self_approval = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            approver=Role.ORCHESTRATOR,
        )
        with self.assertRaises(UnauthorizedTransitionError):
            StateController(contracts=(self_approval_contract,)).transition(self_approval)
        human_approval = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            approver=Role.HUMAN_RELEASE,
        )
        with self.assertRaises(UnauthorizedTransitionError):
            StateController(contracts=(contract,)).transition(human_approval)

    def test_missing_duplicate_unbound_and_unfrozen_artifacts_fail_closed(self) -> None:
        registry = self.registry()
        first = self.put(registry, b"first", logical_type="first_evidence")
        second = self.put(registry, b"second", logical_type="second_evidence")
        refs = (first.to_ref(), second.to_ref())
        contract = self.contract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            artifacts=("first_evidence", "second_evidence"),
            evaluators=(EvaluatorClass.E0,),
        )
        valid_evaluation = self.passing_e0(refs)
        controller = StateController(contracts=(contract,), artifact_registry=registry)
        missing = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(first.to_ref(),),
            evaluations=(valid_evaluation,),
        )
        with self.assertRaises(IncompleteTransitionError):
            controller.transition(missing)
        duplicate = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(first.to_ref(), first.to_ref(), second.to_ref()),
            evaluations=(self.passing_e0((first.to_ref(), first.to_ref(), second.to_ref())),),
        )
        with self.assertRaises(IncompleteTransitionError):
            controller.transition(duplicate)
        unbound = ArtifactRef("f" * 64, "second_evidence", size=6, frozen=True)
        unbound_request = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(first.to_ref(), unbound),
            evaluations=(self.passing_e0((first.to_ref(), unbound)),),
        )
        with self.assertRaises(IncompleteTransitionError):
            controller.transition(unbound_request)
        pending = registry.put_bytes(
            b"pending",
            logical_type="second_evidence",
            origin="pending fixture",
            creator_role=Role.EXPERIMENT_RUNNER,
            validation_result="PENDING",
            frozen=False,
        )
        pending_request = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(first.to_ref(), pending.to_ref()),
            evaluations=(self.passing_e0((first.to_ref(), pending.to_ref())),),
        )
        with self.assertRaises(IncompleteTransitionError):
            controller.transition(pending_request)

    def test_evaluator_binding_requires_pass_and_rejects_failures_or_objections(self) -> None:
        registry = self.registry()
        record = self.put(registry, logical_type="evidence")
        ref = record.to_ref()
        contract = self.contract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            artifacts=("evidence",),
            evaluators=(EvaluatorClass.E0,),
        )
        wrong_hash = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.PASS,
            ("f" * 64,),
            "pass is not bound to the required artifact",
        )
        request = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(ref,),
            evaluations=(wrong_hash,),
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(contracts=(contract,), artifact_registry=registry).transition(request)
        failing = Evaluation(
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            Decision.FAIL,
            (ref.sha256,),
            "deterministic failure",
            critical_objection=True,
        )
        request = self.request(
            run_id="run-1",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            refs=(ref,),
            evaluations=(failing,),
        )
        with self.assertRaises(IncompleteTransitionError):
            StateController(contracts=(contract,), artifact_registry=registry).transition(request)

    def test_e2_e3_reviewer_requires_distinct_producer_role_and_e4_is_impossible(self) -> None:
        with self.assertRaises(ValueError):
            Evaluation(
                EvaluatorClass.E2,
                Role.SCIENTIFIC_REVIEWER,
                Decision.PASS,
                (),
                "missing producer identity",
            )
        with self.assertRaises(ValueError):
            Evaluation(
                EvaluatorClass.E3,
                Role.ADVERSARIAL_REVIEWER,
                Decision.PASS,
                (),
                "same logical producer and reviewer",
                producer_role=Role.ADVERSARIAL_REVIEWER,
            )
        with self.assertRaises(ValueError):
            Evaluation(
                EvaluatorClass.E4,
                Role.HUMAN_RELEASE,
                Decision.PASS,
                (),
                "forged human release",
            )

    def test_negative_terminal_transition_is_typed_and_terminal(self) -> None:
        refs = (
            ArtifactRef("1" * 64, "machine_results"),
            ArtifactRef("2" * 64, "terminal_report"),
        )
        hashes = tuple(item.sha256 for item in refs)
        evaluations = (
            Evaluation(EvaluatorClass.E0, Role.ORCHESTRATOR, Decision.PASS, hashes, "validated"),
            Evaluation(
                EvaluatorClass.E2,
                Role.SCIENTIFIC_REVIEWER,
                Decision.PASS,
                hashes,
                "negative result is supported",
                producer_role=Role.EXPERIMENT_RUNNER,
            ),
        )
        contract = self.contract(
            MacroState.CONFIRM,
            TerminalState.NEGATIVE_RESULT,
            artifacts=("machine_results", "terminal_report"),
            evaluators=(EvaluatorClass.E0, EvaluatorClass.E2),
        )
        controller = StateController(
            MacroState.CONFIRM,
            contracts=(contract,),
            artifact_verifier=lambda _reference: True,
        )
        result = controller.transition(
            self.request(
                run_id="run-negative",
                source=MacroState.CONFIRM,
                destination=TerminalState.NEGATIVE_RESULT,
                refs=refs,
                evaluations=evaluations,
                key="negative-terminal-1",
                reason="primary result is negative",
            )
        )
        self.assertEqual(result.current_state, TerminalState.NEGATIVE_RESULT)
        self.assertTrue(controller.terminal)

    def test_role_bundle_freezes_context_and_blocks_same_role_review(self) -> None:
        context = {"nested": ["original"]}
        bundle = make_role_bundle(
            Role.SCIENTIFIC_REVIEWER,
            "run-1",
            ("a" * 64,),
            context,
            producer_role=Role.EXPERIMENT_RUNNER,
        )
        context["nested"].append("changed")
        self.assertEqual(bundle.context["nested"], ("original",))
        with self.assertRaises(TypeError):
            bundle.context["new"] = True  # type: ignore[index]
        with self.assertRaises(ValueError):
            make_role_bundle(
                Role.SCIENTIFIC_REVIEWER,
                "run-1",
                (),
                {},
                producer_role=Role.SCIENTIFIC_REVIEWER,
            )

    def test_restored_receipts_must_form_a_contiguous_state_chain(self) -> None:
        first_contract = self.contract(MacroState.CALIBRATE, MacroState.CHARTER)
        second_contract = self.contract(MacroState.CHARTER, MacroState.GROUND)
        third_contract = self.contract(MacroState.GROUND, MacroState.RELEASE)
        first_request = self.request(
            run_id="run-resume",
            source=MacroState.CALIBRATE,
            destination=MacroState.CHARTER,
            key="resume-1",
        )
        second_request = self.request(
            run_id="run-resume",
            source=MacroState.CHARTER,
            destination=MacroState.GROUND,
            key="resume-2",
        )
        controller = StateController(contracts=(first_contract, second_contract))
        first = controller.transition(first_request)
        second = controller.transition(second_request)
        with self.assertRaises(ValueError):
            StateController(
                MacroState.CHARTER,
                contracts=(first_contract, second_contract),
                prior_receipts=(second.to_dict(),),
            )

        orphan_controller = StateController(
            MacroState.GROUND,
            contracts=(third_contract,),
        )
        orphan_request = self.request(
            run_id="run-resume",
            source=MacroState.GROUND,
            destination=MacroState.RELEASE,
            key="resume-orphan",
        )
        orphan = orphan_controller.transition(orphan_request)
        with self.assertRaises(ValueError):
            StateController(
                MacroState.RELEASE,
                contracts=(first_contract, second_contract, third_contract),
                prior_receipts=(first.to_dict(), orphan.to_dict()),
            )


class LedgerReconstructionTests(FrozenKernelFixtures):
    def test_append_only_hash_chain_and_exact_schema_validate(self) -> None:
        ledger = self.ledger()
        first = self.append_fixture(ledger, "event-1")
        second = self.append_fixture(ledger, "event-2")
        result = ledger.validate(raise_on_error=True)
        self.assertEqual(result.event_count, 2)
        self.assertEqual(second.prior_event_hash, first.event_hash)
        self.assertEqual(result.head_hash, second.event_hash)
        parsed = json.loads(ledger.path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(parsed["event_hash"], event_hash(parsed))
        self.assertEqual(set(parsed), set(first.to_dict()))

    def test_mid_chain_tampering_is_detected_and_blocks_append(self) -> None:
        ledger = self.ledger()
        self.append_fixture(ledger, "event-1")
        payload = json.loads(ledger.path.read_text(encoding="utf-8"))
        payload["reason"] = "tampered"
        ledger.path.write_bytes(canonical_json_bytes(payload) + b"\n")
        self.assertFalse(ledger.validate().valid)
        with self.assertRaises(LedgerCorruptionError):
            self.append_fixture(ledger, "event-2")

    def test_duplicate_id_and_wrong_prior_hash_cannot_mutate_the_ledger(self) -> None:
        ledger = self.ledger()
        first = self.append_fixture(ledger, "event-1")
        before = ledger.path.read_bytes()
        with self.assertRaises(LedgerError):
            self.append_fixture(ledger, "event-1")
        forged = LedgerEvent.create(
            run_id="run-1",
            event_id="event-2",
            timestamp="2026-09-19T12:00:02Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CHARTER,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=("b" * 64,),
            code_version="semantic-reconstruction",
            configuration_hash=CONFIGURATION_HASH,
            reason="wrong chain head",
            prior_event_hash="f" * 64,
        )
        with self.assertRaises(LedgerError):
            ledger.append(forged)
        self.assertEqual(ledger.path.read_bytes(), before)
        self.assertEqual(ledger.validate(raise_on_error=True).head_hash, first.event_hash)

    def test_correction_appends_without_editing_the_superseded_event(self) -> None:
        ledger = self.ledger()
        original = self.append_fixture(ledger, "event-1")
        original_bytes = ledger.path.read_bytes()
        correction = ledger.append_correction(
            original.event_id,
            actor_role=Role.ORCHESTRATOR,
            event_id="correction-1",
            timestamp="2026-09-19T12:00:02Z",
            reason="correct a descriptive label",
            corrected_fields={"dataset_label": "synthetic-v2"},
        )
        self.assertEqual(correction.event_type, "CORRECTION")
        self.assertEqual(correction.supersedes_event_id, original.event_id)
        self.assertTrue(ledger.path.read_bytes().startswith(original_bytes))
        self.assertEqual(ledger.validate(raise_on_error=True).event_count, 2)
        with self.assertRaises(LedgerError):
            ledger.append_correction(
                "missing-event",
                actor_role=Role.ORCHESTRATOR,
                reason="invalid correction",
                corrected_fields={"x": 1},
            )

    def test_event_metadata_is_frozen_and_invalid_json_or_seed_is_rejected(self) -> None:
        metadata = {"nested": ["original"]}
        event = LedgerEvent.create(
            run_id="run-1",
            event_id="event-frozen",
            timestamp="2026-09-19T12:00:00Z",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.CALIBRATE,
            requested_state_after=MacroState.CHARTER,
            artifact_hashes=("a" * 64,),
            code_version="semantic-reconstruction",
            configuration_hash=CONFIGURATION_HASH,
            metadata=metadata,
            reason="immutable metadata",
            prior_event_hash=None,
        )
        metadata["nested"].append("mutated")
        self.assertEqual(event.to_dict()["metadata"], {"nested": ["original"]})
        with self.assertRaises(TypeError):
            event.metadata["replacement"] = True  # type: ignore[index]
        with self.assertRaises(ValueError):
            LedgerEvent.create(
                run_id="run-1",
                event_id="event-bool",
                timestamp="2026-09-19T12:00:00Z",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CHARTER,
                artifact_hashes=("a" * 64,),
                code_version="semantic-reconstruction",
                configuration_hash=CONFIGURATION_HASH,
                random_seeds=(True,),
                reason="invalid seed",
                prior_event_hash=None,
            )
        with self.assertRaises(ValueError):
            LedgerEvent.create(
                run_id="run-1",
                event_id="event-nan",
                timestamp="2026-09-19T12:00:00Z",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CALIBRATE,
                requested_state_after=MacroState.CHARTER,
                artifact_hashes=("a" * 64,),
                code_version="semantic-reconstruction",
                configuration_hash=CONFIGURATION_HASH,
                metadata={"value": float("nan")},
                reason="invalid JSON",
                prior_event_hash=None,
            )

    def test_torn_final_append_is_quarantined_and_valid_prefix_restored(self) -> None:
        ledger = self.ledger()
        self.append_fixture(ledger, "event-1")
        with ledger.path.open("ab") as handle:
            handle.write(b'{"event_id":"partial"')
        result = ledger.validate()
        self.assertFalse(result.valid)
        self.assertTrue(result.recoverable_truncated_tail)
        quarantine = ledger.recover_truncated_tail()
        self.assertTrue(quarantine.is_file())
        self.assertEqual(ledger.validate(raise_on_error=True).event_count, 1)

    def test_truncated_first_event_is_fatal_and_not_silently_reset(self) -> None:
        ledger = self.ledger()
        ledger.path.write_bytes(b'{"event_id":"partial"')
        result = ledger.validate()
        self.assertFalse(result.valid)
        self.assertFalse(result.recoverable_truncated_tail)
        with self.assertRaises(LedgerError):
            ledger.recover_truncated_tail()
        self.assertEqual(ledger.path.read_bytes(), b'{"event_id":"partial"')

    def test_event_and_byte_caps_fail_before_an_append(self) -> None:
        ledger = self.ledger("state/events-limit.jsonl")
        first = self.append_fixture(ledger, "event-1")
        before = ledger.path.read_bytes()
        with mock.patch.object(ledger_module, "MAX_LEDGER_EVENTS", 1):
            with self.assertRaises(LedgerError):
                self.append_fixture(ledger, "event-2")
        self.assertEqual(ledger.path.read_bytes(), before)
        self.assertEqual(ledger.validate(raise_on_error=True).head_hash, first.event_hash)
        with mock.patch.object(ledger_module, "MAX_LEDGER_BYTES", len(before) + 1):
            with self.assertRaises(LedgerError):
                self.append_fixture(ledger, "event-2")
        self.assertEqual(ledger.path.read_bytes(), before)

    def test_ledger_run_identity_must_remain_constant(self) -> None:
        ledger = self.ledger("state/run-identity.jsonl")
        self.append_fixture(ledger, "event-1", run_id="run-1")
        with self.assertRaises(LedgerError):
            self.append_fixture(ledger, "event-2", run_id="run-2")
        self.assertEqual(ledger.validate(raise_on_error=True).event_count, 1)


class ArtifactReconstructionTests(FrozenKernelFixtures):
    def test_content_addressed_bytes_metadata_and_registration_are_idempotent(self) -> None:
        registry = self.registry()
        first = self.put(registry, b"evidence", logical_type="result_artifact")
        second = self.put(registry, b"evidence", logical_type="result_artifact")
        self.assertEqual(first, second)
        self.assertEqual(first.sha256, hashlib.sha256(b"evidence").hexdigest())
        self.assertEqual(first.size, len(b"evidence"))
        self.assertEqual(registry.get_bytes(first.sha256), b"evidence")
        self.assertEqual(registry.get_metadata(first.sha256), first)
        self.assertTrue(registry.verify(first.sha256))
        self.assertEqual(registry.verify_all(raise_on_error=True).count, 1)
        with self.assertRaises(FrozenArtifactError):
            self.put(registry, b"evidence", logical_type="different_type", creator_role=Role.IMPLEMENTER)

    def test_blob_and_metadata_corruption_are_detected_on_every_read(self) -> None:
        registry = self.registry()
        record = self.put(registry, b"original", logical_type="result_artifact")
        (self.root / record.path).write_bytes(b"tampered")
        self.assertFalse(registry.verify(record.sha256))
        with self.assertRaises(ArtifactCorruptionError):
            registry.get_bytes(record.sha256)

        clean_root = Path(self._temporary.name) / "clean-project"
        clean_root.mkdir()
        clean_registry = ArtifactRegistry(clean_root)
        clean = self.put(clean_registry, b"clean", logical_type="result_artifact")
        metadata = clean_root / clean.metadata_path
        value = json.loads(metadata.read_text(encoding="utf-8"))
        value["origin"] = "tampered"
        metadata.write_bytes(canonical_json_bytes(value) + b"\n")
        self.assertFalse(clean_registry.verify(clean.sha256))
        with self.assertRaises(ArtifactCorruptionError):
            clean_registry.get_metadata(clean.sha256)

    def test_parent_provenance_requires_existing_valid_ancestors(self) -> None:
        registry = self.registry()
        with self.assertRaises(ArtifactError):
            self.put(
                registry,
                b"child",
                logical_type="child_artifact",
                parent_artifacts=("f" * 64,),
            )
        parent = self.put(registry, b"parent", logical_type="source_artifact")
        child = self.put(
            registry,
            b"child",
            logical_type="child_artifact",
            creator_role=Role.IMPLEMENTER,
            parent_artifacts=(parent.sha256,),
        )
        self.assertEqual(child.parent_artifacts, (parent.sha256,))
        (self.root / parent.path).write_bytes(b"corrupt-parent")
        self.assertFalse(registry.verify(child.sha256))

    def test_recursive_provenance_walk_is_bounded_by_depth_and_edge_limits(self) -> None:
        registry = self.registry()
        chain = [self.put(registry, b"root", logical_type="chain_root")]
        for index in range(4):
            chain.append(
                self.put(
                    registry,
                    f"child-{index}".encode(),
                    logical_type=f"chain_{index}",
                    parent_artifacts=(chain[-1].sha256,),
                )
            )
        with mock.patch.object(artifacts_module, "MAX_PROVENANCE_DEPTH", 2):
            self.assertFalse(registry.verify(chain[-1].sha256))
            self.assertFalse(registry.verify_all().valid)
        with mock.patch.object(artifacts_module, "MAX_PROVENANCE_EDGES", 2):
            self.assertFalse(registry.verify(chain[-1].sha256))
            self.assertFalse(registry.verify_all().valid)

    def test_artifact_parent_count_and_duplicate_parents_are_rejected(self) -> None:
        with mock.patch.object(artifacts_module, "MAX_ARTIFACT_PARENTS", 2):
            with self.assertRaises(ValidationError):
                ArtifactRecord(
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
                    parent_artifacts=("1" * 64, "2" * 64, "3" * 64),
                    validation_result="PASS",
                    frozen=True,
                    created_at="2026-09-19T12:00:00Z",
                )
        registry = self.registry()
        parent = self.put(registry, b"parent", logical_type="parent")
        with self.assertRaises(ValidationError):
            self.put(
                registry,
                b"duplicate-parent-list",
                logical_type="duplicate_parent_list",
                parent_artifacts=(parent.sha256, parent.sha256),
            )

    def test_registry_record_cap_rejects_before_publishing_a_second_object(self) -> None:
        registry = self.registry()
        first = self.put(registry, b"one", logical_type="first")
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
                self.put(registry, b"two", logical_type="second")
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
        self.assertEqual(registry.verify_all(raise_on_error=True).count, 1)
        self.assertTrue(registry.verify(first.sha256))

    def test_manifest_rejects_multiple_versions_of_one_logical_type(self) -> None:
        registry = self.registry()
        self.put(registry, b"version-one", logical_type="result_artifact")
        self.put(registry, b"version-two", logical_type="result_artifact")
        with self.assertRaises(ArtifactCollisionError):
            registry.manifest()


if __name__ == "__main__":
    unittest.main()
