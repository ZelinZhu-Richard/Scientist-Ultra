"""Deterministic, authority-separated Scientist-One state controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from .errors import (
    ApprovalForgeryError,
    IdempotencyConflictError,
    IncompleteTransitionError,
    InvalidTransitionError,
    UnauthorizedTransitionError,
)
from .evaluators import Decision, Evaluation, EvaluatorClass
from .models import (
    ArtifactRef,
    MacroState,
    State,
    TerminalState,
    TransitionRequest,
    parse_state,
)
from .roles import Role
from .roles import transition_role_context_sha256
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


TransitionValidator = Callable[[TransitionRequest], bool]
ArtifactVerifier = Callable[[ArtifactRef], bool]
ArtifactLoader = Callable[[ArtifactRef], bytes]


MACRO_SEQUENCE: tuple[MacroState, ...] = tuple(MacroState)
TRANSITION_RECEIPT_SCHEMA_VERSION = "scientist-one-transition-receipt/v2"
LEGACY_EVALUATION_RECEIPT_KEYS = frozenset(
    {
        "evaluator_class",
        "authority",
        "decision",
        "critical_objection",
        "artifact_hashes",
        "evaluation_sha256",
        "frozen_context_sha256",
        "producer_role",
        "reason",
        "r_checks",
        "logically_separated",
        "human_independence_claimed",
        "run_id",
        "gate_id",
    }
)


@dataclass(frozen=True)
class TransitionContract:
    source: State
    destination: State
    required_artifact_types: frozenset[str]
    required_evaluators: frozenset[EvaluatorClass]
    allowed_requesters: frozenset[Role]
    allowed_approvers: frozenset[Role]
    generated_artifact_types: frozenset[str]
    failure_states: frozenset[TerminalState]
    validation_rules: tuple[str, ...] = (
        "typed_artifacts_present",
        "artifact_hashes_bound_to_each_required_evaluation",
        "passing_evaluator_decisions",
        "no_critical_objection",
        "requester_approver_separation",
    )
    idempotency_rule: str = "exact_request_fingerprint"
    validators: tuple[TransitionValidator, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", parse_state(self.source))
        object.__setattr__(self, "destination", parse_state(self.destination))
        if not self.allowed_requesters or not self.allowed_approvers:
            raise ValueError("transition contract requires requester and approver authorities")
        if EvaluatorClass.E1 in self.required_evaluators:
            raise ValueError("E1 cannot be a required authorizing evaluator")
        if EvaluatorClass.E4 in self.required_evaluators:
            raise ValueError("autonomous transition contracts cannot require or simulate E4")
        if self.source == self.destination:
            raise ValueError("state transition contract cannot be a self-loop")

    def to_dict(self) -> dict[str, object]:
        """Serialize the public contract without executable validator objects."""

        return {
            "source": self.source.value,
            "destination": self.destination.value,
            "required_artifacts": sorted(self.required_artifact_types),
            "required_artifact_types": sorted(self.required_artifact_types),
            "required_evaluators": sorted(item.value for item in self.required_evaluators),
            "requester": sorted(item.value for item in self.allowed_requesters),
            "allowed_requesters": sorted(item.value for item in self.allowed_requesters),
            "approvers": sorted(item.value for item in self.allowed_approvers),
            "allowed_approvers": sorted(item.value for item in self.allowed_approvers),
            "generated_artifacts": sorted(self.generated_artifact_types),
            "generated_artifact_types": sorted(self.generated_artifact_types),
            "failure_states": sorted(item.value for item in self.failure_states),
            "validation_rules": list(self.validation_rules),
            "validator_count": len(self.validators),
            "idempotency": self.idempotency_rule,
            "idempotency_rule": self.idempotency_rule,
        }


@dataclass(frozen=True)
class TransitionResult:
    run_id: str
    prior_state: State
    current_state: State
    idempotency_key: str
    request_fingerprint: str
    replayed: bool
    generated_artifact_types: tuple[str, ...]
    transition_request: TransitionRequest

    def __post_init__(self) -> None:
        if not isinstance(self.transition_request, TransitionRequest):
            raise ValueError("transition receipt requires its exact typed request")
        if (
            self.run_id != self.transition_request.run_id
            or self.prior_state != self.transition_request.from_state
            or self.current_state != self.transition_request.to_state
            or self.idempotency_key != self.transition_request.idempotency_key
            or self.request_fingerprint
            != request_fingerprint(self.transition_request)
        ):
            raise ValueError("transition receipt differs from its exact request")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": TRANSITION_RECEIPT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "prior_state": self.prior_state.value,
            "current_state": self.current_state.value,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "replayed": self.replayed,
            "generated_artifact_types": list(self.generated_artifact_types),
            "transition_request": self.transition_request.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionResult":
        try:
            if set(value) != {
                "schema_version",
                "run_id",
                "prior_state",
                "current_state",
                "idempotency_key",
                "request_fingerprint",
                "replayed",
                "generated_artifact_types",
                "transition_request",
            } or value.get("schema_version") != TRANSITION_RECEIPT_SCHEMA_VERSION:
                raise ValueError("invalid transition receipt schema")
            fingerprint = str(value["request_fingerprint"])
            if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
                raise ValueError("invalid request fingerprint")
            replayed = value.get("replayed", False)
            if not isinstance(replayed, bool):
                raise ValueError("invalid replay flag")
            request = TransitionRequest.from_dict(value["transition_request"])
            return cls(
                run_id=str(value["run_id"]),
                prior_state=parse_state(value["prior_state"]),
                current_state=parse_state(value["current_state"]),
                idempotency_key=str(value["idempotency_key"]),
                request_fingerprint=fingerprint,
                replayed=replayed,
                generated_artifact_types=tuple(value.get("generated_artifact_types", ())),
                transition_request=request,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed transition receipt") from exc


_ALL_STOP_STATES = frozenset(
    {
        TerminalState.BLOCKED_EXTERNAL,
        TerminalState.STOP_SCIENTIFIC_INVALIDITY,
        TerminalState.STOP_SECURITY,
        TerminalState.STOP_BUDGET,
    }
)


def _contract(
    source: MacroState,
    destination: MacroState | TerminalState,
    artifacts: Iterable[str],
    evaluators: Iterable[EvaluatorClass],
    generated: Iterable[str],
    *,
    approvers: Iterable[Role] = (Role.SCIENTIFIC_REVIEWER,),
) -> TransitionContract:
    return TransitionContract(
        source=source,
        destination=destination,
        required_artifact_types=frozenset(artifacts),
        required_evaluators=frozenset(evaluators),
        allowed_requesters=frozenset({Role.ORCHESTRATOR}),
        allowed_approvers=frozenset(approvers),
        generated_artifact_types=frozenset(generated),
        failure_states=_ALL_STOP_STATES,
    )


def default_transition_contracts() -> tuple[TransitionContract, ...]:
    """Return the frozen v1 macro-state contract set.

    Detailed scientific phases are represented by required typed evidence; no
    second, ambiguous state controller is introduced.
    """

    contracts: list[TransitionContract] = [
        _contract(
            MacroState.CALIBRATE,
            MacroState.CHARTER,
            ("bootstrap_receipt", "calibration_report"),
            (EvaluatorClass.E0,),
            ("bootstrap_receipt", "calibration_report"),
        ),
        _contract(
            MacroState.CHARTER,
            MacroState.GROUND,
            ("research_charter",),
            (EvaluatorClass.E0,),
            ("research_charter",),
        ),
        _contract(
            MacroState.GROUND,
            MacroState.PROTOCOL,
            ("evidence_inventory",),
            (EvaluatorClass.E0,),
            ("evidence_inventory",),
        ),
        _contract(
            MacroState.PROTOCOL,
            MacroState.PREFLIGHT,
            ("frozen_protocol",),
            (EvaluatorClass.E0, EvaluatorClass.E2),
            ("frozen_protocol",),
        ),
        _contract(
            MacroState.PREFLIGHT,
            MacroState.IDEATE,
            ("preflight_report",),
            (EvaluatorClass.E0,),
            ("preflight_report",),
        ),
        _contract(
            MacroState.IDEATE,
            MacroState.DISCOVER,
            ("hypothesis_set",),
            (EvaluatorClass.E0,),
            ("hypothesis_set",),
        ),
        _contract(
            MacroState.DISCOVER,
            MacroState.CANDIDATE,
            ("workflow_benchmark",),
            (EvaluatorClass.E0, EvaluatorClass.E2),
            ("workflow_benchmark",),
        ),
        _contract(
            MacroState.CANDIDATE,
            MacroState.CONFIRM,
            ("pilot_report", "midrun_review", "blind_interpretation"),
            (EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3),
            ("pilot_report", "midrun_review", "blind_interpretation"),
            approvers=(Role.SCIENTIFIC_REVIEWER, Role.ADVERSARIAL_REVIEWER),
        ),
        _contract(
            MacroState.CONFIRM,
            MacroState.CLAIMS,
            ("custody_record", "machine_results"),
            (EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3),
            ("custody_record", "machine_results"),
            approvers=(Role.SCIENTIFIC_REVIEWER, Role.ADVERSARIAL_REVIEWER),
        ),
        _contract(
            MacroState.CLAIMS,
            MacroState.WRITE,
            ("claim_graph",),
            (EvaluatorClass.E0, EvaluatorClass.E2),
            ("claim_graph",),
            approvers=(Role.CLAIM_VERIFIER, Role.SCIENTIFIC_REVIEWER),
        ),
        _contract(
            MacroState.WRITE,
            MacroState.AUDIT,
            ("results_table", "results_figure", "demo_paper"),
            (EvaluatorClass.E0, EvaluatorClass.E2),
            ("results_table", "results_figure", "demo_paper"),
            approvers=(Role.SCIENTIFIC_REVIEWER,),
        ),
        _contract(
            MacroState.AUDIT,
            MacroState.RELEASE,
            ("audit_report", "reproduction_report", "e2_review", "e3_review", "readiness_report"),
            (EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3),
            ("audit_report", "reproduction_report", "e2_review", "e3_review", "readiness_report"),
            approvers=(Role.ADVERSARIAL_REVIEWER, Role.REPRODUCTION_VERIFIER),
        ),
        _contract(
            MacroState.RELEASE,
            TerminalState.READY_FOR_HUMAN_REVIEW,
            ("release_candidate",),
            (EvaluatorClass.E0, EvaluatorClass.E2, EvaluatorClass.E3),
            ("release_candidate",),
            approvers=(Role.RELEASE_PACKAGER, Role.ADVERSARIAL_REVIEWER),
        ),
    ]

    # Fail/stop outcomes are evidence-bearing transitions, never free-form
    # shortcuts. Negative/inconclusive outcomes require confirmatory evidence;
    # safety/budget/external stops require a typed terminal report.
    for source in MacroState:
        for destination in _ALL_STOP_STATES:
            contracts.append(
                _contract(
                    source,
                    destination,
                    ("terminal_report",),
                    (EvaluatorClass.E0,),
                    (),
                )
            )
    for source in (MacroState.CONFIRM, MacroState.CLAIMS, MacroState.WRITE, MacroState.AUDIT):
        for destination in (TerminalState.NEGATIVE_RESULT, TerminalState.INCONCLUSIVE):
            contracts.append(
                _contract(
                    source,
                    destination,
                    ("machine_results", "terminal_report"),
                    (EvaluatorClass.E0, EvaluatorClass.E2),
                    (),
                )
            )
    return tuple(contracts)


def macro_transition_contracts() -> tuple[TransitionContract, ...]:
    """Return only the canonical forward macro chain, in sequence order."""

    contracts = default_transition_contracts()
    result: list[TransitionContract] = []
    for index, source in enumerate(MACRO_SEQUENCE):
        destination: State = (
            MACRO_SEQUENCE[index + 1]
            if index + 1 < len(MACRO_SEQUENCE)
            else TerminalState.READY_FOR_HUMAN_REVIEW
        )
        result.append(next(item for item in contracts if item.source == source and item.destination == destination))
    return tuple(result)


def transition_contracts_by_source() -> Mapping[MacroState, TransitionContract]:
    """Stable adapter for orchestration/status serialization without a second table."""

    return {contract.source: contract for contract in macro_transition_contracts()}  # type: ignore[misc]


def request_fingerprint(request: TransitionRequest) -> str:
    return sha256_bytes(canonical_json_bytes(request.to_dict()))


def evaluation_gate_id(
    evaluator_class: EvaluatorClass,
    source: State,
    destination: State,
) -> str:
    """Return the canonical legacy gate identity for one evaluator context."""

    terminal_branch = isinstance(destination, TerminalState) and destination is not (
        TerminalState.READY_FOR_HUMAN_REVIEW
    )
    suffix = f"->{destination.value}" if terminal_branch else ""
    return f"{evaluator_class.value}:{source.value}{suffix}"


def legacy_evaluation_receipt(evaluation: Evaluation) -> dict[str, object]:
    """Serialize one legacy evaluator authority with its exact gate context."""

    if not evaluation.context_bound:
        raise ValueError("legacy evaluator authority requires a frozen gate context")
    return {
        "evaluator_class": evaluation.evaluator_class.value,
        "authority": evaluation.actor_role.value,
        "decision": evaluation.decision.value,
        "critical_objection": evaluation.critical_objection,
        "artifact_hashes": list(evaluation.artifact_hashes),
        "evaluation_sha256": evaluation.sha256,
        "frozen_context_sha256": evaluation.frozen_context_sha256,
        "producer_role": (
            evaluation.producer_role.value if evaluation.producer_role else None
        ),
        "reason": evaluation.reason,
        "r_checks": [item.value for item in evaluation.r_checks],
        "logically_separated": (
            evaluation.producer_role is None
            or evaluation.producer_role is not evaluation.actor_role
        ),
        "human_independence_claimed": evaluation.human_independence_claimed,
        "run_id": evaluation.run_id,
        "gate_id": evaluation.gate_id,
    }


def validate_legacy_transition_event_receipt(
    event: Mapping[str, Any],
) -> TransitionResult:
    """Reconstruct and bind a v2 receipt to one legacy ledger transition."""

    try:
        event_type = event["event_type"]
        run_id = event["run_id"]
        source = parse_state(event["state_before"])
        destination = parse_state(event["requested_state_after"])
        artifact_hashes = tuple(event["artifact_hashes"])
        evaluator_outputs = tuple(event["evaluator_outputs"])
        metadata = event["metadata"]
        if not isinstance(metadata, Mapping):
            raise ValueError("legacy transition metadata is malformed")
        artifact_types = tuple(metadata["artifact_types"])
        evaluator_keys = tuple(metadata["evaluator_keys"])
        raw_receipt = metadata["transition_receipt"]
        if not isinstance(raw_receipt, Mapping):
            raise ValueError("legacy transition receipt is absent")
        receipt = TransitionResult.from_dict(raw_receipt)
        contract = next(
            item
            for item in default_transition_contracts()
            if item.source == source and item.destination == destination
        )
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        raise ValueError("legacy transition authority is malformed") from exc

    request = receipt.transition_request
    expected_event_type = (
        "SECURITY_STOP"
        if destination is TerminalState.STOP_SECURITY
        else "TRANSITION"
    )
    if (
        event_type != expected_event_type
        or receipt.to_dict() != dict(raw_receipt)
        or receipt.run_id != run_id
        or receipt.prior_state != source
        or receipt.current_state != destination
        or receipt.idempotency_key
        != f"{run_id}:{source.value}:{destination.value}"
        or receipt.replayed
        or receipt.generated_artifact_types
        != tuple(sorted(contract.generated_artifact_types))
        or request.requester not in contract.allowed_requesters
        or request.approver not in contract.allowed_approvers
        or tuple(item.sha256 for item in request.artifacts) != artifact_hashes
        or tuple(item.logical_type for item in request.artifacts) != artifact_types
        or not all(item.frozen for item in request.artifacts)
        or {item.logical_type for item in request.artifacts}
        != contract.required_artifact_types
        or len(request.evaluations) != len(evaluator_outputs)
        or len(evaluator_keys) != len(evaluator_outputs)
    ):
        raise ValueError("legacy transition receipt differs from its ledger event")

    required_classes = tuple(
        sorted(contract.required_evaluators, key=lambda item: item.value)
    )
    if tuple(item.evaluator_class for item in request.evaluations) != required_classes:
        raise ValueError("legacy transition evaluator classes differ from contract")
    for evaluation, key, raw_output in zip(
        request.evaluations,
        evaluator_keys,
        evaluator_outputs,
        strict=True,
    ):
        gate_id = evaluation_gate_id(evaluation.evaluator_class, source, destination)
        try:
            expected_context = transition_role_context_sha256(
                evaluation.actor_role,
                str(run_id),
                evaluation.artifact_hashes,
                gate_id,
                producer_role=evaluation.producer_role,
            )
        except ValueError as exc:
            raise ValueError("legacy evaluator context is malformed") from exc
        if (
            not isinstance(raw_output, Mapping)
            or set(raw_output) != LEGACY_EVALUATION_RECEIPT_KEYS
            or key != gate_id
            or legacy_evaluation_receipt(evaluation) != dict(raw_output)
            or evaluation.run_id != run_id
            or evaluation.gate_id != gate_id
            or evaluation.frozen_context_sha256 != expected_context
            or evaluation.human_independence_claimed
        ):
            raise ValueError("legacy evaluator authority is not context-bound")
    return receipt


def validate_legacy_transition_prefix(
    events: Iterable[Mapping[str, Any]],
) -> tuple[TransitionResult, ...]:
    """Require the initialized legacy ledger to be one canonical typed prefix."""

    materialized = tuple(events)
    if not materialized:
        raise ValueError("legacy ledger is empty")
    first = materialized[0]
    first_metadata = first.get("metadata")
    if (
        first.get("event_type") != "CHECKPOINT"
        or first.get("state_before") != MacroState.CALIBRATE.value
        or first.get("requested_state_after") != MacroState.CALIBRATE.value
        or not isinstance(first_metadata, Mapping)
        or first_metadata.get("initialization") is not True
    ):
        raise ValueError("legacy ledger lacks its canonical initialization prefix")

    receipts: list[TransitionResult] = []
    current: State = MacroState.CALIBRATE
    for index, event in enumerate(materialized):
        metadata = event.get("metadata")
        if not isinstance(metadata, Mapping):
            raise ValueError("legacy event metadata is malformed")
        if index and metadata.get("initialization") not in (None, False):
            raise ValueError("legacy initialization marker is misplaced")
        source = parse_state(event.get("state_before"))
        destination = parse_state(event.get("requested_state_after"))
        if source != current:
            raise ValueError("legacy transition prefix is discontinuous")
        changes_state = source != destination
        if changes_state:
            if event.get("event_type") not in {"TRANSITION", "SECURITY_STOP"}:
                raise ValueError("non-semantic event changes legacy macro state")
            if isinstance(current, TerminalState):
                raise ValueError("legacy terminal state has a successor")
            if isinstance(destination, MacroState):
                source_index = MACRO_SEQUENCE.index(current)
                if (
                    source_index + 1 >= len(MACRO_SEQUENCE)
                    or MACRO_SEQUENCE[source_index + 1] != destination
                ):
                    raise ValueError("legacy macro transition skips its canonical prefix")
            receipts.append(validate_legacy_transition_event_receipt(event))
            current = destination
        elif metadata.get("transition_receipt") is not None:
            raise ValueError("non-transition event carries transition authority")
    return tuple(receipts)


class StateController:
    """Validate and apply one explicit transition at a time."""

    def __init__(
        self,
        initial_state: State = MacroState.CALIBRATE,
        *,
        contracts: Iterable[TransitionContract] | None = None,
        artifact_registry: Any | None = None,
        artifact_verifier: ArtifactVerifier | None = None,
        artifact_loader: ArtifactLoader | None = None,
        semantic_validators: Mapping[str, ArtifactVerifier] | None = None,
        prior_receipts: Iterable[TransitionResult | Mapping[str, Any]] = (),
    ) -> None:
        requested_initial_state = parse_state(initial_state)
        self._state = requested_initial_state
        supplied = tuple(contracts) if contracts is not None else default_transition_contracts()
        self._contracts: dict[tuple[State, State], TransitionContract] = {}
        for contract in supplied:
            key = (contract.source, contract.destination)
            if key in self._contracts:
                raise ValueError("duplicate transition contract")
            self._contracts[key] = contract
        self._idempotency: dict[str, tuple[str, TransitionResult]] = {}
        self._artifact_registry = artifact_registry
        self._artifact_verifier = artifact_verifier
        self._artifact_loader = artifact_loader
        self._semantic_validators = dict(semantic_validators or {})
        restored: list[TransitionResult] = []
        for raw_receipt in prior_receipts:
            receipt = (
                raw_receipt
                if isinstance(raw_receipt, TransitionResult)
                else TransitionResult.from_dict(raw_receipt)
            )
            self.contract_for(receipt.prior_state, receipt.current_state)
            restored.append(receipt)
        for prior, following in zip(restored, restored[1:]):
            if prior.current_state != following.prior_state:
                raise ValueError("restored transition receipts do not form a contiguous chain")
        if restored and restored[-1].current_state != requested_initial_state:
            raise ValueError("restored receipts do not end at the resumed controller state")
        if restored:
            if len({receipt.run_id for receipt in restored}) != 1:
                raise ValueError("restored transition receipts change run identity")
            self._state = restored[0].prior_state
            for receipt in restored:
                if receipt.replayed:
                    raise ValueError("stored transition receipts cannot be replay views")
                rebuilt = self.transition(receipt.transition_request)
                if rebuilt.to_dict() != receipt.to_dict():
                    raise ValueError(
                        "restored transition receipt is not an exact validated replay"
                    )
            if self._state != requested_initial_state:
                raise ValueError("restored receipts do not reach the resumed state")

    def _verify_artifact(self, reference: ArtifactRef) -> bool:
        if self._artifact_registry is not None:
            try:
                if not self._artifact_registry.verify(reference.sha256, raise_on_error=True):
                    return False
                metadata = self._artifact_registry.get_metadata(reference.sha256)
            except Exception:
                return False
            return (
                metadata.logical_type == reference.logical_type
                and metadata.schema_version == reference.schema_version
                and metadata.size == reference.size
                and metadata.frozen == reference.frozen
                and (reference.path is None or metadata.path == reference.path)
            )
        if self._artifact_verifier is None:
            return False
        try:
            return self._artifact_verifier(reference) is True
        except Exception:
            return False

    def _load_artifact(self, reference: ArtifactRef) -> bytes:
        if self._artifact_registry is not None:
            return self._artifact_registry.get_bytes(reference.sha256)
        if self._artifact_loader is not None:
            return self._artifact_loader(reference)
        raise IncompleteTransitionError("semantic artifact loader is unavailable")

    def _validate_semantic_artifact(self, reference: ArtifactRef) -> bool:
        custom = self._semantic_validators.get(reference.logical_type)
        custom_passed = True
        if custom is not None:
            try:
                custom_passed = custom(reference) is True
            except Exception:
                custom_passed = False
        if not custom_passed:
            return False
        if reference.logical_type == "bootstrap_receipt":
            try:
                receipt = safe_json_loads(self._load_artifact(reference))
            except Exception:
                return False
            built_in_passed = (
                isinstance(receipt, dict)
                and receipt.get("app_session_bootstrap") == "PASS"
                and isinstance(receipt.get("bootstrap_checks"), list)
                and bool(receipt["bootstrap_checks"])
                and all(
                    isinstance(item, dict) and item.get("result") == "PASS"
                    for item in receipt["bootstrap_checks"]
                )
            )
            return built_in_passed
        if reference.logical_type == "calibration_report":
            try:
                serialized = safe_json_loads(self._load_artifact(reference))
                from .calibration import assert_calibrated, run_calibration

                canonical = assert_calibrated(run_calibration()).to_dict()
            except Exception:
                return False
            # This binds the transition to a deterministic local re-evaluation,
            # not merely to a caller-declared status or arbitrary digest.
            if not isinstance(serialized, dict):
                return False
            observed = dict(serialized)
            # The CLI response wrapper may add only these two inert disclosure
            # fields; the scientific report underneath must be byte-semantically
            # identical to a fresh local deterministic evaluation.
            status = observed.pop("status", None)
            integrations = observed.pop("external_integrations_used", None)
            if status not in (None, "PASS"):
                return False
            if integrations not in (None, []):
                return False
            return observed == canonical
        return custom_passed

    @property
    def current_state(self) -> State:
        return self._state

    @property
    def state(self) -> State:
        return self._state

    @property
    def terminal(self) -> bool:
        return isinstance(self._state, TerminalState)

    def contract_for(self, source: State | str, destination: State | str) -> TransitionContract:
        key = (parse_state(source), parse_state(destination))
        try:
            return self._contracts[key]
        except KeyError as exc:
            raise InvalidTransitionError("transition edge is not defined") from exc

    def can_transition(self, request: TransitionRequest) -> bool:
        try:
            self.validate(request)
        except (
            InvalidTransitionError,
            IncompleteTransitionError,
            UnauthorizedTransitionError,
            ApprovalForgeryError,
            IdempotencyConflictError,
        ):
            return False
        return True

    def validate(self, request: TransitionRequest) -> TransitionContract:
        if not isinstance(request, TransitionRequest):
            raise InvalidTransitionError("transition request must be typed")
        fingerprint = request_fingerprint(request)
        replay = self._idempotency.get(request.idempotency_key)
        if replay is not None:
            if replay[0] != fingerprint:
                raise IdempotencyConflictError("idempotency key reused with different evidence")
            return self.contract_for(request.from_state, request.to_state)
        if self.terminal:
            raise InvalidTransitionError("terminal states cannot be exited")
        if request.from_state != self._state:
            raise InvalidTransitionError("request source does not match current state")
        contract = self.contract_for(request.from_state, request.to_state)

        if request.requester not in contract.allowed_requesters:
            raise UnauthorizedTransitionError("requester lacks transition authority")
        if request.approver not in contract.allowed_approvers:
            raise UnauthorizedTransitionError("approver lacks transition authority")
        if request.requester is request.approver:
            raise UnauthorizedTransitionError("requester cannot approve its own transition")
        if request.approver is Role.HUMAN_RELEASE:
            raise ApprovalForgeryError("E4 human authority cannot be self-issued")

        artifact_types = {item.logical_type for item in request.artifacts}
        missing = contract.required_artifact_types - artifact_types
        if missing:
            raise IncompleteTransitionError("required typed artifacts are missing")
        if any(
            sum(item.logical_type == logical_type for item in request.artifacts) != 1
            for logical_type in contract.required_artifact_types
        ):
            raise IncompleteTransitionError("each required artifact type must resolve to exactly one artifact")
        required_artifacts = tuple(
            item for item in request.artifacts if item.logical_type in contract.required_artifact_types
        )
        if any(not item.frozen for item in required_artifacts):
            raise IncompleteTransitionError("required transition artifacts must be frozen")
        if any(not self._verify_artifact(item) for item in required_artifacts):
            raise IncompleteTransitionError("required artifact is absent, corrupt, or not registry-bound")
        if any(not self._validate_semantic_artifact(item) for item in required_artifacts):
            raise IncompleteTransitionError("required artifact failed its semantic validation receipt")
        required_hashes = {item.sha256 for item in required_artifacts}

        if any(item.evaluator_class is EvaluatorClass.E4 for item in request.evaluations):
            raise ApprovalForgeryError("E4 decisions cannot be autonomously constructed")
        if any(item.critical_objection or item.decision is Decision.FAIL for item in request.evaluations):
            raise IncompleteTransitionError("failing or critical evaluator decision blocks transition")
        for evaluation in request.evaluations:
            gate_id = evaluation_gate_id(
                evaluation.evaluator_class,
                request.from_state,
                request.to_state,
            )
            try:
                expected_context = transition_role_context_sha256(
                    evaluation.actor_role,
                    request.run_id,
                    evaluation.artifact_hashes,
                    gate_id,
                    producer_role=evaluation.producer_role,
                )
            except ValueError as exc:
                raise IncompleteTransitionError(
                    "evaluator role context is malformed"
                ) from exc
            if (
                not evaluation.context_bound
                or evaluation.run_id != request.run_id
                or evaluation.gate_id != gate_id
                or evaluation.frozen_context_sha256 != expected_context
                or evaluation.human_independence_claimed
            ):
                raise IncompleteTransitionError(
                    "evaluator decision is not bound to this run and gate context"
                )
        for evaluator_class in contract.required_evaluators:
            candidates = [
                item
                for item in request.evaluations
                if item.evaluator_class is evaluator_class and item.decision is Decision.PASS
            ]
            if not candidates:
                raise IncompleteTransitionError("required passing evaluator decision is missing")
            if not any(required_hashes.issubset(set(item.artifact_hashes)) for item in candidates):
                raise IncompleteTransitionError("evaluator decision is not bound to required artifacts")
        # E1 is advisory even if present and therefore never counted above.
        for validator in contract.validators:
            try:
                passed = validator(request)
            except Exception as exc:
                raise IncompleteTransitionError("transition validator failed closed") from exc
            if passed is not True:
                raise IncompleteTransitionError("transition validation rule failed")
        return contract

    def transition(self, request: TransitionRequest) -> TransitionResult:
        fingerprint = request_fingerprint(request)
        prior = self._idempotency.get(request.idempotency_key)
        if prior is not None:
            if prior[0] != fingerprint:
                raise IdempotencyConflictError("idempotency key reused with different evidence")
            result = prior[1]
            return TransitionResult(
                run_id=result.run_id,
                prior_state=result.prior_state,
                current_state=result.current_state,
                idempotency_key=result.idempotency_key,
                request_fingerprint=result.request_fingerprint,
                replayed=True,
                generated_artifact_types=result.generated_artifact_types,
                transition_request=result.transition_request,
            )
        contract = self.validate(request)
        prior_state = self._state
        self._state = request.to_state
        result = TransitionResult(
            run_id=request.run_id,
            prior_state=prior_state,
            current_state=self._state,
            idempotency_key=request.idempotency_key,
            request_fingerprint=fingerprint,
            replayed=False,
            generated_artifact_types=tuple(sorted(contract.generated_artifact_types)),
            transition_request=request,
        )
        self._idempotency[request.idempotency_key] = (fingerprint, result)
        return result

    def idempotency_receipts(self) -> Mapping[str, str]:
        return {key: value[0] for key, value in self._idempotency.items()}

    def transition_receipts(self) -> tuple[TransitionResult, ...]:
        """Return immutable receipts suitable for a fail-closed resumed controller."""

        return tuple(value[1] for value in self._idempotency.values())


DeterministicStateMachine = StateController
StateMachine = StateController
