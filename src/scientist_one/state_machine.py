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
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


TransitionValidator = Callable[[TransitionRequest], bool]
ArtifactVerifier = Callable[[ArtifactRef], bool]
ArtifactLoader = Callable[[ArtifactRef], bytes]


MACRO_SEQUENCE: tuple[MacroState, ...] = tuple(MacroState)


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

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "prior_state": self.prior_state.value,
            "current_state": self.current_state.value,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "replayed": self.replayed,
            "generated_artifact_types": list(self.generated_artifact_types),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionResult":
        try:
            fingerprint = str(value["request_fingerprint"])
            if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
                raise ValueError("invalid request fingerprint")
            replayed = value.get("replayed", False)
            if not isinstance(replayed, bool):
                raise ValueError("invalid replay flag")
            return cls(
                run_id=str(value["run_id"]),
                prior_state=parse_state(value["prior_state"]),
                current_state=parse_state(value["current_state"]),
                idempotency_key=str(value["idempotency_key"]),
                request_fingerprint=fingerprint,
                replayed=replayed,
                generated_artifact_types=tuple(value.get("generated_artifact_types", ())),
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
        self._state = parse_state(initial_state)
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
        if restored and restored[-1].current_state != self._state:
            raise ValueError("restored receipts do not end at the resumed controller state")
        for receipt in restored:
            existing = self._idempotency.get(receipt.idempotency_key)
            if existing is not None and existing[0] != receipt.request_fingerprint:
                raise IdempotencyConflictError("conflicting restored idempotency receipts")
            self._idempotency[receipt.idempotency_key] = (
                receipt.request_fingerprint,
                TransitionResult(
                    receipt.run_id,
                    receipt.prior_state,
                    receipt.current_state,
                    receipt.idempotency_key,
                    receipt.request_fingerprint,
                    False,
                    receipt.generated_artifact_types,
                ),
            )

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
