"""Stable typed records shared by the Scientist-One control plane."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import re
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ValidationError
from .evaluators import Decision, Evaluation, EvaluatorClass, RCheck
from .roles import Role


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
LOGICAL_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class MacroState(StrEnum):
    CALIBRATE = "CALIBRATE"
    CHARTER = "CHARTER"
    GROUND = "GROUND"
    PROTOCOL = "PROTOCOL"
    PREFLIGHT = "PREFLIGHT"
    IDEATE = "IDEATE"
    DISCOVER = "DISCOVER"
    CANDIDATE = "CANDIDATE"
    CONFIRM = "CONFIRM"
    CLAIMS = "CLAIMS"
    WRITE = "WRITE"
    AUDIT = "AUDIT"
    RELEASE = "RELEASE"


class TerminalState(StrEnum):
    READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
    NEGATIVE_RESULT = "NEGATIVE_RESULT"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    STOP_SCIENTIFIC_INVALIDITY = "STOP_SCIENTIFIC_INVALIDITY"
    STOP_SECURITY = "STOP_SECURITY"
    STOP_BUDGET = "STOP_BUDGET"


# The objective uses both terms; one enum identity prevents drift.
TerminalOutcome = TerminalState
State = MacroState | TerminalState


class Authority(StrEnum):
    ORCHESTRATION = "orchestration"
    ARTIFACT_PRODUCTION = "artifact_production"
    DETERMINISTIC_VALIDATION = "deterministic_validation"
    INDEPENDENT_SCIENTIFIC_REVIEW = "independent_scientific_review"
    ADVERSARIAL_REVIEW = "adversarial_review"
    HOLDOUT_CUSTODY = "holdout_custody"
    CLAIM_VERIFICATION = "claim_verification"
    WRITING = "writing"
    REPRODUCTION = "reproduction"
    RELEASE_PACKAGING = "release_packaging"
    HUMAN_RELEASE = "human_release"


ROLE_AUTHORITIES: dict[Role, frozenset[Authority]] = {
    Role.ORCHESTRATOR: frozenset({Authority.ORCHESTRATION, Authority.DETERMINISTIC_VALIDATION}),
    Role.PROBLEM_INVESTIGATOR: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.EVIDENCE_CURATOR: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.HYPOTHESIS_DESIGNER: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.PROTOCOL_DESIGNER: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.IMPLEMENTER: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.EXPERIMENT_RUNNER: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.STATISTICIAN: frozenset({Authority.ARTIFACT_PRODUCTION}),
    Role.SCIENTIFIC_REVIEWER: frozenset({Authority.INDEPENDENT_SCIENTIFIC_REVIEW}),
    Role.ADVERSARIAL_REVIEWER: frozenset({Authority.ADVERSARIAL_REVIEW}),
    Role.CLAIM_VERIFIER: frozenset({Authority.CLAIM_VERIFICATION}),
    Role.PAPER_WRITER: frozenset({Authority.WRITING}),
    Role.REPRODUCTION_VERIFIER: frozenset({Authority.ADVERSARIAL_REVIEW, Authority.REPRODUCTION}),
    Role.RELEASE_PACKAGER: frozenset({Authority.RELEASE_PACKAGING}),
    Role.HOLDOUT_CUSTODIAN: frozenset({Authority.HOLDOUT_CUSTODY}),
    Role.HUMAN_RELEASE: frozenset({Authority.HUMAN_RELEASE}),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_identifier(value: str, label: str = "identifier") -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValidationError(f"invalid {label}")
    return value


def validate_sha256(value: str, label: str = "SHA-256") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValidationError(f"invalid {label}")
    return value


def parse_state(value: State | str) -> State:
    if isinstance(value, (MacroState, TerminalState)):
        return value
    if not isinstance(value, str):
        raise ValidationError("state must be a string enum value")
    try:
        return MacroState(value)
    except ValueError:
        try:
            return TerminalState(value)
        except ValueError as exc:
            raise ValidationError("unknown state") from exc


def role_has_authority(role: Role, authority: Authority) -> bool:
    return authority in ROLE_AUTHORITIES.get(role, frozenset())


def freeze_json(value: Any) -> Any:
    """Copy a JSON-shaped value into recursively immutable containers."""

    return _freeze_json(value, depth=0, ancestors=frozenset(), budget=[250_000])


def _freeze_json(
    value: Any,
    *,
    depth: int,
    ancestors: frozenset[int],
    budget: list[int],
) -> Any:
    budget[0] -= 1
    if budget[0] < 0:
        raise ValidationError("JSON item limit exceeded")
    if depth > 64:
        raise ValidationError("JSON nesting limit exceeded")

    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 4096:
            raise ValidationError("JSON integer exceeds safety limit")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValidationError("non-finite JSON value is forbidden")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValidationError("JSON object keys must be strings")
        if id(value) in ancestors:
            raise ValidationError("cyclic JSON value is forbidden")
        nested = ancestors | {id(value)}
        return MappingProxyType(
            {
                key: _freeze_json(
                    child,
                    depth=depth + 1,
                    ancestors=nested,
                    budget=budget,
                )
                for key, child in value.items()
            }
        )
    if isinstance(value, (list, tuple)):
        if id(value) in ancestors:
            raise ValidationError("cyclic JSON value is forbidden")
        nested = ancestors | {id(value)}
        return tuple(
            _freeze_json(
                child,
                depth=depth + 1,
                ancestors=nested,
                budget=budget,
            )
            for child in value
        )
    raise ValidationError("value is not JSON-shaped data")


def thaw_json(value: Any) -> Any:
    """Convert recursively frozen JSON-shaped values to plain dict/list data."""

    if isinstance(value, Mapping):
        return {key: thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(child) for child in value]
    return value


@dataclass(frozen=True)
class ArtifactRef:
    sha256: str
    logical_type: str
    schema_version: str = "1.0"
    size: int = 0
    frozen: bool = True
    path: str | None = None

    def __post_init__(self) -> None:
        validate_sha256(self.sha256, "artifact SHA-256")
        if not isinstance(self.logical_type, str) or not LOGICAL_TYPE_RE.fullmatch(self.logical_type):
            raise ValidationError("invalid artifact logical type")
        if not isinstance(self.schema_version, str) or not self.schema_version or len(self.schema_version) > 32:
            raise ValidationError("invalid artifact schema version")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValidationError("artifact size must be a non-negative integer")
        if not isinstance(self.frozen, bool):
            raise ValidationError("artifact frozen flag must be boolean")
        if self.path is not None:
            if not isinstance(self.path, str) or not self.path or self.path.startswith("/"):
                raise ValidationError("artifact path must be project-relative")
            if ".." in self.path.replace("\\", "/").split("/"):
                raise ValidationError("artifact path contains traversal")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRef":
        if not isinstance(value, Mapping):
            raise ValidationError("artifact reference must be an object")
        allowed = {"sha256", "logical_type", "schema_version", "size", "frozen", "path"}
        if set(value) - allowed:
            raise ValidationError("artifact reference has unknown fields")
        try:
            return cls(**dict(value))
        except TypeError as exc:
            raise ValidationError("malformed artifact reference") from exc


def evaluation_to_dict(evaluation: Evaluation) -> dict[str, Any]:
    return {
        "evaluator_class": evaluation.evaluator_class.value,
        "actor_role": evaluation.actor_role.value,
        "decision": evaluation.decision.value,
        "artifact_hashes": list(evaluation.artifact_hashes),
        "reason": evaluation.reason,
        "r_checks": [item.value for item in evaluation.r_checks],
        "critical_objection": evaluation.critical_objection,
        "producer_role": evaluation.producer_role.value if evaluation.producer_role else None,
        "run_id": evaluation.run_id,
        "gate_id": evaluation.gate_id,
        "frozen_context_sha256": evaluation.frozen_context_sha256,
        "human_independence_claimed": evaluation.human_independence_claimed,
        "sha256": evaluation.sha256,
    }


def evaluation_from_dict(value: Mapping[str, Any]) -> Evaluation:
    if not isinstance(value, Mapping):
        raise ValidationError("evaluation must be an object")
    allowed = {
        "evaluator_class",
        "actor_role",
        "decision",
        "artifact_hashes",
        "reason",
        "r_checks",
        "critical_objection",
        "producer_role",
        "run_id",
        "gate_id",
        "frozen_context_sha256",
        "human_independence_claimed",
        "sha256",
    }
    if set(value) - allowed:
        raise ValidationError("evaluation has unknown fields")
    try:
        hashes = tuple(value.get("artifact_hashes", ()))
        for digest in hashes:
            validate_sha256(digest, "evaluation artifact SHA-256")
        evaluation = Evaluation(
            evaluator_class=EvaluatorClass(value["evaluator_class"]),
            actor_role=Role(value["actor_role"]),
            decision=Decision(value["decision"]),
            artifact_hashes=hashes,
            reason=value["reason"],
            r_checks=tuple(RCheck(item) for item in value.get("r_checks", ())),
            critical_objection=value.get("critical_objection", False),
            producer_role=Role(value["producer_role"]) if value.get("producer_role") else None,
            run_id=value.get("run_id"),
            gate_id=value.get("gate_id"),
            frozen_context_sha256=value.get("frozen_context_sha256"),
            human_independence_claimed=value.get(
                "human_independence_claimed", False
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("malformed evaluation") from exc
    supplied = value.get("sha256")
    if supplied is not None and supplied != evaluation.sha256:
        raise ValidationError("evaluation hash mismatch")
    return evaluation


EvaluatorDecision = Evaluation


@dataclass(frozen=True)
class TransitionRequest:
    run_id: str
    from_state: State
    to_state: State
    requester: Role
    approver: Role
    artifacts: tuple[ArtifactRef, ...]
    evaluations: tuple[Evaluation, ...]
    idempotency_key: str
    reason: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "run ID")
        object.__setattr__(self, "from_state", parse_state(self.from_state))
        object.__setattr__(self, "to_state", parse_state(self.to_state))
        if not isinstance(self.requester, Role) or not isinstance(self.approver, Role):
            raise ValidationError("transition roles must be Role values")
        if not isinstance(self.artifacts, tuple) or not all(isinstance(item, ArtifactRef) for item in self.artifacts):
            raise ValidationError("transition artifacts must be an ArtifactRef tuple")
        if not isinstance(self.evaluations, tuple) or not all(isinstance(item, Evaluation) for item in self.evaluations):
            raise ValidationError("transition evaluations must be an Evaluation tuple")
        validate_identifier(self.idempotency_key, "idempotency key")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > 4096:
            raise ValidationError("transition reason must be non-empty bounded text")
        if not isinstance(self.metadata, Mapping):
            raise ValidationError("transition metadata must be an object")
        object.__setattr__(self, "metadata", freeze_json(self.metadata))

    @property
    def artifact_hashes(self) -> tuple[str, ...]:
        return tuple(item.sha256 for item in self.artifacts)

    @property
    def requester_role(self) -> Role:
        return self.requester

    @property
    def approver_role(self) -> Role:
        return self.approver

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "requester": self.requester.value,
            "approver": self.approver.value,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "evaluations": [evaluation_to_dict(item) for item in self.evaluations],
            "idempotency_key": self.idempotency_key,
            "reason": self.reason,
            "metadata": thaw_json(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TransitionRequest":
        if not isinstance(value, Mapping):
            raise ValidationError("transition request must be an object")
        required = {
            "run_id",
            "from_state",
            "to_state",
            "requester",
            "approver",
            "artifacts",
            "evaluations",
            "idempotency_key",
            "reason",
            "metadata",
        }
        if set(value) != required:
            raise ValidationError(
                "transition request schema is incomplete or has unknown fields"
            )
        try:
            artifacts = value["artifacts"]
            evaluations = value["evaluations"]
            if not isinstance(artifacts, (list, tuple)) or not isinstance(
                evaluations, (list, tuple)
            ):
                raise TypeError("transition request collections are malformed")
            return cls(
                run_id=value["run_id"],
                from_state=parse_state(value["from_state"]),
                to_state=parse_state(value["to_state"]),
                requester=Role(value["requester"]),
                approver=Role(value["approver"]),
                artifacts=tuple(ArtifactRef.from_dict(item) for item in artifacts),
                evaluations=tuple(
                    evaluation_from_dict(item) for item in evaluations
                ),
                idempotency_key=value["idempotency_key"],
                reason=value["reason"],
                metadata=value["metadata"],
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            if isinstance(exc, ValidationError):
                raise
            raise ValidationError("malformed transition request") from exc


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    requested_action: str
    executable_and_arguments: tuple[str, ...]
    paths: tuple[str, ...]
    necessity: str
    alternatives_attempted: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    risks: tuple[str, ...]
    rollback_plan: str
    independent_work_continued: tuple[str, ...]
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        validate_identifier(self.request_id, "approval request ID")
        scalar_text = (self.requested_action, self.necessity, self.rollback_plan, self.created_at)
        if any(not isinstance(item, str) or not item.strip() for item in scalar_text):
            raise ValidationError("approval request text fields must be non-empty")
        collections = (
            self.executable_and_arguments,
            self.paths,
            self.alternatives_attempted,
            self.expected_outputs,
            self.risks,
            self.independent_work_continued,
        )
        if any(not isinstance(items, tuple) or any(not isinstance(item, str) for item in items) for items in collections):
            raise ValidationError("approval request list fields must be string tuples")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for key, item in tuple(value.items()):
            if isinstance(item, tuple):
                value[key] = list(item)
        return value
