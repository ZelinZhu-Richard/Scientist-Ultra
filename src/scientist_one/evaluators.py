"""Evaluator decisions and R0-R7 audit aggregation."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
import hashlib
from itertools import islice
import json
import math
import re
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from .roles import Role

if TYPE_CHECKING:
    from .scientific_cohort_bundle import RCheckAuthorityBundleV2


class EvaluatorClass(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"


class Decision(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ADVISORY = "ADVISORY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RCheck(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"
    R6 = "R6"
    R7 = "R7"


R_CHECK_MEANINGS: dict[RCheck, str] = {
    RCheck.R0: "artifact integrity, provenance, schemas, and state-machine validity",
    RCheck.R1: "problem, hypothesis, estimand, protocol, and claim-scope validity",
    RCheck.R2: "implementation, metric, and baseline-equivalence correctness",
    RCheck.R3: "data quality, split integrity, leakage, contamination, and unit validity",
    RCheck.R4: "statistical assumptions, uncertainty, resampling, multiplicity, and calibration",
    RCheck.R5: "robustness, ablations, domain nulls, controls, and distribution shift",
    RCheck.R6: "claim-evidence consistency, citations, limitations, and writing accuracy",
    RCheck.R7: "independent reproduction, packaging, and residual-risk audit",
}

ALLOWED_EVALUATOR_ROLES: dict[EvaluatorClass, set[Role]] = {
    EvaluatorClass.E0: {Role.ORCHESTRATOR},
    EvaluatorClass.E1: set(Role) - {Role.HUMAN_RELEASE},
    EvaluatorClass.E2: {Role.SCIENTIFIC_REVIEWER},
    EvaluatorClass.E3: {Role.ADVERSARIAL_REVIEWER, Role.REPRODUCTION_VERIFIER},
    EvaluatorClass.E4: {Role.HUMAN_RELEASE},
}

REQUIRED_R_AUTHORITIES: dict[RCheck, frozenset[EvaluatorClass]] = {
    RCheck.R0: frozenset({EvaluatorClass.E0}),
    RCheck.R1: frozenset({EvaluatorClass.E0, EvaluatorClass.E2}),
    RCheck.R2: frozenset({EvaluatorClass.E0, EvaluatorClass.E2}),
    RCheck.R3: frozenset({EvaluatorClass.E0, EvaluatorClass.E3}),
    RCheck.R4: frozenset({EvaluatorClass.E0, EvaluatorClass.E2}),
    RCheck.R5: frozenset({EvaluatorClass.E2, EvaluatorClass.E3}),
    RCheck.R6: frozenset({EvaluatorClass.E2, EvaluatorClass.E3}),
    RCheck.R7: frozenset({EvaluatorClass.E3}),
}

# Evaluator receipts are control-plane metadata.  Keep their domain budget
# substantially below the shared JSON parser's generic eight-MiB ceiling so a
# malformed local receipt is rejected before hashing, ledger projection, or
# release-envelope construction traverses it.
MAX_EVALUATION_ARTIFACT_HASHES = 256
MAX_EVALUATION_REASON_BYTES = 4 * 1024
MAX_EVALUATION_RECEIPTS = 256
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

R_CHECK_AUTHORITY_SCHEMA_VERSION = "r-check-authority/v1"
R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION = "r-check-authority-bundle/v1"
R_CHECK_AUTHORITY_LOGICAL_TYPE = "r_check_authority"
R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE = "r_check_authority_bundle"
FROZEN_READINESS_RUBRIC_LOGICAL_TYPE = "paper_readiness_rubric"
READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION = (
    "readiness-category-score/v1"
)
READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE = (
    "readiness_category_score_authority"
)
SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE = (
    "scientific_semantic_judgment_receipt"
)
MAX_R_CHECK_SOURCE_ARTIFACTS = 128
MAX_R_CHECK_SOURCE_BYTES = 8 * 1024 * 1024
MAX_READINESS_CATEGORIES = 64
MAX_READINESS_SCORE_INPUT_BYTES = 1024 * 1024
READINESS_CATEGORY_SCORE_INSTRUCTIONS = (
    "Evaluate exactly one frozen paper-readiness rubric category from the "
    "retained candidate and evidence. Return only the closed structured "
    "judgment. The outcome must be SCORE:<fraction> with a finite fraction "
    "in [0,1]; no score may override a hard scientific blocker."
)


class AuthorityStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNTESTED = "UNTESTED"


class AuthorityScope(StrEnum):
    SYSTEM_FIXTURE = "SYSTEM_FIXTURE"
    SCIENTIFIC = "SCIENTIFIC"


class CategoryScoreStatus(StrEnum):
    SCORED = "SCORED"
    UNTESTED = "UNTESTED"


@dataclass(frozen=True)
class Evaluation:
    evaluator_class: EvaluatorClass
    actor_role: Role
    decision: Decision
    artifact_hashes: tuple[str, ...]
    reason: str
    r_checks: tuple[RCheck, ...] = ()
    critical_objection: bool = False
    producer_role: Role | None = None
    run_id: str | None = None
    gate_id: str | None = None
    frozen_context_sha256: str | None = None
    human_independence_claimed: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.artifact_hashes, tuple)
            or len(self.artifact_hashes) > MAX_EVALUATION_ARTIFACT_HASHES
            or any(
                not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                for digest in self.artifact_hashes
            )
        ):
            raise ValueError("evaluation artifact hashes must be a bounded SHA-256 tuple")
        if (
            not isinstance(self.reason, str)
            or len(self.reason) > MAX_EVALUATION_REASON_BYTES
        ):
            raise ValueError("evaluation reason must be non-empty bounded text")
        try:
            reason_bytes = self.reason.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("evaluation reason must be valid UTF-8 text") from exc
        if (
            len(reason_bytes) > MAX_EVALUATION_REASON_BYTES
            or not self.reason.strip()
        ):
            raise ValueError("evaluation reason must be non-empty bounded text")
        if (
            not isinstance(self.r_checks, tuple)
            or len(self.r_checks) > len(RCheck)
            or any(not isinstance(check, RCheck) for check in self.r_checks)
        ):
            raise ValueError("evaluation R checks must be a bounded typed tuple")
        if self.actor_role not in ALLOWED_EVALUATOR_ROLES[self.evaluator_class]:
            raise ValueError(f"{self.actor_role.value} cannot issue {self.evaluator_class.value}")
        if self.evaluator_class is EvaluatorClass.E1 and self.decision is Decision.PASS:
            raise ValueError("E1 is advisory and cannot authoritatively pass a gate")
        if self.evaluator_class in {EvaluatorClass.E2, EvaluatorClass.E3} and self.producer_role is self.actor_role:
            raise ValueError("producer and independent reviewer must be logically separated")
        if self.evaluator_class in {EvaluatorClass.E2, EvaluatorClass.E3} and self.producer_role is None:
            raise ValueError("independent review must identify the producer role")
        if self.evaluator_class is EvaluatorClass.E4:
            # A Role enum is not human identity or approval custody. Autonomous
            # code may record an external approval request, but it may never
            # construct an authoritative E4 evaluation.
            raise ValueError("E4 decisions must be imported through unavailable human custody")
        context_fields = (self.run_id, self.gate_id, self.frozen_context_sha256)
        if any(value is not None for value in context_fields):
            if not all(isinstance(value, str) for value in context_fields):
                raise ValueError(
                    "evaluation run, gate, and frozen context must be bound together"
                )
            assert self.run_id is not None
            assert self.gate_id is not None
            assert self.frozen_context_sha256 is not None
            if _IDENTIFIER_PATTERN.fullmatch(self.run_id) is None:
                raise ValueError("evaluation run ID is invalid")
            if (
                not self.gate_id.strip()
                or len(self.gate_id) > 256
                or any(ord(character) < 0x20 for character in self.gate_id)
            ):
                raise ValueError("evaluation gate ID is invalid")
            if _SHA256_PATTERN.fullmatch(self.frozen_context_sha256) is None:
                raise ValueError("evaluation frozen context SHA-256 is invalid")
        if not isinstance(self.human_independence_claimed, bool):
            raise ValueError("evaluation human-independence disclosure must be boolean")
        if self.human_independence_claimed:
            raise ValueError(
                "logical evaluator roles cannot claim independent human identity"
            )

    @property
    def context_bound(self) -> bool:
        return (
            self.run_id is not None
            and self.gate_id is not None
            and self.frozen_context_sha256 is not None
        )

    @property
    def sha256(self) -> str:
        payload = asdict(self)
        payload["evaluator_class"] = self.evaluator_class.value
        payload["actor_role"] = self.actor_role.value
        payload["decision"] = self.decision.value
        payload["r_checks"] = [item.value for item in self.r_checks]
        payload["producer_role"] = self.producer_role.value if self.producer_role else None
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class AuthoritySourceBinding:
    artifact_sha256: str
    artifact_record_hash: str
    logical_type: str
    creator_role: Role
    parent_artifacts: tuple[str, ...]
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int

    def __post_init__(self) -> None:
        for label, value in (
            ("source artifact SHA-256", self.artifact_sha256),
            ("source artifact record hash", self.artifact_record_hash),
            ("source ledger event hash", self.ledger_event_hash),
        ):
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{label} is invalid")
        if (
            not isinstance(self.logical_type, str)
            or not self.logical_type
            or len(self.logical_type) > 128
            or not isinstance(self.creator_role, Role)
            or not isinstance(self.parent_artifacts, tuple)
            or any(_SHA256_PATTERN.fullmatch(value) is None for value in self.parent_artifacts)
            or not isinstance(self.ledger_event_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(self.ledger_event_id) is None
            or isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
        ):
            raise ValueError("R-check source binding is malformed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "artifact_record_hash": self.artifact_record_hash,
            "logical_type": self.logical_type,
            "creator_role": self.creator_role.value,
            "parent_artifacts": list(self.parent_artifacts),
            "ledger_event_id": self.ledger_event_id,
            "ledger_event_hash": self.ledger_event_hash,
            "ledger_event_index": self.ledger_event_index,
        }


@dataclass(frozen=True)
class ReadinessCategoryScoreAuthority:
    run_id: str
    category_id: str
    asserted_score_fraction: float
    status: CategoryScoreStatus
    scope: AuthorityScope
    rubric_binding: AuthoritySourceBinding
    candidate_binding: AuthoritySourceBinding
    evidence_bindings: tuple[AuthoritySourceBinding, ...]
    semantic_judgment_binding: AuthoritySourceBinding
    ledger_prefix_head_hash: str
    ledger_prefix_event_count: int
    reason_code: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(self.run_id) is None
            or not isinstance(self.category_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(self.category_id) is None
            or isinstance(self.asserted_score_fraction, bool)
            or not isinstance(self.asserted_score_fraction, (int, float))
            or not math.isfinite(float(self.asserted_score_fraction))
            or not 0.0 <= float(self.asserted_score_fraction) <= 1.0
            or not isinstance(self.status, CategoryScoreStatus)
            or not isinstance(self.scope, AuthorityScope)
            or not isinstance(self.rubric_binding, AuthoritySourceBinding)
            or not isinstance(self.candidate_binding, AuthoritySourceBinding)
            or not isinstance(self.evidence_bindings, tuple)
            or not self.evidence_bindings
            or len(self.evidence_bindings) > MAX_R_CHECK_SOURCE_ARTIFACTS
            or any(
                not isinstance(value, AuthoritySourceBinding)
                for value in self.evidence_bindings
            )
            or not isinstance(
                self.semantic_judgment_binding,
                AuthoritySourceBinding,
            )
        ):
            raise ValueError("readiness category score authority is malformed")
        bindings = (
            self.rubric_binding,
            self.candidate_binding,
            *self.evidence_bindings,
            self.semantic_judgment_binding,
        )
        if len({value.artifact_sha256 for value in bindings}) != len(bindings):
            raise ValueError("readiness category score sources must be distinct")
        if (
            self.rubric_binding.logical_type
            != FROZEN_READINESS_RUBRIC_LOGICAL_TYPE
            or self.rubric_binding.creator_role is not Role.PROTOCOL_DESIGNER
            or self.candidate_binding.logical_type != "paper_candidate"
            or self.candidate_binding.creator_role is not Role.PAPER_WRITER
            or self.semantic_judgment_binding.logical_type
            != SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE
            or self.semantic_judgment_binding.creator_role
            is not Role.SCIENTIFIC_REVIEWER
        ):
            raise ValueError("readiness category score source roles are invalid")
        if (
            (self.status is CategoryScoreStatus.SCORED)
            is not (self.scope is AuthorityScope.SCIENTIFIC)
            or not isinstance(self.ledger_prefix_head_hash, str)
            or _SHA256_PATTERN.fullmatch(self.ledger_prefix_head_hash) is None
            or isinstance(self.ledger_prefix_event_count, bool)
            or not isinstance(self.ledger_prefix_event_count, int)
            or self.ledger_prefix_event_count <= 0
            or not isinstance(self.reason_code, str)
            or not self.reason_code
            or len(self.reason_code) > 128
        ):
            raise ValueError("readiness category score disposition is invalid")

    @property
    def authoritative_score_fraction(self) -> float | None:
        return (
            float(self.asserted_score_fraction)
            if self.status is CategoryScoreStatus.SCORED
            and self.scope is AuthorityScope.SCIENTIFIC
            else None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION,
            "kind": "READINESS_CATEGORY_SCORE_AUTHORITY",
            "run_id": self.run_id,
            "category_id": self.category_id,
            "asserted_score_fraction": float(self.asserted_score_fraction),
            "status": self.status.value,
            "scope": self.scope.value,
            "rubric_binding": self.rubric_binding.to_dict(),
            "candidate_binding": self.candidate_binding.to_dict(),
            "evidence_bindings": [
                value.to_dict() for value in self.evidence_bindings
            ],
            "semantic_judgment_binding": (
                self.semantic_judgment_binding.to_dict()
            ),
            "ledger_prefix_head_hash": self.ledger_prefix_head_hash,
            "ledger_prefix_event_count": self.ledger_prefix_event_count,
            "reason_code": self.reason_code,
            "human_independence_claimed": False,
            "e4_synthesized": False,
        }


@dataclass(frozen=True)
class RCheckAuthority:
    run_id: str
    r_check: RCheck
    evaluator_class: EvaluatorClass
    actor_role: Role
    status: AuthorityStatus
    scope: AuthorityScope
    source_bindings: tuple[AuthoritySourceBinding, ...]
    ledger_prefix_head_hash: str
    ledger_prefix_event_count: int
    reason_code: str
    derivation_checks: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or _IDENTIFIER_PATTERN.fullmatch(self.run_id) is None:
            raise ValueError("R-check authority run ID is invalid")
        if (
            not isinstance(self.r_check, RCheck)
            or not isinstance(self.evaluator_class, EvaluatorClass)
            or self.evaluator_class not in REQUIRED_R_AUTHORITIES[self.r_check]
            or not isinstance(self.actor_role, Role)
            or self.actor_role not in ALLOWED_EVALUATOR_ROLES[self.evaluator_class]
            or not isinstance(self.status, AuthorityStatus)
            or not isinstance(self.scope, AuthorityScope)
            or not isinstance(self.source_bindings, tuple)
            or len(self.source_bindings) > MAX_R_CHECK_SOURCE_ARTIFACTS
            or any(not isinstance(value, AuthoritySourceBinding) for value in self.source_bindings)
            or len({value.artifact_sha256 for value in self.source_bindings})
            != len(self.source_bindings)
        ):
            raise ValueError("R-check authority identity is invalid")
        if (
            not isinstance(self.ledger_prefix_head_hash, str)
            or _SHA256_PATTERN.fullmatch(self.ledger_prefix_head_hash) is None
            or isinstance(self.ledger_prefix_event_count, bool)
            or not isinstance(self.ledger_prefix_event_count, int)
            or self.ledger_prefix_event_count <= 0
            or not isinstance(self.reason_code, str)
            or not self.reason_code
            or len(self.reason_code) > 128
            or not isinstance(self.derivation_checks, tuple)
            or any(
                not isinstance(key, str)
                or not key
                or not isinstance(value, str)
                or not value
                for key, value in self.derivation_checks
            )
        ):
            raise ValueError("R-check authority derivation is invalid")
        if self.evaluator_class is EvaluatorClass.E4:
            raise ValueError("R-check authority cannot synthesize E4")

    @property
    def source_artifact_sha256s(self) -> tuple[str, ...]:
        return tuple(value.artifact_sha256 for value in self.source_bindings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": R_CHECK_AUTHORITY_SCHEMA_VERSION,
            "kind": "R_CHECK_AUTHORITY",
            "run_id": self.run_id,
            "r_check": self.r_check.value,
            "evaluator_class": self.evaluator_class.value,
            "actor_role": self.actor_role.value,
            "status": self.status.value,
            "scope": self.scope.value,
            "source_bindings": [value.to_dict() for value in self.source_bindings],
            "ledger_prefix_head_hash": self.ledger_prefix_head_hash,
            "ledger_prefix_event_count": self.ledger_prefix_event_count,
            "reason_code": self.reason_code,
            "derivation_checks": [
                {"check": key, "result": value}
                for key, value in self.derivation_checks
            ],
            "human_independence_claimed": False,
            "e4_synthesized": False,
        }

    def as_evaluation(self) -> Evaluation:
        decision = {
            AuthorityStatus.PASS: Decision.PASS,
            AuthorityStatus.FAIL: Decision.FAIL,
            AuthorityStatus.UNTESTED: Decision.ADVISORY,
        }[self.status]
        return Evaluation(
            self.evaluator_class,
            self.actor_role,
            decision,
            self.source_artifact_sha256s,
            self.reason_code,
            (self.r_check,),
            critical_objection=self.status is AuthorityStatus.FAIL,
            producer_role=(
                None
                if self.evaluator_class is EvaluatorClass.E0
                else Role.ORCHESTRATOR
            ),
        )


@dataclass(frozen=True, slots=True)
class _RCheckAuthorityDerivation:
    """Ephemeral full-owner replay, including its paired source snapshot."""

    authority: RCheckAuthority
    source_records: tuple[Any, ...]
    scientific_resolution: Any
    entry_snapshot: tuple[Any, Any]


@dataclass(frozen=True, slots=True)
class _RCheckAuthorityReplay:
    """Ephemeral authority readback companion; never a persisted DTO."""

    authority: RCheckAuthority
    record: Any
    source_records: tuple[Any, ...]
    scientific_resolution: Any
    entry_snapshot: tuple[Any, Any]


@dataclass(frozen=True)
class RCheckAuthorityBundle:
    run_id: str
    scope: AuthorityScope
    authority_artifact_sha256s: tuple[str, ...]
    rubric_artifact_sha256: str
    rubric_record_hash: str
    rubric_ledger_event_id: str
    rubric_ledger_event_hash: str
    rubric_ledger_event_index: int
    statuses: tuple[tuple[RCheck, AuthorityStatus], ...]
    category_statuses: tuple[tuple[str, CategoryScoreStatus], ...]
    category_scope: AuthorityScope
    category_score_authority_artifact_sha256s: tuple[str, ...]
    candidate_artifact_sha256: str | None
    ledger_prefix_head_hash: str
    ledger_prefix_event_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or _IDENTIFIER_PATTERN.fullmatch(self.run_id) is None:
            raise ValueError("R-check bundle run ID is invalid")
        if (
            not isinstance(self.scope, AuthorityScope)
            or not isinstance(self.authority_artifact_sha256s, tuple)
            or len(self.authority_artifact_sha256s) != _required_authority_count()
            or len(set(self.authority_artifact_sha256s))
            != len(self.authority_artifact_sha256s)
            or any(_SHA256_PATTERN.fullmatch(value) is None for value in self.authority_artifact_sha256s)
            or _SHA256_PATTERN.fullmatch(self.rubric_artifact_sha256) is None
            or _SHA256_PATTERN.fullmatch(self.rubric_record_hash) is None
            or _IDENTIFIER_PATTERN.fullmatch(self.rubric_ledger_event_id) is None
            or _SHA256_PATTERN.fullmatch(self.rubric_ledger_event_hash) is None
            or isinstance(self.rubric_ledger_event_index, bool)
            or not isinstance(self.rubric_ledger_event_index, int)
            or self.rubric_ledger_event_index < 0
            or not isinstance(self.statuses, tuple)
            or tuple(check for check, _status in self.statuses) != tuple(RCheck)
            or any(not isinstance(status, AuthorityStatus) for _check, status in self.statuses)
            or not isinstance(self.category_statuses, tuple)
            or not isinstance(self.category_scope, AuthorityScope)
            or not self.category_statuses
            or len({name for name, _status in self.category_statuses})
            != len(self.category_statuses)
            or len(self.category_statuses) > MAX_READINESS_CATEGORIES
            or any(
                not isinstance(name, str)
                or _IDENTIFIER_PATTERN.fullmatch(name) is None
                or not isinstance(status, CategoryScoreStatus)
                for name, status in self.category_statuses
            )
            or len(self.category_score_authority_artifact_sha256s)
            not in {0, len(self.category_statuses)}
            or len(set(self.category_score_authority_artifact_sha256s))
            != len(self.category_score_authority_artifact_sha256s)
            or any(
                _SHA256_PATTERN.fullmatch(value) is None
                for value in self.category_score_authority_artifact_sha256s
            )
            or (
                not self.category_score_authority_artifact_sha256s
                and any(
                    status is not CategoryScoreStatus.UNTESTED
                    for _name, status in self.category_statuses
                )
            )
            or (
                self.category_scope is AuthorityScope.SCIENTIFIC
            )
            is not (
                bool(self.category_score_authority_artifact_sha256s)
                and all(
                    status is CategoryScoreStatus.SCORED
                    for _name, status in self.category_statuses
                )
            )
            or (
                self.candidate_artifact_sha256 is None
                and self.category_score_authority_artifact_sha256s
            )
            or (
                self.candidate_artifact_sha256 is not None
                and not self.category_score_authority_artifact_sha256s
            )
            or (
                self.candidate_artifact_sha256 is not None
                and _SHA256_PATTERN.fullmatch(
                    self.candidate_artifact_sha256
                )
                is None
            )
            or _SHA256_PATTERN.fullmatch(self.ledger_prefix_head_hash) is None
            or isinstance(self.ledger_prefix_event_count, bool)
            or not isinstance(self.ledger_prefix_event_count, int)
            or self.ledger_prefix_event_count <= 0
        ):
            raise ValueError("R-check authority bundle is malformed")

    @property
    def status_by_r_check(self) -> dict[str, str]:
        return {check.value: status.value for check, status in self.statuses}

    @property
    def mandatory_pass(self) -> bool:
        return all(status is AuthorityStatus.PASS for _check, status in self.statuses)

    @property
    def category_status_by_id(self) -> dict[str, str]:
        return {name: status.value for name, status in self.category_statuses}

    @property
    def scientific_mandatory_pass(self) -> bool:
        return self.scope is AuthorityScope.SCIENTIFIC and self.mandatory_pass

    @property
    def readiness_scope(self) -> AuthorityScope:
        return (
            AuthorityScope.SCIENTIFIC
            if self.scope is AuthorityScope.SCIENTIFIC
            and self.category_scope is AuthorityScope.SCIENTIFIC
            else AuthorityScope.SYSTEM_FIXTURE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION,
            "kind": "R_CHECK_AUTHORITY_BUNDLE",
            "run_id": self.run_id,
            "scope": self.scope.value,
            "authority_artifact_sha256s": list(self.authority_artifact_sha256s),
            "rubric": {
                "artifact_sha256": self.rubric_artifact_sha256,
                "record_hash": self.rubric_record_hash,
                "ledger_event_id": self.rubric_ledger_event_id,
                "ledger_event_hash": self.rubric_ledger_event_hash,
                "ledger_event_index": self.rubric_ledger_event_index,
            },
            "statuses": self.status_by_r_check,
            "category_scoring": {
                "scope": self.category_scope.value,
                "candidate_artifact_sha256": (
                    self.candidate_artifact_sha256
                ),
                "statuses": {
                    name: status.value for name, status in self.category_statuses
                },
                "score_authority_artifact_sha256s": list(
                    self.category_score_authority_artifact_sha256s
                ),
                "reason_code": (
                    "REGISTRY_AND_LEDGER_RESOLVED_CATEGORY_SCORE_AUTHORITY"
                    if self.category_score_authority_artifact_sha256s
                    else "NO_REGISTRY_RESOLVED_CATEGORY_SCORE_AUTHORITY"
                ),
            },
            "ledger_prefix_head_hash": self.ledger_prefix_head_hash,
            "ledger_prefix_event_count": self.ledger_prefix_event_count,
            "human_independence_claimed": False,
            "e4_synthesized": False,
        }


def _required_authority_identities() -> tuple[tuple[RCheck, EvaluatorClass], ...]:
    return tuple(
        (check, evaluator_class)
        for check in RCheck
        for evaluator_class in sorted(
            REQUIRED_R_AUTHORITIES[check], key=lambda value: value.value
        )
    )


def _required_authority_count() -> int:
    return len(_required_authority_identities())


_SOURCE_ROLES: dict[str, Role] = {
    "audit_report": Role.ORCHESTRATOR,
    "canonical_research_state_final_snapshot": Role.ORCHESTRATOR,
    "paper_verification": Role.SCIENTIFIC_REVIEWER,
    "research_brief": Role.PROBLEM_INVESTIGATOR,
    "problem_investigation_state": Role.PROBLEM_INVESTIGATOR,
    "hypothesis_register": Role.HYPOTHESIS_DESIGNER,
    "evaluation_contract": Role.PROTOCOL_DESIGNER,
    "research_question_gate_assessment": Role.CLAIM_VERIFIER,
    "evaluation_contract_freeze_gate_receipt": Role.CLAIM_VERIFIER,
    "frozen_protocol": Role.PROTOCOL_DESIGNER,
    "autonomous_implementation.semantic_validation": Role.SCIENTIFIC_REVIEWER,
    "aggregate_experiment_result": Role.STATISTICIAN,
    "machine_results": Role.EXPERIMENT_RUNNER,
    "custody_record": Role.HOLDOUT_CUSTODIAN,
    "confirmatory_timeline_receipt": Role.CLAIM_VERIFIER,
    "statistical_analysis": Role.STATISTICIAN,
    "ablation_validation": Role.SCIENTIFIC_REVIEWER,
    "workflow_benchmark": Role.EXPERIMENT_RUNNER,
    "challenger_finding": Role.ADVERSARIAL_REVIEWER,
    "challenger_attack_execution_receipt": Role.ADVERSARIAL_REVIEWER,
    "challenger_category_review": Role.ADVERSARIAL_REVIEWER,
    "semantic_challenge_audit_authority": Role.ADVERSARIAL_REVIEWER,
    "alternative_explanations_scientific_authority": Role.SCIENTIFIC_REVIEWER,
    "claim_evidence_graph": Role.CLAIM_VERIFIER,
    "claim_graph": Role.CLAIM_VERIFIER,
    "e2_review": Role.SCIENTIFIC_REVIEWER,
    "e3_review": Role.ADVERSARIAL_REVIEWER,
    "reproduction_report": Role.REPRODUCTION_VERIFIER,
    "scientific_clean_rerun_authority": Role.REPRODUCTION_VERIFIER,
    "research_state.result": Role.STATISTICIAN,
    "research_state.statistical_test": Role.STATISTICIAN,
    "research_state.run": Role.EXPERIMENT_RUNNER,
    "research_state.implementation": Role.IMPLEMENTER,
    "frozen_run_spec": Role.EXPERIMENT_RUNNER,
    "scientific_confirmatory_timeline_receipt_v2": Role.CLAIM_VERIFIER,
}

# These newly selected sources require cohort-aware bundle aggregation.  The
# Method owner has two historical producer shapes; neither role alone proves
# scientific eligibility or a prospective method-intention binding.
_CANONICAL_RESULT_SOURCE_TYPES = frozenset({
    "research_state.result", "research_state.statistical_test",
})
_CANONICAL_IMPLEMENTATION_SOURCE_TYPES = frozenset({
    "research_state.run", "research_state.implementation",
    "research_state.method", "frozen_run_spec",
})
_COHORT_ONLY_SOURCE_TYPES = (
    _CANONICAL_RESULT_SOURCE_TYPES | _CANONICAL_IMPLEMENTATION_SOURCE_TYPES
    | {"scientific_confirmatory_timeline_receipt_v2"}
)

_ALLOWED_SOURCE_TYPES: dict[RCheck, frozenset[str]] = {
    RCheck.R0: frozenset({"audit_report", "canonical_research_state_final_snapshot", "paper_verification"}),
    RCheck.R1: frozenset({"research_brief", "problem_investigation_state", "hypothesis_register", "evaluation_contract", "frozen_protocol", "e2_review", "research_question_gate_assessment", "evaluation_contract_freeze_gate_receipt", "semantic_challenge_audit_authority"}),
    RCheck.R2: frozenset({"evaluation_contract", "autonomous_implementation.semantic_validation", "aggregate_experiment_result", "machine_results", "e2_review", "semantic_challenge_audit_authority"}) | _CANONICAL_RESULT_SOURCE_TYPES | _CANONICAL_IMPLEMENTATION_SOURCE_TYPES,
    RCheck.R3: frozenset({"custody_record", "machine_results", "confirmatory_timeline_receipt", "e3_review", "scientific_confirmatory_timeline_receipt_v2"}),
    RCheck.R4: frozenset({"evaluation_contract", "aggregate_experiment_result", "statistical_analysis", "machine_results", "e2_review", "semantic_challenge_audit_authority"}) | _CANONICAL_RESULT_SOURCE_TYPES,
    RCheck.R5: frozenset({"ablation_validation", "workflow_benchmark", "challenger_finding", "challenger_attack_execution_receipt", "challenger_category_review", "semantic_challenge_audit_authority", "alternative_explanations_scientific_authority", "e2_review", "e3_review"}),
    RCheck.R6: frozenset({"claim_evidence_graph", "claim_graph", "paper_verification", "challenger_finding", "challenger_attack_execution_receipt", "challenger_category_review", "semantic_challenge_audit_authority", "e2_review", "e3_review"}),
    RCheck.R7: frozenset({"reproduction_report", "scientific_clean_rerun_authority", "semantic_challenge_audit_authority", "e3_review"}),
}


_DOMAIN_VALIDITY_SOURCE_TYPES = frozenset({
    "domain_validity.generic_ml", "domain_validity.medical_imaging",
    "domain_validity.time_series", "domain_validity.recommender_systems",
    "domain_validity.operations_research", "domain_validity.systems",
})

# This is a closed classification policy, not an authorization policy.  A
# scientific classification still requires the source owner's fresh replay in
# _derive_status.  New source types must be reviewed explicitly; the absence of
# a fixture label must never give an unknown source scientific scope.
_SCIENTIFIC_SCOPE_SOURCE_TYPES = frozenset({
    "canonical_research_state_final_snapshot", "paper_verification",
    "research_brief", "problem_investigation_state", "hypothesis_register",
    "evaluation_contract", "aggregate_experiment_result", "statistical_analysis",
    "research_question_gate_assessment", "evaluation_contract_freeze_gate_receipt",
    "ablation_validation", "challenger_finding",
    "challenger_attack_execution_receipt", "challenger_category_review",
    "claim_evidence_graph", "scientific_clean_rerun_authority",
    "semantic_challenge_audit_authority",
    "alternative_explanations_scientific_authority",
}) | _DOMAIN_VALIDITY_SOURCE_TYPES | _COHORT_ONLY_SOURCE_TYPES


def _source_role(logical_type: str) -> Role | None:
    if logical_type in _DOMAIN_VALIDITY_SOURCE_TYPES:
        return Role.SCIENTIFIC_REVIEWER
    return _SOURCE_ROLES.get(logical_type)


def _require_legacy_bundle_source_profile(records: Sequence[Any]) -> None:
    """Do not reinterpret V1's one-per-identity aggregation as cohort coverage.

    Call only on source records retained by full leaf replay.  In particular,
    inspect every R5 source too: a plural reproduction audit can be selected
    inside that aggregate, not only by R7.
    """
    if any(
        record.logical_type in _COHORT_ONLY_SOURCE_TYPES
        or (
            record.logical_type == "semantic_challenge_audit_authority"
            and record.schema_version != "1.0"
        )
        for record in records
    ):
        raise ValueError("R-check source requires the cohort-aware V2 bundle")


def _owned_scientific_source_bindings(
    events: Sequence[Any], records: Sequence[Any], resolution: Any,
) -> tuple[AuthoritySourceBinding, ...]:
    """Transport completed owner replay, never discover or grant admission.

    A diagnostic failure with no authenticated admissions is not a source
    binding. New routes must not fall back to arbitrary later references when
    an owner is unavailable. Actual derived-receipt input checkpoints need not
    contain the later artifact hash; their full owner establishes that join.
    """
    from .scientific_r_checks import (
        ScientificRCheckResolution, _ScientificSourceAdmission,
    )

    if type(resolution) is not ScientificRCheckResolution:
        raise ValueError("scientific source bindings require full owner resolution")
    admissions = resolution.source_admissions
    if (
        not records
        or any(type(item) is not _ScientificSourceAdmission for item in admissions)
        or len(admissions) != len(records)
        or len({record.sha256 for record in records}) != len(records)
        or {item.artifact_sha256 for item in admissions}
        != {record.sha256 for record in records}
    ):
        raise ValueError("scientific source owner admissions are incomplete or substituted")
    by_digest = {item.artifact_sha256: item for item in admissions}
    bindings = []
    for record in records:
        admission = by_digest[record.sha256]
        index = admission.ledger_event_index
        if (
            record.record_hash != admission.artifact_record_hash
            or index >= len(events)
            or events[index].event_id != admission.ledger_event_id
            or events[index].event_hash != admission.ledger_event_hash
        ):
            raise ValueError("scientific source owner checkpoint was substituted")
        bindings.append(AuthoritySourceBinding(
            record.sha256, str(record.record_hash), record.logical_type,
            record.creator_role, record.parent_artifacts,
            admission.ledger_event_id, admission.ledger_event_hash, index,
        ))
    return tuple(bindings)


def _validate_runtime(registry: Any, ledger: Any, run_id: str) -> tuple[Any, ...]:
    # Local imports avoid the models -> evaluators import cycle.
    from .artifacts import ArtifactRegistry
    from .ledger import EventLedger

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ValueError("R-check authority requires exact ArtifactRegistry and EventLedger")
    if registry.policy.root != ledger.policy.root:
        raise ValueError("R-check registry and ledger roots differ")
    if not isinstance(run_id, str) or _IDENTIFIER_PATTERN.fullmatch(run_id) is None:
        raise ValueError("R-check run ID is invalid")
    try:
        registry.verify_all(raise_on_error=True)
        result = ledger.validate(raise_on_error=True)
    except Exception as exc:
        raise ValueError("R-check registry or ledger is invalid") from exc
    if not result.events or result.head_hash is None:
        raise ValueError("R-check authority requires a non-empty ledger")
    if any(event.run_id != run_id for event in result.events):
        raise ValueError("R-check ledger contains another run identity")
    return result.events


def _r_check_read_snapshot(registry: Any, ledger: Any) -> tuple[Any, Any]:
    """Bracket a complete cross-owner read with one registry/ledger view."""
    from .artifacts import ArtifactRegistry
    from .ledger import EventLedger

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ValueError("R-check snapshot requires exact registry and ledger")
    if registry.policy.root != ledger.policy.root:
        raise ValueError("R-check snapshot roots differ")
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            registry_state = registry._verify_all_locked(
                registry_guard, raise_on_error=True
            )
            ledger_state = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if not ledger_state.valid:
                raise ValueError("R-check snapshot ledger is invalid")
            return registry_state, ledger_state
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)


def _canonical_json_artifact(registry: Any, record: Any) -> Mapping[str, Any]:
    from .security import canonical_json_bytes, safe_json_loads

    try:
        content = registry.get_bytes(record.sha256)
        value = safe_json_loads(content, max_bytes=MAX_R_CHECK_SOURCE_BYTES)
    except Exception as exc:
        raise ValueError("R-check source payload is absent or unsafe") from exc
    if (
        not isinstance(value, Mapping)
        or content != canonical_json_bytes(value) + b"\n"
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or record.frozen is not True
        or record.record_hash is None
    ):
        raise ValueError("R-check source is not exact frozen canonical JSON")
    return value


def _event_binding(events: Sequence[Any], record: Any) -> AuthoritySourceBinding:
    matches: list[AuthoritySourceBinding] = []
    # These owners distinguish publication from later uses of the same source.
    # A slot or verification input reference must not masquerade as a second
    # admission. This selector grants no authority: _derive_status still calls
    # the source owner's complete fresh replay. Preserve legacy descriptors.
    publication_key = {
        "scientific_clean_rerun_authority": (
            "scientific_clean_rerun_authority_publication"
        ),
        "semantic_challenge_audit_authority": (
            "semantic_challenge_audit_authority_publication"
        ),
    }.get(record.logical_type)
    if record.logical_type in _DOMAIN_VALIDITY_SOURCE_TYPES:
        publication_key = "scientific_domain_validity"
    has_publication = publication_key is not None and any(
        publication_key in event.metadata
        and record.sha256 in event.artifact_hashes
        for event in events
    )
    for index, event in enumerate(events):
        if has_publication and publication_key not in event.metadata:
            continue
        positions = tuple(
            position
            for position, digest in enumerate(event.artifact_hashes)
            if digest == record.sha256
        )
        if not positions:
            continue
        artifact_types = event.metadata.get("artifact_types")
        record_hashes = event.metadata.get("artifact_record_hashes")
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
            or event.event_hash is None
        ):
            raise ValueError("R-check source ledger descriptor is incomplete")
        for position in positions:
            if (
                artifact_types[position] != record.logical_type
                or record_hashes[position] != record.record_hash
            ):
                raise ValueError("R-check source ledger descriptor was substituted")
            matches.append(
                AuthoritySourceBinding(
                    record.sha256,
                    str(record.record_hash),
                    record.logical_type,
                    record.creator_role,
                    record.parent_artifacts,
                    event.event_id,
                    str(event.event_hash),
                    index,
                )
            )
    if len(matches) != 1:
        raise ValueError("R-check source must have one exact ledger admission")
    return matches[0]


def _alternative_source_binding(
    registry: Any,
    ledger: Any,
    events: Sequence[Any],
    run_id: str,
    record: Any,
    payload: Mapping[str, Any],
) -> AuthoritySourceBinding:
    """Bind the existing aggregate owner's checkpoint, not a fake publication.

    This historical owner materializes its exact derived receipt after its
    verification checkpoint. The checkpoint binds the complete inputs rather
    than the later receipt hash. Only fresh owner replay establishes that this
    artifact is its exact output; generic event references cannot replace it.
    """
    from .gates import (
        AlternativeExplanationsAuthority,
        require_alternative_explanations_authority,
    )

    stated = AlternativeExplanationsAuthority.from_dict(payload)
    verified = require_alternative_explanations_authority(
        registry,
        ledger,
        authority_artifact_hash=record.sha256,
        expected_assessment_id=stated.assessment_id,
        expected_run_id=run_id,
        expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
        expected_central_claim_ids=tuple(item.claim_id for item in stated.central_claims),
    )
    index = verified.verification_event_index
    if (
        verified != stated
        or verified.run_id != run_id
        or index < 0
        or index >= len(events)
        or events[index].event_id != verified.verification_event_id
        or events[index].event_hash != verified.verification_event_hash
        or record.parent_artifacts != verified.input_artifact_hashes
    ):
        raise ValueError("alternative source owner checkpoint differs from its receipt")
    return AuthoritySourceBinding(
        record.sha256,
        str(record.record_hash),
        record.logical_type,
        record.creator_role,
        record.parent_artifacts,
        verified.verification_event_id,
        verified.verification_event_hash,
        index,
    )


def _research_design_source_binding(
    registry: Any,
    ledger: Any,
    events: Sequence[Any],
    run_id: str,
    record: Any,
    payload: Mapping[str, Any],
) -> AuthoritySourceBinding:
    """Bind source-derived design receipts to their actual input checkpoint.

    These owners materialize their exact receipt after the checkpoint that
    binds its inputs. Later receipt uses are not additional admissions, and
    arbitrary event references cannot substitute for the owner's fresh replay.
    """
    from .scientific_design import (
        EvaluationContractFreezeGateReceipt,
        ResearchQuestionGateAssessment,
        require_evaluation_contract_freeze_gate_receipt,
        require_research_question_gate_assessment,
    )

    if record.logical_type == "research_question_gate_assessment":
        stated = ResearchQuestionGateAssessment.from_dict(payload)
        verified = require_research_question_gate_assessment(
            registry,
            ledger,
            assessment_artifact_sha256=record.sha256,
            expected_run_id=run_id,
            expected_object_id=stated.object_id,
        )
        index = verified.gate_event_index
        event_id = verified.gate_event_id
        event_hash = verified.gate_event_hash
    elif record.logical_type == "evaluation_contract_freeze_gate_receipt":
        stated = EvaluationContractFreezeGateReceipt.from_dict(payload)
        verified = require_evaluation_contract_freeze_gate_receipt(
            registry,
            ledger,
            receipt_artifact_sha256=record.sha256,
            expected_run_id=run_id,
            expected_contract_id=stated.object_id,
        )
        index = verified.design_freeze_event_index
        event_id = verified.design_freeze_event_id
        event_hash = verified.design_freeze_event_hash
    else:
        raise ValueError("research design checkpoint source type is unsupported")
    if (
        verified != stated
        or verified.run_id != run_id
        or verified.ledger_path != ledger.relative_path.as_posix()
        or type(index) is not int
        or index < 0
        or index >= len(events)
        or events[index].event_id != event_id
        or events[index].event_hash != event_hash
    ):
        raise ValueError("research design source checkpoint differs from its receipt")
    return AuthoritySourceBinding(
        record.sha256,
        str(record.record_hash),
        record.logical_type,
        record.creator_role,
        record.parent_artifacts,
        event_id,
        event_hash,
        index,
    )


def _fixture_scope(records: Sequence[Any], payloads: Sequence[Mapping[str, Any]]) -> AuthorityScope:
    if len(records) != len(payloads):
        raise ValueError("R-check source scope requires paired records and payloads")
    if not records or any(
        record.logical_type not in _SCIENTIFIC_SCOPE_SOURCE_TYPES
        for record in records
    ):
        return AuthorityScope.SYSTEM_FIXTURE
    for payload in payloads:
        if not isinstance(payload, Mapping):
            raise ValueError("R-check source scope requires structured payloads")
        # An outer scope field is an evidence classification.  Nested `scope`
        # fields may instead contain scientific claim text and are not grants.
        if "scope" in payload and (
            not isinstance(payload["scope"], str)
            or payload["scope"] not in {"SCIENTIFIC", "SCIENTIFIC_EVIDENCE"}
        ):
            return AuthorityScope.SYSTEM_FIXTURE
    stack: list[Any] = list(payloads)
    visited = 0
    while stack:
        value = stack.pop()
        visited += 1
        if visited > 100_000:
            raise ValueError("R-check source scope traversal exceeds its bound")
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key == "fixture_notice":
                    return AuthorityScope.SYSTEM_FIXTURE
                if key in {"scientific_evidence", "scientific_evidence_eligible", "scientific_source_qualified"} and item is not True:
                    return AuthorityScope.SYSTEM_FIXTURE
                if key in {"evidence_use", "evidence_scope"} and (
                    not isinstance(item, str)
                    or item not in {"SCIENTIFIC", "SCIENTIFIC_EVIDENCE"}
                ):
                    return AuthorityScope.SYSTEM_FIXTURE
                if key == "scope" and (
                    not isinstance(item, str)
                    or item in {
                        "SYSTEM_FIXTURE", "NON_EVIDENTIARY_FIXTURE",
                        "NON_EVIDENTIARY", "REVIEW_ONLY_ARCHITECTURE_CONTROL",
                    }
                ):
                    return AuthorityScope.SYSTEM_FIXTURE
                stack.append(item)
        elif isinstance(value, (list, tuple)):
            stack.extend(value)
    return AuthorityScope.SCIENTIFIC


def _explicit_failure(check: RCheck, payloads: Sequence[Mapping[str, Any]]) -> bool:
    for value in payloads:
        status = value.get("status")
        if isinstance(status, str) and status in {"FAIL", "FAILED", "INVALID", "REJECTED", "STOP_SCIENTIFIC_INVALIDITY"}:
            return True
        if value.get("critical_objection") is True or value.get("decision") == "FAIL":
            return True
        if check is RCheck.R6:
            verification = value.get("verification")
            if isinstance(verification, Mapping) and verification.get("passed") is False:
                return True
    return False


def _cross_parent(records: Sequence[Any], child: str, parents: set[str]) -> bool:
    by_type = {record.logical_type: record for record in records}
    child_record = by_type.get(child)
    return child_record is not None and {
        by_type[name].sha256 for name in parents if name in by_type
    }.issubset(set(child_record.parent_artifacts))


def _paper_authority_bundle(registry: Any, paper_record: Any, run_id: str) -> Any:
    from .paper_pipeline import (
        _authoritative_bundle_from_json,
        _read_registry_json,
    )

    if len(paper_record.parent_artifacts) != 2:
        raise ValueError("paper verification parent graph is malformed")
    _record, wrapper = _read_registry_json(
        registry,
        paper_record.parent_artifacts[1],
        logical_type="authoritative_research_bundle",
        creator_role=Role.ORCHESTRATOR,
    )
    bundle_value = wrapper.get("bundle")
    if bundle_value is None:
        raise ValueError("paper verification bundle payload is absent")
    bundle = _authoritative_bundle_from_json(bundle_value)
    if bundle.run_id != run_id:
        raise ValueError("paper verification bundle belongs to another run")
    return bundle


def _replay_semantic_audit_source(
    registry: Any,
    ledger: Any,
    run_id: str,
    record: Any,
    payload: Mapping[str, Any],
    *,
    expected_category: Any = None,
    _replayed_peer: Any = None,
) -> Any:
    authority, _packages = _replay_semantic_audit_source_with_packages(
        registry, ledger, run_id, record, payload,
        expected_category=expected_category, _replayed_peer=_replayed_peer,
    )
    return authority


def _replay_semantic_audit_source_with_packages(
    registry: Any,
    ledger: Any,
    run_id: str,
    record: Any,
    payload: Mapping[str, Any],
    *,
    expected_category: Any = None,
    _replayed_peer: Any = None,
) -> tuple[Any, tuple[Any, ...] | None]:
    """Replay the selected owner, retaining a plural owner's complete packages.

    Absence of package outputs denotes the legacy owner or the existing static
    peer seam, never a singular package alias or a source-coverage assertion.
    """
    from .gates import (
        ChallengeCategory,
        SemanticChallengeAuditAuthority,
        SemanticReproductionCohortAuditAuthority,
        _SemanticChallengerAuditPublishedPeer,
        _SemanticReproductionCohortAuditReplay,
        _require_semantic_reproduction_cohort_audit_source,
        require_semantic_challenge_audit_authority,
    )

    # Parsed values select a source; only the owner can validate those values.
    if (
        record.logical_type != "semantic_challenge_audit_authority"
        or type(record.schema_version) is not str
        or type(payload.get("schema_version")) is not str
    ):
        raise ValueError("semantic audit registry/payload family is malformed")
    family = (record.schema_version, payload["schema_version"])
    if family == ("1.0", "semantic-challenge-audit-authority/v1"):
        stated = SemanticChallengeAuditAuthority.from_dict(payload)
    elif family == ("2.0", "semantic-challenge-audit-authority/v2"):
        stated = SemanticReproductionCohortAuditAuthority.from_dict(payload)
        if stated.category is not ChallengeCategory.REPRODUCTION:
            raise ValueError("plural semantic audit is not a reproduction audit")
    else:
        raise ValueError("semantic audit registry/payload versions do not match")
    if stated.run_id != run_id or (
        expected_category is not None and stated.category is not expected_category
    ):
        raise ValueError("semantic audit names another run or category")
    if _replayed_peer is not None:
        # Private recursion seam used only while replaying the same round's
        # soundness. Public registration/readback never accepts this argument.
        # The gate has already checked this publication's entire static closure.
        if (
            type(_replayed_peer) is not _SemanticChallengerAuditPublishedPeer
            or type(_replayed_peer.record) is not type(record)
            or type(_replayed_peer.authority) is not type(stated)
            or _replayed_peer.record != record
            or _replayed_peer.authority != stated
            or expected_category is not ChallengeCategory.REPRODUCTION
        ):
            raise ValueError("replayed semantic audit peer names another exact source")
        return stated, None
    if type(stated) is SemanticReproductionCohortAuditAuthority:
        replay = _require_semantic_reproduction_cohort_audit_source(
            registry,
            ledger,
            authority_artifact_hash=record.sha256,
            expected_run_id=run_id,
            expected_assessment_id=stated.assessment_id,
            expected_research_state_snapshot_artifact_hash=(
                stated.research_state_snapshot_artifact_hash
            ),
            expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
            expected_central_claim_ids=stated.central_claim_ids,
            expected_reproduction_package_bindings=stated.reproduction_package_bindings,
        )
        if (
            type(replay) is not _SemanticReproductionCohortAuditReplay
            or replay.authority != stated
            or replay.record != record
            or replay.authority.run_id != run_id
        ):
            raise ValueError("plural semantic audit owner returned another source")
        return replay.authority, replay.canonical_scope.package_authorities
    verified = require_semantic_challenge_audit_authority(
        registry,
        ledger,
        authority_artifact_hash=record.sha256,
        expected_run_id=run_id,
        expected_assessment_id=stated.assessment_id,
        expected_category=(
            stated.category if expected_category is None else expected_category
        ),
        expected_research_state_snapshot_artifact_hash=(
            stated.research_state_snapshot_artifact_hash
        ),
        expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
        expected_central_claim_ids=stated.central_claim_ids,
        expected_reproducibility_package_artifact_hash=(
            stated.reproducibility_package_artifact_hash
        ),
    )
    if verified != stated or verified.run_id != run_id:
        raise ValueError("semantic audit owner returned another source")
    return verified, None


def _replay_reproduction_cohort_packages(
    registry: Any, ledger: Any, run_id: str, audit: Any,
) -> tuple[Any, ...]:
    """Replay every static peer mapping through the ordinary package owner.

    The same-round gate owns complete canonical coverage; this function does
    not reenter that audit or turn a caller-selected mapping into coverage.
    """
    from .gates import SemanticReproductionCohortAuditAuthority
    from .research_state import (
        ReproducibilityPackage,
        require_scientific_reproducibility_package,
    )

    if type(audit) is not SemanticReproductionCohortAuditAuthority:
        raise ValueError("reproduction cohort requires its exact plural audit")
    packages = []
    for row in audit.reproduction_package_bindings:
        package_record = registry.get_metadata(
            row.reproducibility_package_artifact_sha256,
        )
        if package_record.record_hash != row.reproducibility_package_artifact_record_hash:
            raise ValueError("reproduction cohort package record was substituted")
        stated_package = ReproducibilityPackage.from_dict(
            _canonical_json_artifact(registry, package_record),
        )
        if type(stated_package) is not ReproducibilityPackage:
            raise ValueError("reproduction cohort names another canonical kind")
        packages.append(require_scientific_reproducibility_package(
            registry,
            ledger,
            package_state_artifact_sha256=package_record.sha256,
            expected_ledger_run_id=run_id,
            expected_package_id=stated_package.object_id,
        ))
    return tuple(packages)


def _reproduction_cohort_clean_outcomes(
    run_id: str, audit: Any, packages: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Join already-owned outputs; this pure check does not confer authority."""
    from .gates import SemanticReproductionCohortAuditAuthority
    from .reproduction import ScientificCleanRerunAuthority, ScientificCleanRerunOutcome
    from .research_state import ScientificReproducibilityPackageAuthority

    if (
        type(audit) is not SemanticReproductionCohortAuditAuthority
        or audit.run_id != run_id
        or type(packages) is not tuple
        or not packages
        or len(packages) != len(audit.reproduction_package_bindings)
    ):
        raise ValueError("reproduction cohort package coverage is incomplete")
    outcomes = []
    for row, package in zip(audit.reproduction_package_bindings, packages, strict=True):
        if (
            type(package) is not ScientificReproducibilityPackageAuthority
            or type(package.clean_rerun_authority) is not ScientificCleanRerunAuthority
            or package.ledger_run_id != run_id
            or package.package_binding.artifact_sha256
            != row.reproducibility_package_artifact_sha256
            or package.package_binding.artifact_record_hash
            != row.reproducibility_package_artifact_record_hash
            or package.original_result_binding.artifact_sha256 != row.result_artifact_sha256
            or package.original_result_binding.artifact_record_hash
            != row.result_artifact_record_hash
            or type(package.clean_rerun_authority.outcome) is not ScientificCleanRerunOutcome
        ):
            raise ValueError("reproduction cohort and full package sources disagree")
        outcomes.append(package.clean_rerun_authority.outcome)
    return tuple(outcomes)


def _derive_reproduction_cohort_status(
    clean_outcomes: tuple[Any, ...], audit_status: Any, scope: AuthorityScope,
) -> tuple[AuthorityStatus, str]:
    """Finite outcome conjunction only, never source admission or eligibility."""
    from .gates import SemanticChallengeAuditStatus
    from .reproduction import ScientificCleanRerunOutcome

    if (
        type(clean_outcomes) is not tuple
        or not clean_outcomes
        or any(type(value) is not ScientificCleanRerunOutcome for value in clean_outcomes)
        or type(audit_status) is not SemanticChallengeAuditStatus
        or type(scope) is not AuthorityScope
    ):
        raise ValueError("reproduction cohort outcome projection is malformed")
    if any(value is not ScientificCleanRerunOutcome.PASS for value in clean_outcomes):
        return AuthorityStatus.FAIL, "SCIENTIFIC_CLEAN_RERUN_FAILED"
    if audit_status is SemanticChallengeAuditStatus.FAIL:
        return AuthorityStatus.FAIL, "REPRODUCTION_AUDIT_FAILED"
    if audit_status is not SemanticChallengeAuditStatus.PASS or scope is not AuthorityScope.SCIENTIFIC:
        return AuthorityStatus.UNTESTED, "REPRODUCTION_AUDIT_INCOMPLETE"
    return AuthorityStatus.PASS, "SCIENTIFIC_CLEAN_COHORT_AND_AUDIT_REPLAYED"


def _derive_complete_challenger_status(
    registry: Any,
    ledger: Any,
    run_id: str,
    check: RCheck,
    records: Sequence[Any],
    payloads: Sequence[Mapping[str, Any]],
    scope: AuthorityScope,
    checks: list[tuple[str, str]],
) -> tuple[AuthorityStatus, str, tuple[tuple[str, str], ...]]:
    from .gates import (
        AlternativeExplanationsStatus,
        ChallengeCategory,
        ChallengeSeverity,
        ChallengeStatus,
        ChallengerExecutionStatus,
        ChallengerExecutorKind,
        SemanticChallengeAuditStatus,
        _load_challenge_finding,
        _load_challenger_attack_execution_receipt,
        _load_challenger_category_review,
        require_alternative_explanations_authority,
        require_alternative_falsification_projection,
    )

    if any(
        record.logical_type not in {
            "semantic_challenge_audit_authority", "challenger_category_review",
            "alternative_explanations_scientific_authority",
        }
        for record in records
    ):
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_SOURCE_MISMATCH", tuple(checks)
    try:
        audits = tuple(
            _replay_semantic_audit_source(
                registry, ledger, run_id, record, payload,
                expected_category=(
                    ChallengeCategory.OVERCLAIMING if check is RCheck.R6 else None
                ),
            )
            for record, payload in zip(records, payloads, strict=True)
            if record.logical_type == "semantic_challenge_audit_authority"
        )
        reviews = tuple(
            _load_challenger_category_review(registry, record.sha256, ledger=ledger)
            for record in records
            if record.logical_type == "challenger_category_review"
        )
    except Exception:
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_OWNER_REPLAY_FAILED", tuple(checks)
    if not audits:
        return AuthorityStatus.UNTESTED, "CHALLENGER_COVERAGE_INCOMPLETE", tuple(checks)
    alternative_records = tuple(
        record for record in records
        if record.logical_type == "alternative_explanations_scientific_authority"
    )
    categories = (
        *(value.category for value in (*audits, *reviews)),
        *(ChallengeCategory.ALTERNATIVE_EXPLANATION for _ in alternative_records),
    )
    if len(set(categories)) != len(categories):
        return AuthorityStatus.FAIL, "CHALLENGER_CATEGORY_AMBIGUOUS", tuple(checks)
    anchor = audits[0]
    if any(
        value.assessment_id != anchor.assessment_id
        or value.research_state_snapshot_artifact_hash
        != anchor.research_state_snapshot_artifact_hash
        or value.research_state_snapshot_artifact_record_hash
        != anchor.research_state_snapshot_artifact_record_hash
        or value.claim_graph_artifact_hash != anchor.claim_graph_artifact_hash
        or value.claim_graph_artifact_record_hash
        != anchor.claim_graph_artifact_record_hash
        or value.central_claim_ids != anchor.central_claim_ids
        or value.result_artifact_hashes != anchor.result_artifact_hashes
        or value.result_artifact_record_hashes != anchor.result_artifact_record_hashes
        for value in audits
    ) or any(
        value.claim_graph_artifact_hash != anchor.claim_graph_artifact_hash
        or tuple(sorted(value.target_claim_ids)) != anchor.central_claim_ids
        for value in reviews
    ):
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_SUBJECT_MISMATCH", tuple(checks)
    if check is RCheck.R6 and (
        len(audits) != 1 or reviews or alternative_records
        or anchor.category is not ChallengeCategory.OVERCLAIMING
    ):
        return AuthorityStatus.FAIL, "OVERCLAIMING_AUDIT_SOURCE_MISMATCH", tuple(checks)
    deterministic_categories = {
        ChallengeCategory.ALTERNATIVE_EXPLANATION,
        ChallengeCategory.EXTERNAL_VALIDITY,
    }
    if any(value.category not in deterministic_categories for value in reviews):
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_LEGACY_SEMANTIC_SOURCE", tuple(checks)
    failed = any(value.status is SemanticChallengeAuditStatus.FAIL for value in audits)
    incomplete = any(
        value.status is not SemanticChallengeAuditStatus.PASS for value in audits
    )
    missing_alternative_authority = False
    missing_external_validity_authority = False
    external_adequacy_untested = False
    try:
        for record in alternative_records:
            alternative = require_alternative_explanations_authority(
                registry,
                ledger,
                authority_artifact_hash=record.sha256,
                expected_assessment_id=anchor.assessment_id,
                expected_run_id=run_id,
                expected_claim_graph_artifact_hash=anchor.claim_graph_artifact_hash,
                expected_central_claim_ids=anchor.central_claim_ids,
            )
            if (
                alternative.assessment_id != anchor.assessment_id
                or alternative.run_id != run_id
                or alternative.claim_graph_artifact_hash != anchor.claim_graph_artifact_hash
                or tuple(item.claim_id for item in alternative.central_claims)
                != anchor.central_claim_ids
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_SUBJECT_MISMATCH", tuple(checks)
            projection = require_alternative_falsification_projection(
                registry,
                ledger,
                projection_artifact_hash=alternative.projection_artifact_hash,
                expected_assessment_id=anchor.assessment_id,
                expected_run_id=run_id,
                expected_plan_artifact_hash=alternative.plan_artifact_hash,
            )
            if (
                projection.plan_artifact_hash != alternative.plan_artifact_hash
                or projection.plan_artifact_record_hash != alternative.plan_artifact_record_hash
                or registry.get_metadata(alternative.projection_artifact_hash).record_hash
                != alternative.projection_artifact_record_hash
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_SUBJECT_MISMATCH", tuple(checks)
            # The prospective alternative plan owns which attempts are required;
            # its resolver proves complete coverage of that plan. Every Result
            # and StatisticalTest it actually uses must belong, with the exact
            # metadata identity, to the semantic audits' one frozen whole-state
            # projection. Unrelated results in that snapshot need not become
            # alternative-falsification attempts merely to equalize the sets.
            anchored_results = dict(zip(
                anchor.result_artifact_hashes,
                anchor.result_artifact_record_hashes,
                strict=True,
            ))
            if not projection.attempt_results or any(
                anchored_results.get(digest) != record_hash
                for attempt in projection.attempt_results
                for digest, record_hash in (
                    (attempt.result_artifact_hash, attempt.result_artifact_record_hash),
                    (attempt.statistical_test_artifact_hash, attempt.statistical_test_artifact_record_hash),
                )
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_SUBJECT_MISMATCH", tuple(checks)
            failed |= alternative.status is AlternativeExplanationsStatus.SURVIVING_EXPLANATION
            incomplete |= alternative.status is not AlternativeExplanationsStatus.EXHAUSTIVELY_FALSIFIED
            checks.append(("alternative_completeness_owner_replay", alternative.status.value))
        for review in reviews:
            # Generic deterministic EXECUTED is not semantic completeness.
            # Alternative completeness has the aggregate owner above. The
            # The historical external procedure is fixture-only. The separate
            # scientific procedure owns a complete scope inventory, not
            # external adequacy or a scientific PASS.
            missing_alternative_authority |= review.category is ChallengeCategory.ALTERNATIVE_EXPLANATION
            if review.execution_status is not ChallengerExecutionStatus.EXECUTED:
                missing_external_validity_authority |= review.category is ChallengeCategory.EXTERNAL_VALIDITY
                incomplete = True
                continue
            execution = _load_challenger_attack_execution_receipt(
                registry, review.execution_receipt_hash, ledger=ledger
            )
            if (
                review.deterministic is not True
                or execution.executor_kind is not ChallengerExecutorKind.DETERMINISTIC
                or execution.run_id != run_id
                or execution.category is not review.category
                or execution.claim_graph_artifact_hash != anchor.claim_graph_artifact_hash
                or tuple(sorted(execution.target_claim_ids)) != anchor.central_claim_ids
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_DETERMINISTIC_SOURCE_MISMATCH", tuple(checks)
            if review.category is ChallengeCategory.EXTERNAL_VALIDITY:
                from .scientific_external_validity_gate import (
                    is_scientific_external_validity_execution,
                    require_scientific_external_validity_audit_join,
                    require_scientific_external_validity_execution_record,
                )
                if is_scientific_external_validity_execution(execution):
                    boundary = require_scientific_external_validity_execution_record(
                        registry, ledger, execution,
                        registry.get_metadata(review.execution_receipt_hash),
                    )
                    require_scientific_external_validity_audit_join(boundary, anchor)
                    checks.append(("external_validity_scope_inventory", "PASS"))
                    external_adequacy_untested = True
                else:
                    missing_external_validity_authority = True
            for digest in review.finding_artifact_hashes:
                finding = _load_challenge_finding(registry, digest, ledger=ledger)
                if finding.status is ChallengeStatus.UNRESOLVED:
                    failed |= finding.severity is ChallengeSeverity.BLOCKING
                    incomplete |= finding.severity is ChallengeSeverity.MAJOR
    except Exception:
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_OWNER_REPLAY_FAILED", tuple(checks)
    checks.append(("complete_challenger_audit_owner_replay", "PASS"))
    if failed:
        return AuthorityStatus.FAIL, "CHALLENGER_AUDIT_FAILED", tuple(checks)
    required_categories = (
        set(ChallengeCategory) if check is RCheck.R5
        else {ChallengeCategory.OVERCLAIMING}
    )
    if set(categories) != required_categories:
        return AuthorityStatus.UNTESTED, "CHALLENGER_COVERAGE_INCOMPLETE", tuple(checks)
    if missing_alternative_authority:
        return AuthorityStatus.UNTESTED, "ALTERNATIVE_COMPLETENESS_AUTHORITY_UNAVAILABLE", tuple(checks)
    if missing_external_validity_authority:
        return AuthorityStatus.UNTESTED, "EXTERNAL_VALIDITY_SCIENTIFIC_CLOSURE_UNAVAILABLE", tuple(checks)
    if external_adequacy_untested:
        return AuthorityStatus.UNTESTED, "EXTERNAL_VALIDITY_SCIENTIFIC_ADEQUACY_UNTESTED", tuple(checks)
    if incomplete or scope is not AuthorityScope.SCIENTIFIC:
        return AuthorityStatus.UNTESTED, "CHALLENGER_AUDIT_INCOMPLETE", tuple(checks)
    return AuthorityStatus.PASS, "COMPLETE_CHALLENGER_AUDIT_REPLAYED", tuple(checks)


def _derive_native_numeric_ablation_adequacy(
    clean_outcomes: tuple[Any, ...], audit_status: Any, scope: AuthorityScope,
) -> tuple[AuthorityStatus, str]:
    """Preserve adverse/incomplete outcomes; coverage never grants adequacy."""

    status, reason = _derive_reproduction_cohort_status(clean_outcomes, audit_status, scope)
    if status is AuthorityStatus.PASS:
        return AuthorityStatus.UNTESTED, "NATIVE_ABLATION_SCIENTIFIC_ADEQUACY_UNTESTED"
    return status, reason


def _derive_native_numeric_ablation_status(
    registry: Any, ledger: Any, run_id: str, records: Sequence[Any],
    payloads: Sequence[Mapping[str, Any]], scope: AuthorityScope,
    checks: list[tuple[str, str]],
) -> tuple[AuthorityStatus, str, tuple[tuple[str, str], ...]]:
    """R5/E2 is downstream of one full plural audit and its identical cohort.

    Even an adverse stored label must pass through the complete source owners.
    This path is not consumed from Soundness and takes no private round peer.
    """

    from .gates import (
        SemanticReproductionCohortAuditAuthority, _SemanticReproductionCohortAuditReplay,
        _require_semantic_reproduction_cohort_audit_source,
    )
    from .scientific_design import _locked_checked_result_authority_snapshot
    from .scientific_numeric_ablation_cohort import require_scientific_numeric_ablation_cohort
    from .scientific_numeric_ablation_soundness import (
        _native_numeric_ablation_declared_in_owned_state, _require_numeric_ablation_audit_cohort_join,
    )

    try:
        if (len(records) != 1 or len(payloads) != 1
                or records[0].logical_type != "semantic_challenge_audit_authority"
                or records[0].schema_version != "2.0"
                or payloads[0].get("schema_version") != "semantic-challenge-audit-authority/v2"):
            raise ValueError("native R5/E2 requires one exact plural reproduction audit")
        before = _locked_checked_result_authority_snapshot(registry, ledger)
        stated = SemanticReproductionCohortAuditAuthority.from_dict(payloads[0])
        replay = _require_semantic_reproduction_cohort_audit_source(
            registry, ledger, authority_artifact_hash=records[0].sha256,
            expected_run_id=run_id, expected_assessment_id=stated.assessment_id,
            expected_research_state_snapshot_artifact_hash=stated.research_state_snapshot_artifact_hash,
            expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
            expected_central_claim_ids=stated.central_claim_ids,
            expected_reproduction_package_bindings=stated.reproduction_package_bindings,
        )
        if (type(replay) is not _SemanticReproductionCohortAuditReplay
                or replay.authority != stated or replay.record != records[0]
                or replay.entry_snapshot != before):
            raise ValueError("native applicability requires the exact full plural audit output")
        audit, packages = replay.authority, replay.canonical_scope.package_authorities
        if not _native_numeric_ablation_declared_in_owned_state(registry, replay.canonical_scope.state):
            if _locked_checked_result_authority_snapshot(registry, ledger) != before:
                raise ValueError("non-native applicability sources changed during replay")
            # The pre-D066 plural family also supports non-native Results.
            # Preserve its old E2 result exactly, never relabel unsupported
            # numerical coverage as a failed scientific experiment.
            if _explicit_failure(RCheck.R5, payloads):
                return AuthorityStatus.FAIL, "SOURCE_AUTHORITY_FAILED", (*checks, ("source_failure", "TRUE"))
            return AuthorityStatus.UNTESTED, "REQUIRED_SEMANTIC_AUTHORITY_UNAVAILABLE", tuple(checks)
        cohort = require_scientific_numeric_ablation_cohort(
            registry, ledger, expected_ledger_run_id=run_id,
            snapshot_artifact_sha256=audit.research_state_snapshot_artifact_hash,
        )
        _require_numeric_ablation_audit_cohort_join(cohort, audit, run_id=run_id)
        clean_outcomes = _reproduction_cohort_clean_outcomes(run_id, audit, packages)
        status, reason = _derive_native_numeric_ablation_adequacy(clean_outcomes, audit.status, scope)
        if (cohort.entry_snapshot != before
                or _locked_checked_result_authority_snapshot(registry, ledger) != before):
            raise ValueError("native R5/E2 sources changed during complete replay")
    except Exception:
        return AuthorityStatus.FAIL, "NATIVE_ABLATION_COHORT_OWNER_REPLAY_FAILED", tuple(checks)
    checks.extend((
        ("complete_reproduction_audit_owner_replay", "PASS"),
        ("complete_native_numeric_ablation_cohort_replay", "PASS"),
        ("exact_snapshot_and_result_test_cohort_join", "PASS"),
        ("native_ablation_scientific_adequacy", "UNTESTED"),
    ))
    return status, reason, tuple(checks)


def _derive_status(
    registry: Any,
    ledger: Any,
    run_id: str,
    check: RCheck,
    evaluator_class: EvaluatorClass,
    records: Sequence[Any],
    payloads: Sequence[Mapping[str, Any]],
    scope: AuthorityScope,
    *,
    _replayed_semantic_peer: Any = None,
) -> tuple[AuthorityStatus, str, tuple[tuple[str, str], ...]]:
    types = {record.logical_type for record in records}
    type_counts = Counter(record.logical_type for record in records)
    checks: list[tuple[str, str]] = [("source_scope", scope.value)]
    if not records:
        return AuthorityStatus.UNTESTED, "NO_RESOLVABLE_SOURCE_AUTHORITY", tuple(checks)
    if (check is RCheck.R5 and evaluator_class is EvaluatorClass.E2
            and len(records) == 1 and len(payloads) == 1
            and records[0].logical_type == "semantic_challenge_audit_authority"
            and (records[0].schema_version == "2.0"
                 or payloads[0].get("schema_version") == "semantic-challenge-audit-authority/v2")):
        return _derive_native_numeric_ablation_status(
            registry, ledger, run_id, records, payloads, scope, checks,
        )
    if _explicit_failure(check, payloads):
        checks.append(("source_failure", "TRUE"))
        return AuthorityStatus.FAIL, "SOURCE_AUTHORITY_FAILED", tuple(checks)
    repeatable_types = {"ablation_validation", "challenger_category_review"}
    if check is RCheck.R5:
        repeatable_types.add("semantic_challenge_audit_authority")
    if any(
        count != 1 and logical_type not in repeatable_types
        for logical_type, count in type_counts.items()
    ):
        checks.append(("source_cardinality", "AMBIGUOUS"))
        return AuthorityStatus.FAIL, "SOURCE_AUTHORITY_AMBIGUOUS", tuple(checks)

    if check is RCheck.R0 and evaluator_class is EvaluatorClass.E0:
        if types == {"audit_report"}:
            # The PASS label is ignored. Registry closure and the exact ledger
            # admission above are recomputed directly.
            checks.extend((("registry_closure", "PASS"), ("ledger_chain", "PASS")))
            return AuthorityStatus.PASS, "SYSTEM_INTEGRITY_RECOMPUTED", tuple(checks)
        if types == {
            "canonical_research_state_final_snapshot",
            "paper_verification",
        }:
            snapshot = next(
                record for record in records
                if record.logical_type == "canonical_research_state_final_snapshot"
            )
            paper = next(
                record for record in records
                if record.logical_type == "paper_verification"
            )
            try:
                from .paper_pipeline import require_paper_verification
                from .research_state import resolve_research_state_authority

                resolve_research_state_authority(
                    registry,
                    ledger,
                    run_id=run_id,
                    snapshot_artifact_hash=snapshot.sha256,
                )
                verification = require_paper_verification(
                    registry,
                    ledger,
                    run_id=run_id,
                    verification_artifact_hash=paper.sha256,
                )
                paper_bundle = _paper_authority_bundle(
                    registry,
                    paper,
                    run_id,
                )
            except Exception:
                return AuthorityStatus.FAIL, "CANONICAL_STATE_REPLAY_FAILED", tuple(checks)
            if (
                verification.passed is not True
                or paper_bundle.research_state_hash != snapshot.sha256
            ):
                return AuthorityStatus.FAIL, "PAPER_AUTHORITY_FAILED", tuple(checks)
            checks.append(("canonical_state_replay", "PASS"))
            checks.append(("paper_authority_replay", "PASS"))
            return AuthorityStatus.PASS, "CANONICAL_STATE_REPLAYED", tuple(checks)
        return AuthorityStatus.FAIL, "R0_SOURCE_SET_AMBIGUOUS", tuple(checks)

    if check is RCheck.R1:
        vnext = {
            "research_brief", "problem_investigation_state",
            "hypothesis_register", "evaluation_contract",
        }
        if types == vnext:
            parents_valid = (
                _cross_parent(records, "research_brief", {"problem_investigation_state"})
                and _cross_parent(records, "hypothesis_register", {"research_brief"})
                and _cross_parent(
                    records,
                    "evaluation_contract",
                    {"research_brief", "hypothesis_register"},
                )
            )
            checks.append(("design_parent_graph", "PASS" if parents_valid else "FAIL"))
            if not parents_valid:
                return AuthorityStatus.FAIL, "DESIGN_PARENT_GRAPH_INVALID", tuple(checks)
            if evaluator_class is EvaluatorClass.E0 and scope is AuthorityScope.SYSTEM_FIXTURE:
                return AuthorityStatus.PASS, "FIXTURE_DESIGN_STRUCTURE_REPLAYED", tuple(checks)
            return AuthorityStatus.UNTESTED, "SEMANTIC_RESEARCH_GATE_UNAVAILABLE", tuple(checks)
        if types == {"frozen_protocol"}:
            checks.append(("legacy_protocol_label", "NONAUTHORITATIVE"))
            return AuthorityStatus.UNTESTED, "LEGACY_E2_LABEL_IS_NONAUTHORITATIVE", tuple(checks)

    if check is RCheck.R2:
        required = {"evaluation_contract", "aggregate_experiment_result"}
        if frozenset(types) in {
            frozenset(required),
            frozenset(
                required
                | {"autonomous_implementation.semantic_validation"}
            ),
        }:
            checks.append(("contract_aggregate_binding", "PASS"))
            if (
                evaluator_class is EvaluatorClass.E2
                and "autonomous_implementation.semantic_validation" in types
                and scope is AuthorityScope.SYSTEM_FIXTURE
            ):
                semantic = next(
                    value for record, value in zip(records, payloads, strict=True)
                    if record.logical_type == "autonomous_implementation.semantic_validation"
                )
                if (
                    semantic.get("status") == "PASS"
                    and semantic.get("scientific_evidence") is False
                    and semantic.get("schema_version")
                    == "AUTONOMOUS_IMPLEMENTATION_SEMANTIC_VALIDATION_V1"
                ):
                    checks.append(("fixture_semantic_label", "NONAUTHORITATIVE"))
            return AuthorityStatus.UNTESTED, "SCIENTIFIC_IMPLEMENTATION_AUTHORITY_UNAVAILABLE", tuple(checks)
        if types == {"machine_results"}:
            checks.append(("legacy_machine_result_label", "NONAUTHORITATIVE"))
            return AuthorityStatus.UNTESTED, "LEGACY_RESULT_LABEL_IS_NONAUTHORITATIVE", tuple(checks)

    if check is RCheck.R3:
        if evaluator_class is EvaluatorClass.E3:
            timelines = tuple(
                (record, value)
                for record, value in zip(records, payloads, strict=True)
                if record.logical_type == "confirmatory_timeline_receipt"
            )
            if len(timelines) == 1 and types == {"confirmatory_timeline_receipt"}:
                timeline_record, timeline_value = timelines[0]
                try:
                    from .scientific_design import (
                        ConfirmatoryTimelineReceipt,
                        require_confirmatory_timeline_receipt,
                    )

                    timeline = ConfirmatoryTimelineReceipt.from_dict(timeline_value)
                    require_confirmatory_timeline_receipt(
                        registry,
                        ledger,
                        receipt_artifact_sha256=timeline_record.sha256,
                        run_id=run_id,
                        study_id=timeline.study_id,
                        study_version=timeline.study_version,
                        protocol_artifact_sha256=(
                            timeline.protocol_artifact_sha256
                        ),
                        fresh_custody_receipt_sha256=(
                            timeline.fresh_custody_receipt_sha256
                        ),
                        custody_record_sha256=timeline.custody_record_sha256,
                        result_artifact_sha256=timeline.result_artifact_sha256,
                    )
                except Exception:
                    return (
                        AuthorityStatus.FAIL,
                        "CONFIRMATORY_TIMELINE_REPLAY_FAILED",
                        tuple(checks),
                    )
                checks.append(("confirmatory_timeline_replay", "PASS"))
                if scope is AuthorityScope.SYSTEM_FIXTURE:
                    checks.append(
                        ("confirmatory_timeline_scope", "NONAUTHORITATIVE")
                    )
                    return (
                        AuthorityStatus.UNTESTED,
                        "SCIENTIFIC_CONFIRMATORY_AUTHORITY_UNAVAILABLE",
                        tuple(checks),
                    )
                return (
                    AuthorityStatus.PASS,
                    "CONFIRMATORY_TIMELINE_REPLAYED",
                    tuple(checks),
                )
            if timelines:
                return (
                    AuthorityStatus.FAIL,
                    "CONFIRMATORY_TIMELINE_AMBIGUOUS",
                    tuple(checks),
                )
        domain_records = tuple(
            record for record in records if record.logical_type in _DOMAIN_VALIDITY_SOURCE_TYPES
        )
        if domain_records:
            domain = domain_records[0]
            value = payloads[records.index(domain)]
            try:
                from .domains import DomainKind, DomainValidityStatus, resolve_domain_validity

                resolved = resolve_domain_validity(
                    registry,
                    domain.sha256,
                    expected_run_id=str(value["run_id"]),
                    expected_domain=DomainKind(str(value["domain"])),
                    expected_object_id=str(value["object_id"]),
                    expected_task_id=str(value["task_id"]),
                    ledger=ledger,
                )
            except Exception:
                return AuthorityStatus.FAIL, "DOMAIN_VALIDITY_REPLAY_FAILED", tuple(checks)
            if resolved.run_id != run_id:
                return AuthorityStatus.FAIL, "DOMAIN_VALIDITY_RUN_MISMATCH", tuple(checks)
            if resolved.outcome.status is not DomainValidityStatus.PASS:
                return AuthorityStatus.FAIL, "DOMAIN_VALIDITY_FAILED", tuple(checks)
            checks.append(("domain_adapter_replay", "PASS"))
            if evaluator_class is EvaluatorClass.E0 and len(records) == 1:
                return AuthorityStatus.PASS, "DOMAIN_VALIDITY_REPLAYED", tuple(checks)
            return AuthorityStatus.UNTESTED, "CONFIRMATORY_CUSTODY_AUTHORITY_UNAVAILABLE", tuple(checks)
        if types == {"custody_record", "machine_results"}:
            checks.append(("legacy_custody_labels", "NONAUTHORITATIVE"))
            return AuthorityStatus.UNTESTED, "LEGACY_CUSTODY_LABELS_ARE_NONAUTHORITATIVE", tuple(checks)

    if check is RCheck.R4:
        if types == {"aggregate_experiment_result", "statistical_analysis"}:
            by_type = {
                record.logical_type: (record, value)
                for record, value in zip(records, payloads, strict=True)
            }
            aggregate_record, aggregate = by_type["aggregate_experiment_result"]
            statistics_record, statistics = by_type["statistical_analysis"]
            try:
                expected_effect = float(aggregate["candidate_accuracy"]) - float(aggregate["baseline_accuracy"])
                observed_effect = float(statistics["effect"])
            except (KeyError, TypeError, ValueError):
                return AuthorityStatus.FAIL, "STATISTICAL_PAYLOAD_MALFORMED", tuple(checks)
            replayed = (
                math.isfinite(expected_effect)
                and math.isfinite(observed_effect)
                and math.isclose(expected_effect, observed_effect, rel_tol=0.0, abs_tol=1e-12)
                and statistics_record.parent_artifacts == (aggregate_record.sha256,)
            )
            checks.append(("effect_recomputation", "PASS" if replayed else "FAIL"))
            if not replayed:
                return AuthorityStatus.FAIL, "STATISTICAL_RECOMPUTATION_FAILED", tuple(checks)
            checks.append(("raw_outcome_replay", "UNAVAILABLE"))
            return AuthorityStatus.UNTESTED, "RAW_STATISTICAL_REPLAY_UNAVAILABLE", tuple(checks)
        if types == {"machine_results"}:
            return AuthorityStatus.UNTESTED, "LEGACY_RESULT_LABEL_IS_NONAUTHORITATIVE", tuple(checks)

    if check is RCheck.R5 and evaluator_class is EvaluatorClass.E2:
        if types == {"ablation_validation"}:
            ablations = tuple(
                value for record, value in zip(records, payloads, strict=True)
                if record.logical_type == "ablation_validation"
            )
            if any(value.get("validation") != "PASS" for value in ablations):
                return AuthorityStatus.FAIL, "ABLATION_VALIDATION_FAILED", tuple(checks)
            checks.append(("ablation_labels", "NONAUTHORITATIVE"))
            return AuthorityStatus.UNTESTED, "ABLATION_REPLAY_AUTHORITY_UNAVAILABLE", tuple(checks)
        if types == {"workflow_benchmark"}:
            return AuthorityStatus.UNTESTED, "LEGACY_E2_LABEL_IS_NONAUTHORITATIVE", tuple(checks)

    if check in {RCheck.R5, RCheck.R6} and evaluator_class is EvaluatorClass.E3:
        if "semantic_challenge_audit_authority" in types:
            return _derive_complete_challenger_status(
                registry, ledger, run_id, check, records, payloads, scope, checks
            )
        reviews = tuple(
            record for record in records
            if record.logical_type == "challenger_category_review"
        )
        if reviews and types == {"challenger_category_review"}:
            try:
                from .gates import (
                    ChallengeCategory,
                    ChallengeSeverity,
                    ChallengeStatus,
                    ChallengerExecutorKind,
                    ChallengerExecutionStatus,
                    _load_challenge_finding,
                    _load_challenger_attack_execution_receipt,
                    _load_challenger_category_review,
                )

                loaded = tuple(
                    _load_challenger_category_review(
                        registry, record.sha256, ledger=ledger
                    )
                    for record in reviews
                )
            except Exception:
                return AuthorityStatus.FAIL, "CHALLENGER_REPLAY_FAILED", tuple(checks)
            relevant = (
                loaded
                if check is RCheck.R5
                else tuple(
                    value for value in loaded
                    if value.category is ChallengeCategory.OVERCLAIMING
                )
            )
            if len({value.category for value in loaded}) != len(loaded):
                return AuthorityStatus.FAIL, "CHALLENGER_CATEGORY_AMBIGUOUS", tuple(checks)
            if check is RCheck.R5 and {value.category for value in relevant} != set(ChallengeCategory):
                return AuthorityStatus.UNTESTED, "CHALLENGER_COVERAGE_INCOMPLETE", tuple(checks)
            if not relevant or any(
                value.execution_status is not ChallengerExecutionStatus.EXECUTED
                for value in relevant
            ):
                return AuthorityStatus.UNTESTED, "CHALLENGER_EXECUTION_UNTESTED", tuple(checks)
            try:
                executions = tuple(
                    _load_challenger_attack_execution_receipt(
                        registry,
                        value.execution_receipt_hash,
                        ledger=ledger,
                    )
                    for value in relevant
                    if value.execution_receipt_hash is not None
                )
            except Exception:
                return AuthorityStatus.FAIL, "CHALLENGER_REPLAY_FAILED", tuple(checks)
            if (
                len(executions) != len(relevant)
                or any(value.run_id != run_id for value in executions)
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_RUN_MISMATCH", tuple(checks)
            try:
                findings = tuple(
                    _load_challenge_finding(registry, digest, ledger=ledger)
                    for review in relevant
                    for digest in review.finding_artifact_hashes
                )
            except Exception:
                return AuthorityStatus.FAIL, "CHALLENGER_REPLAY_FAILED", tuple(checks)
            if any(
                value.status is ChallengeStatus.UNRESOLVED
                and value.severity is ChallengeSeverity.BLOCKING
                for value in findings
            ):
                return AuthorityStatus.FAIL, "CHALLENGER_BLOCKING_FINDING", tuple(checks)
            if any(
                value.status is ChallengeStatus.UNRESOLVED
                and value.severity is ChallengeSeverity.MAJOR
                for value in findings
            ):
                return AuthorityStatus.UNTESTED, "CHALLENGER_MAJOR_FINDING_UNRESOLVED", tuple(checks)
            checks.append(("challenger_execution_replay", "PASS"))
            if any(
                value.executor_kind is ChallengerExecutorKind.SEMANTIC
                for value in executions
            ):
                # The pinned generic semantic receipt attests EXECUTED only.
                # It does not prove the caller's finding set is exhaustive or
                # that no adverse review was omitted from this category.
                return (
                    AuthorityStatus.UNTESTED,
                    "CHALLENGER_FINDING_CLOSURE_AUTHORITY_UNAVAILABLE",
                    tuple(checks),
                )
            # No legacy review-only combination proves the complete gate.
            # Today the closed category map makes this all-deterministic
            # fallback unreachable for full R5 or OVERCLAIMING, but a future
            # procedure must not turn completion into audit completeness.
            return (
                AuthorityStatus.UNTESTED,
                "CHALLENGER_FINDING_CLOSURE_AUTHORITY_UNAVAILABLE",
                tuple(checks),
            )
        return AuthorityStatus.UNTESTED, "CHALLENGER_EXECUTION_UNTESTED", tuple(checks)

    if check is RCheck.R6 and evaluator_class is EvaluatorClass.E2:
        if types == {"claim_evidence_graph", "paper_verification"}:
            try:
                from .gates import _resolve_claim_graph_authority
                from .paper_pipeline import require_paper_verification

                graph = next(record for record in records if record.logical_type == "claim_evidence_graph")
                paper = next(record for record in records if record.logical_type == "paper_verification")
                _resolve_claim_graph_authority(registry, graph.sha256)
                verification = require_paper_verification(
                    registry,
                    ledger,
                    run_id=run_id,
                    verification_artifact_hash=paper.sha256,
                )
                paper_bundle = _paper_authority_bundle(
                    registry,
                    paper,
                    run_id,
                )
            except Exception:
                return AuthorityStatus.FAIL, "CLAIM_GRAPH_REPLAY_FAILED", tuple(checks)
            if (
                verification.passed is not True
                or paper_bundle.claim_graph_hash != graph.sha256
            ):
                return AuthorityStatus.FAIL, "PAPER_AUTHORITY_FAILED", tuple(checks)
            checks.append(("claim_graph_replay", "PASS"))
            checks.append(("paper_authority_replay", "PASS"))
            return AuthorityStatus.PASS, "CLAIM_AND_PAPER_AUTHORITY_REPLAYED", tuple(checks)
        if types == {"claim_graph"}:
            return AuthorityStatus.UNTESTED, "LEGACY_E2_LABEL_IS_NONAUTHORITATIVE", tuple(checks)

    if check is RCheck.R7 and evaluator_class is EvaluatorClass.E3:
        if len(records) == 1 and types == {"semantic_challenge_audit_authority"}:
            try:
                from .gates import (
                    ChallengeCategory,
                    SemanticChallengeAuditStatus,
                    SemanticReproductionCohortAuditAuthority,
                )
                from .research_state import (
                    ReproducibilityPackage,
                    require_scientific_reproducibility_package,
                )

                if records[0].schema_version == "2.0":
                    audit, cohort_packages = _replay_semantic_audit_source_with_packages(
                        registry, ledger, run_id, records[0], payloads[0],
                        expected_category=ChallengeCategory.REPRODUCTION,
                        _replayed_peer=_replayed_semantic_peer,
                    )
                else:
                    audit = _replay_semantic_audit_source(
                        registry, ledger, run_id, records[0], payloads[0],
                        expected_category=ChallengeCategory.REPRODUCTION,
                        _replayed_peer=_replayed_semantic_peer,
                    )
                    cohort_packages = None
                cohort = type(audit) is SemanticReproductionCohortAuditAuthority
                if cohort:
                    if cohort_packages is None:
                        if _replayed_semantic_peer is None:
                            raise ValueError("reproduction cohort lacks its full owner outputs")
                        cohort_packages = _replay_reproduction_cohort_packages(
                            registry, ledger, run_id, audit,
                        )
                    clean_outcomes = _reproduction_cohort_clean_outcomes(
                        run_id, audit, cohort_packages,
                    )
                else:
                    package_hash = audit.reproducibility_package_artifact_hash
                    if package_hash is None:
                        raise ValueError("reproduction audit omits its canonical package")
                    package_record = registry.get_metadata(package_hash)
                    package_value = _canonical_json_artifact(registry, package_record)
                    stated_package = ReproducibilityPackage.from_dict(package_value)
                    if not isinstance(stated_package, ReproducibilityPackage):
                        raise ValueError("reproduction audit names another canonical kind")
                    package = require_scientific_reproducibility_package(
                        registry,
                        ledger,
                        package_state_artifact_sha256=package_hash,
                        expected_ledger_run_id=run_id,
                        expected_package_id=stated_package.object_id,
                    )
                    if (
                        package.ledger_run_id != run_id
                        or package.package_binding.artifact_sha256 != package_hash
                        or package.package_binding.artifact_record_hash
                        != package_record.record_hash
                        or package.original_result_binding.artifact_sha256
                        not in audit.result_artifact_hashes
                        or audit.result_artifact_record_hashes[
                            audit.result_artifact_hashes.index(
                                package.original_result_binding.artifact_sha256
                            )
                        ] != package.original_result_binding.artifact_record_hash
                    ):
                        raise ValueError("reproduction audit and package sources disagree")
            except Exception:
                return (
                    AuthorityStatus.FAIL,
                    "R7_CLEAN_PACKAGE_AUDIT_OWNER_REPLAY_FAILED",
                    tuple(checks),
                )
            checks.extend((
                ("scientific_clean_rerun_owner_replay", "PASS"),
                ("canonical_reproducibility_package_owner_replay", "PASS"),
                ("complete_reproduction_audit_owner_replay", "PASS"),
            ))
            if cohort:
                checks.append(("complete_reproduction_result_package_coverage", "PASS"))
                status, reason = _derive_reproduction_cohort_status(
                    clean_outcomes, audit.status, scope,
                )
                return status, reason, tuple(checks)
            if not package.clean_rerun_authority.reproduction_passed:
                return AuthorityStatus.FAIL, "SCIENTIFIC_CLEAN_RERUN_FAILED", tuple(checks)
            if audit.status is SemanticChallengeAuditStatus.FAIL:
                return AuthorityStatus.FAIL, "REPRODUCTION_AUDIT_FAILED", tuple(checks)
            if (
                audit.status is not SemanticChallengeAuditStatus.PASS
                or scope is not AuthorityScope.SCIENTIFIC
            ):
                return AuthorityStatus.UNTESTED, "REPRODUCTION_AUDIT_INCOMPLETE", tuple(checks)
            return (
                AuthorityStatus.PASS,
                "SCIENTIFIC_CLEAN_PACKAGE_AND_AUDIT_REPLAYED",
                tuple(checks),
            )
        if len(records) == 1 and types == {"scientific_clean_rerun_authority"}:
            try:
                from .reproduction import (
                    ScientificCleanRerunAuthority,
                    require_scientific_clean_rerun_authority,
                )

                # The DTO supplies selectors only; it does not confer scope,
                # independence, or a passing result without source-owner replay.
                stated = ScientificCleanRerunAuthority.from_mapping(payloads[0])
                verified = require_scientific_clean_rerun_authority(
                    registry,
                    ledger,
                    authority_artifact_sha256=records[0].sha256,
                    expected_ledger_run_id=run_id,
                    expected_original_execution_run_id=(
                        stated.original_execution_run_id
                    ),
                    expected_rerun_execution_run_id=stated.rerun_execution_run_id,
                )
            except Exception:
                return (
                    AuthorityStatus.FAIL,
                    "SCIENTIFIC_CLEAN_RERUN_AUTHORITY_REPLAY_FAILED",
                    tuple(checks),
                )
            checks.append(("scientific_clean_rerun_owner_replay", "PASS"))
            if not verified.reproduction_passed:
                return (
                    AuthorityStatus.FAIL,
                    "SCIENTIFIC_CLEAN_RERUN_FAILED",
                    tuple(checks),
                )
            checks.append(("scientific_clean_rerun_comparison", "PASS"))
            # Normative R7 additionally requires package audit and residual
            # risks. A genuine matching rerun is necessary but not sufficient
            # for that full release-audit claim.
            return (
                AuthorityStatus.UNTESTED,
                "R7_PACKAGE_AND_RESIDUAL_RISK_AUTHORITY_UNAVAILABLE",
                tuple(checks),
            )
        reproduction = (
            payloads[0]
            if len(records) == 1 and types == {"reproduction_report"}
            else None
        )
        if reproduction is not None:
            try:
                from .reproduction import (
                    ARCHITECTURE_CONTROL_REPLAY_STATUS,
                    verify_frozen_architecture_control_reproduction,
                    verify_frozen_reproduction,
                )

                architecture_control = (
                    reproduction.get("status") == ARCHITECTURE_CONTROL_REPLAY_STATUS
                )
                verifier = (
                    verify_frozen_architecture_control_reproduction
                    if architecture_control
                    else verify_frozen_reproduction
                )
                expected_status = (
                    ARCHITECTURE_CONTROL_REPLAY_STATUS
                    if architecture_control
                    else "PASS"
                )
                verified = verifier(
                    registry.policy.root,
                    run_id,
                    reproduction,
                )
            except Exception:
                return AuthorityStatus.FAIL, "FROZEN_REPRODUCTION_REPLAY_FAILED", tuple(checks)
            if verified.status != expected_status:
                return AuthorityStatus.FAIL, "FROZEN_REPRODUCTION_FAILED", tuple(checks)
            checks.append(("frozen_reproduction_replay", "PASS"))
            # Both legacy adapters replay the built-in local synthetic fixture.
            # Byte-for-byte replay is useful architecture evidence, but cannot
            # establish independent scientific reproduction or pass R7.
            return (
                AuthorityStatus.UNTESTED,
                (
                    "ARCHITECTURE_CONTROL_REPRODUCTION_NON_EVIDENTIARY"
                    if architecture_control
                    else "LEGACY_SYNTHETIC_REPRODUCTION_NON_EVIDENTIARY"
                ),
                tuple(checks),
            )

    return AuthorityStatus.UNTESTED, "REQUIRED_SEMANTIC_AUTHORITY_UNAVAILABLE", tuple(checks)


def _derive_r_check_authority_source(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    r_check: RCheck,
    evaluator_class: EvaluatorClass,
    source_artifact_sha256s: Iterable[str],
    _replayed_semantic_peer: Any = None,
) -> _RCheckAuthorityDerivation:
    if not isinstance(r_check, RCheck) or not isinstance(evaluator_class, EvaluatorClass):
        raise ValueError("R-check authority requires typed check and evaluator class")
    if evaluator_class not in REQUIRED_R_AUTHORITIES[r_check]:
        raise ValueError("evaluator class is not authoritative for this R check")
    values = tuple(islice(source_artifact_sha256s, MAX_R_CHECK_SOURCE_ARTIFACTS + 1))
    if (
        len(values) > MAX_R_CHECK_SOURCE_ARTIFACTS
        or len(set(values)) != len(values)
        or any(not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None for value in values)
    ):
        raise ValueError("R-check source hashes must be a bounded unique SHA-256 collection")
    if _replayed_semantic_peer is not None and (
        r_check is not RCheck.R7
        or evaluator_class is not EvaluatorClass.E3
        or values != (_replayed_semantic_peer.record.sha256,)
    ):
        raise ValueError("round replay is restricted to the exact R7 semantic source")
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    records: list[Any] = []
    payloads: list[Mapping[str, Any]] = []
    for digest in values:
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
        except Exception as exc:
            raise ValueError("R-check source artifact is absent or corrupt") from exc
        if (
            record.logical_type not in _ALLOWED_SOURCE_TYPES[r_check]
            and not (
                r_check is RCheck.R3
                and record.logical_type in _DOMAIN_VALIDITY_SOURCE_TYPES
            )
        ):
            raise ValueError("R-check source has the wrong logical type")
        role = _source_role(record.logical_type)
        role_matches = (
            record.creator_role in {Role.HYPOTHESIS_DESIGNER, Role.PROTOCOL_DESIGNER}
            if record.logical_type == "research_state.method"
            else role is not None and record.creator_role is role
        )
        if not role_matches:
            raise ValueError("R-check source has the wrong creator role")
        payload = _canonical_json_artifact(registry, record)
        records.append(record)
        payloads.append(payload)
    cohort_route = any(
        record.logical_type in _COHORT_ONLY_SOURCE_TYPES
        or (
            r_check in {RCheck.R2, RCheck.R4}
            and record.logical_type == "semantic_challenge_audit_authority"
        )
        for record in records
    )
    bindings: list[AuthoritySourceBinding] = []
    if not cohort_route:
        # Preserve historical binding selectors before semantic resolution.
        # New source families require the full owner's admissions below.
        for record, payload in zip(records, payloads, strict=True):
            if record.logical_type == "alternative_explanations_scientific_authority":
                binding = _alternative_source_binding(
                    registry, ledger, events, run_id, record, payload
                )
            elif record.logical_type in {
                "research_question_gate_assessment",
                "evaluation_contract_freeze_gate_receipt",
            }:
                binding = _research_design_source_binding(
                    registry, ledger, events, run_id, record, payload
                )
            else:
                binding = _event_binding(events, record)
            bindings.append(binding)
    by_digest = {record.sha256: binding for record, binding in zip(records, bindings)}
    ordered = sorted(
        zip(records, payloads, strict=True),
        key=lambda value: (value[0].logical_type, value[0].sha256),
    )
    records = [value[0] for value in ordered]
    payloads = [value[1] for value in ordered]
    if not cohort_route:
        bindings = [by_digest[record.sha256] for record in records]
    scope = _fixture_scope(records, payloads) if records else AuthorityScope.SYSTEM_FIXTURE
    scientific_resolution = None
    if cohort_route or (
        r_check is RCheck.R1
        and any(
            record.logical_type in {
                "research_question_gate_assessment",
                "evaluation_contract_freeze_gate_receipt",
            }
            for record in records
        )
    ) or (
        r_check is RCheck.R3
        and evaluator_class is EvaluatorClass.E0
        and any(
            record.logical_type == "domain_validity.generic_ml"
            and record.schema_version == "domain-validity-receipt/v3"
            for record in records
        )
    ):
        # The import is lazy because the source owners depend on the evaluator
        # vocabulary. Exact source multisets and all semantic decisions remain
        # owned by this non-persisting resolver, not by this routing predicate.
        from .scientific_r_checks import resolve_scientific_r_check_sources

        scientific_resolution = resolve_scientific_r_check_sources(
            registry,
            ledger,
            run_id=run_id,
            r_check=r_check,
            evaluator_class=evaluator_class,
            source_artifact_sha256s=tuple(record.sha256 for record in records),
        )
    if cohort_route:
        # The closed resolver's exact multiset and source profile own routing.
        # Unsupported or unqualified new sources cannot acquire a fallback
        # publication or diagnostic receipt from generic event references.
        bindings = list(_owned_scientific_source_bindings(
            events, records, scientific_resolution,
        ))
    if scientific_resolution is None:
        status, reason, checks = _derive_status(
            registry,
            ledger,
            run_id,
            r_check,
            evaluator_class,
            records,
            payloads,
            scope,
            _replayed_semantic_peer=_replayed_semantic_peer,
        )
    else:
        if (
            scientific_resolution.r_check is not r_check
            or scientific_resolution.evaluator_class is not evaluator_class
            or dict(scientific_resolution.subject_key).get("run_id") != run_id
        ):
            raise ValueError("scientific R-check resolver returned another subject")
        # Neither the closed payload classification nor a composed source owner
        # can upgrade evidence the other classifies as non-scientific.
        if scientific_resolution.scope is not AuthorityScope.SCIENTIFIC:
            scope = AuthorityScope.SYSTEM_FIXTURE
        status = scientific_resolution.status
        reason = scientific_resolution.reason_code
        checks = (("source_scope", scope.value), *scientific_resolution.checks)
    latest_index = max(
        (value.ledger_event_index for value in bindings),
        default=len(events) - 1,
    )
    prefix = events[latest_index].event_hash
    if prefix is None:
        raise ValueError("R-check ledger prefix hash is absent")
    actor = (
        Role.REPRODUCTION_VERIFIER
        if r_check is RCheck.R7 and evaluator_class is EvaluatorClass.E3
        else {
            EvaluatorClass.E0: Role.ORCHESTRATOR,
            EvaluatorClass.E2: Role.SCIENTIFIC_REVIEWER,
            EvaluatorClass.E3: Role.ADVERSARIAL_REVIEWER,
        }[evaluator_class]
    )
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("R-check sources changed during complete owner replay")
    return _RCheckAuthorityDerivation(
        authority=RCheckAuthority(
            run_id,
            r_check,
            evaluator_class,
            actor,
            status,
            scope,
            tuple(bindings),
            str(prefix),
            latest_index + 1,
            reason,
            checks,
        ),
        source_records=tuple(records),
        scientific_resolution=scientific_resolution,
        entry_snapshot=entry_snapshot,
    )


def _derive_r_check_authority(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    r_check: RCheck,
    evaluator_class: EvaluatorClass,
    source_artifact_sha256s: Iterable[str],
    _replayed_semantic_peer: Any = None,
) -> tuple[RCheckAuthority, tuple[Any, ...]]:
    derivation = _derive_r_check_authority_source(
        registry,
        ledger,
        run_id=run_id,
        r_check=r_check,
        evaluator_class=evaluator_class,
        source_artifact_sha256s=source_artifact_sha256s,
        _replayed_semantic_peer=_replayed_semantic_peer,
    )
    return derivation.authority, derivation.source_records


def register_r_check_authority(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    r_check: RCheck,
    evaluator_class: EvaluatorClass,
    source_artifact_sha256s: Iterable[str] = (),
) -> Any:
    authority, records = _derive_r_check_authority(
        registry,
        ledger,
        run_id=run_id,
        r_check=r_check,
        evaluator_class=evaluator_class,
        source_artifact_sha256s=source_artifact_sha256s,
    )
    record = registry.put_json(
        authority.to_dict(),
        logical_type=R_CHECK_AUTHORITY_LOGICAL_TYPE,
        origin=(
            f"fresh registry-and-ledger R-check authority for "
            f"{run_id}:{r_check.value}:{evaluator_class.value}"
        ),
        creator_role=authority.actor_role,
        creation_command=("scientist-one", "resolve-r-check-authority"),
        parent_artifacts=tuple(value.sha256 for value in records),
        schema_version=R_CHECK_AUTHORITY_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    resolve_r_check_authority(
        registry,
        ledger,
        authority_artifact_sha256=record.sha256,
        run_id=run_id,
    )
    return record


def resolve_r_check_authority(
    registry: Any,
    ledger: Any,
    *,
    authority_artifact_sha256: str,
    run_id: str,
) -> RCheckAuthority:
    return _resolve_r_check_authority(
        registry, ledger, authority_artifact_sha256=authority_artifact_sha256,
        run_id=run_id,
    )


def _resolve_r_check_authority_source(
    registry: Any,
    ledger: Any,
    *,
    authority_artifact_sha256: str,
    run_id: str,
    _replayed_semantic_peer: Any = None,
) -> _RCheckAuthorityReplay:
    """Shared full readback; one private same-round R7 recursion seam only."""

    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    if not isinstance(authority_artifact_sha256, str) or _SHA256_PATTERN.fullmatch(authority_artifact_sha256) is None:
        raise ValueError("R-check authority artifact SHA-256 is invalid")
    try:
        registry.verify(authority_artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(authority_artifact_sha256)
        payload = _canonical_json_artifact(registry, record)
    except Exception as exc:
        raise ValueError("R-check authority artifact is absent or corrupt") from exc
    required = {
        "schema_version", "kind", "run_id", "r_check", "evaluator_class",
        "actor_role", "status", "scope", "source_bindings",
        "ledger_prefix_head_hash", "ledger_prefix_event_count", "reason_code",
        "derivation_checks", "human_independence_claimed", "e4_synthesized",
    }
    if set(payload) != required:
        raise ValueError("R-check authority payload schema is incomplete or unknown")
    try:
        r_check = RCheck(payload["r_check"])
        evaluator_class = EvaluatorClass(payload["evaluator_class"])
        source_values = payload["source_bindings"]
        source_hashes = tuple(value["artifact_sha256"] for value in source_values)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("R-check authority payload identity is malformed") from exc
    if _replayed_semantic_peer is not None:
        if r_check is not RCheck.R7 or evaluator_class is not EvaluatorClass.E3:
            raise ValueError("round replay is restricted to R7/E3")
        if not any(
            registry.get_metadata(digest).logical_type == "semantic_challenge_audit_authority"
            for digest in source_hashes
        ):
            # Existing clean-rerun and mechanical reproduction source families
            # have no recursive semantic peer and retain their ordinary owner.
            _replayed_semantic_peer = None
    derivation = _derive_r_check_authority_source(
        registry,
        ledger,
        run_id=run_id,
        r_check=r_check,
        evaluator_class=evaluator_class,
        source_artifact_sha256s=source_hashes,
        _replayed_semantic_peer=_replayed_semantic_peer,
    )
    expected = derivation.authority
    source_records = derivation.source_records
    if not source_hashes:
        # A source-free receipt is deliberately UNTESTED, but it still binds
        # the exact valid ledger prefix at issuance.  Later append-only events
        # do not change that determination.  A correction of any event in the
        # bound prefix does, and is rejected below.
        expected = replace(
            expected,
            ledger_prefix_head_hash=payload["ledger_prefix_head_hash"],
            ledger_prefix_event_count=payload["ledger_prefix_event_count"],
        )
    if (
        payload != expected.to_dict()
        or record.logical_type != R_CHECK_AUTHORITY_LOGICAL_TYPE
        or record.schema_version != R_CHECK_AUTHORITY_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin
        != f"fresh registry-and-ledger R-check authority for {run_id}:{r_check.value}:{evaluator_class.value}"
        or record.creator_role is not expected.actor_role
        or record.creation_command != ("scientist-one", "resolve-r-check-authority")
        or record.parent_artifacts != tuple(value.sha256 for value in source_records)
        or record.validation_result != "PASS"
        or record.frozen is not True
        or payload["human_independence_claimed"] is not False
        or payload["e4_synthesized"] is not False
    ):
        raise ValueError("R-check authority differs from fresh deterministic resolution")
    if not _ledger_prefix_is_current(
        events,
        expected.ledger_prefix_event_count,
        expected.ledger_prefix_head_hash,
    ):
        raise ValueError("R-check authority ledger prefix is stale")
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("R-check target or sources changed during complete replay")
    return _RCheckAuthorityReplay(
        authority=expected,
        record=record,
        source_records=source_records,
        scientific_resolution=derivation.scientific_resolution,
        entry_snapshot=entry_snapshot,
    )


def _resolve_r_check_authority(
    registry: Any,
    ledger: Any,
    *,
    authority_artifact_sha256: str,
    run_id: str,
    _replayed_semantic_peer: Any = None,
) -> RCheckAuthority:
    replay = _resolve_r_check_authority_source(
        registry,
        ledger,
        authority_artifact_sha256=authority_artifact_sha256,
        run_id=run_id,
        _replayed_semantic_peer=_replayed_semantic_peer,
    )
    return replay.authority


def _ledger_prefix_is_current(
    events: Sequence[Any],
    event_count: int,
    head_hash: str,
) -> bool:
    if (
        isinstance(event_count, bool)
        or not isinstance(event_count, int)
        or event_count <= 0
        or event_count > len(events)
        or not isinstance(head_hash, str)
        or _SHA256_PATTERN.fullmatch(head_hash) is None
        or events[event_count - 1].event_hash != head_hash
    ):
        return False
    prefix_event_ids = {event.event_id for event in events[:event_count]}
    return not any(
        event.event_type == "CORRECTION"
        and event.supersedes_event_id in prefix_event_ids
        for event in events[event_count:]
    )


def _rubric_binding(
    registry: Any,
    events: Sequence[Any],
    digest: str,
) -> tuple[Any, AuthoritySourceBinding, Mapping[str, Any]]:
    from .security import safe_json_loads

    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        rubric = safe_json_loads(
            registry.get_bytes(record.sha256),
            max_bytes=MAX_R_CHECK_SOURCE_BYTES,
        )
    except Exception as exc:
        raise ValueError("readiness rubric artifact is absent or corrupt") from exc
    if (
        not isinstance(rubric, Mapping)
        or record.logical_type != FROZEN_READINESS_RUBRIC_LOGICAL_TYPE
        or record.creator_role is not Role.PROTOCOL_DESIGNER
        or record.schema_version != "paper-readiness-rubric/v1"
        or record.origin != "frozen paper-readiness rubric authority"
        or record.creation_command != ("scientist-one", "freeze-paper-readiness-rubric")
        or record.parent_artifacts
        or record.validation_result != "PASS"
        or record.frozen is not True
    ):
        raise ValueError("readiness rubric lacks exact frozen authority metadata")
    return record, _event_binding(events, record), rubric


def _rubric_category_ids(rubric: Mapping[str, Any]) -> tuple[str, ...]:
    categories = rubric.get("categories")
    if not isinstance(categories, list) or not categories:
        raise ValueError("readiness rubric categories are absent")
    result: list[str] = []
    for value in categories:
        if not isinstance(value, Mapping):
            raise ValueError("readiness rubric category is malformed")
        identifier = value.get("id")
        if (
            not isinstance(identifier, str)
            or _IDENTIFIER_PATTERN.fullmatch(identifier) is None
        ):
            raise ValueError("readiness rubric category identity is malformed")
        result.append(identifier)
    if len(set(result)) != len(result):
        raise ValueError("readiness rubric category identities are duplicated")
    return tuple(result)


def _payload_is_non_evidentiary_fixture(value: Any) -> bool:
    stack: list[Any] = [value]
    visited = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 100_000:
            raise ValueError("readiness evidence scope traversal exceeds its bound")
        if isinstance(current, Mapping):
            for key, item in current.items():
                if key == "fixture_notice":
                    return True
                if key in {
                    "scientific_evidence",
                    "scientific_evidence_eligible",
                    "scientific_source_qualified",
                } and item is not True:
                    return True
                if key in {
                    "evidence_use",
                    "evidence_scope",
                    "scope",
                    "scientific_evidence_status",
                } and isinstance(item, str) and item in {
                    "SYSTEM_FIXTURE",
                    "NON_EVIDENTIARY_FIXTURE",
                    "NON_EVIDENTIARY",
                }:
                    return True
                if key == "package_kind" and item == "DEMO_RESEARCH_PACKAGE":
                    return True
                stack.append(item)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return False


def _readiness_category_score_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            name: {"type": "string", "maxLength": 8192}
            for name in (
                "subject_kind",
                "subject_id",
                "outcome",
                "rationale",
            )
        },
        "required": [
            "subject_kind",
            "subject_id",
            "outcome",
            "rationale",
        ],
        "additionalProperties": False,
    }


def _readiness_category_score_input(
    *,
    run_id: str,
    category: Mapping[str, Any],
    rubric_record: Any,
    rubric: Mapping[str, Any],
    candidate_record: Any,
    candidate_payload: Mapping[str, Any],
    evidence: Sequence[tuple[Any, Mapping[str, Any]]],
) -> dict[str, Any]:
    return {
        "schema_version": "readiness-category-score-input/v1",
        "subject_kind": "VENUE_DIMENSION",
        "subject_id": category["id"],
        "run_id": run_id,
        "rubric": {
            "artifact_sha256": rubric_record.sha256,
            "artifact_record_hash": rubric_record.record_hash,
            "value": dict(rubric),
        },
        "category": dict(category),
        "candidate": {
            "artifact_sha256": candidate_record.sha256,
            "artifact_record_hash": candidate_record.record_hash,
            "logical_type": candidate_record.logical_type,
            "creator_role": candidate_record.creator_role.value,
            "parent_artifacts": list(candidate_record.parent_artifacts),
            "value": dict(candidate_payload),
        },
        "evidence": [
            {
                "artifact_sha256": record.sha256,
                "artifact_record_hash": record.record_hash,
                "logical_type": record.logical_type,
                "creator_role": record.creator_role.value,
                "parent_artifacts": list(record.parent_artifacts),
                "value": dict(payload),
            }
            for record, payload in evidence
        ],
        "scoring_contract": {
            "range": [0.0, 1.0],
            "minimum_fraction": float(category["minimum_fraction"]),
            "weight": float(category["weight"]),
            "hard_blockers_override_score": True,
        },
    }


def _record_is_non_evidentiary_fixture(registry: Any, record: Any) -> bool:
    from .security import safe_json_loads

    if "fixture" in record.logical_type.lower() or "fixture" in record.origin.lower():
        return True
    if record.mime_type != "application/json":
        registry.get_bytes(record.sha256)
        return False
    try:
        value = safe_json_loads(
            registry.get_bytes(record.sha256),
            max_bytes=MAX_R_CHECK_SOURCE_BYTES,
        )
    except Exception as exc:
        raise ValueError("readiness evidence JSON cannot be reopened") from exc
    return _payload_is_non_evidentiary_fixture(value)


def _semantic_judgment_has_audited_live_transport_custody(
    registry: Any,
    ledger: Any,
    run_id: str,
    judgment: Any,
    model_output: Mapping[str, Any],
) -> bool:
    """Replay signed gateway issuance across exact provider custody."""

    from .external import (
        AUDITED_LIVE_TRANSPORT_AUTHORITY,
        require_audited_live_transport_execution,
    )
    from .security import safe_json_loads

    try:
        provider_response_record = registry.get_metadata(
            judgment.provider_response_artifact_hash
        )
        if len(provider_response_record.parent_artifacts) != 3:
            return False
        raw_response_hash = provider_response_record.parent_artifacts[0]
        response_receipt_hash = provider_response_record.parent_artifacts[1]
        execution_authority_hash = provider_response_record.parent_artifacts[2]
        response_receipt_record = registry.get_metadata(response_receipt_hash)
        provider_response = safe_json_loads(
            registry.get_bytes(judgment.provider_response_artifact_hash),
            max_bytes=MAX_R_CHECK_SOURCE_BYTES,
        )
        response_receipt = safe_json_loads(
            registry.get_bytes(response_receipt_hash),
            max_bytes=MAX_R_CHECK_SOURCE_BYTES,
        )
        execution_authority = require_audited_live_transport_execution(
            registry,
            ledger,
            run_id=run_id,
            authority_artifact_sha256=execution_authority_hash,
            response_receipt_artifact_sha256=response_receipt_hash,
        )
    except Exception:
        return False
    if (
        response_receipt_record.logical_type != "external_response_receipt"
        or not isinstance(provider_response, Mapping)
        or not isinstance(response_receipt, Mapping)
        or execution_authority.response_receipt_artifact.sha256
        != response_receipt_hash
        or execution_authority.raw_response_artifact.sha256
        != raw_response_hash
        or execution_authority.request_artifact.sha256
        != response_receipt.get("request_artifact_sha256")
        or provider_response.get(
            "transport_execution_authority_artifact_sha256"
        )
        != execution_authority_hash
        or model_output.get(
            "transport_execution_authority_artifact_sha256"
        )
        != execution_authority_hash
    ):
        return False
    expected = (
        True,
        "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED",
        AUDITED_LIVE_TRANSPORT_AUTHORITY,
    )
    return all(
        (
            value.get("network_used"),
            value.get("external_validation"),
            value.get("transport_authority"),
        )
        == expected
        for value in (response_receipt, provider_response, model_output)
    )


def _derive_readiness_category_score_authority(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    category_id: str,
    asserted_score_fraction: float,
    rubric_artifact_sha256: str,
    candidate_artifact_sha256: str,
    evidence_artifact_sha256s: Iterable[str],
    semantic_judgment_artifact_sha256: str,
) -> tuple[ReadinessCategoryScoreAuthority, tuple[Any, ...]]:
    from .gates import JudgmentSubjectKind, require_semantic_judgment_receipt
    from .paper_pipeline import (
        _venue_score_outcome,
        require_paper_verification,
    )
    from .security import canonical_json_bytes, safe_json_loads

    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    if (
        not isinstance(category_id, str)
        or _IDENTIFIER_PATTERN.fullmatch(category_id) is None
        or isinstance(asserted_score_fraction, bool)
        or not isinstance(asserted_score_fraction, (int, float))
        or not math.isfinite(float(asserted_score_fraction))
        or not 0.0 <= float(asserted_score_fraction) <= 1.0
    ):
        raise ValueError("readiness category score identity is invalid")
    evidence_hashes = tuple(
        islice(
            evidence_artifact_sha256s,
            MAX_R_CHECK_SOURCE_ARTIFACTS + 1,
        )
    )
    all_hashes = (
        rubric_artifact_sha256,
        candidate_artifact_sha256,
        *evidence_hashes,
        semantic_judgment_artifact_sha256,
    )
    if (
        not evidence_hashes
        or len(evidence_hashes) > MAX_R_CHECK_SOURCE_ARTIFACTS
        or len(set(all_hashes)) != len(all_hashes)
        or any(
            not isinstance(value, str)
            or _SHA256_PATTERN.fullmatch(value) is None
            for value in all_hashes
        )
    ):
        raise ValueError(
            "readiness category score sources must be bounded distinct SHA-256s"
        )
    rubric_record, rubric_binding, rubric = _rubric_binding(
        registry,
        events,
        rubric_artifact_sha256,
    )
    if category_id not in _rubric_category_ids(rubric):
        raise ValueError("readiness category score names an unknown rubric category")
    category = next(
        value for value in rubric["categories"]
        if value["id"] == category_id
    )

    try:
        registry.verify(candidate_artifact_sha256, raise_on_error=True)
        candidate_record = registry.get_metadata(candidate_artifact_sha256)
        candidate_payload = _canonical_json_artifact(
            registry,
            candidate_record,
        )
    except Exception as exc:
        raise ValueError("readiness score candidate is absent or corrupt") from exc
    if (
        candidate_record.logical_type != "paper_candidate"
        or candidate_record.creator_role is not Role.PAPER_WRITER
    ):
        raise ValueError("readiness score candidate has the wrong authority")
    candidate_binding = _event_binding(events, candidate_record)

    evidence_records: list[Any] = []
    evidence_payloads: list[Mapping[str, Any]] = []
    evidence_bindings: list[AuthoritySourceBinding] = []
    for digest in evidence_hashes:
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
            evidence_payload = _canonical_json_artifact(registry, record)
        except Exception as exc:
            raise ValueError("readiness score evidence is absent or corrupt") from exc
        if (
            record.validation_result != "PASS"
            or record.frozen is not True
            or record.record_hash is None
        ):
            raise ValueError("readiness score evidence is not frozen PASS authority")
        evidence_records.append(record)
        evidence_payloads.append(evidence_payload)
        evidence_bindings.append(_event_binding(events, record))

    score = float(asserted_score_fraction)
    outcome = _venue_score_outcome(score)
    try:
        judgment = require_semantic_judgment_receipt(
            registry,
            receipt_artifact_hash=semantic_judgment_artifact_sha256,
            subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
            subject_id=category_id,
            outcome=outcome,
            evidence_hashes=evidence_hashes,
            context_hashes=(
                candidate_artifact_sha256,
                rubric_artifact_sha256,
            ),
        )
        semantic_record = registry.get_metadata(
            semantic_judgment_artifact_sha256
        )
        semantic_binding = _event_binding(events, semantic_record)
        model_output = safe_json_loads(
            registry.get_bytes(judgment.model_output_artifact_hash),
            max_bytes=MAX_R_CHECK_SOURCE_BYTES,
        )
    except Exception as exc:
        raise ValueError(
            "readiness category semantic custody cannot be replayed"
        ) from exc
    if (
        semantic_record.logical_type != SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE
        or semantic_record.creator_role is not Role.SCIENTIFIC_REVIEWER
        or not isinstance(model_output, Mapping)
    ):
        raise ValueError("readiness category semantic authority is malformed")
    expected_input = _readiness_category_score_input(
        run_id=run_id,
        category=category,
        rubric_record=rubric_record,
        rubric=rubric,
        candidate_record=candidate_record,
        candidate_payload=candidate_payload,
        evidence=tuple(
            zip(evidence_records, evidence_payloads, strict=True)
        ),
    )
    expected_input_bytes = canonical_json_bytes(expected_input)
    expected_schema = _readiness_category_score_schema()
    expected_schema_bytes = canonical_json_bytes(expected_schema)
    try:
        retained_instructions = registry.get_bytes(
            judgment.instructions_artifact_hash
        )
        retained_input = registry.get_bytes(judgment.input_artifact_hash)
        retained_schema = registry.get_bytes(
            judgment.output_schema_artifact_hash
        )
    except Exception as exc:
        raise ValueError("readiness retained semantic inputs are absent") from exc
    if (
        len(expected_input_bytes) > MAX_READINESS_SCORE_INPUT_BYTES
        or retained_instructions
        != READINESS_CATEGORY_SCORE_INSTRUCTIONS.encode("utf-8")
        or retained_input != expected_input_bytes
        or retained_schema != expected_schema_bytes
        or judgment.prompt_template_id != "readiness-category-score"
        or judgment.prompt_template_version != "1.0"
        or judgment.prompt_template_hash
        != hashlib.sha256(retained_instructions).hexdigest()
    ):
        raise ValueError(
            "readiness semantic judgment did not evaluate the exact rubric inputs"
        )
    if rubric_binding.ledger_event_index >= semantic_binding.ledger_event_index:
        raise ValueError("readiness rubric was not frozen before semantic scoring")

    non_evidentiary = _payload_is_non_evidentiary_fixture(
        candidate_payload
    ) or any(
        _record_is_non_evidentiary_fixture(registry, record)
        for record in evidence_records
    )
    live_custody = _semantic_judgment_has_audited_live_transport_custody(
        registry,
        ledger,
        run_id,
        judgment,
        model_output,
    )
    paper_records = tuple(
        record
        for record in evidence_records
        if record.logical_type == "paper_verification"
    )
    paper_authority = False
    if live_custody and not non_evidentiary and len(paper_records) == 1:
        paper_record = paper_records[0]
        try:
            verification = require_paper_verification(
                registry,
                ledger,
                run_id=run_id,
                verification_artifact_hash=paper_record.sha256,
            )
            paper_bundle = _paper_authority_bundle(
                registry,
                paper_record,
                run_id,
            )
            paper_authority = (
                verification.passed is True
                and paper_record.parent_artifacts[:1]
                == (candidate_artifact_sha256,)
                and paper_bundle.run_id == run_id
            )
        except Exception:
            paper_authority = False
    status = (
        CategoryScoreStatus.SCORED
        if live_custody and not non_evidentiary and paper_authority
        else CategoryScoreStatus.UNTESTED
    )
    scope = (
        AuthorityScope.SCIENTIFIC
        if status is CategoryScoreStatus.SCORED
        else AuthorityScope.SYSTEM_FIXTURE
    )
    reason = (
        "LIVE_PAPER_SEMANTIC_SCORE_REPLAYED"
        if status is CategoryScoreStatus.SCORED
        else "FIXTURE_OR_INSUFFICIENT_SCORE_AUTHORITY"
    )
    bindings = (
        rubric_binding,
        candidate_binding,
        *evidence_bindings,
        semantic_binding,
    )
    latest_index = max(value.ledger_event_index for value in bindings)
    prefix = events[latest_index].event_hash
    if prefix is None:
        raise ValueError("readiness category score ledger prefix is absent")
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("readiness category score sources changed during complete owner replay")
    return (
        ReadinessCategoryScoreAuthority(
            run_id,
            category_id,
            score,
            status,
            scope,
            rubric_binding,
            candidate_binding,
            tuple(evidence_bindings),
            semantic_binding,
            str(prefix),
            latest_index + 1,
            reason,
        ),
        (
            rubric_record,
            candidate_record,
            *evidence_records,
            semantic_record,
        ),
    )


def register_readiness_category_score_authority(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    category_id: str,
    asserted_score_fraction: float,
    rubric_artifact_sha256: str,
    candidate_artifact_sha256: str,
    evidence_artifact_sha256s: Iterable[str],
    semantic_judgment_artifact_sha256: str,
) -> Any:
    authority, records = _derive_readiness_category_score_authority(
        registry,
        ledger,
        run_id=run_id,
        category_id=category_id,
        asserted_score_fraction=asserted_score_fraction,
        rubric_artifact_sha256=rubric_artifact_sha256,
        candidate_artifact_sha256=candidate_artifact_sha256,
        evidence_artifact_sha256s=evidence_artifact_sha256s,
        semantic_judgment_artifact_sha256=(
            semantic_judgment_artifact_sha256
        ),
    )
    record = registry.put_json(
        authority.to_dict(),
        logical_type=READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE,
        origin=(
            "registry-and-ledger resolved readiness category score authority"
        ),
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=("scientist-one", "resolve-readiness-category-score"),
        parent_artifacts=tuple(value.sha256 for value in records),
        schema_version=READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    resolve_readiness_category_score_authority(
        registry,
        ledger,
        authority_artifact_sha256=record.sha256,
        run_id=run_id,
    )
    return record


def resolve_readiness_category_score_authority(
    registry: Any,
    ledger: Any,
    *,
    authority_artifact_sha256: str,
    run_id: str,
) -> ReadinessCategoryScoreAuthority:
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    if (
        not isinstance(authority_artifact_sha256, str)
        or _SHA256_PATTERN.fullmatch(authority_artifact_sha256) is None
    ):
        raise ValueError("readiness category score artifact SHA-256 is invalid")
    try:
        registry.verify(authority_artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(authority_artifact_sha256)
        payload = _canonical_json_artifact(registry, record)
        evidence_hashes = tuple(
            value["artifact_sha256"]
            for value in payload["evidence_bindings"]
        )
        rubric_hash = payload["rubric_binding"]["artifact_sha256"]
        candidate_hash = payload["candidate_binding"]["artifact_sha256"]
        semantic_hash = payload["semantic_judgment_binding"][
            "artifact_sha256"
        ]
    except Exception as exc:
        raise ValueError(
            "readiness category score artifact is absent or malformed"
        ) from exc
    required = {
        "schema_version",
        "kind",
        "run_id",
        "category_id",
        "asserted_score_fraction",
        "status",
        "scope",
        "rubric_binding",
        "candidate_binding",
        "evidence_bindings",
        "semantic_judgment_binding",
        "ledger_prefix_head_hash",
        "ledger_prefix_event_count",
        "reason_code",
        "human_independence_claimed",
        "e4_synthesized",
    }
    if set(payload) != required:
        raise ValueError("readiness category score payload schema is invalid")
    expected, source_records = _derive_readiness_category_score_authority(
        registry,
        ledger,
        run_id=run_id,
        category_id=payload["category_id"],
        asserted_score_fraction=payload["asserted_score_fraction"],
        rubric_artifact_sha256=rubric_hash,
        candidate_artifact_sha256=candidate_hash,
        evidence_artifact_sha256s=evidence_hashes,
        semantic_judgment_artifact_sha256=semantic_hash,
    )
    if (
        payload != expected.to_dict()
        or record.logical_type
        != READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE
        or record.schema_version
        != READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin
        != "registry-and-ledger resolved readiness category score authority"
        or record.creator_role is not Role.SCIENTIFIC_REVIEWER
        or record.creation_command
        != ("scientist-one", "resolve-readiness-category-score")
        or record.parent_artifacts
        != tuple(value.sha256 for value in source_records)
        or record.validation_result != "PASS"
        or record.frozen is not True
        or payload["human_independence_claimed"] is not False
        or payload["e4_synthesized"] is not False
    ):
        raise ValueError(
            "readiness category score differs from fresh deterministic resolution"
        )
    if not _ledger_prefix_is_current(
        events,
        expected.ledger_prefix_event_count,
        expected.ledger_prefix_head_hash,
    ):
        raise ValueError("readiness category score ledger prefix is stale")
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("readiness category score target or sources changed during replay")
    return expected


def _derive_r_check_authority_bundle(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    authority_artifact_sha256s: Iterable[str],
    rubric_artifact_sha256: str,
    category_score_authority_artifact_sha256s: Iterable[str] = (),
) -> tuple[RCheckAuthorityBundle, tuple[Any, ...]]:
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    values = tuple(authority_artifact_sha256s)
    if (
        len(values) != _required_authority_count()
        or len(set(values)) != len(values)
        or any(not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None for value in values)
    ):
        raise ValueError("R-check bundle requires one exact authority per required identity")
    resolved: list[tuple[RCheckAuthority, Any]] = []
    for digest in values:
        authority = resolve_r_check_authority(
            registry,
            ledger,
            authority_artifact_sha256=digest,
            run_id=run_id,
        )
        _require_legacy_bundle_source_profile(tuple(
            registry.get_metadata(binding.artifact_sha256)
            for binding in authority.source_bindings
        ))
        resolved.append((authority, registry.get_metadata(digest)))
    by_identity = {
        (authority.r_check, authority.evaluator_class): (authority, record)
        for authority, record in resolved
    }
    if len(by_identity) != len(resolved) or set(by_identity) != set(_required_authority_identities()):
        raise ValueError("R-check bundle authorities are missing, duplicated, or substituted")
    ordered = tuple(by_identity[identity] for identity in _required_authority_identities())
    rubric_record, rubric_binding, rubric = _rubric_binding(
        registry, events, rubric_artifact_sha256
    )
    category_ids = _rubric_category_ids(rubric)
    category_hashes = tuple(
        islice(
            category_score_authority_artifact_sha256s,
            MAX_READINESS_CATEGORIES + 1,
        )
    )
    if (
        category_hashes
        and len(category_hashes) != len(category_ids)
        or len(category_hashes) > MAX_READINESS_CATEGORIES
        or len(set(category_hashes)) != len(category_hashes)
        or any(
            not isinstance(value, str)
            or _SHA256_PATTERN.fullmatch(value) is None
            for value in category_hashes
        )
    ):
        raise ValueError(
            "readiness category score authorities must be empty or complete"
        )
    category_pairs: list[tuple[ReadinessCategoryScoreAuthority, Any]] = []
    for digest in category_hashes:
        category_pairs.append(
            (
                resolve_readiness_category_score_authority(
                    registry,
                    ledger,
                    authority_artifact_sha256=digest,
                    run_id=run_id,
                ),
                registry.get_metadata(digest),
            )
        )
    category_by_id = {
        authority.category_id: (authority, record)
        for authority, record in category_pairs
    }
    if category_hashes and (
        len(category_by_id) != len(category_pairs)
        or set(category_by_id) != set(category_ids)
    ):
        raise ValueError(
            "readiness category score authorities are missing or substituted"
        )
    ordered_categories = tuple(
        category_by_id[identifier] for identifier in category_ids
    ) if category_hashes else ()
    if any(
        authority.rubric_binding.artifact_sha256 != rubric_record.sha256
        for authority, _record in ordered_categories
    ):
        raise ValueError("readiness category score uses another rubric")
    candidate_hashes = {
        authority.candidate_binding.artifact_sha256
        for authority, _record in ordered_categories
    }
    if len(candidate_hashes) > 1:
        raise ValueError("readiness category scores use different candidates")
    candidate_hash = next(iter(candidate_hashes), None)
    source_indexes = tuple(
        binding.ledger_event_index
        for authority, _record in ordered
        for binding in authority.source_bindings
    )
    if source_indexes and rubric_binding.ledger_event_index > min(source_indexes):
        raise ValueError("readiness rubric was not frozen before evaluated evidence")
    statuses: list[tuple[RCheck, AuthorityStatus]] = []
    for check in RCheck:
        authorities = tuple(
            by_identity[(check, evaluator_class)][0]
            for evaluator_class in sorted(
                REQUIRED_R_AUTHORITIES[check], key=lambda value: value.value
            )
        )
        if any(value.status is AuthorityStatus.FAIL for value in authorities):
            status = AuthorityStatus.FAIL
        elif all(value.status is AuthorityStatus.PASS for value in authorities):
            status = AuthorityStatus.PASS
        else:
            status = AuthorityStatus.UNTESTED
        statuses.append((check, status))
    r_scope = (
        AuthorityScope.SYSTEM_FIXTURE
        if any(authority.scope is AuthorityScope.SYSTEM_FIXTURE for authority, _record in ordered)
        else AuthorityScope.SCIENTIFIC
    )
    category_statuses = (
        tuple(
            (identifier, category_by_id[identifier][0].status)
            for identifier in category_ids
        )
        if category_hashes
        else tuple(
            (identifier, CategoryScoreStatus.UNTESTED)
            for identifier in category_ids
        )
    )
    category_scope = (
        AuthorityScope.SCIENTIFIC
        if ordered_categories
        and all(
            authority.scope is AuthorityScope.SCIENTIFIC
            and authority.status is CategoryScoreStatus.SCORED
            for authority, _record in ordered_categories
        )
        else AuthorityScope.SYSTEM_FIXTURE
    )
    latest_index = max(
        rubric_binding.ledger_event_index,
        *(authority.ledger_prefix_event_count - 1 for authority, _record in ordered),
        *(
            authority.ledger_prefix_event_count - 1
            for authority, _record in ordered_categories
        ),
    )
    prefix = events[latest_index].event_hash
    if prefix is None:
        raise ValueError("R-check bundle ledger prefix hash is absent")
    bundle = RCheckAuthorityBundle(
        run_id,
        r_scope,
        tuple(record.sha256 for _authority, record in ordered),
        rubric_record.sha256,
        str(rubric_record.record_hash),
        rubric_binding.ledger_event_id,
        rubric_binding.ledger_event_hash,
        rubric_binding.ledger_event_index,
        tuple(statuses),
        category_statuses,
        category_scope,
        tuple(record.sha256 for _authority, record in ordered_categories),
        candidate_hash,
        str(prefix),
        latest_index + 1,
    )
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("R-check bundle sources changed during complete owner replay")
    return bundle, (
        *(record for _authority, record in ordered),
        *(record for _authority, record in ordered_categories),
    )


def register_r_check_authority_bundle(
    registry: Any,
    ledger: Any,
    *,
    run_id: str,
    authority_artifact_sha256s: Iterable[str],
    rubric_artifact_sha256: str,
    category_score_authority_artifact_sha256s: Iterable[str] = (),
) -> Any:
    bundle, authority_records = _derive_r_check_authority_bundle(
        registry,
        ledger,
        run_id=run_id,
        authority_artifact_sha256s=authority_artifact_sha256s,
        rubric_artifact_sha256=rubric_artifact_sha256,
        category_score_authority_artifact_sha256s=(
            category_score_authority_artifact_sha256s
        ),
    )
    record = registry.put_json(
        bundle.to_dict(),
        logical_type=R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
        origin=f"exact R0-R7 authority bundle for {run_id}",
        creator_role=Role.ORCHESTRATOR,
        creation_command=("scientist-one", "bundle-r-check-authorities"),
        parent_artifacts=(
            bundle.rubric_artifact_sha256,
            *(value.sha256 for value in authority_records),
        ),
        schema_version=R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    resolve_r_check_authority_bundle(
        registry,
        ledger,
        bundle_artifact_sha256=record.sha256,
        run_id=run_id,
    )
    return record


def resolve_r_check_authority_bundle(
    registry: Any,
    ledger: Any,
    *,
    bundle_artifact_sha256: str,
    run_id: str,
) -> RCheckAuthorityBundle | RCheckAuthorityBundleV2:
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    if not isinstance(bundle_artifact_sha256, str) or _SHA256_PATTERN.fullmatch(bundle_artifact_sha256) is None:
        raise ValueError("R-check bundle artifact SHA-256 is invalid")
    try:
        registry.verify(bundle_artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(bundle_artifact_sha256)
    except Exception as exc:
        raise ValueError("R-check authority bundle is absent or malformed") from exc
    if (
        record.logical_type == R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE
        and record.schema_version == "2.0"
    ):
        # Metadata selects the distinct full cohort owner, never a fallback
        # into the old fixed-cardinality meaning. The outer snapshot covers
        # the dispatch interval as well as the owner's own replay interval.
        from .scientific_cohort_bundle import (
            RCheckAuthorityBundleV2,
            resolve_r_check_authority_bundle_v2,
        )

        try:
            resolved = resolve_r_check_authority_bundle_v2(
                registry,
                ledger,
                bundle_artifact_sha256=bundle_artifact_sha256,
                run_id=run_id,
            )
        except Exception as exc:
            raise ValueError("cohort bundle authority cannot be freshly resolved") from exc
        if type(resolved) is not RCheckAuthorityBundleV2:
            raise ValueError("cohort bundle owner returned a different profile")
        if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
            raise ValueError("R-check bundle target or sources changed during replay")
        return resolved
    try:
        payload = _canonical_json_artifact(registry, record)
        authority_hashes = tuple(payload["authority_artifact_sha256s"])
        category_hashes = tuple(
            payload["category_scoring"][
                "score_authority_artifact_sha256s"
            ]
        )
        rubric_hash = str(payload["rubric"]["artifact_sha256"])
    except Exception as exc:
        raise ValueError("R-check authority bundle is absent or malformed") from exc
    expected, authority_records = _derive_r_check_authority_bundle(
        registry,
        ledger,
        run_id=run_id,
        authority_artifact_sha256s=authority_hashes,
        rubric_artifact_sha256=rubric_hash,
        category_score_authority_artifact_sha256s=category_hashes,
    )
    if (
        payload != expected.to_dict()
        or record.logical_type != R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE
        or record.schema_version != R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin != f"exact R0-R7 authority bundle for {run_id}"
        or record.creator_role is not Role.ORCHESTRATOR
        or record.creation_command != ("scientist-one", "bundle-r-check-authorities")
        or record.parent_artifacts
        != (
            expected.rubric_artifact_sha256,
            *(value.sha256 for value in authority_records),
        )
        or record.validation_result != "PASS"
        or record.frozen is not True
        or payload.get("human_independence_claimed") is not False
        or payload.get("e4_synthesized") is not False
    ):
        raise ValueError("R-check bundle differs from fresh deterministic resolution")
    if not _ledger_prefix_is_current(
        events,
        expected.ledger_prefix_event_count,
        expected.ledger_prefix_head_hash,
    ):
        raise ValueError("R-check bundle ledger prefix is stale")
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("R-check bundle target or sources changed during replay")
    return expected


@dataclass
class AuditSummary:
    evaluations: list[Evaluation] = field(default_factory=list)
    authority_bundle_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        self._bounded_evaluations()
        if (
            self.authority_bundle_artifact_sha256 is not None
            and (
                not isinstance(self.authority_bundle_artifact_sha256, str)
                or _SHA256_PATTERN.fullmatch(
                    self.authority_bundle_artifact_sha256
                )
                is None
            )
        ):
            raise ValueError("audit authority bundle must be a SHA-256 identity")

    def _bounded_evaluations(self) -> tuple[Evaluation, ...]:
        if (
            not isinstance(self.evaluations, list)
            or len(self.evaluations) > MAX_EVALUATION_RECEIPTS
            or any(
                not isinstance(evaluation, Evaluation)
                for evaluation in self.evaluations
            )
        ):
            raise ValueError("audit evaluations must be a bounded receipt list")
        return tuple(self.evaluations)

    def add(self, evaluation: Evaluation) -> None:
        self._bounded_evaluations()
        if not isinstance(evaluation, Evaluation):
            raise ValueError("audit evaluation must be a typed receipt")
        if len(self.evaluations) >= MAX_EVALUATION_RECEIPTS:
            raise ValueError("audit evaluations must be a bounded receipt list")
        self.evaluations.append(evaluation)

    def descriptive_status_by_r_check(self) -> dict[str, str]:
        """Return the legacy label projection without granting authority."""

        evaluations = self._bounded_evaluations()
        statuses: dict[str, str] = {item.value: "MISSING" for item in RCheck}
        for check in RCheck:
            related = [evaluation for evaluation in evaluations if check in evaluation.r_checks]
            if any(evaluation.decision is Decision.FAIL for evaluation in related):
                statuses[check.value] = "FAIL"
            elif related:
                statuses[check.value] = "DESCRIPTIVE_ONLY"
        return statuses

    def resolve_bundle(
        self,
        registry: Any,
        ledger: Any,
        *,
        run_id: str,
    ) -> RCheckAuthorityBundle | RCheckAuthorityBundleV2:
        self._bounded_evaluations()
        if self.authority_bundle_artifact_sha256 is None:
            raise ValueError("audit has no R-check authority bundle")
        return resolve_r_check_authority_bundle(
            registry,
            ledger,
            bundle_artifact_sha256=self.authority_bundle_artifact_sha256,
            run_id=run_id,
        )

    def status_by_r_check(
        self,
        registry: Any | None = None,
        ledger: Any | None = None,
        *,
        run_id: str | None = None,
    ) -> dict[str, str]:
        if registry is None or ledger is None or run_id is None:
            return {item.value: "MISSING_AUTHORITY" for item in RCheck}
        return self.resolve_bundle(registry, ledger, run_id=run_id).status_by_r_check

    def mandatory_pass(
        self,
        registry: Any | None = None,
        ledger: Any | None = None,
        *,
        run_id: str | None = None,
        required_scope: AuthorityScope = AuthorityScope.SCIENTIFIC,
    ) -> bool:
        if not isinstance(required_scope, AuthorityScope):
            raise ValueError("mandatory audit scope must be typed")
        if registry is None or ledger is None or run_id is None:
            return False
        try:
            bundle = self.resolve_bundle(registry, ledger, run_id=run_id)
        except ValueError:
            return False
        return bundle.scope is required_scope and bundle.mandatory_pass

    def hashes(self) -> tuple[str, ...]:
        descriptive = tuple(
            evaluation.sha256 for evaluation in self._bounded_evaluations()
        )
        return (
            descriptive
            if self.authority_bundle_artifact_sha256 is None
            else (*descriptive, self.authority_bundle_artifact_sha256)
        )


def require_gate(
    audit: AuditSummary,
    required: Iterable[EvaluatorClass],
    *,
    r_checks: Iterable[RCheck],
    registry: Any,
    ledger: Any,
    run_id: str,
    required_scope: AuthorityScope = AuthorityScope.SCIENTIFIC,
) -> None:
    if not isinstance(audit, AuditSummary):
        raise ValueError("gate requires an AuditSummary")
    required_values = tuple(islice(required, len(EvaluatorClass) + 1))
    check_values = tuple(islice(r_checks, len(RCheck) + 1))
    if (
        len(required_values) > len(EvaluatorClass)
        or not required_values
        or len(set(required_values)) != len(required_values)
        or any(
            not isinstance(evaluator_class, EvaluatorClass)
            for evaluator_class in required_values
        )
    ):
        raise ValueError("required evaluator classes must be a bounded typed collection")
    if (
        len(check_values) > len(RCheck)
        or not check_values
        or len(set(check_values)) != len(check_values)
        or any(not isinstance(check, RCheck) for check in check_values)
    ):
        raise ValueError("required R checks must be a bounded typed collection")
    if not isinstance(required_scope, AuthorityScope):
        raise ValueError("required gate scope must be typed")
    if audit.authority_bundle_artifact_sha256 is None:
        raise ValueError("audit has no R-check authority bundle")
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    bundle = audit.resolve_bundle(registry, ledger, run_id=run_id)
    if bundle.scope is not required_scope:
        raise ValueError(
            f"gate requires {required_scope.value} authority, got {bundle.scope.value}"
        )
    authorities = tuple(
        resolve_r_check_authority(
            registry,
            ledger,
            authority_artifact_sha256=digest,
            run_id=run_id,
        )
        for digest in bundle.authority_artifact_sha256s
    )
    by_identity = {
        (value.r_check, value.evaluator_class): value for value in authorities
    }
    for check in check_values:
        for evaluator_class in required_values:
            if evaluator_class not in REQUIRED_R_AUTHORITIES[check]:
                raise ValueError(
                    f"{evaluator_class.value} is not an authority for {check.value}"
                )
            authority = by_identity.get((check, evaluator_class))
            if authority is None or authority.status is not AuthorityStatus.PASS:
                raise ValueError(
                    f"missing passing {check.value}/{evaluator_class.value} authority"
                )
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("gate authorities changed during complete owner replay")
