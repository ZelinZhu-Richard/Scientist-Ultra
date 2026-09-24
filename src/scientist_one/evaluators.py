"""Evaluator decisions and R0-R7 audit aggregation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import hashlib
from itertools import islice
import json
import re
from typing import Iterable

from .roles import Role


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

    @property
    def sha256(self) -> str:
        payload = asdict(self)
        payload["evaluator_class"] = self.evaluator_class.value
        payload["actor_role"] = self.actor_role.value
        payload["decision"] = self.decision.value
        payload["r_checks"] = [item.value for item in self.r_checks]
        payload["producer_role"] = self.producer_role.value if self.producer_role else None
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class AuditSummary:
    evaluations: list[Evaluation] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._bounded_evaluations()

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

    def status_by_r_check(self) -> dict[str, str]:
        evaluations = self._bounded_evaluations()
        statuses: dict[str, str] = {item.value: "MISSING" for item in RCheck}
        for check in RCheck:
            related = [evaluation for evaluation in evaluations if check in evaluation.r_checks]
            if any(evaluation.decision is Decision.FAIL for evaluation in related):
                statuses[check.value] = "FAIL"
            elif REQUIRED_R_AUTHORITIES[check].issubset(
                {
                    evaluation.evaluator_class
                    for evaluation in related
                    if evaluation.decision is Decision.PASS and not evaluation.critical_objection
                }
            ):
                statuses[check.value] = "PASS"
            elif related:
                statuses[check.value] = "ADVISORY_ONLY"
        return statuses

    def mandatory_pass(self) -> bool:
        evaluations = self._bounded_evaluations()
        return all(value == "PASS" for value in self.status_by_r_check().values()) and not any(
            evaluation.critical_objection or evaluation.decision is Decision.FAIL
            for evaluation in evaluations
            if evaluation.evaluator_class in {EvaluatorClass.E2, EvaluatorClass.E3}
        )

    def hashes(self) -> tuple[str, ...]:
        return tuple(
            evaluation.sha256 for evaluation in self._bounded_evaluations()
        )


def require_gate(evaluations: Iterable[Evaluation], required: Iterable[EvaluatorClass]) -> None:
    values = tuple(islice(evaluations, MAX_EVALUATION_RECEIPTS + 1))
    required_values = tuple(islice(required, len(EvaluatorClass) + 1))
    if (
        len(values) > MAX_EVALUATION_RECEIPTS
        or any(not isinstance(value, Evaluation) for value in values)
    ):
        raise ValueError("gate evaluations must be a bounded receipt collection")
    if (
        len(required_values) > len(EvaluatorClass)
        or any(
            not isinstance(evaluator_class, EvaluatorClass)
            for evaluator_class in required_values
        )
    ):
        raise ValueError("required evaluator classes must be a bounded typed collection")
    for evaluator_class in required_values:
        if not any(
            item.evaluator_class is evaluator_class and item.decision is Decision.PASS
            for item in values
        ):
            raise ValueError(f"missing passing {evaluator_class.value} evaluation")
    if any(item.critical_objection for item in values):
        raise ValueError("critical evaluator objection blocks the gate")
