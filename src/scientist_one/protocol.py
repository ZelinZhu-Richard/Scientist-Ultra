"""Frozen scientific protocols and study-version lineage.

The protocol model is deliberately dependency-free and deeply immutable.  A
confirmatory reveal never changes a protocol in place: recording a reveal and
creating a revision both return new :class:`StudyVersion` values, preserving
the hash and state of the earlier value.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
from typing import Any, Iterable

from .errors import ValidationError


DEFAULT_VALIDITY_RESERVE = 0.40
MIN_VALIDITY_RESERVE = 0.30
MAX_VALIDITY_RESERVE = 0.50


class ProtocolValidationError(ValidationError):
    """A protocol is incomplete, internally inconsistent, or not immutable."""


class ProtocolStateError(ProtocolValidationError):
    """An operation is invalid for the study's reveal/version state."""


def _nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _nonempty_tuple(values: tuple[Any, ...], field_name: str) -> tuple[Any, ...]:
    if not isinstance(values, tuple) or not values:
        raise ProtocolValidationError(f"{field_name} must be a non-empty tuple")
    return values


def _strings(values: tuple[str, ...], field_name: str, *, allow_empty: bool = False) -> None:
    if not isinstance(values, tuple):
        raise ProtocolValidationError(f"{field_name} must be a tuple")
    if not allow_empty and not values:
        raise ProtocolValidationError(f"{field_name} must not be empty")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ProtocolValidationError(f"{field_name} entries must be non-empty strings")
    if len(set(values)) != len(values):
        raise ProtocolValidationError(f"{field_name} entries must be unique")


def _sha256(value: str, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProtocolValidationError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass(frozen=True, slots=True)
class DataRoles:
    """Frozen identities for each data role; roles must not overlap."""

    train: tuple[str, ...]
    development: tuple[str, ...]
    validation: tuple[str, ...]
    holdout: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("train", "development", "validation", "holdout"):
            _strings(getattr(self, name), f"data_roles.{name}")
        seen: dict[str, str] = {}
        for role in ("train", "development", "validation", "holdout"):
            for identifier in getattr(self, role):
                if identifier in seen:
                    raise ProtocolValidationError(
                        f"data identity {identifier!r} appears in both {seen[identifier]} and {role}"
                    )
                seen[identifier] = role


@dataclass(frozen=True, slots=True)
class ExecutionConditions:
    """Conditions that must be equivalent for a fair baseline comparison."""

    preprocessing: str
    data_access: str
    tuning_budget: int
    early_stopping: str
    compute_budget: float
    feature_set: str
    implementation_verified: bool = True

    def __post_init__(self) -> None:
        for name in ("preprocessing", "data_access", "early_stopping", "feature_set"):
            _nonempty(getattr(self, name), name)
        if (
            isinstance(self.tuning_budget, bool)
            or not isinstance(self.tuning_budget, int)
            or self.tuning_budget < 0
        ):
            raise ProtocolValidationError("tuning_budget must be a non-negative integer")
        if isinstance(self.compute_budget, bool) or not isinstance(self.compute_budget, (int, float)):
            raise ProtocolValidationError("compute_budget must be numeric")
        if not math.isfinite(float(self.compute_budget)) or self.compute_budget <= 0:
            raise ProtocolValidationError("compute_budget must be finite and positive")
        if not isinstance(self.implementation_verified, bool):
            raise ProtocolValidationError("implementation_verified must be boolean")


@dataclass(frozen=True, slots=True)
class BaselineSpec:
    name: str
    conditions: ExecutionConditions

    def __post_init__(self) -> None:
        _nonempty(self.name, "baseline.name")
        if not isinstance(self.conditions, ExecutionConditions):
            raise ProtocolValidationError("baseline.conditions must be ExecutionConditions")


@dataclass(frozen=True, slots=True)
class DomainNullSpec:
    """A preregistered domain null with explicit exchangeability assumptions."""

    name: str
    method: str
    exchangeability_unit: str
    structures_preserved: tuple[str, ...]
    assumptions: tuple[str, ...]
    exchangeability_justified: bool

    def __post_init__(self) -> None:
        for name in ("name", "method", "exchangeability_unit"):
            _nonempty(getattr(self, name), f"domain_null.{name}")
        _strings(self.structures_preserved, "domain_null.structures_preserved")
        _strings(self.assumptions, "domain_null.assumptions")
        if not isinstance(self.exchangeability_justified, bool):
            raise ProtocolValidationError("exchangeability_justified must be boolean")


@dataclass(frozen=True, slots=True)
class StatisticalTestSpec:
    name: str
    test_family: str
    null_name: str
    alternative: str
    alpha: float = 0.05

    def __post_init__(self) -> None:
        for name in ("name", "test_family", "null_name"):
            _nonempty(getattr(self, name), f"statistical_test.{name}")
        if self.alternative not in {"two-sided", "greater", "less"}:
            raise ProtocolValidationError("alternative must be two-sided, greater, or less")
        if isinstance(self.alpha, bool) or not isinstance(self.alpha, (int, float)):
            raise ProtocolValidationError("alpha must be numeric")
        if not math.isfinite(self.alpha) or not 0 < self.alpha < 1:
            raise ProtocolValidationError("alpha must be between zero and one")


@dataclass(frozen=True, slots=True)
class ConfidenceIntervalSpec:
    method: str
    level: float
    resampling_unit: str

    def __post_init__(self) -> None:
        _nonempty(self.method, "confidence_interval.method")
        _nonempty(self.resampling_unit, "confidence_interval.resampling_unit")
        if isinstance(self.level, bool) or not isinstance(self.level, (int, float)):
            raise ProtocolValidationError("confidence interval level must be numeric")
        if not math.isfinite(self.level) or not 0 < self.level < 1:
            raise ProtocolValidationError("confidence interval level must be between zero and one")


@dataclass(frozen=True, slots=True)
class SeedPolicy:
    seeds: tuple[int, ...]
    selection_rule: str
    technical_retry_rule: str

    def __post_init__(self) -> None:
        if not isinstance(self.seeds, tuple) or not self.seeds:
            raise ProtocolValidationError("seed_policy.seeds must be a non-empty tuple")
        if any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in self.seeds):
            raise ProtocolValidationError("seeds must be non-negative integers")
        if len(set(self.seeds)) != len(self.seeds):
            raise ProtocolValidationError("seeds must be unique")
        _nonempty(self.selection_rule, "seed_policy.selection_rule")
        _nonempty(self.technical_retry_rule, "seed_policy.technical_retry_rule")


@dataclass(frozen=True, slots=True)
class ProtocolComputeBudget:
    max_runs: int
    max_wall_seconds: float
    max_cpu_workers: int
    max_gpu_jobs: int = 1

    def __post_init__(self) -> None:
        for name in ("max_runs", "max_cpu_workers"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ProtocolValidationError(f"{name} must be a positive integer")
        if (
            isinstance(self.max_gpu_jobs, bool)
            or not isinstance(self.max_gpu_jobs, int)
            or self.max_gpu_jobs < 0
        ):
            raise ProtocolValidationError("max_gpu_jobs must be a non-negative integer")
        if self.max_gpu_jobs > 1:
            raise ProtocolValidationError("at most one GPU experiment may run at a time")
        if isinstance(self.max_wall_seconds, bool) or not isinstance(
            self.max_wall_seconds, (int, float)
        ):
            raise ProtocolValidationError("max_wall_seconds must be numeric")
        if not math.isfinite(self.max_wall_seconds) or self.max_wall_seconds <= 0:
            raise ProtocolValidationError("max_wall_seconds must be finite and positive")


@dataclass(frozen=True, slots=True)
class InterpretationRules:
    positive: str
    null: str
    contradictory: str
    unstable: str

    def __post_init__(self) -> None:
        for name in ("positive", "null", "contradictory", "unstable"):
            _nonempty(getattr(self, name), f"interpretation_rules.{name}")


@dataclass(frozen=True, slots=True)
class BaselineEquivalenceReport:
    baseline_name: str
    equivalent: bool
    mismatches: tuple[str, ...]


_EQUIVALENCE_FIELDS = (
    "preprocessing",
    "data_access",
    "tuning_budget",
    "early_stopping",
    "compute_budget",
    "feature_set",
)


def baseline_equivalence(
    candidate: ExecutionConditions,
    baseline: BaselineSpec,
) -> BaselineEquivalenceReport:
    """Compare all known researcher-degree-of-freedom dimensions."""

    mismatches = tuple(
        field_name
        for field_name in _EQUIVALENCE_FIELDS
        if getattr(candidate, field_name) != getattr(baseline.conditions, field_name)
    )
    if not candidate.implementation_verified or not baseline.conditions.implementation_verified:
        mismatches += ("implementation_verified",)
    return BaselineEquivalenceReport(baseline.name, not mismatches, mismatches)


def validate_baseline_equivalence(
    candidate: ExecutionConditions,
    baselines: Iterable[BaselineSpec],
    *,
    raise_on_failure: bool = True,
) -> tuple[BaselineEquivalenceReport, ...]:
    reports = tuple(baseline_equivalence(candidate, baseline) for baseline in baselines)
    if not reports:
        raise ProtocolValidationError("at least one baseline is required")
    failures = tuple(report for report in reports if not report.equivalent)
    if failures and raise_on_failure:
        detail = "; ".join(
            f"{report.baseline_name}: {', '.join(report.mismatches)}" for report in failures
        )
        raise ProtocolValidationError(f"baseline equivalence failed: {detail}")
    return reports


@dataclass(frozen=True, slots=True)
class ResearchProtocol:
    """Complete preregistration contract for one study version."""

    study_id: str
    study_version: int
    primary_hypothesis: str
    primary_estimand: str
    primary_metric: str
    secondary_metrics: tuple[str, ...]
    unit_of_analysis: str
    resampling_unit: str
    data_exclusions: tuple[str, ...]
    data_roles: DataRoles
    candidate_conditions: ExecutionConditions
    baseline_set: tuple[BaselineSpec, ...]
    ablation_set: tuple[str, ...]
    negative_controls: tuple[str, ...]
    domain_nulls: tuple[DomainNullSpec, ...]
    statistical_tests: tuple[StatisticalTestSpec, ...]
    confidence_intervals: tuple[ConfidenceIntervalSpec, ...]
    multiple_comparison_correction: str
    seed_policy: SeedPolicy
    compute_budget: ProtocolComputeBudget
    stopping_rules: tuple[str, ...]
    decision_ladder: tuple[str, ...]
    claim_scope_contract: str
    interpretation_rules: InterpretationRules
    validity_reserve_fraction: float = DEFAULT_VALIDITY_RESERVE
    reserve_basis: str = "data"
    parent_protocol_hash: str | None = None
    revision_reason: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "study_id",
            "primary_hypothesis",
            "primary_estimand",
            "primary_metric",
            "unit_of_analysis",
            "resampling_unit",
            "multiple_comparison_correction",
            "claim_scope_contract",
            "reserve_basis",
        ):
            _nonempty(getattr(self, name), name)
        if (
            isinstance(self.study_version, bool)
            or not isinstance(self.study_version, int)
            or self.study_version < 1
        ):
            raise ProtocolValidationError("study_version must be a positive integer")
        _strings(self.secondary_metrics, "secondary_metrics", allow_empty=True)
        _strings(self.data_exclusions, "data_exclusions", allow_empty=True)
        for name in ("ablation_set", "negative_controls", "stopping_rules", "decision_ladder"):
            _strings(getattr(self, name), name)
        _nonempty_tuple(self.baseline_set, "baseline_set")
        _nonempty_tuple(self.domain_nulls, "domain_nulls")
        _nonempty_tuple(self.statistical_tests, "statistical_tests")
        _nonempty_tuple(self.confidence_intervals, "confidence_intervals")
        if not isinstance(self.data_roles, DataRoles):
            raise ProtocolValidationError("data_roles must be DataRoles")
        if not isinstance(self.candidate_conditions, ExecutionConditions):
            raise ProtocolValidationError("candidate_conditions must be ExecutionConditions")
        typed_collections = (
            (self.baseline_set, BaselineSpec, "baseline_set"),
            (self.domain_nulls, DomainNullSpec, "domain_nulls"),
            (self.statistical_tests, StatisticalTestSpec, "statistical_tests"),
            (self.confidence_intervals, ConfidenceIntervalSpec, "confidence_intervals"),
        )
        for values, expected, name in typed_collections:
            if not all(isinstance(value, expected) for value in values):
                raise ProtocolValidationError(f"{name} contains an invalid value")
        if not isinstance(self.seed_policy, SeedPolicy):
            raise ProtocolValidationError("seed_policy must be SeedPolicy")
        if not isinstance(self.compute_budget, ProtocolComputeBudget):
            raise ProtocolValidationError("compute_budget must be ProtocolComputeBudget")
        if not isinstance(self.interpretation_rules, InterpretationRules):
            raise ProtocolValidationError("interpretation_rules must be InterpretationRules")
        if isinstance(self.validity_reserve_fraction, bool) or not isinstance(
            self.validity_reserve_fraction, (int, float)
        ):
            raise ProtocolValidationError("validity_reserve_fraction must be numeric")
        if (
            not math.isfinite(self.validity_reserve_fraction)
            or not MIN_VALIDITY_RESERVE
            <= self.validity_reserve_fraction
            <= MAX_VALIDITY_RESERVE
        ):
            raise ProtocolValidationError(
                f"validity_reserve_fraction must be between {MIN_VALIDITY_RESERVE:.2f} "
                f"and {MAX_VALIDITY_RESERVE:.2f}"
            )
        if self.reserve_basis not in {"data", "compute", "data_and_compute"}:
            raise ProtocolValidationError("reserve_basis must be data, compute, or data_and_compute")
        if self.parent_protocol_hash is None:
            if self.study_version != 1:
                raise ProtocolValidationError("study versions after one require parent_protocol_hash")
            if self.revision_reason is not None:
                raise ProtocolValidationError("initial protocol cannot have a revision_reason")
        else:
            _sha256(self.parent_protocol_hash, "parent_protocol_hash")
            if self.study_version == 1:
                raise ProtocolValidationError("study version one cannot have a parent protocol")
            _nonempty(self.revision_reason or "", "revision_reason")
        null_names = {item.name for item in self.domain_nulls}
        if len(null_names) != len(self.domain_nulls):
            raise ProtocolValidationError("domain null names must be unique")
        baseline_names = {item.name for item in self.baseline_set}
        if len(baseline_names) != len(self.baseline_set):
            raise ProtocolValidationError("baseline names must be unique")
        test_names = {item.name for item in self.statistical_tests}
        if len(test_names) != len(self.statistical_tests):
            raise ProtocolValidationError("statistical test names must be unique")
        missing_nulls = sorted({item.null_name for item in self.statistical_tests} - null_names)
        if missing_nulls:
            raise ProtocolValidationError(
                "statistical tests reference unknown nulls: " + ", ".join(missing_nulls)
            )
        if any(interval.resampling_unit != self.resampling_unit for interval in self.confidence_intervals):
            raise ProtocolValidationError(
                "confidence interval resampling units must match the protocol resampling unit"
            )
        pseudo_units = {
            "seed", "seeds", "fold", "folds", "repeat", "repeats", "timepoint",
            "time_point", "checkpoint", "checkpoints", "model_checkpoint",
        }
        normalized_resampling = self.resampling_unit.casefold().replace(" ", "_").replace("-", "_")
        if normalized_resampling in pseudo_units:
            raise ProtocolValidationError(
                "seeds, folds, repeats, time points, and checkpoints cannot be preregistered "
                "as the confirmatory resampling unit"
            )
        unjustified_nulls = [item.name for item in self.domain_nulls if not item.exchangeability_justified]
        if unjustified_nulls:
            raise ProtocolValidationError(
                "domain nulls lack exchangeability justification: " + ", ".join(unjustified_nulls)
            )
        if (
            len(self.statistical_tests) > 1 or self.secondary_metrics
        ) and self.multiple_comparison_correction.casefold() in {
            "none", "unadjusted", "naive", "not applicable", "n/a",
        }:
            raise ProtocolValidationError("multiple outcomes/tests require a correction plan")
        validate_baseline_equivalence(self.candidate_conditions, self.baseline_set)

    @property
    def canonical_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.canonical_dict)).hexdigest()


@dataclass(frozen=True, slots=True)
class ConfirmatoryRevealRecord:
    release_hash: str
    revealed_at: str

    def __post_init__(self) -> None:
        _sha256(self.release_hash, "release_hash")
        _nonempty(self.revealed_at, "revealed_at")


@dataclass(frozen=True, slots=True)
class StudyVersion:
    """Immutable lifecycle wrapper for a frozen protocol version."""

    protocol: ResearchProtocol
    reveal: ConfirmatoryRevealRecord | None = None
    requires_fresh_confirmatory_reserve: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, ResearchProtocol):
            raise ProtocolValidationError("study version requires ResearchProtocol")
        if self.reveal is not None and not isinstance(self.reveal, ConfirmatoryRevealRecord):
            raise ProtocolValidationError("reveal must be ConfirmatoryRevealRecord when present")
        if not isinstance(self.requires_fresh_confirmatory_reserve, bool):
            raise ProtocolValidationError("requires_fresh_confirmatory_reserve must be boolean")

    @property
    def study_id(self) -> str:
        return self.protocol.study_id

    @property
    def version(self) -> int:
        return self.protocol.study_version

    @property
    def confirmatory_revealed(self) -> bool:
        return self.reveal is not None

    @property
    def protocol_hash(self) -> str:
        return self.protocol.sha256


def freeze_protocol(protocol: ResearchProtocol) -> StudyVersion:
    """Validate and wrap an already deeply frozen protocol."""

    if not isinstance(protocol, ResearchProtocol):
        raise ProtocolValidationError("freeze_protocol requires ResearchProtocol")
    return StudyVersion(protocol=protocol)


def record_confirmatory_reveal(
    study: StudyVersion,
    *,
    release_hash: str,
    revealed_at: str,
) -> StudyVersion:
    """Return a revealed lifecycle value while preserving the unrevealed value."""

    if study.confirmatory_revealed:
        raise ProtocolStateError("a study version can have only one confirmatory reveal")
    return replace(
        study,
        reveal=ConfirmatoryRevealRecord(release_hash=release_hash, revealed_at=revealed_at),
    )


def revise_study_version(
    current: StudyVersion,
    *,
    revision_reason: str,
    changes: dict[str, Any],
) -> StudyVersion:
    """Create a new version; never edit the current or revealed protocol.

    Scientific fields may be changed only through this lineage operation.  A
    revision derived after reveal is marked as requiring a fresh untouched
    confirmatory reserve and may not reuse the prior release.
    """

    _nonempty(revision_reason, "revision_reason")
    forbidden = {"study_id", "study_version", "parent_protocol_hash", "revision_reason"}
    attempted = forbidden.intersection(changes)
    if attempted:
        raise ProtocolStateError(
            "version lineage fields are controller-owned: " + ", ".join(sorted(attempted))
        )
    if not isinstance(changes, dict) or not changes:
        raise ProtocolStateError("changes must be a non-empty mapping")
    try:
        replacement = replace(
            current.protocol,
            **changes,
            study_version=current.version + 1,
            parent_protocol_hash=current.protocol_hash,
            revision_reason=revision_reason,
        )
    except TypeError as exc:
        raise ProtocolStateError("revision contains an unknown protocol field") from exc
    return StudyVersion(
        protocol=replacement,
        reveal=None,
        requires_fresh_confirmatory_reserve=current.confirmatory_revealed,
    )


def validate_study_lineage(parent: StudyVersion, child: StudyVersion) -> None:
    """Fail closed if a revision skips or rewrites lineage."""

    if parent.study_id != child.study_id:
        raise ProtocolStateError("study_id cannot change within a study lineage")
    if child.version != parent.version + 1:
        raise ProtocolStateError("child must be exactly the next study version")
    if child.protocol.parent_protocol_hash != parent.protocol_hash:
        raise ProtocolStateError("child parent_protocol_hash does not bind the parent")
    if parent.confirmatory_revealed and not child.requires_fresh_confirmatory_reserve:
        raise ProtocolStateError("a post-reveal revision requires a fresh confirmatory reserve")


def validate_protocol(protocol: ResearchProtocol) -> tuple[BaselineEquivalenceReport, ...]:
    """Return machine-readable baseline validation after constructor checks."""

    if not isinstance(protocol, ResearchProtocol):
        raise ProtocolValidationError("expected ResearchProtocol")
    return validate_baseline_equivalence(protocol.candidate_conditions, protocol.baseline_set)


__all__ = [
    "DEFAULT_VALIDITY_RESERVE",
    "MIN_VALIDITY_RESERVE",
    "MAX_VALIDITY_RESERVE",
    "ProtocolValidationError",
    "ProtocolStateError",
    "DataRoles",
    "ExecutionConditions",
    "BaselineSpec",
    "DomainNullSpec",
    "StatisticalTestSpec",
    "ConfidenceIntervalSpec",
    "SeedPolicy",
    "ProtocolComputeBudget",
    "InterpretationRules",
    "BaselineEquivalenceReport",
    "ResearchProtocol",
    "ConfirmatoryRevealRecord",
    "StudyVersion",
    "baseline_equivalence",
    "validate_baseline_equivalence",
    "freeze_protocol",
    "record_confirmatory_reveal",
    "revise_study_version",
    "validate_study_lineage",
    "validate_protocol",
]
