"""Deterministic, offline reproduction of frozen Scientist-One results.

The reproduction engine deliberately understands only the local synthetic
fixture format used by the built-in demonstration.  A real experiment runner
is an external provider behind an interface; this module never invokes one or
uses the network.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
from typing import Any, Mapping, Protocol, Sequence

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .domains import SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
from .errors import ArtifactError, PathSecurityError, UnsafeSerializationError
from .experiments import (
    FrozenRunSpec,
    SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA,
    SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA,
    ScientificExecutionAuthority,
    ScientificExecutionOutcome,
    require_scientific_execution_authority,
    require_scientific_execution_run_spec,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .models import MacroState, thaw_json, utc_now, validate_identifier, validate_sha256
from .roles import Role
from .security import (
    DEFAULT_MAX_JSON_BYTES,
    canonical_json_bytes,
    read_confined_bytes,
    safe_json_loads,
    secure_directory,
    open_confined_directory_fd,
)


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_INVENTORY_ENTRIES = 2_048
MAX_INVENTORY_TOTAL_BYTES = 64 * 1024 * 1024
SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS = "SYNTHETIC_CONFIRMATORY_FIXTURE"
ARCHITECTURE_CONTROL_EVIDENCE_CLASS = "ARCHITECTURE_CONTROL"
ARCHITECTURE_CONTROL_EXECUTION_KIND = (
    "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
)
ARCHITECTURE_CONTROL_REPLAY_SCOPE = "REVIEW_ONLY_ARCHITECTURE_CONTROL"
ARCHITECTURE_CONTROL_REPLAY_STATUS = "ARCHITECTURE_CONTROL_REPLAY_PASS"
SCIENTIFIC_CLEAN_RERUN_PLAN_SCHEMA = "scientific_clean_rerun_plan/v1"
SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE = "scientific_clean_rerun_plan"
SCIENTIFIC_CLEAN_RERUN_PLAN_EVENT_SCHEMA = (
    "scientific_clean_rerun_plan_event/v1"
)
SCIENTIFIC_CLEAN_RERUN_AUTHORITY_SCHEMA = (
    "scientific_clean_rerun_authority/v1"
)
SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE = (
    "scientific_clean_rerun_authority"
)
SCIENTIFIC_CLEAN_RERUN_AUTHORITY_EVENT_SCHEMA = (
    "scientific_clean_rerun_authority_event/v1"
)
SCIENTIFIC_CLEAN_RERUN_PLAN_V2_SCHEMA = "scientific_clean_rerun_plan/v2"
SCIENTIFIC_CLEAN_RERUN_PLAN_V2_EVENT_SCHEMA = "scientific_clean_rerun_plan_event/v2"
SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_SCHEMA = "scientific_clean_rerun_authority/v2"
SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_EVENT_SCHEMA = (
    "scientific_clean_rerun_authority_event/v2"
)
BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID = (
    "fixed-complete-bounded-mean-clean-rerun/v1"
)
_SCIENTIFIC_CLEAN_RERUN_PLAN_ORIGIN = (
    "source-owned prospective scientific clean-rerun plan"
)
_SCIENTIFIC_CLEAN_RERUN_PLAN_COMMAND = (
    "scientist-one",
    "prepare-scientific-clean-rerun",
)
_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_ORIGIN = (
    "source-owned independently attested scientific clean-rerun comparison"
)
_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_COMMAND = (
    "scientist-one",
    "verify-scientific-clean-rerun",
)
_SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS = (
    "contract_sha256",
    "hypothesis_id",
    "metric_id",
    "metric_unit",
    "metric_scope",
    "baseline_id",
    "sample_size",
    "hypothesis_status",
    "outcome",
)
_SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS = (
    "candidate_value",
    "baseline_value",
    "improvement_effect",
    "confidence_low",
    "confidence_high",
    "adjusted_p_value",
)
_BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS = (
    *_SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS,
    "inference_profile_id",
    "statistical_use_authority_artifact_sha256",
    "statistical_use_authority_record_hash",
    "seed_order",
    "paired_unit_ids",
    "paired_unit_hashes",
)
_BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS = (
    *_SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS[:-1],
    "mean_zero_p_upper",
)
_BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS = ("candidate_values", "baseline_values")
_CLEAN_RERUN_PROFILE_FIELDS = frozenset({
    "comparison_profile_id", "inference_profile_id",
    "statistical_use_authority_artifact_sha256",
    "statistical_use_authority_record_hash",
})
_CLEAN_RERUN_PLAN_V2_FIELDS = _CLEAN_RERUN_PROFILE_FIELDS | {"grid_comparison_fields"}
_CLEAN_RERUN_AUTHORITY_V2_FIELDS = _CLEAN_RERUN_PROFILE_FIELDS | {
    "grid_comparisons", "new_data_replication_claimed",
    "training_randomness_generalization_claimed",
}
_MAX_CLEAN_RERUN_LEDGER_EVENT_BYTES = 64 * 1024
_SCIENTIFIC_DOMAIN_TRUST_ROOT_BYTES = 32
_ARCHITECTURE_CONTROL_BOUNDARY_KEYS = {
    "evidence_class",
    "replay_scope",
    "scientific_evidence",
    "independent_confirmation",
    "publication_eligible",
}
FROZEN_RECORD_KEYS = {
    "run_id", "status", "reproduction_id", "expected", "observed",
    "absolute_difference", "tolerance", "manifest_path", "result_path",
    "source_result_sha256", "manifest_sha256", "manifest_record_hash",
    "result_sha256", "result_record_hash",
}
FROZEN_MANIFEST_KEYS = {
    "schema_version", "kind", "run_id", "reproduction_id", "created_at",
    "offline", "command", "algorithm", "source_artifacts", "source_ledger",
    "environment", "device_execution", "code_fingerprint",
    "configuration_sha256", "dataset_fixture_ids", "random_seeds",
    "input_hashes", "expected_source_output_hashes", "accepted_tolerance",
    "expected_primary_estimate", "provider", "external_integrations_used",
}
REPRODUCTION_RESULT_KEYS = {
    "schema_version", "kind", "run_id", "reproduction_id", "status",
    "expected_primary_estimate", "observed_primary_estimate",
    "absolute_difference", "accepted_tolerance", "numeric_comparison_passed",
    "reproduced_output_hashes", "expected_source_output_hashes", "input_hashes",
    "code_fingerprint", "configuration_sha256", "dataset_fixture_ids",
    "random_seeds", "source_result_sha256", "frozen_manifest_sha256",
    "discrepancies",
}
ARCHITECTURE_CONTROL_FROZEN_MANIFEST_KEYS = (
    FROZEN_MANIFEST_KEYS | _ARCHITECTURE_CONTROL_BOUNDARY_KEYS
)
ARCHITECTURE_CONTROL_REPRODUCTION_RESULT_KEYS = (
    REPRODUCTION_RESULT_KEYS | _ARCHITECTURE_CONTROL_BOUNDARY_KEYS
)


class ReproductionError(RuntimeError):
    """Raised when a frozen result cannot be safely reproduced."""


def _clean_identifier(value: Any, label: str) -> str:
    try:
        validate_identifier(value, label)
    except Exception as exc:
        raise ReproductionError(f"{label} is invalid") from exc
    return value


def _clean_sha256(value: Any, label: str) -> str:
    try:
        validate_sha256(value, label)
    except Exception as exc:
        raise ReproductionError(f"{label} must be SHA-256") from exc
    return value


def _clean_finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReproductionError(f"{label} must be finite")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError(f"{label} must be finite") from exc
    if not math.isfinite(result):
        raise ReproductionError(f"{label} must be finite")
    return result


def _bounded_clean_finite(value: Any, label: str) -> float:
    if type(value) is not int and type(value) is not float:
        raise ReproductionError(f"{label} must be a finite native number")
    return _clean_finite(value, label)


def _clean_rerun_profile(value: Any) -> bool:
    """All-or-none v2 discriminator; legacy objects acquire no new wire fields."""
    from .bounded_mean_inference import BOUNDED_MEAN_PROFILE_ID

    profile = tuple(getattr(value, name) for name in sorted(_CLEAN_RERUN_PROFILE_FIELDS))
    if all(item is None for item in profile):
        return False
    if (
        value.comparison_profile_id != BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID
        or value.inference_profile_id != BOUNDED_MEAN_PROFILE_ID
    ):
        raise ReproductionError("clean-rerun bounded-mean profile is incomplete or unsupported")
    _clean_sha256(value.statistical_use_authority_artifact_sha256, "statistical-use artifact")
    _clean_sha256(value.statistical_use_authority_record_hash, "statistical-use record")
    return True


def _clean_rerun_profile_dict(value: Any) -> dict[str, Any]:
    return {name: getattr(value, name) for name in sorted(_CLEAN_RERUN_PROFILE_FIELDS)}


def _clean_utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReproductionError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReproductionError(f"{label} is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ReproductionError(f"{label} must be UTC")
    return parsed


class ScientificCleanRerunOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    OUTSIDE_TOLERANCE = "OUTSIDE_TOLERANCE"


class ScientificCleanRerunResolutionStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class ScientificCleanRerunPlan:
    """Prospective protocol for a distinct second scientific execution."""

    plan_id: str
    ledger_run_id: str
    original_result_id: str
    rerun_result_id: str
    rerun_assessment_id: str
    rerun_domain: str
    rerun_domain_task_id: str
    original_execution_run_id: str
    rerun_execution_run_id: str
    original_result_promotion_artifact_sha256: str
    original_result_promotion_record_hash: str
    original_result_assessment_artifact_sha256: str
    original_result_assessment_record_hash: str
    original_execution_authority_artifact_sha256: str
    original_execution_authority_record_hash: str
    rerun_frozen_run_spec_artifact_sha256: str
    rerun_frozen_run_spec_record_hash: str
    scientific_binding_sha256: str
    comparison_tolerance: float
    exact_match_fields: tuple[str, ...]
    numeric_comparison_fields: tuple[str, ...]
    planned_at: str
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    authority_scope: str = "PROSPECTIVE_SCIENTIFIC_CLEAN_RERUN"
    scientific_evidence: bool = False
    comparison_profile_id: str | None = None
    inference_profile_id: str | None = None
    statistical_use_authority_artifact_sha256: str | None = None
    statistical_use_authority_record_hash: str | None = None
    grid_comparison_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "plan_id",
            "ledger_run_id",
            "original_result_id",
            "rerun_result_id",
            "rerun_assessment_id",
            "rerun_domain",
            "rerun_domain_task_id",
            "original_execution_run_id",
            "rerun_execution_run_id",
            "ledger_event_id",
        ):
            object.__setattr__(
                self,
                name,
                _clean_identifier(getattr(self, name), name.replace("_", " ")),
            )
        from .domains import DomainKind

        try:
            object.__setattr__(
                self,
                "rerun_domain",
                DomainKind(self.rerun_domain).value,
            )
        except ValueError as exc:
            raise ReproductionError(
                "clean-rerun domain is unsupported"
            ) from exc
        if self.original_execution_run_id == self.rerun_execution_run_id:
            raise ReproductionError("clean rerun requires a distinct execution run")
        if self.original_result_id == self.rerun_result_id:
            raise ReproductionError("clean rerun requires a distinct Result identity")
        for name in (
            "original_result_promotion_artifact_sha256",
            "original_result_promotion_record_hash",
            "original_result_assessment_artifact_sha256",
            "original_result_assessment_record_hash",
            "original_execution_authority_artifact_sha256",
            "original_execution_authority_record_hash",
            "rerun_frozen_run_spec_artifact_sha256",
            "rerun_frozen_run_spec_record_hash",
            "scientific_binding_sha256",
            "ledger_event_hash",
        ):
            object.__setattr__(
                self,
                name,
                _clean_sha256(getattr(self, name), name.replace("_", " ")),
            )
        bounded = _clean_rerun_profile(self)
        if bounded and self.rerun_domain != DomainKind.GENERIC_ML.value:
            raise ReproductionError("bounded clean-rerun profile requires Generic-ML domain closure")
        tolerance = (_bounded_clean_finite if bounded else _clean_finite)(
            self.comparison_tolerance,
            "clean-rerun comparison tolerance",
        )
        if tolerance < 0:
            raise ReproductionError("clean-rerun tolerance cannot be negative")
        object.__setattr__(self, "comparison_tolerance", tolerance)
        if bounded and any(type(getattr(self, name)) is not tuple for name in (
            "exact_match_fields", "numeric_comparison_fields", "grid_comparison_fields",
        )):
            raise ReproductionError("bounded clean-rerun field sets must be exact tuples")
        if self.exact_match_fields != (
            _BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS if bounded
            else _SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS
        ):
            raise ReproductionError("clean-rerun exact comparison fields changed")
        if self.numeric_comparison_fields != (
            _BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS if bounded
            else _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS
        ):
            raise ReproductionError("clean-rerun numeric comparison fields changed")
        if self.grid_comparison_fields != (
            _BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS if bounded else ()
        ):
            raise ReproductionError("clean-rerun grid comparison fields changed")
        _clean_utc_timestamp(self.planned_at, "clean-rerun planned time")
        if (
            isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
            or self.authority_scope != "PROSPECTIVE_SCIENTIFIC_CLEAN_RERUN"
            or self.scientific_evidence is not False
        ):
            raise ReproductionError("clean-rerun plan exceeds prospective scope")
        if len(set(self.source_artifact_hashes)) != len(
            self.source_artifact_hashes
        ):
            raise ReproductionError("clean-rerun plan sources are aliased")

    @property
    def is_bounded_mean(self) -> bool:
        return self.comparison_profile_id is not None

    @property
    def source_artifact_hashes(self) -> tuple[str, ...]:
        return (
            self.original_result_promotion_artifact_sha256,
            self.original_result_assessment_artifact_sha256,
            self.original_execution_authority_artifact_sha256,
            self.rerun_frozen_run_spec_artifact_sha256,
        ) + ((str(self.statistical_use_authority_artifact_sha256),) if self.is_bounded_mean else ())

    def to_dict(self) -> dict[str, Any]:
        result = {field.name: getattr(self, field.name) for field in fields(self)}
        if self.is_bounded_mean:
            result["schema_version"] = SCIENTIFIC_CLEAN_RERUN_PLAN_V2_SCHEMA
            result["grid_comparison_fields"] = list(self.grid_comparison_fields)
        else:
            result = {key: item for key, item in result.items() if key not in _CLEAN_RERUN_PLAN_V2_FIELDS}
            result["schema_version"] = SCIENTIFIC_CLEAN_RERUN_PLAN_SCHEMA
        result["exact_match_fields"] = list(self.exact_match_fields)
        result["numeric_comparison_fields"] = list(
            self.numeric_comparison_fields
        )
        return result

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ScientificCleanRerunPlan:
        if not isinstance(value, Mapping):
            raise ReproductionError("scientific clean-rerun plan schema is invalid")
        bounded = value.get("schema_version") == SCIENTIFIC_CLEAN_RERUN_PLAN_V2_SCHEMA
        if value.get("schema_version") not in (
            SCIENTIFIC_CLEAN_RERUN_PLAN_SCHEMA, SCIENTIFIC_CLEAN_RERUN_PLAN_V2_SCHEMA,
        ):
            raise ReproductionError("unsupported scientific clean-rerun plan schema")
        names = set(cls.__dataclass_fields__) - (set() if bounded else _CLEAN_RERUN_PLAN_V2_FIELDS)
        if set(value) != names | {"schema_version"}:
            raise ReproductionError("scientific clean-rerun plan schema is invalid")
        try:
            arguments = {name: value[name] for name in names}
            if bounded:
                if any(type(arguments[name]) is not list for name in (
                    "exact_match_fields", "numeric_comparison_fields", "grid_comparison_fields",
                )):
                    raise ReproductionError("bounded clean-rerun wire fields must be arrays")
                arguments["grid_comparison_fields"] = tuple(arguments["grid_comparison_fields"])
                if arguments["comparison_profile_id"] is None:
                    raise ReproductionError("bounded clean-rerun plan omits its profile")
            arguments["exact_match_fields"] = tuple(arguments["exact_match_fields"])
            arguments["numeric_comparison_fields"] = tuple(
                arguments["numeric_comparison_fields"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ReproductionError("scientific clean-rerun plan is malformed") from exc


@dataclass(frozen=True, slots=True)
class ScientificCleanRerunDifference:
    field_name: str
    original_value: float | None
    rerun_value: float | None
    absolute_difference: float | None
    tolerance: float
    within_tolerance: bool

    def __post_init__(self) -> None:
        if self.field_name not in _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS:
            raise ReproductionError("clean-rerun difference field is unsupported")
        tolerance = _clean_finite(self.tolerance, "clean-rerun field tolerance")
        if tolerance < 0:
            raise ReproductionError("clean-rerun field tolerance cannot be negative")
        object.__setattr__(self, "tolerance", tolerance)
        if not isinstance(self.within_tolerance, bool):
            raise ReproductionError("clean-rerun comparison flag must be boolean")
        values = (self.original_value, self.rerun_value)
        if values == (None, None):
            if self.absolute_difference is not None or not self.within_tolerance:
                raise ReproductionError("clean-rerun absent values disagree")
            return
        if None in values:
            if self.absolute_difference is not None or self.within_tolerance:
                raise ReproductionError("clean-rerun optional numeric values disagree")
            return
        original = _clean_finite(self.original_value, "original result value")
        rerun = _clean_finite(self.rerun_value, "rerun result value")
        difference = _clean_finite(
            self.absolute_difference,
            "clean-rerun absolute difference",
        )
        expected = abs(original - rerun)
        if difference != expected or self.within_tolerance is not (expected <= tolerance):
            raise ReproductionError("clean-rerun difference is not deterministic")
        object.__setattr__(self, "original_value", original)
        object.__setattr__(self, "rerun_value", rerun)
        object.__setattr__(self, "absolute_difference", difference)

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> ScientificCleanRerunDifference:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ReproductionError("clean-rerun difference schema is invalid")
        try:
            return cls(**{name: value[name] for name in cls.__dataclass_fields__})
        except (KeyError, TypeError, ValueError) as exc:
            raise ReproductionError("clean-rerun difference is malformed") from exc


@dataclass(frozen=True, slots=True)
class ScientificCleanRerunComparison:
    """Pure mechanical comparison; never scientific authority by itself."""

    exact_mismatches: tuple[str, ...]
    differences: tuple[ScientificCleanRerunDifference, ...]
    outcome: ScientificCleanRerunOutcome
    authority_scope: str = "NON_EVIDENTIARY_MECHANICAL_COMPARISON"
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.exact_mismatches, tuple)
            or any(item not in _SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS for item in self.exact_mismatches)
            or len(set(self.exact_mismatches)) != len(self.exact_mismatches)
            or tuple(item.field_name for item in self.differences)
            != _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS
        ):
            raise ReproductionError("clean-rerun comparison closure is invalid")
        try:
            outcome = ScientificCleanRerunOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise ReproductionError("clean-rerun outcome is invalid") from exc
        object.__setattr__(self, "outcome", outcome)
        expected = (
            ScientificCleanRerunOutcome.FAIL
            if self.exact_mismatches
            else ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE
            if any(not item.within_tolerance for item in self.differences)
            else ScientificCleanRerunOutcome.PASS
        )
        if (
            outcome is not expected
            or self.authority_scope != "NON_EVIDENTIARY_MECHANICAL_COMPARISON"
            or self.scientific_evidence is not False
        ):
            raise ReproductionError("clean-rerun comparison outcome is inconsistent")


@dataclass(frozen=True, slots=True)
class BoundedMeanCleanRerunDifference:
    """Required primary mean inference quantities, never optional legacy p values."""

    field_name: str
    original_value: float
    rerun_value: float
    absolute_difference: float
    tolerance: float
    within_tolerance: bool

    def __post_init__(self) -> None:
        if type(self.field_name) is not str or self.field_name not in _BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS:
            raise ReproductionError("bounded clean-rerun difference field is unsupported")
        for name in ("original_value", "rerun_value", "absolute_difference", "tolerance"):
            object.__setattr__(self, name, _bounded_clean_finite(getattr(self, name), name))
        difference = abs(self.original_value - self.rerun_value)
        if (
            self.tolerance < 0 or self.absolute_difference != difference
            or type(self.within_tolerance) is not bool
            or self.within_tolerance is not (difference <= self.tolerance)
        ):
            raise ReproductionError("bounded clean-rerun difference is not deterministic")
        if self.field_name == "mean_zero_p_upper" and not (
            0 < self.original_value <= 1 and 0 < self.rerun_value <= 1
        ):
            raise ReproductionError("bounded mean-zero probability is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BoundedMeanCleanRerunDifference:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ReproductionError("bounded clean-rerun difference schema is invalid")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class BoundedMeanCleanRerunGridComparison:
    """Compact summary recomputed from all source-owned seed/unit cells."""

    field_name: str
    compared_value_count: int
    maximum_absolute_difference: float
    outside_tolerance_count: int
    tolerance: float
    within_tolerance: bool

    def __post_init__(self) -> None:
        from .bounded_mean_inference import MAX_BOUNDED_MEAN_SEEDS, MAX_BOUNDED_MEAN_UNITS

        if (
            type(self.field_name) is not str
            or self.field_name not in _BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS
            or type(self.compared_value_count) is not int
            or not 1 <= self.compared_value_count <= MAX_BOUNDED_MEAN_UNITS * MAX_BOUNDED_MEAN_SEEDS
            or type(self.outside_tolerance_count) is not int
            or not 0 <= self.outside_tolerance_count <= self.compared_value_count
            or type(self.within_tolerance) is not bool
        ):
            raise ReproductionError("bounded clean-rerun grid closure is invalid")
        for name in ("maximum_absolute_difference", "tolerance"):
            object.__setattr__(self, name, _bounded_clean_finite(getattr(self, name), name))
        if (
            self.tolerance < 0 or not 0 <= self.maximum_absolute_difference <= 1
            or self.within_tolerance is not (self.outside_tolerance_count == 0)
            or self.within_tolerance is not (self.maximum_absolute_difference <= self.tolerance)
        ):
            raise ReproductionError("bounded clean-rerun grid summary is inconsistent")

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> BoundedMeanCleanRerunGridComparison:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ReproductionError("bounded clean-rerun grid schema is invalid")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class BoundedMeanCleanRerunComparison:
    """Non-evidentiary execution repeat, not new-data or seed generalization.

    The native source owner replays mean-zero log/underflow and auxiliary sign
    diagnostics. They are not clean-rerun acceptance fields: a probability
    tolerance does not define a log tolerance or a different sign estimand.
    """

    exact_mismatches: tuple[str, ...]
    differences: tuple[BoundedMeanCleanRerunDifference, ...]
    grid_comparisons: tuple[BoundedMeanCleanRerunGridComparison, ...]
    outcome: ScientificCleanRerunOutcome
    comparison_profile_id: str = BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID
    authority_scope: str = "NON_EVIDENTIARY_MECHANICAL_COMPARISON"
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.exact_mismatches) is not tuple
            or any(type(item) is not str or item not in _BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS for item in self.exact_mismatches)
            or len(set(self.exact_mismatches)) != len(self.exact_mismatches)
            or type(self.differences) is not tuple
            or any(type(item) is not BoundedMeanCleanRerunDifference for item in self.differences)
            or tuple(item.field_name for item in self.differences) != _BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS
            or type(self.grid_comparisons) is not tuple
            or any(type(item) is not BoundedMeanCleanRerunGridComparison for item in self.grid_comparisons)
            or tuple(item.field_name for item in self.grid_comparisons) != _BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS
            or len({item.tolerance for item in (*self.differences, *self.grid_comparisons)}) != 1
            or len({item.compared_value_count for item in self.grid_comparisons}) != 1
        ):
            raise ReproductionError("bounded clean-rerun comparison closure is invalid")
        if self.exact_mismatches != tuple(name for name in _BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS
                                          if name in self.exact_mismatches):
            raise ReproductionError("bounded clean-rerun mismatch ordering is not canonical")
        try:
            outcome = ScientificCleanRerunOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise ReproductionError("bounded clean-rerun outcome is invalid") from exc
        expected = (
            ScientificCleanRerunOutcome.FAIL if self.exact_mismatches else
            ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE
            if any(not item.within_tolerance for item in (*self.differences, *self.grid_comparisons))
            else ScientificCleanRerunOutcome.PASS
        )
        if (
            outcome is not expected
            or self.comparison_profile_id != BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID
            or self.authority_scope != "NON_EVIDENTIARY_MECHANICAL_COMPARISON"
            or self.scientific_evidence is not False
        ):
            raise ReproductionError("bounded clean-rerun comparison outcome is inconsistent")
        object.__setattr__(self, "outcome", outcome)


@dataclass(frozen=True, slots=True)
class ScientificCleanRerunAuthority:
    """Scientific comparison of two source-owned, independent executions."""

    authority_id: str
    ledger_run_id: str
    plan_artifact_sha256: str
    plan_record_hash: str
    original_result_promotion_artifact_sha256: str
    original_result_promotion_record_hash: str
    original_result_id: str
    rerun_result_id: str
    rerun_assessment_id: str
    rerun_domain_validity_receipt_artifact_sha256: str
    rerun_domain_validity_receipt_record_hash: str
    rerun_domain: str
    rerun_domain_task_id: str
    rerun_domain_validity_status: str
    rerun_domain_evidence_scope: str
    original_result_assessment_artifact_sha256: str
    original_result_assessment_record_hash: str
    rerun_result_assessment_artifact_sha256: str
    rerun_result_assessment_record_hash: str
    original_execution_authority_artifact_sha256: str
    original_execution_authority_record_hash: str
    rerun_execution_authority_artifact_sha256: str
    rerun_execution_authority_record_hash: str
    original_execution_run_id: str
    rerun_execution_run_id: str
    original_preparation_artifact_sha256: str
    rerun_preparation_artifact_sha256: str
    original_output_manifest_artifact_sha256: str
    rerun_output_manifest_artifact_sha256: str
    original_environment_artifact_sha256: str
    original_environment_record_hash: str
    rerun_environment_artifact_sha256: str
    rerun_environment_record_hash: str
    original_isolation_attestation_artifact_sha256: str
    rerun_isolation_attestation_artifact_sha256: str
    original_environment_fingerprint: str
    rerun_environment_fingerprint: str
    original_host_instance_id: str
    rerun_host_instance_id: str
    original_boot_session_id: str
    rerun_boot_session_id: str
    original_writable_storage_id: str
    rerun_writable_storage_id: str
    original_backend_namespace_sha256: str
    rerun_backend_namespace_sha256: str
    original_backend_job_id: str
    rerun_backend_job_id: str
    original_provider_invocation_id: str
    rerun_provider_invocation_id: str
    original_cache_used: bool
    original_checkpoint_used: bool
    original_resumed_from_checkpoint: bool
    rerun_cache_used: bool
    rerun_checkpoint_used: bool
    rerun_resumed_from_checkpoint: bool
    original_challenge_nonce: str
    rerun_challenge_nonce: str
    exact_mismatches: tuple[str, ...]
    differences: tuple[ScientificCleanRerunDifference, ...] | tuple[BoundedMeanCleanRerunDifference, ...]
    outcome: ScientificCleanRerunOutcome
    verification_event_id: str
    verification_event_hash: str
    verification_event_index: int
    authority_scope: str = "SCIENTIFIC_CLEAN_RERUN_COMPARISON"
    scientific_evidence: bool = True
    comparison_profile_id: str | None = None
    inference_profile_id: str | None = None
    statistical_use_authority_artifact_sha256: str | None = None
    statistical_use_authority_record_hash: str | None = None
    grid_comparisons: tuple[BoundedMeanCleanRerunGridComparison, ...] = ()
    new_data_replication_claimed: bool = False
    training_randomness_generalization_claimed: bool = False

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "ledger_run_id",
            "original_result_id",
            "rerun_result_id",
            "rerun_assessment_id",
            "original_execution_run_id",
            "rerun_execution_run_id",
            "original_host_instance_id",
            "rerun_host_instance_id",
            "original_boot_session_id",
            "rerun_boot_session_id",
            "original_writable_storage_id",
            "rerun_writable_storage_id",
            "verification_event_id",
        ):
            object.__setattr__(
                self,
                name,
                _clean_identifier(getattr(self, name), name.replace("_", " ")),
            )
        for name in (
            "plan_artifact_sha256",
            "plan_record_hash",
            "original_result_promotion_artifact_sha256",
            "original_result_promotion_record_hash",
            "rerun_domain_validity_receipt_artifact_sha256",
            "rerun_domain_validity_receipt_record_hash",
            "original_result_assessment_artifact_sha256",
            "original_result_assessment_record_hash",
            "rerun_result_assessment_artifact_sha256",
            "rerun_result_assessment_record_hash",
            "original_execution_authority_artifact_sha256",
            "original_execution_authority_record_hash",
            "rerun_execution_authority_artifact_sha256",
            "rerun_execution_authority_record_hash",
            "original_preparation_artifact_sha256",
            "rerun_preparation_artifact_sha256",
            "original_output_manifest_artifact_sha256",
            "rerun_output_manifest_artifact_sha256",
            "original_environment_artifact_sha256",
            "original_environment_record_hash",
            "rerun_environment_artifact_sha256",
            "rerun_environment_record_hash",
            "original_isolation_attestation_artifact_sha256",
            "rerun_isolation_attestation_artifact_sha256",
            "original_environment_fingerprint",
            "rerun_environment_fingerprint",
            "original_backend_namespace_sha256",
            "rerun_backend_namespace_sha256",
            "verification_event_hash",
        ):
            object.__setattr__(
                self,
                name,
                _clean_sha256(getattr(self, name), name.replace("_", " ")),
            )
        for name in ("rerun_domain", "rerun_domain_task_id"):
            object.__setattr__(
                self,
                name,
                _clean_identifier(getattr(self, name), name.replace("_", " ")),
            )
        if (
            self.rerun_domain_validity_status != "PASS"
            or self.rerun_domain_evidence_scope != "SCIENTIFIC_EVIDENCE"
        ):
            raise ReproductionError(
                "scientific clean rerun requires source-owned rerun domain PASS"
            )
        distinct_pairs = (
            (self.original_result_id, self.rerun_result_id),
            (self.original_execution_run_id, self.rerun_execution_run_id),
            (
                self.original_execution_authority_artifact_sha256,
                self.rerun_execution_authority_artifact_sha256,
            ),
            (
                self.original_preparation_artifact_sha256,
                self.rerun_preparation_artifact_sha256,
            ),
            (
                self.original_output_manifest_artifact_sha256,
                self.rerun_output_manifest_artifact_sha256,
            ),
            (
                self.original_environment_artifact_sha256,
                self.rerun_environment_artifact_sha256,
            ),
            (
                self.original_isolation_attestation_artifact_sha256,
                self.rerun_isolation_attestation_artifact_sha256,
            ),
            (
                self.original_writable_storage_id,
                self.rerun_writable_storage_id,
            ),
            (
                self.original_challenge_nonce,
                self.rerun_challenge_nonce,
            ),
        )
        if any(original == rerun for original, rerun in distinct_pairs):
            raise ReproductionError(
                "scientific clean rerun does not prove independent execution"
            )
        for name in (
            "original_backend_job_id",
            "rerun_backend_job_id",
            "original_provider_invocation_id",
            "rerun_provider_invocation_id",
        ):
            object.__setattr__(
                self,
                name,
                _clean_identifier(getattr(self, name), name.replace("_", " ")),
            )
        if (
            self.original_backend_namespace_sha256
            == self.rerun_backend_namespace_sha256
            and (
                self.original_backend_job_id == self.rerun_backend_job_id
                or self.original_provider_invocation_id
                == self.rerun_provider_invocation_id
            )
        ):
            raise ReproductionError(
                "scientific clean rerun reuses a backend execution identity"
            )
        for nonce in (self.original_challenge_nonce, self.rerun_challenge_nonce):
            if (
                not isinstance(nonce, str)
                or len(nonce) != 64
                or any(character not in "0123456789abcdef" for character in nonce)
            ):
                raise ReproductionError("clean-rerun challenge nonce is invalid")
        for name in (
            "original_cache_used",
            "original_checkpoint_used",
            "original_resumed_from_checkpoint",
            "rerun_cache_used",
            "rerun_checkpoint_used",
            "rerun_resumed_from_checkpoint",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ReproductionError(
                    "clean-rerun isolation-use flags must be boolean"
                )
        if (
            self.rerun_cache_used
            or self.rerun_checkpoint_used
            or self.rerun_resumed_from_checkpoint
        ):
            raise ReproductionError(
                "scientific clean rerun must not use cache or checkpoint state"
            )
        if _clean_rerun_profile(self):
            if self.rerun_domain != "GENERIC_ML":
                raise ReproductionError("bounded clean-rerun authority requires Generic-ML domain closure")
            comparison = BoundedMeanCleanRerunComparison(
                exact_mismatches=self.exact_mismatches,
                differences=self.differences,
                grid_comparisons=self.grid_comparisons,
                outcome=self.outcome,
            )
        else:
            if self.grid_comparisons:
                raise ReproductionError("legacy clean-rerun authority cannot contain grid comparisons")
            comparison = ScientificCleanRerunComparison(
                exact_mismatches=self.exact_mismatches,
                differences=self.differences,
                outcome=self.outcome,
            )
        if (
            self.new_data_replication_claimed is not False
            or self.training_randomness_generalization_claimed is not False
        ):
            raise ReproductionError("clean execution repeat does not establish new-data or seed generalization")
        object.__setattr__(self, "outcome", comparison.outcome)
        if (
            isinstance(self.verification_event_index, bool)
            or not isinstance(self.verification_event_index, int)
            or self.verification_event_index < 0
            or self.authority_scope != "SCIENTIFIC_CLEAN_RERUN_COMPARISON"
            or self.scientific_evidence is not True
        ):
            raise ReproductionError("scientific clean-rerun authority is invalid")
        if (
            len(self.source_artifact_hashes) > MAX_ARTIFACT_PARENTS
            or len(set(self.source_artifact_hashes))
            != len(self.source_artifact_hashes)
        ):
            raise ReproductionError(
                "scientific clean-rerun authority source closure is ambiguous"
            )

    @property
    def reproduction_passed(self) -> bool:
        return self.outcome is ScientificCleanRerunOutcome.PASS

    @property
    def is_bounded_mean(self) -> bool:
        return self.comparison_profile_id is not None

    @property
    def source_artifact_hashes(self) -> tuple[str, ...]:
        return (
            self.plan_artifact_sha256,
            self.original_result_promotion_artifact_sha256,
            self.rerun_domain_validity_receipt_artifact_sha256,
            self.original_result_assessment_artifact_sha256,
            self.rerun_result_assessment_artifact_sha256,
            self.original_execution_authority_artifact_sha256,
            self.rerun_execution_authority_artifact_sha256,
            self.original_environment_artifact_sha256,
            self.rerun_environment_artifact_sha256,
            self.original_isolation_attestation_artifact_sha256,
            self.rerun_isolation_attestation_artifact_sha256,
        ) + ((str(self.statistical_use_authority_artifact_sha256),) if self.is_bounded_mean else ())

    def to_dict(self) -> dict[str, Any]:
        result = {field.name: getattr(self, field.name) for field in fields(self)}
        if self.is_bounded_mean:
            result["schema_version"] = SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_SCHEMA
            result["grid_comparisons"] = [item.to_dict() for item in self.grid_comparisons]
        else:
            result = {key: item for key, item in result.items() if key not in _CLEAN_RERUN_AUTHORITY_V2_FIELDS}
            result["schema_version"] = SCIENTIFIC_CLEAN_RERUN_AUTHORITY_SCHEMA
        result["exact_mismatches"] = list(self.exact_mismatches)
        result["differences"] = [item.to_dict() for item in self.differences]
        result["outcome"] = self.outcome.value
        return result

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> ScientificCleanRerunAuthority:
        if not isinstance(value, Mapping):
            raise ReproductionError(
                "scientific clean-rerun authority schema is invalid"
            )
        bounded = value.get("schema_version") == SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_SCHEMA
        if value.get("schema_version") not in (
            SCIENTIFIC_CLEAN_RERUN_AUTHORITY_SCHEMA, SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_SCHEMA,
        ):
            raise ReproductionError(
                "unsupported scientific clean-rerun authority schema"
            )
        names = set(cls.__dataclass_fields__) - (set() if bounded else _CLEAN_RERUN_AUTHORITY_V2_FIELDS)
        if set(value) != names | {"schema_version"}:
            raise ReproductionError("scientific clean-rerun authority schema is invalid")
        try:
            arguments = {name: value[name] for name in names}
            if bounded and any(type(arguments[name]) is not list for name in (
                "exact_mismatches", "differences", "grid_comparisons",
            )):
                raise ReproductionError("bounded clean-rerun wire comparisons must be arrays")
            arguments["exact_mismatches"] = tuple(arguments["exact_mismatches"])
            difference_type = BoundedMeanCleanRerunDifference if bounded else ScientificCleanRerunDifference
            arguments["differences"] = tuple(
                difference_type.from_mapping(item)
                for item in arguments["differences"]
            )
            if bounded:
                if arguments["comparison_profile_id"] is None:
                    raise ReproductionError("bounded clean-rerun authority omits its profile")
                arguments["grid_comparisons"] = tuple(
                    BoundedMeanCleanRerunGridComparison.from_mapping(item)
                    for item in arguments["grid_comparisons"]
                )
            arguments["outcome"] = ScientificCleanRerunOutcome(
                arguments["outcome"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ReproductionError(
                "scientific clean-rerun authority is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificCleanRerunAuthorityResolution:
    status: ScientificCleanRerunResolutionStatus
    reason_code: str
    reason: str
    plan_artifact_sha256: str
    authority_artifact_sha256: str | None = None
    authority: ScientificCleanRerunAuthority | None = None

    def __post_init__(self) -> None:
        try:
            status = ScientificCleanRerunResolutionStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ReproductionError("clean-rerun resolution status is invalid") from exc
        object.__setattr__(self, "status", status)
        _clean_identifier(self.reason_code, "clean-rerun reason code")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ReproductionError("clean-rerun resolution reason is invalid")
        _clean_sha256(self.plan_artifact_sha256, "clean-rerun plan artifact")
        if self.authority_artifact_sha256 is not None:
            _clean_sha256(
                self.authority_artifact_sha256,
                "clean-rerun authority artifact",
            )
        if status is ScientificCleanRerunResolutionStatus.AUTHORIZED:
            if (
                self.authority_artifact_sha256 is None
                or not isinstance(self.authority, ScientificCleanRerunAuthority)
            ):
                raise ReproductionError(
                    "authorized clean-rerun resolution lacks its authority"
                )
        elif self.authority_artifact_sha256 is not None or self.authority is not None:
            raise ReproductionError(
                "blocked clean-rerun resolution cannot carry an authority"
            )


class ExperimentReplayProvider(Protocol):
    """Narrow interface for a future, separately authorized real runner."""

    def replay(self, frozen_manifest: Mapping[str, Any]) -> Mapping[str, Any]:
        """Replay a frozen manifest without changing its source evidence."""


@dataclass(frozen=True)
class ReproductionResult:
    run_id: str
    status: str
    reproduction_id: str
    expected: float
    observed: float
    absolute_difference: float
    tolerance: float
    manifest_path: str
    result_path: str
    source_result_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _require_clean_rerun_runtime(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    ledger_run_id: str,
) -> tuple[LedgerEvent, ...]:
    _, ledger_snapshot = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        ledger_run_id,
    )
    return ledger_snapshot.events


def _validate_clean_rerun_runtime_identity(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    ledger_run_id: str,
) -> None:
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ReproductionError(
            "scientific clean rerun requires exact registry and ledger"
        )
    _clean_identifier(ledger_run_id, "scientific clean-rerun ledger run ID")
    if (
        registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise ReproductionError(
            "scientific clean rerun requires canonical paired registry and ledger"
        )


def _locked_clean_rerun_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    ledger_run_id: str,
) -> tuple[RegistryValidationResult, LedgerValidationResult]:
    """Capture one exact registry->ledger snapshot without nested owner calls."""

    _validate_clean_rerun_runtime_identity(registry, ledger, ledger_run_id)
    # Materialize each subsystem's root lock before nesting them.  Creating the
    # ledger lock while the registry guard is open would itself change the
    # registry guard's pinned root namespace on a new run directory.
    try:
        registry.verify_all(raise_on_error=True)
        ledger.assert_valid()
    except Exception as exc:
        raise ReproductionError(
            "scientific clean-rerun registry or ledger cannot be verified"
        ) from exc
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            registry_snapshot = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            ledger_snapshot = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if not ledger_snapshot.valid:
                raise ReproductionError(
                    "scientific clean-rerun ledger is invalid"
                )
        finally:
            ledger._unlock(ledger_guard)
    except ReproductionError:
        raise
    except Exception as exc:
        raise ReproductionError(
            "scientific clean-rerun registry or ledger cannot be verified"
        ) from exc
    finally:
        registry._unlock_mutation(registry_guard)
    if ledger_snapshot.events and any(
        event.run_id != ledger_run_id for event in ledger_snapshot.events
    ):
        raise ReproductionError("scientific clean-rerun ledger names another run")
    return registry_snapshot, ledger_snapshot


def _require_clean_rerun_snapshot_unchanged(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    ledger_run_id: str,
    expected_registry: RegistryValidationResult,
    expected_ledger: LedgerValidationResult,
) -> None:
    current_registry, current_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        ledger_run_id,
    )
    if current_registry != expected_registry or current_ledger != expected_ledger:
        raise ReproductionError(
            "scientific clean-rerun sources changed during fresh replay"
        )


def _load_clean_rerun_json(
    registry: ArtifactRegistry,
    artifact_sha256: str,
    *,
    logical_type: str,
    creator_role: Role,
    schema_version: str | tuple[str, ...] = "1.0",
) -> tuple[ArtifactRecord, Mapping[str, Any]]:
    _clean_sha256(artifact_sha256, f"{logical_type} artifact")
    try:
        registry.verify(artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(artifact_sha256)
        if record.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError(f"{logical_type} exceeds bounded JSON size")
        raw = registry.get_bytes(artifact_sha256)
        value = safe_json_loads(raw)
    except Exception as exc:
        raise ReproductionError(f"{logical_type} cannot be reopened") from exc
    if (
        record.logical_type != logical_type
        or record.creator_role is not creator_role
        or record.schema_version not in (
            (schema_version,) if isinstance(schema_version, str) else schema_version
        )
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or not record.frozen
        or record.record_hash is None
        or not isinstance(value, Mapping)
        or raw != canonical_json_bytes(value) + b"\n"
    ):
        raise ReproductionError(f"{logical_type} metadata or bytes are not exact")
    return record, value


@dataclass(frozen=True, slots=True)
class _CleanRerunPlanSources:
    result_promotion_record: ArtifactRecord
    result_resolution: Any
    assessment_record: ArtifactRecord
    original_execution_record: ArtifactRecord
    original_execution: ScientificExecutionAuthority
    rerun_spec_record: ArtifactRecord
    rerun_spec: FrozenRunSpec
    original_promotion_event_index: int
    original_domain_event_index: int
    statistical_use_record: ArtifactRecord | None = None

    @property
    def source_records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.result_promotion_record,
            self.assessment_record,
            self.original_execution_record,
            self.rerun_spec_record,
        ) + ((self.statistical_use_record,) if self.statistical_use_record else ())

    @property
    def profile_fields(self) -> dict[str, Any]:
        if self.statistical_use_record is None:
            return {}
        from .bounded_mean_inference import BOUNDED_MEAN_PROFILE_ID

        return {
            "comparison_profile_id": BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID,
            "inference_profile_id": BOUNDED_MEAN_PROFILE_ID,
            "statistical_use_authority_artifact_sha256": self.statistical_use_record.sha256,
            "statistical_use_authority_record_hash": str(self.statistical_use_record.record_hash),
        }


def _clean_rerun_owned_domain_publication_index(
    events: tuple[LedgerEvent, ...], receipt_sha256: str,
) -> int:
    """Locate the exact event after the caller replays the full domain owner."""
    from .domains import _scientific_domain_validity_event_id

    event_id = _scientific_domain_validity_event_id(receipt_sha256)
    indexes = tuple(index for index, event in enumerate(events) if event.event_id == event_id)
    if len(indexes) != 1:
        raise ReproductionError("clean-rerun domain publication is absent or ambiguous")
    return indexes[0]


def _resolve_clean_rerun_plan_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    ledger_run_id: str,
    original_result_id: str,
    original_execution_run_id: str,
    original_result_promotion_artifact_sha256: str,
    rerun_frozen_run_spec_artifact_sha256: str,
) -> _CleanRerunPlanSources:
    from .scientific_design import (
        ScientificResultPromotionReceiptV3,
        _resolve_scientific_result_promotion_v3_event_from_events,
        _scientific_result_promotion_v3_event_binding,
        require_scientific_result_promotion_authority_v3,
    )

    resolution = require_scientific_result_promotion_authority_v3(
        registry,
        ledger,
        promotion_receipt_artifact_sha256=(
            original_result_promotion_artifact_sha256
        ),
        expected_ledger_run_id=ledger_run_id,
        expected_execution_run_id=original_execution_run_id,
        expected_result_id=original_result_id,
    )
    result_record = registry.get_metadata(
        original_result_promotion_artifact_sha256
    )
    # Resolve the assessment identity from the authoritative outer receipt;
    # the returned assessment object deliberately does not self-name its
    # registry artifact.
    receipt_value = safe_json_loads(
        registry.get_bytes(original_result_promotion_artifact_sha256)
    )
    assessment_sha256 = (
        receipt_value.get("checked_result_assessment_artifact_sha256")
        if isinstance(receipt_value, Mapping)
        else None
    )
    if not isinstance(assessment_sha256, str):
        raise ReproductionError(
            "scientific result promotion omits its checked assessment"
        )
    # The full owner above qualified this exact receipt. Use its own event
    # parser to retain admission order, never an arbitrary later artifact use.
    receipt = ScientificResultPromotionReceiptV3.from_dict(receipt_value)
    promotion_sources = tuple(registry.get_metadata(digest) for digest in receipt.source_artifact_hashes)
    promotion_event = _resolve_scientific_result_promotion_v3_event_from_events(
        ledger.events(), receipt=receipt, receipt_record=result_record,
        source_records=promotion_sources,
        binding=_scientific_result_promotion_v3_event_binding(
            receipt=receipt, receipt_record=result_record, source_records=promotion_sources,
        ),
    )
    if promotion_event is None:
        raise ReproductionError("clean-rerun original Result promotion is unpublished")
    assessment_record = registry.get_metadata(assessment_sha256)
    execution_sha256 = (
        resolution.assessment.scientific_execution_authority_artifact_sha256
    )
    original_execution = require_scientific_execution_authority(
        registry,
        ledger,
        authority_artifact_sha256=execution_sha256,
        expected_ledger_run_id=ledger_run_id,
        expected_execution_run_id=original_execution_run_id,
    )
    original_execution_record = registry.get_metadata(execution_sha256)
    rerun_spec = require_scientific_execution_run_spec(
        registry,
        frozen_run_spec_artifact_sha256=(
            rerun_frozen_run_spec_artifact_sha256
        ),
    )
    rerun_spec_record = registry.get_metadata(
        rerun_frozen_run_spec_artifact_sha256
    )
    if (
        resolution.assessment.execution_run_id != original_execution_run_id
        or original_execution.outcome is not ScientificExecutionOutcome.COMPLETED
        or not original_execution.scientific_evidence_eligible
        or rerun_spec.run_id == original_execution_run_id
        or rerun_spec.scientific_binding_sha256
        != original_execution.scientific_binding_sha256
    ):
        raise ReproductionError(
            "clean-rerun plan does not bind a distinct equivalent scientific attempt"
        )
    for record in (
        result_record,
        assessment_record,
        original_execution_record,
        rerun_spec_record,
    ):
        if record.record_hash is None:
            raise ReproductionError("clean-rerun source lacks a record hash")
    statistical_use_record = None
    if resolution.assessment.is_bounded_mean:
        from .experiments import (
            resolve_scientific_reference_work_binding,
            resolve_scientific_statistical_use_binding,
        )

        original_spec = require_scientific_execution_run_spec(
            registry,
            frozen_run_spec_artifact_sha256=original_execution.frozen_run_spec_artifact_sha256,
        )
        uses = tuple(
            resolve_scientific_statistical_use_binding(
                registry, spec=spec,
                expected_contract_artifact_sha256=resolution.assessment.contract_artifact_sha256,
            )
            for spec in (original_spec, rerun_spec)
        )
        if any(
            use is None
            or use.run_id != ledger_run_id  # Ledger identity, never execution_run_id.
            or use.artifact_hash != resolution.assessment.statistical_use_authority_artifact_sha256
            or use.record_hash != resolution.assessment.statistical_use_authority_record_hash
            or use.profile_id != resolution.assessment.inference_profile_id
            for use in uses
        ) or uses[0].bounded_mean_plan != uses[1].bounded_mean_plan:
            raise ReproductionError("bounded clean-rerun plan differs from its prospective statistical use")
        statistical_use_record = registry.get_metadata(uses[0].artifact_hash)
        if statistical_use_record.record_hash != uses[0].record_hash:
            raise ReproductionError("bounded clean-rerun statistical-use record differs")
        reference_bindings = tuple(
            resolve_scientific_reference_work_binding(
                registry, spec=spec,
                expected_contract_artifact_sha256=resolution.assessment.contract_artifact_sha256,
            )
            for spec in (original_spec, rerun_spec)
        )
        if any(binding is not None for binding in reference_bindings):
            original_reference, rerun_reference = reference_bindings
            if any(binding is None for binding in reference_bindings):
                raise ReproductionError("clean rerun cannot mix legacy and fixed-model reference-work profiles")
            if (
                any(binding.run_id != ledger_run_id for binding in reference_bindings)
                or original_reference.execution_run_id != original_execution_run_id
                or rerun_reference.execution_run_id != rerun_spec.run_id
                or any(binding.statistical_use_record != statistical_use_record for binding in reference_bindings)
                or original_reference.policy != rerun_reference.policy
                or original_reference.reference_work != rerun_reference.reference_work
                or original_reference.timeout_seconds != rerun_reference.timeout_seconds
                or original_reference.contract_wall_cap_seconds != rerun_reference.contract_wall_cap_seconds
                or original_reference.source_records != rerun_reference.source_records
            ):
                raise ReproductionError("clean rerun changes its prospectively bound fixed-model reference work")
    return _CleanRerunPlanSources(
        result_promotion_record=result_record,
        result_resolution=resolution,
        assessment_record=assessment_record,
        original_execution_record=original_execution_record,
        original_execution=original_execution,
        rerun_spec_record=rerun_spec_record,
        rerun_spec=rerun_spec,
        original_promotion_event_index=promotion_event[1],
        original_domain_event_index=_clean_rerun_owned_domain_publication_index(
            ledger.events(), receipt.domain_validity_receipt_artifact_sha256,
        ),
        statistical_use_record=statistical_use_record,
    )


def _scientific_clean_rerun_plan_binding(
    *,
    plan_id: str,
    ledger_run_id: str,
    original_result_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_domain: str,
    rerun_domain_task_id: str,
    sources: _CleanRerunPlanSources,
) -> dict[str, Any]:
    bounded = sources.statistical_use_record is not None
    value = {
        "schema_version": (SCIENTIFIC_CLEAN_RERUN_PLAN_V2_EVENT_SCHEMA if bounded
                           else SCIENTIFIC_CLEAN_RERUN_PLAN_EVENT_SCHEMA),
        "kind": "SCIENTIFIC_CLEAN_RERUN_PLANNED",
        "plan_id": plan_id,
        "ledger_run_id": ledger_run_id,
        "original_result_id": original_result_id,
        "rerun_result_id": rerun_result_id,
        "rerun_assessment_id": rerun_assessment_id,
        "rerun_domain": rerun_domain,
        "rerun_domain_task_id": rerun_domain_task_id,
        "original_execution_run_id": (
            sources.original_execution.execution_run_id
        ),
        "rerun_execution_run_id": sources.rerun_spec.run_id,
        "source_artifact_sha256s": [
            item.sha256 for item in sources.source_records
        ],
        "source_artifact_record_hashes": [
            str(item.record_hash) for item in sources.source_records
        ],
        "scientific_binding_sha256": (
            sources.rerun_spec.scientific_binding_sha256
        ),
        "comparison_tolerance": sources.rerun_spec.comparison_tolerance,
        "exact_match_fields": list(_BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS if bounded
                                   else _SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS),
        "numeric_comparison_fields": list(
            _BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS if bounded
            else _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS
        ),
        "authority_scope": "PROSPECTIVE_SCIENTIFIC_CLEAN_RERUN",
        "scientific_evidence": False,
    }
    if bounded:
        value.update(sources.profile_fields)
        value["grid_comparison_fields"] = list(_BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS)
    return value


def _scientific_clean_rerun_plan_from_event(
    *,
    event: LedgerEvent,
    event_index: int,
    plan_id: str,
    ledger_run_id: str,
    original_result_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_domain: str,
    rerun_domain_task_id: str,
    sources: _CleanRerunPlanSources,
) -> ScientificCleanRerunPlan:
    if event.event_hash is None:
        raise ReproductionError("clean-rerun plan event hash is absent")
    return ScientificCleanRerunPlan(
        plan_id=plan_id,
        ledger_run_id=ledger_run_id,
        original_result_id=original_result_id,
        rerun_result_id=rerun_result_id,
        rerun_assessment_id=rerun_assessment_id,
        rerun_domain=rerun_domain,
        rerun_domain_task_id=rerun_domain_task_id,
        original_execution_run_id=sources.original_execution.execution_run_id,
        rerun_execution_run_id=sources.rerun_spec.run_id,
        original_result_promotion_artifact_sha256=(
            sources.result_promotion_record.sha256
        ),
        original_result_promotion_record_hash=str(
            sources.result_promotion_record.record_hash
        ),
        original_result_assessment_artifact_sha256=(
            sources.assessment_record.sha256
        ),
        original_result_assessment_record_hash=str(
            sources.assessment_record.record_hash
        ),
        original_execution_authority_artifact_sha256=(
            sources.original_execution_record.sha256
        ),
        original_execution_authority_record_hash=str(
            sources.original_execution_record.record_hash
        ),
        rerun_frozen_run_spec_artifact_sha256=sources.rerun_spec_record.sha256,
        rerun_frozen_run_spec_record_hash=str(
            sources.rerun_spec_record.record_hash
        ),
        scientific_binding_sha256=sources.rerun_spec.scientific_binding_sha256,
        comparison_tolerance=sources.rerun_spec.comparison_tolerance,
        exact_match_fields=(_BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS if sources.statistical_use_record
                            else _SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS),
        numeric_comparison_fields=(_BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS if sources.statistical_use_record
                                   else _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS),
        grid_comparison_fields=(_BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS if sources.statistical_use_record else ()),
        **sources.profile_fields,
        planned_at=event.timestamp,
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=event_index,
    )


def _require_clean_rerun_source_chronology(
    event: LedgerEvent, records: tuple[ArtifactRecord, ...],
) -> None:
    """An event cannot consume a source created after its retained timestamp.

    Callers separately replay complete source owners. This read-only temporal
    join applies to fresh publication and retained recovery prefixes alike;
    it is not evidence of scientific validity or an owned publication index.
    """
    consumed_at = _clean_utc_timestamp(event.timestamp, "clean-rerun source consumption time")
    for record in records:
        if _clean_utc_timestamp(record.created_at, "clean-rerun source creation time") > consumed_at:
            raise ReproductionError("clean-rerun event predates a consumed source")


def _validate_scientific_clean_rerun_plan_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    binding: Mapping[str, Any],
    sources: _CleanRerunPlanSources,
) -> None:
    _require_clean_rerun_event_bound(event)
    preparation_indexes = tuple(
        index
        for index, item in enumerate(events)
        if isinstance(
            candidate := thaw_json(item.metadata).get(
                "scientific_execution_preparation"
            ),
            Mapping,
        )
        and candidate.get("execution_run_id") == sources.rerun_spec.run_id
    )
    if (
        event.event_hash is None
        or event.actor_role is not Role.PROTOCOL_DESIGNER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes
        != tuple(item.sha256 for item in sources.source_records)
        or event.code_version != f"sha256:{sources.rerun_spec.code_sha256}"
        or event.configuration_hash != sources.rerun_spec.configuration_sha256
        or event.dataset_identifiers != (sources.rerun_spec.data_sha256,)
        or event.random_seeds != sources.rerun_spec.seeds
        or event.evaluator_outputs
        or event.reason
        != "froze a distinct scientific clean-rerun comparison before preparation"
        or thaw_json(event.metadata)
        != {"scientific_clean_rerun_plan": dict(binding)}
        or event_index <= sources.original_execution.ledger_event_index
        or type(sources.original_promotion_event_index) is not int
        or not 0 <= sources.original_promotion_event_index < event_index
        or type(sources.original_domain_event_index) is not int
        or not 0 <= sources.original_domain_event_index < event_index
        or any(index <= event_index for index in preparation_indexes)
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ReproductionError(
            "scientific clean-rerun plan is stale, post hoc, or substituted"
        )
    _require_clean_rerun_source_chronology(event, sources.source_records)


def _clean_rerun_plan_slot_matches(
    value: Mapping[str, Any],
    *,
    plan_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_execution_run_id: str,
) -> bool:
    """Reserve every caller-selectable prospective clean-rerun identity."""

    return any(
        value.get(name) == expected
        for name, expected in (
            ("plan_id", plan_id),
            ("rerun_result_id", rerun_result_id),
            ("rerun_assessment_id", rerun_assessment_id),
            ("rerun_execution_run_id", rerun_execution_run_id),
        )
    )


def _matching_clean_rerun_plan_events(
    events: tuple[LedgerEvent, ...],
    *,
    plan_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_execution_run_id: str,
) -> tuple[tuple[int, LedgerEvent], ...]:
    matches: list[tuple[int, LedgerEvent]] = []
    for index, event in enumerate(events):
        candidate = thaw_json(event.metadata).get("scientific_clean_rerun_plan")
        if isinstance(candidate, Mapping) and _clean_rerun_plan_slot_matches(
            candidate,
            plan_id=plan_id,
            rerun_result_id=rerun_result_id,
            rerun_assessment_id=rerun_assessment_id,
            rerun_execution_run_id=rerun_execution_run_id,
        ):
            matches.append((index, event))
    return tuple(matches)


def _matching_clean_rerun_plan_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    plan_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_execution_run_id: str,
) -> tuple[ArtifactRecord, ...]:
    matches: list[ArtifactRecord] = []
    for record in records:
        if record.logical_type != SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE:
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise ReproductionError(
                "scientific clean-rerun plan slot cannot be reopened"
            ) from exc
        if not isinstance(value, Mapping):
            raise ReproductionError("scientific clean-rerun plan slot is malformed")
        if _clean_rerun_plan_slot_matches(
            value,
            plan_id=plan_id,
            rerun_result_id=rerun_result_id,
            rerun_assessment_id=rerun_assessment_id,
            rerun_execution_run_id=rerun_execution_run_id,
        ):
            matches.append(record)
    return tuple(matches)


def _require_clean_rerun_capacity(
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    *,
    registry_records_needed: int,
    ledger_events_needed: int,
) -> None:
    """Fail before a multi-step admission can exhaust either bounded store."""

    if (
        type(registry_records_needed) is not int
        or type(ledger_events_needed) is not int
        or registry_records_needed < 0
        or ledger_events_needed < 0
    ):
        raise ReproductionError("clean-rerun capacity request is invalid")
    if registry_snapshot.count + registry_records_needed > MAX_REGISTRY_RECORDS:
        raise ReproductionError(
            "scientific clean-rerun registry capacity is insufficient"
        )
    if ledger_snapshot.event_count + ledger_events_needed > MAX_LEDGER_EVENTS:
        raise ReproductionError(
            "scientific clean-rerun ledger event capacity is insufficient"
        )
    if (
        ledger_snapshot.valid_prefix_bytes
        + ledger_events_needed * _MAX_CLEAN_RERUN_LEDGER_EVENT_BYTES
        > MAX_LEDGER_BYTES
    ):
        raise ReproductionError(
            "scientific clean-rerun ledger byte capacity is insufficient"
        )


def _require_clean_rerun_event_bound(event: LedgerEvent) -> None:
    if (
        len(canonical_json_bytes(event.to_dict()) + b"\n")
        > _MAX_CLEAN_RERUN_LEDGER_EVENT_BYTES
    ):
        raise ReproductionError(
            "scientific clean-rerun event exceeds its reserved byte bound"
        )


def _preflight_clean_rerun_record(
    registry: ArtifactRegistry,
    snapshot: RegistryValidationResult,
    data: bytes,
    *,
    logical_type: str,
    creator_role: Role,
    origin: str,
    creation_command: tuple[str, ...],
    parent_artifacts: tuple[str, ...],
    schema_version: str,
    created_at: str,
) -> ArtifactRecord:
    """Validate prospective bytes/metadata/parents without publishing anything.

    Existing records retain their exact timestamp and record hash on recovery.
    This is mechanical staging, not a scientific source-owner substitute.
    """
    if len(data) > DEFAULT_MAX_JSON_BYTES:
        raise ReproductionError("clean-rerun artifact exceeds bounded JSON size")
    digest = hashlib.sha256(data).hexdigest()
    by_hash = {item.sha256: item for item in snapshot.records}
    if any(parent not in by_hash for parent in parent_artifacts):
        raise ReproductionError("clean-rerun prospective parent closure is absent")
    existing = by_hash.get(digest)
    path = registry._object_relative(digest).as_posix()
    record = ArtifactRecord(
        sha256=digest, path=path, relative_path=path,
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=logical_type, schema_version=schema_version,
        mime_type="application/json", size=len(data), origin=origin,
        creator_role=creator_role, creation_command=creation_command,
        parent_artifacts=parent_artifacts, validation_result="PASS", frozen=True,
        created_at=existing.created_at if existing else created_at,
    )
    if existing is not None and existing != record:
        raise ReproductionError("clean-rerun prospective metadata conflicts with an existing record")
    return record


def register_scientific_clean_rerun_plan(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_id: str,
    ledger_run_id: str,
    original_result_id: str,
    rerun_result_id: str,
    rerun_assessment_id: str,
    rerun_domain: str,
    rerun_domain_task_id: str,
    original_execution_run_id: str,
    original_result_promotion_artifact_sha256: str,
    rerun_frozen_run_spec_artifact_sha256: str,
) -> ArtifactRecord:
    """Register an exact plan before the second execution is prepared."""

    entry_registry, entry_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        ledger_run_id,
    )
    plan_id = _clean_identifier(plan_id, "clean-rerun plan ID")
    original_result_id = _clean_identifier(
        original_result_id,
        "clean-rerun original result ID",
    )
    rerun_result_id = _clean_identifier(
        rerun_result_id,
        "clean-rerun Result ID",
    )
    rerun_assessment_id = _clean_identifier(
        rerun_assessment_id,
        "clean-rerun assessment ID",
    )
    rerun_domain = _clean_identifier(rerun_domain, "clean-rerun domain")
    from .domains import DomainKind

    try:
        rerun_domain = DomainKind(rerun_domain).value
    except ValueError as exc:
        raise ReproductionError("clean-rerun domain is unsupported") from exc
    rerun_domain_task_id = _clean_identifier(
        rerun_domain_task_id,
        "clean-rerun domain task ID",
    )
    if rerun_result_id == original_result_id:
        raise ReproductionError("clean rerun requires a distinct Result identity")
    original_execution_run_id = _clean_identifier(
        original_execution_run_id,
        "clean-rerun original execution run ID",
    )
    sources = _resolve_clean_rerun_plan_sources(
        registry,
        ledger,
        ledger_run_id=ledger_run_id,
        original_result_id=original_result_id,
        original_execution_run_id=original_execution_run_id,
        original_result_promotion_artifact_sha256=(
            original_result_promotion_artifact_sha256
        ),
        rerun_frozen_run_spec_artifact_sha256=(
            rerun_frozen_run_spec_artifact_sha256
        ),
    )
    existing = _matching_clean_rerun_plan_records(
        registry,
        entry_registry.records,
        plan_id=plan_id,
        rerun_result_id=rerun_result_id,
        rerun_assessment_id=rerun_assessment_id,
        rerun_execution_run_id=sources.rerun_spec.run_id,
    )
    if len(existing) > 1:
        raise ReproductionError("scientific clean-rerun plan slot is ambiguous")
    if existing:
        plan = require_scientific_clean_rerun_plan(
            registry,
            ledger,
            plan_artifact_sha256=existing[0].sha256,
            expected_ledger_run_id=ledger_run_id,
            expected_original_execution_run_id=original_execution_run_id,
            expected_rerun_execution_run_id=sources.rerun_spec.run_id,
        )
        if (
            plan.plan_id != plan_id
            or plan.original_result_id != original_result_id
            or plan.rerun_result_id != rerun_result_id
            or plan.rerun_assessment_id != rerun_assessment_id
            or plan.rerun_domain != rerun_domain
            or plan.rerun_domain_task_id != rerun_domain_task_id
            or plan.original_result_promotion_artifact_sha256
            != sources.result_promotion_record.sha256
            or plan.rerun_frozen_run_spec_artifact_sha256 != sources.rerun_spec_record.sha256
            or plan.rerun_frozen_run_spec_record_hash != sources.rerun_spec_record.record_hash
        ):
            raise ReproductionError(
                "scientific clean-rerun plan slot already names another protocol"
            )
        _require_clean_rerun_snapshot_unchanged(
            registry, ledger, ledger_run_id, entry_registry, entry_ledger,
        )
        return existing[0]
    binding = _scientific_clean_rerun_plan_binding(
        plan_id=plan_id,
        ledger_run_id=ledger_run_id,
        original_result_id=original_result_id,
        rerun_result_id=rerun_result_id,
        rerun_assessment_id=rerun_assessment_id,
        rerun_domain=rerun_domain,
        rerun_domain_task_id=rerun_domain_task_id,
        sources=sources,
    )
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                locked_registry != entry_registry
                or locked_ledger != entry_ledger
                or not locked_ledger.valid
            ):
                raise ReproductionError(
                    "clean-rerun plan sources changed before admission"
                )
            admitted = _matching_clean_rerun_plan_events(
                locked_ledger.events,
                plan_id=plan_id,
                rerun_result_id=rerun_result_id,
                rerun_assessment_id=rerun_assessment_id,
                rerun_execution_run_id=sources.rerun_spec.run_id,
            )
            if len(admitted) > 1:
                raise ReproductionError(
                    "scientific clean-rerun plan event is ambiguous"
                )
            if admitted:
                event_index, event = admitted[0]
                if (
                    thaw_json(event.metadata).get(
                        "scientific_clean_rerun_plan"
                    )
                    != binding
                ):
                    raise ReproductionError(
                        "clean-rerun plan recovery differs from the admitted event"
                    )
                committed_ledger = locked_ledger
            else:

                _require_clean_rerun_capacity(
                    locked_registry,
                    locked_ledger,
                    registry_records_needed=1,
                    ledger_events_needed=1,
                )

                def build_plan_event(
                    current: LedgerValidationResult,
                ) -> LedgerEvent:
                    if current != locked_ledger:
                        raise ReproductionError(
                            "clean-rerun plan ledger changed before admission"
                        )
                    current_state = (
                        current.events[-1].state_after
                        if current.events
                        else MacroState.PREFLIGHT
                    )
                    candidate = LedgerEvent.create(
                        run_id=ledger_run_id,
                        actor_role=Role.PROTOCOL_DESIGNER,
                        state_before=current_state,
                        requested_state_after=current_state,
                        artifact_hashes=tuple(
                            item.sha256 for item in sources.source_records
                        ),
                        code_version=(
                            f"sha256:{sources.rerun_spec.code_sha256}"
                        ),
                        configuration_hash=(
                            sources.rerun_spec.configuration_sha256
                        ),
                        dataset_identifiers=(sources.rerun_spec.data_sha256,),
                        random_seeds=sources.rerun_spec.seeds,
                        evaluator_outputs=(),
                        reason=(
                            "froze a distinct scientific clean-rerun comparison "
                            "before preparation"
                        ),
                        prior_event_hash=current.head_hash,
                        event_type="CHECKPOINT",
                        metadata={"scientific_clean_rerun_plan": binding},
                    )
                    _require_clean_rerun_event_bound(candidate)
                    return candidate

                event = build_plan_event(locked_ledger)
                event_index = len(locked_ledger.events)
                committed_ledger = locked_ledger
            if admitted:
                expected_plan = _scientific_clean_rerun_plan_from_event(
                    event=event,
                    event_index=event_index,
                    plan_id=plan_id,
                    ledger_run_id=ledger_run_id,
                    original_result_id=original_result_id,
                    rerun_result_id=rerun_result_id,
                    rerun_assessment_id=rerun_assessment_id,
                    rerun_domain=rerun_domain,
                    rerun_domain_task_id=rerun_domain_task_id,
                    sources=sources,
                )
                expected_digest = hashlib.sha256(
                    canonical_json_bytes(expected_plan.to_dict()) + b"\n"
                ).hexdigest()
                if not any(
                    item.sha256 == expected_digest
                    for item in locked_registry.records
                ):
                    _require_clean_rerun_capacity(
                        locked_registry,
                        committed_ledger,
                        registry_records_needed=1,
                        ledger_events_needed=0,
                    )
            _validate_scientific_clean_rerun_plan_event(
                event,
                event_index,
                committed_ledger.events if admitted else (*committed_ledger.events, event),
                binding=binding,
                sources=sources,
            )
            plan = _scientific_clean_rerun_plan_from_event(
                event=event,
                event_index=event_index,
                plan_id=plan_id,
                ledger_run_id=ledger_run_id,
                original_result_id=original_result_id,
                rerun_result_id=rerun_result_id,
                rerun_assessment_id=rerun_assessment_id,
                rerun_domain=rerun_domain,
                rerun_domain_task_id=rerun_domain_task_id,
                sources=sources,
            )
            plan_bytes = canonical_json_bytes(plan.to_dict()) + b"\n"
            prospective_record = _preflight_clean_rerun_record(
                registry, locked_registry, plan_bytes,
                logical_type=SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
                origin=_SCIENTIFIC_CLEAN_RERUN_PLAN_ORIGIN,
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=_SCIENTIFIC_CLEAN_RERUN_PLAN_COMMAND,
                parent_artifacts=plan.source_artifact_hashes,
                schema_version="2.0" if plan.is_bounded_mean else "1.0",
                created_at=utc_now(),
            )
            if not admitted:
                def append_plan_event(current: LedgerValidationResult) -> LedgerEvent:
                    if current != locked_ledger:
                        raise ReproductionError("clean-rerun plan ledger changed before admission")
                    return event

                ledger._append_locked(ledger_guard, append_plan_event)
                committed_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
                if not committed_ledger.valid or committed_ledger.events != (*locked_ledger.events, event):
                    raise ReproductionError("clean-rerun plan admission changed unexpectedly")
            record = registry._put_bytes_locked(
                registry_guard,
                plan_bytes,
                logical_type=SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
                origin=_SCIENTIFIC_CLEAN_RERUN_PLAN_ORIGIN,
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=_SCIENTIFIC_CLEAN_RERUN_PLAN_COMMAND,
                parent_artifacts=plan.source_artifact_hashes,
                schema_version=prospective_record.schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=prospective_record.created_at,
            )
            if record != prospective_record:
                raise ReproductionError("clean-rerun plan differs from its prospective metadata")
            final_locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            final_locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            expected_records = tuple(
                sorted(
                    (*locked_registry.records, record),
                    key=lambda item: item.sha256,
                )
            )
            if (
                final_locked_registry.records != expected_records
                or final_locked_registry.errors != locked_registry.errors
                or final_locked_registry.orphan_paths
                != locked_registry.orphan_paths
                or final_locked_ledger != committed_ledger
            ):
                raise ReproductionError(
                    "clean-rerun plan registry or ledger changed during materialization"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    require_scientific_clean_rerun_plan(
        registry,
        ledger,
        plan_artifact_sha256=record.sha256,
        expected_ledger_run_id=ledger_run_id,
        expected_original_execution_run_id=original_execution_run_id,
        expected_rerun_execution_run_id=sources.rerun_spec.run_id,
    )
    return record


def require_scientific_clean_rerun_plan(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_original_execution_run_id: str,
    expected_rerun_execution_run_id: str,
) -> ScientificCleanRerunPlan:
    """Freshly replay a prospective clean-rerun plan and its event."""

    entry_registry, entry_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        expected_ledger_run_id,
    )
    events = entry_ledger.events
    record, value = _load_clean_rerun_json(
        registry,
        plan_artifact_sha256,
        logical_type=SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        schema_version=("1.0", "2.0"),
    )
    if (
        record.origin != _SCIENTIFIC_CLEAN_RERUN_PLAN_ORIGIN
        or record.creation_command != _SCIENTIFIC_CLEAN_RERUN_PLAN_COMMAND
    ):
        raise ReproductionError("scientific clean-rerun plan is not source-owned")
    plan = ScientificCleanRerunPlan.from_mapping(value)
    if (
        record.schema_version != ("2.0" if plan.is_bounded_mean else "1.0")
        or plan.ledger_run_id != expected_ledger_run_id
        or plan.original_execution_run_id
        != expected_original_execution_run_id
        or plan.rerun_execution_run_id != expected_rerun_execution_run_id
        or record.parent_artifacts != plan.source_artifact_hashes
    ):
        raise ReproductionError("scientific clean-rerun plan names another closure")
    if _matching_clean_rerun_plan_records(
        registry,
        entry_registry.records,
        plan_id=plan.plan_id,
        rerun_result_id=plan.rerun_result_id,
        rerun_assessment_id=plan.rerun_assessment_id,
        rerun_execution_run_id=plan.rerun_execution_run_id,
    ) != (record,):
        raise ReproductionError(
            "scientific clean-rerun plan artifact slot is ambiguous"
        )
    sources = _resolve_clean_rerun_plan_sources(
        registry,
        ledger,
        ledger_run_id=expected_ledger_run_id,
        original_result_id=plan.original_result_id,
        original_execution_run_id=expected_original_execution_run_id,
        original_result_promotion_artifact_sha256=(
            plan.original_result_promotion_artifact_sha256
        ),
        rerun_frozen_run_spec_artifact_sha256=(
            plan.rerun_frozen_run_spec_artifact_sha256
        ),
    )
    binding = _scientific_clean_rerun_plan_binding(
        plan_id=plan.plan_id,
        ledger_run_id=expected_ledger_run_id,
        original_result_id=plan.original_result_id,
        rerun_result_id=plan.rerun_result_id,
        rerun_assessment_id=plan.rerun_assessment_id,
        rerun_domain=plan.rerun_domain,
        rerun_domain_task_id=plan.rerun_domain_task_id,
        sources=sources,
    )
    matches = _matching_clean_rerun_plan_events(
        events,
        plan_id=plan.plan_id,
        rerun_result_id=plan.rerun_result_id,
        rerun_assessment_id=plan.rerun_assessment_id,
        rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    if len(matches) != 1:
        raise ReproductionError(
            "scientific clean-rerun plan lacks one exact ledger event"
        )
    event_index, event = matches[0]
    _validate_scientific_clean_rerun_plan_event(
        event,
        event_index,
        events,
        binding=binding,
        sources=sources,
    )
    expected = _scientific_clean_rerun_plan_from_event(
        event=event,
        event_index=event_index,
        plan_id=plan.plan_id,
        ledger_run_id=expected_ledger_run_id,
        original_result_id=plan.original_result_id,
        rerun_result_id=plan.rerun_result_id,
        rerun_assessment_id=plan.rerun_assessment_id,
        rerun_domain=plan.rerun_domain,
        rerun_domain_task_id=plan.rerun_domain_task_id,
        sources=sources,
    )
    if plan != expected:
        raise ReproductionError(
            "scientific clean-rerun plan differs from fresh source replay"
        )
    _require_clean_rerun_snapshot_unchanged(
        registry,
        ledger,
        expected_ledger_run_id,
        entry_registry,
        entry_ledger,
    )
    return plan


def derive_scientific_clean_rerun_comparison(
    original_assessment: Any,
    rerun_assessment: Any,
    *,
    comparison_tolerance: float,
) -> ScientificCleanRerunComparison:
    """Compare two assessment values without conferring evidence authority."""

    from .scientific_design import CheckedResultAssessment

    if not isinstance(original_assessment, CheckedResultAssessment) or not isinstance(
        rerun_assessment,
        CheckedResultAssessment,
    ):
        raise ReproductionError(
            "clean-rerun comparison requires typed checked result assessments"
        )
    if original_assessment.is_bounded_mean or rerun_assessment.is_bounded_mean:
        raise ReproductionError(
            "legacy clean-rerun comparison cannot consume bounded-mean assessments"
        )
    tolerance = _clean_finite(
        comparison_tolerance,
        "clean-rerun comparison tolerance",
    )
    if tolerance < 0:
        raise ReproductionError("clean-rerun tolerance cannot be negative")
    exact_mismatches = tuple(
        name
        for name in _SCIENTIFIC_CLEAN_RERUN_EXACT_FIELDS
        if getattr(original_assessment, name) != getattr(rerun_assessment, name)
    )
    differences: list[ScientificCleanRerunDifference] = []
    for name in _SCIENTIFIC_CLEAN_RERUN_NUMERIC_FIELDS:
        original = getattr(original_assessment, name)
        rerun = getattr(rerun_assessment, name)
        if original is None or rerun is None:
            difference = None
            within = original is None and rerun is None
        else:
            original = _clean_finite(original, f"original {name}")
            rerun = _clean_finite(rerun, f"rerun {name}")
            difference = abs(original - rerun)
            within = difference <= tolerance
        differences.append(
            ScientificCleanRerunDifference(
                field_name=name,
                original_value=original,
                rerun_value=rerun,
                absolute_difference=difference,
                tolerance=tolerance,
                within_tolerance=within,
            )
        )
    outcome = (
        ScientificCleanRerunOutcome.FAIL
        if exact_mismatches
        else ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE
        if any(not item.within_tolerance for item in differences)
        else ScientificCleanRerunOutcome.PASS
    )
    return ScientificCleanRerunComparison(
        exact_mismatches=exact_mismatches,
        differences=tuple(differences),
        outcome=outcome,
    )


def _require_bounded_clean_rerun_assessment_value(value: Any) -> Any:
    """Revalidate inert DTOs without ever coercing hostile scalar subclasses."""
    from .scientific_design import (
        CheckedResultAssessment, HypothesisStatus, MetricScope, MetricUnit, ScientificResultOutcome,
    )

    if type(value) is not CheckedResultAssessment:
        raise ReproductionError("bounded clean rerun requires exact checked assessment types")
    scalar_types = (str, int, float, bool, type(None), HypothesisStatus, MetricScope, MetricUnit, ScientificResultOutcome)
    for field in fields(value):
        item = getattr(value, field.name)
        if not any(type(item) is allowed for allowed in scalar_types) and not (
            type(item) is tuple and all(type(leaf) is str for leaf in item)
        ):
            raise ReproductionError("bounded clean-rerun assessment contains non-native field values")
    try:
        # Frozen objects can still be altered with object.__setattr__. Rebuild
        # the original closed DTO only after excluding all custom scalar hooks.
        rebuilt = replace(value)
    except Exception as exc:
        raise ReproductionError("bounded clean-rerun checked assessment is malformed") from exc
    if not rebuilt.is_bounded_mean:
        raise ReproductionError("bounded clean rerun requires two bounded-mean assessments")
    return rebuilt


def _require_bounded_clean_rerun_projection_native(projection: Any) -> None:
    """Validate scalar types before any equality can dispatch caller code."""
    from .generic_ml_projection import GenericMLPairedMetricProjectionAuthority, GenericMLSeedPairedProjection

    if type(projection) is not GenericMLPairedMetricProjectionAuthority:
        raise ReproductionError("bounded clean rerun requires exact paired projection types")
    integer_tuples = ("seed_order", "reference_labels")
    string_tuples = (
        "paired_unit_ids", "paired_unit_hashes", "split_authority_artifact_sha256s",
        "split_authority_record_hashes", "paired_projection_artifact_sha256s",
        "paired_projection_record_hashes", "domain_consumed_output_artifact_sha256s",
        "domain_consumed_output_record_hashes", "ablation_output_artifact_sha256s",
        "ablation_output_record_hashes",
    )
    for field in fields(projection):
        name, item = field.name, getattr(projection, field.name)
        if name == "seed_projections":
            valid = type(item) is tuple and all(type(row) is GenericMLSeedPairedProjection for row in item)
        elif name in (*integer_tuples, *string_tuples):
            leaf_type = int if name in integer_tuples else str
            valid = type(item) is tuple and all(type(leaf) is leaf_type for leaf in item)
        elif name == "ledger_event_index":
            valid = type(item) is int
        elif name == "scientific_evidence_eligible":
            valid = type(item) is bool
        else:
            valid = type(item) is str
        if not valid:
            raise ReproductionError(f"bounded clean-rerun projection contains non-native values: {name}")
        if type(item) is str and name.endswith(("sha256", "record_hash", "content_hash", "event_hash")):
            _clean_sha256(item, name)
        if name in string_tuples and name != "paired_unit_ids":
            for digest in item:
                _clean_sha256(digest, name)
    for row in projection.seed_projections:
        for field in fields(row):
            name, item = field.name, getattr(row, field.name)
            if name in ("seed", "candidate_parameter_count", "baseline_parameter_count"):
                valid = type(item) is int
            elif name in ("candidate_mean", "baseline_mean"):
                _bounded_clean_finite(item, name)
                valid = True
            elif name in ("candidate_values", "baseline_values"):
                valid = type(item) is tuple and all(type(leaf) is int or type(leaf) is float for leaf in item)
            elif name in ("paired_unit_ids", "paired_unit_hashes", "reference_labels"):
                leaf_type = int if name == "reference_labels" else str
                valid = type(item) is tuple and all(type(leaf) is leaf_type for leaf in item)
            else:
                valid = type(item) is str
            if not valid:
                raise ReproductionError(f"bounded clean-rerun seed contains non-native values: {name}")
            if type(item) is str and name.endswith(("sha256", "record_hash")):
                _clean_sha256(item, name)


def _require_bounded_clean_rerun_projection_pair(original: Any, rerun: Any) -> None:
    """Check identical inputs and full ordered grids, never identical run outputs.

    This pure shape/join check cannot grant authority. Production callers first
    replay both complete checked-result owners, including their Run ancestors.
    """
    from .bounded_mean_inference import MAX_BOUNDED_MEAN_SEEDS, MAX_BOUNDED_MEAN_UNITS
    from .generic_ml_projection import GenericMLSeedPairedProjection

    for projection in (original, rerun):
        _require_bounded_clean_rerun_projection_native(projection)
    shared_fields = (
        "run_id", "comparison_scope", "evaluation_contract_artifact_sha256",
        "evaluation_contract_record_hash", "dataset_authority_artifact_sha256",
        "dataset_authority_record_hash", "dataset_raw_artifact_sha256", "dataset_raw_record_hash",
        "split_authority_artifact_sha256s", "split_authority_record_hashes",
        "frozen_model_configuration_artifact_sha256", "frozen_model_configuration_record_hash",
        "evaluator_artifact_sha256", "evaluator_record_hash", "seed_order",
        "paired_unit_ids", "paired_unit_hashes", "reference_labels",
    )
    for name in shared_fields:
        if getattr(original, name) != getattr(rerun, name):
            raise ReproductionError(f"bounded clean-rerun source grid differs: {name}")
    for projection in (original, rerun):
        if (
            type(projection.seed_order) is not tuple
            or not 1 <= len(projection.seed_order) <= MAX_BOUNDED_MEAN_SEEDS
            or any(type(seed) is not int for seed in projection.seed_order)
            or len(set(projection.seed_order)) != len(projection.seed_order)
            or type(projection.paired_unit_ids) is not tuple
            or not 1 <= len(projection.paired_unit_ids) <= MAX_BOUNDED_MEAN_UNITS
            or any(type(unit) is not str for unit in projection.paired_unit_ids)
            or len(set(projection.paired_unit_ids)) != len(projection.paired_unit_ids)
            or type(projection.paired_unit_hashes) is not tuple
            or len(projection.paired_unit_hashes) != len(projection.paired_unit_ids)
            or type(projection.reference_labels) is not tuple
            or len(projection.reference_labels) != len(projection.paired_unit_ids)
            or any(type(label) is not int for label in projection.reference_labels)
            or type(projection.seed_projections) is not tuple
            or len(projection.seed_projections) != len(projection.seed_order)
            or any(type(row) is not GenericMLSeedPairedProjection for row in projection.seed_projections)
            or tuple(row.seed for row in projection.seed_projections) != projection.seed_order
            or len(projection.split_authority_artifact_sha256s) != 4
            or len(projection.split_authority_record_hashes) != 4
        ):
            raise ReproductionError("bounded clean-rerun grid is incomplete or reordered")
        for digest in projection.paired_unit_hashes:
            if type(digest) is not str:
                raise ReproductionError("bounded clean-rerun paired unit hash must be native text")
            _clean_sha256(digest, "bounded clean-rerun paired unit hash")
        for row in projection.seed_projections:
            if (
                type(row.seed) is not int
                or type(row.paired_unit_ids) is not tuple
                or type(row.paired_unit_hashes) is not tuple
                or type(row.reference_labels) is not tuple
                or type(row.candidate_condition_id) is not str
                or type(row.baseline_condition_id) is not str
                or any(type(item) is not str for item in (*row.paired_unit_ids, *row.paired_unit_hashes))
                or any(type(item) is not int for item in row.reference_labels)
                or row.paired_unit_ids != projection.paired_unit_ids
                or row.paired_unit_hashes != projection.paired_unit_hashes
                or row.reference_labels != projection.reference_labels
            ):
                raise ReproductionError("bounded clean-rerun per-seed unit identity differs")
            for name in _BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS:
                cells = getattr(row, name)
                if (
                    type(cells) is not tuple or len(cells) != len(projection.paired_unit_ids)
                    or any((type(cell) is not int and type(cell) is not float) or cell not in (0, 1) for cell in cells)
                ):
                    raise ReproductionError("bounded clean-rerun grid requires complete binary correctness cells")
    for left, right in zip(original.seed_projections, rerun.seed_projections, strict=True):
        if (
            left.candidate_condition_id != right.candidate_condition_id
            or left.baseline_condition_id != right.baseline_condition_id
        ):
            raise ReproductionError("bounded clean-rerun seed condition identity differs")


def derive_bounded_mean_clean_rerun_comparison(
    original_assessment: Any,
    rerun_assessment: Any,
    *,
    original_projection: Any,
    rerun_projection: Any,
    comparison_tolerance: float,
) -> BoundedMeanCleanRerunComparison:
    """Pure v2 comparison, never a substitute for complete scientific owners.

    Full seed cells are compared before compact summaries are emitted. Native
    mean-log/underflow and auxiliary sign diagnostics remain source-replayed,
    but are not primary acceptance fields under this probability tolerance.
    """
    original_assessment = _require_bounded_clean_rerun_assessment_value(original_assessment)
    rerun_assessment = _require_bounded_clean_rerun_assessment_value(rerun_assessment)
    tolerance = _bounded_clean_finite(comparison_tolerance, "bounded clean-rerun tolerance")
    if tolerance < 0:
        raise ReproductionError("bounded clean-rerun tolerance cannot be negative")
    _require_bounded_clean_rerun_projection_pair(original_projection, rerun_projection)
    for assessment, projection in ((original_assessment, original_projection), (rerun_assessment, rerun_projection)):
        if (
            assessment.ledger_run_id != projection.run_id
            or assessment.execution_run_id != projection.execution_run_id
            or assessment.sample_size != len(projection.paired_unit_ids)
            or assessment.generic_ml_paired_metric_projection_authority_artifact_sha256 != projection.projection_artifact_sha256
            or assessment.generic_ml_paired_metric_projection_authority_record_hash != projection.projection_record_hash
            or assessment.contract_artifact_sha256 != projection.evaluation_contract_artifact_sha256
            or assessment.contract_record_hash != projection.evaluation_contract_record_hash
        ):
            raise ReproductionError("bounded clean-rerun assessment differs from its paired source grid")
    mismatches = tuple(
        name for name in _BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS
        if (getattr(original_projection, name) != getattr(rerun_projection, name)
            if name in ("seed_order", "paired_unit_ids", "paired_unit_hashes")
            else getattr(original_assessment, name) != getattr(rerun_assessment, name))
    )
    differences = tuple(
        BoundedMeanCleanRerunDifference(
            field_name=name,
            original_value=getattr(original_assessment, name),
            rerun_value=getattr(rerun_assessment, name),
            absolute_difference=abs(getattr(original_assessment, name) - getattr(rerun_assessment, name)),
            tolerance=tolerance,
            within_tolerance=abs(getattr(original_assessment, name) - getattr(rerun_assessment, name)) <= tolerance,
        ) for name in _BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS
    )
    grid_comparisons = []
    for name in _BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS:
        maximum, count, outside = 0.0, 0, 0
        for left, right in zip(original_projection.seed_projections, rerun_projection.seed_projections, strict=True):
            for original_cell, rerun_cell in zip(getattr(left, name), getattr(right, name), strict=True):
                difference = abs(original_cell - rerun_cell)
                maximum = max(maximum, difference)
                outside += int(difference > tolerance)
                count += 1
        grid_comparisons.append(BoundedMeanCleanRerunGridComparison(
            field_name=name, compared_value_count=count,
            maximum_absolute_difference=maximum, outside_tolerance_count=outside,
            tolerance=tolerance, within_tolerance=outside == 0,
        ))
    outcome = (
        ScientificCleanRerunOutcome.FAIL if mismatches else
        ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE
        if any(not item.within_tolerance for item in (*differences, *grid_comparisons))
        else ScientificCleanRerunOutcome.PASS
    )
    return BoundedMeanCleanRerunComparison(mismatches, differences, tuple(grid_comparisons), outcome)


def _replay_bounded_clean_rerun_evidence(
    registry: ArtifactRegistry, ledger: EventLedger, assessment: Any,
) -> Any:
    """Acyclic lower-owner replay; never request canonical Result/package state."""
    from .scientific_design import _derive_projection_checked_result_evidence

    evidence = _derive_projection_checked_result_evidence(
        registry, ledger,
        expected_ledger_run_id=assessment.ledger_run_id,
        expected_execution_run_id=assessment.execution_run_id,
        generic_ml_projection_artifact_sha256=assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
        scientific_execution_admissibility_authority_artifact_sha256=assessment.scientific_execution_admissibility_authority_artifact_sha256,
        domain_validity_receipt_artifact_sha256=assessment.domain_validity_receipt_artifact_sha256,
        baseline_exclusion_receipt_sha256s=assessment.baseline_exclusion_receipt_sha256s,
    )
    if (
        evidence.statistical_use_record is None or evidence.bounded_mean_result is None
        or evidence.statistical_use_record.sha256 != assessment.statistical_use_authority_artifact_sha256
        or evidence.statistical_use_record.record_hash != assessment.statistical_use_authority_record_hash
    ):
        raise ReproductionError("bounded clean-rerun evidence lacks the exact native inference source")
    return evidence


def _load_clean_execution_environment(
    registry: ArtifactRegistry,
    authority: ScientificExecutionAuthority,
    *,
    require_clean: bool,
) -> tuple[ArtifactRecord, Mapping[str, Any], ArtifactRecord, Mapping[str, Any]]:
    environment_record, environment = _load_clean_rerun_json(
        registry,
        authority.environment_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    isolation_record, isolation = _load_clean_rerun_json(
        registry,
        authority.isolation_attestation_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    environment_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "backend_profile",
        "environment_fingerprint",
        "host_instance_id",
        "boot_session_id",
        "hardware_fingerprint",
        "writable_storage_id",
        "claims",
    }
    isolation_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "backend_profile",
        "environment_artifact_sha256",
        "isolation_policy_sha256",
        "network_used",
        "network_isolation_attested",
        "shared_writable_state_ids",
        "cache_used",
        "checkpoint_used",
        "resumed_from_checkpoint",
        "claims",
    }
    if (
        set(environment) != environment_keys
        or set(isolation) != isolation_keys
        or environment["schema_version"]
        != SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA
        or isolation["schema_version"] != SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA
        or environment["ledger_run_id"] != authority.ledger_run_id
        or isolation["ledger_run_id"] != authority.ledger_run_id
        or environment["execution_run_id"] != authority.execution_run_id
        or isolation["execution_run_id"] != authority.execution_run_id
        or environment["backend_profile"] != authority.backend_profile.to_dict()
        or isolation["backend_profile"] != authority.backend_profile.to_dict()
        or environment_record.parent_artifacts
        != (authority.preparation_artifact_sha256,)
        or isolation_record.parent_artifacts
        != (
            authority.preparation_artifact_sha256,
            environment_record.sha256,
        )
        or isolation["environment_artifact_sha256"] != environment_record.sha256
        or environment_record.record_hash != authority.environment_record_hash
        or isolation_record.record_hash != authority.isolation_attestation_record_hash
        or environment["environment_fingerprint"]
        != authority.environment_fingerprint
        or isolation["isolation_policy_sha256"] != authority.isolation_policy_sha256
        or isolation["network_used"] is not False
        or isolation["network_isolation_attested"] is not True
        or isolation["shared_writable_state_ids"] != []
        or (
            require_clean
            and (
                isolation["cache_used"] is not False
                or isolation["checkpoint_used"] is not False
                or isolation["resumed_from_checkpoint"] is not False
            )
        )
        or not isinstance(environment["claims"], Mapping)
        or not isinstance(isolation["claims"], Mapping)
    ):
        raise ReproductionError("clean-rerun execution isolation is invalid")
    for name in ("environment_fingerprint", "hardware_fingerprint"):
        _clean_sha256(environment[name], f"clean-rerun {name}")
    _clean_sha256(isolation["isolation_policy_sha256"], "clean-rerun isolation policy")
    for name in ("host_instance_id", "boot_session_id", "writable_storage_id"):
        _clean_identifier(environment[name], f"clean-rerun {name}")
    return environment_record, environment, isolation_record, isolation


@dataclass(frozen=True, slots=True)
class _CleanRerunAuthoritySources:
    plan_record: ArtifactRecord
    plan: ScientificCleanRerunPlan
    result_promotion_record: ArtifactRecord
    rerun_domain_record: ArtifactRecord
    rerun_domain: Any
    original_assessment_record: ArtifactRecord
    original_assessment: Any
    rerun_assessment_record: ArtifactRecord
    rerun_assessment: Any
    original_execution_record: ArtifactRecord
    original_execution: ScientificExecutionAuthority
    rerun_execution_record: ArtifactRecord
    rerun_execution: ScientificExecutionAuthority
    original_environment_record: ArtifactRecord
    original_environment: Mapping[str, Any]
    original_isolation_record: ArtifactRecord
    original_isolation: Mapping[str, Any]
    rerun_environment_record: ArtifactRecord
    rerun_environment: Mapping[str, Any]
    rerun_isolation_record: ArtifactRecord
    rerun_isolation: Mapping[str, Any]
    rerun_spec: FrozenRunSpec
    comparison: ScientificCleanRerunComparison | BoundedMeanCleanRerunComparison
    rerun_domain_event_index: int
    statistical_use_record: ArtifactRecord | None = None

    @property
    def source_records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.plan_record,
            self.result_promotion_record,
            self.rerun_domain_record,
            self.original_assessment_record,
            self.rerun_assessment_record,
            self.original_execution_record,
            self.rerun_execution_record,
            self.original_environment_record,
            self.rerun_environment_record,
            self.original_isolation_record,
            self.rerun_isolation_record,
        ) + ((self.statistical_use_record,) if self.statistical_use_record else ())


def _matching_checked_assessment_slot_records(
    registry: ArtifactRegistry,
    *,
    ledger_run_id: str,
    execution_run_id: str,
    assessment_id: str,
) -> tuple[ArtifactRecord, ...]:
    """Reject post-outcome selection among artifacts for one reserved slot."""

    from .scientific_design import CHECKED_RESULT_ASSESSMENT_LOGICAL_TYPE

    matches: list[ArtifactRecord] = []
    for record in registry.list_records():
        if record.logical_type != CHECKED_RESULT_ASSESSMENT_LOGICAL_TYPE:
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise ReproductionError(
                "clean-rerun checked-assessment slot cannot be reopened"
            ) from exc
        if not isinstance(value, Mapping):
            raise ReproductionError(
                "clean-rerun checked-assessment slot is malformed"
            )
        if (
            value.get("ledger_run_id") == ledger_run_id
            and value.get("execution_run_id") == execution_run_id
            and value.get("assessment_id") == assessment_id
        ):
            matches.append(record)
    return tuple(matches)


def _clean_rerun_authority_slot_matches(
    value: Mapping[str, Any], *, plan_artifact_sha256: str,
    rerun_result_id: str, rerun_assessment_id: str, rerun_execution_run_id: str,
) -> bool:
    """One global slot inventory, irrespective of advertised wire version."""
    return any(value.get(name) == expected for name, expected in (
        ("plan_artifact_sha256", plan_artifact_sha256),
        ("rerun_result_id", rerun_result_id),
        ("rerun_assessment_id", rerun_assessment_id),
        ("rerun_execution_run_id", rerun_execution_run_id),
    ))


def _matching_clean_rerun_authority_records(
    registry: ArtifactRegistry, records: tuple[ArtifactRecord, ...],
    *, plan_artifact_sha256: str, plan: ScientificCleanRerunPlan,
) -> tuple[ArtifactRecord, ...]:
    matches = []
    for record in records:
        if record.logical_type != SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE:
            continue
        if record.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError("clean-rerun authority slot exceeds bounded JSON")
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise ReproductionError("clean-rerun authority slot cannot be reopened") from exc
        if not isinstance(value, Mapping):
            raise ReproductionError("clean-rerun authority slot is malformed")
        if plan_artifact_sha256 in record.parent_artifacts or _clean_rerun_authority_slot_matches(
            value, plan_artifact_sha256=plan_artifact_sha256,
            rerun_result_id=plan.rerun_result_id, rerun_assessment_id=plan.rerun_assessment_id,
            rerun_execution_run_id=plan.rerun_execution_run_id,
        ):
            matches.append(record)
    return tuple(matches)


def _resolve_clean_rerun_authority_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    rerun_result_assessment_artifact_sha256: str,
    rerun_domain_validity_receipt_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_original_execution_run_id: str,
    expected_rerun_execution_run_id: str,
) -> _CleanRerunAuthoritySources:
    from .scientific_design import (
        _require_result_promotion_domain_authority,
        require_checked_result_assessment,
    )

    plan = require_scientific_clean_rerun_plan(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    plan_record = registry.get_metadata(plan_artifact_sha256)
    plan_sources = _resolve_clean_rerun_plan_sources(
        registry,
        ledger,
        ledger_run_id=expected_ledger_run_id,
        original_result_id=plan.original_result_id,
        original_execution_run_id=expected_original_execution_run_id,
        original_result_promotion_artifact_sha256=(
            plan.original_result_promotion_artifact_sha256
        ),
        rerun_frozen_run_spec_artifact_sha256=(
            plan.rerun_frozen_run_spec_artifact_sha256
        ),
    )
    rerun_assessment = require_checked_result_assessment(
        registry,
        ledger,
        assessment_artifact_sha256=(
            rerun_result_assessment_artifact_sha256
        ),
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_rerun_execution_run_id,
    )
    rerun_assessment_record = registry.get_metadata(
        rerun_result_assessment_artifact_sha256
    )
    rerun_projection_artifact_sha256 = (
        rerun_assessment.generic_ml_paired_metric_projection_authority_artifact_sha256
    )
    if (
        not rerun_assessment.is_projection_backed
        or rerun_projection_artifact_sha256 is None
        or rerun_assessment.domain_validity_receipt_artifact_sha256
        != rerun_domain_validity_receipt_artifact_sha256
        or rerun_assessment.assessment_id != plan.rerun_assessment_id
        or _matching_checked_assessment_slot_records(
            registry,
            ledger_run_id=expected_ledger_run_id,
            execution_run_id=expected_rerun_execution_run_id,
            assessment_id=plan.rerun_assessment_id,
        )
        != (rerun_assessment_record,)
    ):
        raise ReproductionError(
            "clean-rerun assessment differs from its prospectively reserved slot"
        )
    try:
        rerun_domain = _require_result_promotion_domain_authority(
            registry,
            ledger,
            artifact_sha256=rerun_domain_validity_receipt_artifact_sha256,
            expected_run_id=expected_ledger_run_id,
            expected_result_id=plan.rerun_result_id,
            expected_projection_artifact_sha256=(
                rerun_projection_artifact_sha256
            ),
        )
    except Exception as exc:
        raise ReproductionError(
            "clean-rerun domain authority failed source-owned replay"
        ) from exc
    from .domains import DomainEvidenceScope, DomainValidityStatus

    if (
        rerun_domain.scope is not DomainEvidenceScope.SCIENTIFIC_EVIDENCE
        or rerun_domain.outcome.status is not DomainValidityStatus.PASS
        or rerun_domain.domain.value != plan.rerun_domain
        or rerun_domain.task_id != plan.rerun_domain_task_id
    ):
        raise ReproductionError(
            "scientific clean rerun requires scientific rerun domain PASS"
        )
    rerun_domain_record = registry.get_metadata(
        rerun_domain_validity_receipt_artifact_sha256
    )
    # Both scientific domain receipt versions have this exact owner-validated
    # publication identity. Their full owner was replayed above; no generic
    # artifact-reference discovery may stand in for this admission.
    domain_event_index = _clean_rerun_owned_domain_publication_index(
        ledger.events(), rerun_domain_record.sha256,
    )
    rerun_execution = require_scientific_execution_authority(
        registry,
        ledger,
        authority_artifact_sha256=(
            rerun_assessment.scientific_execution_authority_artifact_sha256
        ),
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_rerun_execution_run_id,
    )
    rerun_execution_record = registry.get_metadata(
        rerun_assessment.scientific_execution_authority_artifact_sha256
    )
    if (
        rerun_assessment.frozen_run_spec_artifact_sha256
        != plan.rerun_frozen_run_spec_artifact_sha256
        or rerun_execution.frozen_run_spec_artifact_sha256
        != plan.rerun_frozen_run_spec_artifact_sha256
        or rerun_execution.scientific_binding_sha256
        != plan.scientific_binding_sha256
        or rerun_execution.outcome is not ScientificExecutionOutcome.COMPLETED
        or not rerun_execution.scientific_evidence_eligible
    ):
        raise ReproductionError(
            "clean-rerun result differs from its prospective execution plan"
        )
    original_environment_record, original_environment, original_isolation_record, original_isolation = (
        _load_clean_execution_environment(
            registry,
            plan_sources.original_execution,
            require_clean=False,
        )
    )
    rerun_environment_record, rerun_environment, rerun_isolation_record, rerun_isolation = (
        _load_clean_execution_environment(
            registry,
            rerun_execution,
            require_clean=True,
        )
    )
    if (
        plan_sources.original_execution.challenge_nonce
        == rerun_execution.challenge_nonce
        or plan_sources.original_execution.preparation_artifact_sha256
        == rerun_execution.preparation_artifact_sha256
        or original_environment_record.sha256 == rerun_environment_record.sha256
        or original_isolation_record.sha256 == rerun_isolation_record.sha256
        or original_environment["writable_storage_id"]
        == rerun_environment["writable_storage_id"]
        or (
            plan_sources.original_execution.backend_profile.key
            == rerun_execution.backend_profile.key
            and (
                plan_sources.original_execution.backend_job_id
                == rerun_execution.backend_job_id
                or plan_sources.original_execution.provider_invocation_id
                == rerun_execution.provider_invocation_id
            )
        )
        or _clean_utc_timestamp(
            rerun_execution.attested_started_at,
            "clean-rerun attested start",
        )
        < _clean_utc_timestamp(plan.planned_at, "clean-rerun planned time")
    ):
        raise ReproductionError(
            "clean-rerun execution is not prospectively distinct and isolated"
        )
    original_assessment = plan_sources.result_resolution.assessment
    if plan.is_bounded_mean:
        if any(not item.is_bounded_mean for item in (original_assessment, rerun_assessment)):
            raise ReproductionError("bounded clean-rerun plan requires bounded sources on both sides")
        evidence = tuple(_replay_bounded_clean_rerun_evidence(registry, ledger, item)
                         for item in (original_assessment, rerun_assessment))
        if (
            any(item.statistical_use_record != plan_sources.statistical_use_record for item in evidence)
            or evidence[0].bounded_mean_result.plan != evidence[1].bounded_mean_result.plan
            or plan.statistical_use_authority_artifact_sha256 != plan_sources.statistical_use_record.sha256
            or plan.statistical_use_authority_record_hash != plan_sources.statistical_use_record.record_hash
            or any(item.inference_profile_id != plan.inference_profile_id for item in (original_assessment, rerun_assessment))
        ):
            raise ReproductionError("bounded clean rerun differs from its prospectively fixed native plan")
        from .domains import GenericMLFixedModelAdapter, GenericMLFixedModelValidityEvidence

        fixed_profiles = tuple(item.domain.evidence for item in evidence)
        if any(type(profile) is GenericMLFixedModelValidityEvidence for profile in fixed_profiles):
            if (
                any(type(profile) is not GenericMLFixedModelValidityEvidence for profile in fixed_profiles)
                or any(item.domain.outcome.adapter_version != GenericMLFixedModelAdapter.version for item in evidence)
            ):
                raise ReproductionError("clean rerun requires the same exact fixed-model domain profile")
            # Full checked replay above joins each side to its own prospective
            # sources. Compare only common scientific facts, not per-run spec,
            # execution, environment, projection or domain receipt identities.
            if any(
                getattr(fixed_profiles[0], name) != getattr(fixed_profiles[1], name)
                for name in (
                    "reference_work_policy", "reference_work",
                    "statistical_use_authority_artifact_sha256",
                    "statistical_use_authority_record_hash",
                    "requested_timeout_seconds", "contract_wall_cap_seconds",
                )
            ):
                raise ReproductionError("clean rerun changes the full-owned fixed-model domain facts")
        comparison = derive_bounded_mean_clean_rerun_comparison(
            original_assessment, rerun_assessment,
            original_projection=evidence[0].projection, rerun_projection=evidence[1].projection,
            comparison_tolerance=plan.comparison_tolerance,
        )
    else:
        comparison = derive_scientific_clean_rerun_comparison(
            original_assessment, rerun_assessment,
            comparison_tolerance=plan.comparison_tolerance,
        )
    records = (
        plan_record,
        plan_sources.result_promotion_record,
        rerun_domain_record,
        plan_sources.assessment_record,
        rerun_assessment_record,
        plan_sources.original_execution_record,
        rerun_execution_record,
        original_environment_record,
        rerun_environment_record,
        original_isolation_record,
        rerun_isolation_record,
    )
    if any(record.record_hash is None for record in records):
        raise ReproductionError("clean-rerun source lacks a record hash")
    return _CleanRerunAuthoritySources(
        plan_record=plan_record,
        plan=plan,
        result_promotion_record=plan_sources.result_promotion_record,
        rerun_domain_record=rerun_domain_record,
        rerun_domain=rerun_domain,
        original_assessment_record=plan_sources.assessment_record,
        original_assessment=plan_sources.result_resolution.assessment,
        rerun_assessment_record=rerun_assessment_record,
        rerun_assessment=rerun_assessment,
        original_execution_record=plan_sources.original_execution_record,
        original_execution=plan_sources.original_execution,
        rerun_execution_record=rerun_execution_record,
        rerun_execution=rerun_execution,
        original_environment_record=original_environment_record,
        original_environment=original_environment,
        original_isolation_record=original_isolation_record,
        original_isolation=original_isolation,
        rerun_environment_record=rerun_environment_record,
        rerun_environment=rerun_environment,
        rerun_isolation_record=rerun_isolation_record,
        rerun_isolation=rerun_isolation,
        rerun_spec=plan_sources.rerun_spec,
        comparison=comparison,
        rerun_domain_event_index=domain_event_index,
        statistical_use_record=plan_sources.statistical_use_record,
    )


def _scientific_clean_rerun_authority_id(
    sources: _CleanRerunAuthoritySources,
) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                **(_bounded_clean_rerun_comparison_binding(sources) if sources.plan.is_bounded_mean else {}),
                "source_artifact_sha256s": [
                    item.sha256 for item in sources.source_records
                ],
                "source_artifact_record_hashes": [
                    str(item.record_hash) for item in sources.source_records
                ],
                "exact_mismatches": list(
                    sources.comparison.exact_mismatches
                ),
                "differences": [
                    item.to_dict() for item in sources.comparison.differences
                ],
                "outcome": sources.comparison.outcome.value,
            }
        )
    ).hexdigest()
    return f"scientific-clean-rerun-{digest[:24]}"


def _bounded_clean_rerun_comparison_binding(sources: _CleanRerunAuthoritySources) -> dict[str, Any]:
    if not sources.plan.is_bounded_mean:
        return {}
    if type(sources.comparison) is not BoundedMeanCleanRerunComparison:
        raise ReproductionError("bounded clean-rerun plan cannot use a legacy comparison")
    return {
        **_clean_rerun_profile_dict(sources.plan),
        "grid_comparisons": [item.to_dict() for item in sources.comparison.grid_comparisons],
        "new_data_replication_claimed": False,
        "training_randomness_generalization_claimed": False,
    }


def _scientific_clean_rerun_authority_binding(
    sources: _CleanRerunAuthoritySources,
    *,
    authority_id: str,
) -> dict[str, Any]:
    return {
        "schema_version": (SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_EVENT_SCHEMA if sources.plan.is_bounded_mean
                           else SCIENTIFIC_CLEAN_RERUN_AUTHORITY_EVENT_SCHEMA),
        **_bounded_clean_rerun_comparison_binding(sources),
        "kind": "SCIENTIFIC_CLEAN_RERUN_VERIFIED",
        "authority_id": authority_id,
        "ledger_run_id": sources.plan.ledger_run_id,
        "plan_artifact_sha256": sources.plan_record.sha256,
        "original_result_id": sources.plan.original_result_id,
        "rerun_result_id": sources.plan.rerun_result_id,
        "rerun_assessment_id": sources.plan.rerun_assessment_id,
        "rerun_domain_validity_receipt_artifact_sha256": (
            sources.rerun_domain_record.sha256
        ),
        "rerun_domain": sources.rerun_domain.domain.value,
        "rerun_domain_task_id": sources.rerun_domain.task_id,
        "rerun_domain_validity_status": (
            sources.rerun_domain.outcome.status.value
        ),
        "rerun_domain_evidence_scope": sources.rerun_domain.scope.value,
        "original_execution_run_id": (
            sources.original_execution.execution_run_id
        ),
        "rerun_execution_run_id": sources.rerun_execution.execution_run_id,
        "source_artifact_sha256s": [
            item.sha256 for item in sources.source_records
        ],
        "source_artifact_record_hashes": [
            str(item.record_hash) for item in sources.source_records
        ],
        "original_preparation_artifact_sha256": (
            sources.original_execution.preparation_artifact_sha256
        ),
        "rerun_preparation_artifact_sha256": (
            sources.rerun_execution.preparation_artifact_sha256
        ),
        "original_challenge_nonce": sources.original_execution.challenge_nonce,
        "rerun_challenge_nonce": sources.rerun_execution.challenge_nonce,
        "original_environment_artifact_sha256": (
            sources.original_environment_record.sha256
        ),
        "rerun_environment_artifact_sha256": (
            sources.rerun_environment_record.sha256
        ),
        "original_isolation_attestation_artifact_sha256": (
            sources.original_isolation_record.sha256
        ),
        "rerun_isolation_attestation_artifact_sha256": (
            sources.rerun_isolation_record.sha256
        ),
        "original_writable_storage_id": (
            sources.original_environment["writable_storage_id"]
        ),
        "rerun_writable_storage_id": (
            sources.rerun_environment["writable_storage_id"]
        ),
        "original_backend_profile": (
            sources.original_execution.backend_profile.to_dict()
        ),
        "rerun_backend_profile": sources.rerun_execution.backend_profile.to_dict(),
        "original_backend_namespace_sha256": hashlib.sha256(
            canonical_json_bytes(
                sources.original_execution.backend_profile.to_dict()
            )
        ).hexdigest(),
        "rerun_backend_namespace_sha256": hashlib.sha256(
            canonical_json_bytes(sources.rerun_execution.backend_profile.to_dict())
        ).hexdigest(),
        "original_backend_job_id": sources.original_execution.backend_job_id,
        "rerun_backend_job_id": sources.rerun_execution.backend_job_id,
        "original_provider_invocation_id": (
            sources.original_execution.provider_invocation_id
        ),
        "rerun_provider_invocation_id": (
            sources.rerun_execution.provider_invocation_id
        ),
        "backend_execution_identity_distinct": True,
        "same_host_permitted": True,
        "cross_host_replication_claimed": False,
        "original_cache_used": sources.original_isolation["cache_used"],
        "original_checkpoint_used": sources.original_isolation[
            "checkpoint_used"
        ],
        "original_resumed_from_checkpoint": sources.original_isolation[
            "resumed_from_checkpoint"
        ],
        "rerun_cache_used": sources.rerun_isolation["cache_used"],
        "rerun_checkpoint_used": sources.rerun_isolation["checkpoint_used"],
        "rerun_resumed_from_checkpoint": sources.rerun_isolation[
            "resumed_from_checkpoint"
        ],
        "shared_writable_state_ids": [],
        "exact_mismatches": list(sources.comparison.exact_mismatches),
        "differences": [
            item.to_dict() for item in sources.comparison.differences
        ],
        "outcome": sources.comparison.outcome.value,
        "authority_scope": "SCIENTIFIC_CLEAN_RERUN_COMPARISON",
        "scientific_evidence": True,
    }


def _scientific_clean_rerun_authority_from_event(
    sources: _CleanRerunAuthoritySources,
    *,
    authority_id: str,
    event: LedgerEvent,
    event_index: int,
) -> ScientificCleanRerunAuthority:
    if event.event_hash is None:
        raise ReproductionError("clean-rerun verification event hash is absent")
    return ScientificCleanRerunAuthority(
        authority_id=authority_id,
        ledger_run_id=sources.plan.ledger_run_id,
        plan_artifact_sha256=sources.plan_record.sha256,
        plan_record_hash=str(sources.plan_record.record_hash),
        original_result_promotion_artifact_sha256=(
            sources.result_promotion_record.sha256
        ),
        original_result_promotion_record_hash=str(
            sources.result_promotion_record.record_hash
        ),
        original_result_id=sources.plan.original_result_id,
        rerun_result_id=sources.plan.rerun_result_id,
        rerun_assessment_id=sources.plan.rerun_assessment_id,
        rerun_domain_validity_receipt_artifact_sha256=(
            sources.rerun_domain_record.sha256
        ),
        rerun_domain_validity_receipt_record_hash=str(
            sources.rerun_domain_record.record_hash
        ),
        rerun_domain=sources.rerun_domain.domain.value,
        rerun_domain_task_id=sources.rerun_domain.task_id,
        rerun_domain_validity_status=sources.rerun_domain.outcome.status.value,
        rerun_domain_evidence_scope=sources.rerun_domain.scope.value,
        original_result_assessment_artifact_sha256=(
            sources.original_assessment_record.sha256
        ),
        original_result_assessment_record_hash=str(
            sources.original_assessment_record.record_hash
        ),
        rerun_result_assessment_artifact_sha256=(
            sources.rerun_assessment_record.sha256
        ),
        rerun_result_assessment_record_hash=str(
            sources.rerun_assessment_record.record_hash
        ),
        original_execution_authority_artifact_sha256=(
            sources.original_execution_record.sha256
        ),
        original_execution_authority_record_hash=str(
            sources.original_execution_record.record_hash
        ),
        rerun_execution_authority_artifact_sha256=(
            sources.rerun_execution_record.sha256
        ),
        rerun_execution_authority_record_hash=str(
            sources.rerun_execution_record.record_hash
        ),
        original_execution_run_id=sources.original_execution.execution_run_id,
        rerun_execution_run_id=sources.rerun_execution.execution_run_id,
        original_preparation_artifact_sha256=(
            sources.original_execution.preparation_artifact_sha256
        ),
        rerun_preparation_artifact_sha256=(
            sources.rerun_execution.preparation_artifact_sha256
        ),
        original_output_manifest_artifact_sha256=(
            sources.original_execution.output_manifest_artifact_sha256
        ),
        rerun_output_manifest_artifact_sha256=(
            sources.rerun_execution.output_manifest_artifact_sha256
        ),
        original_environment_artifact_sha256=(
            sources.original_environment_record.sha256
        ),
        original_environment_record_hash=str(
            sources.original_environment_record.record_hash
        ),
        rerun_environment_artifact_sha256=(
            sources.rerun_environment_record.sha256
        ),
        rerun_environment_record_hash=str(
            sources.rerun_environment_record.record_hash
        ),
        original_isolation_attestation_artifact_sha256=(
            sources.original_isolation_record.sha256
        ),
        rerun_isolation_attestation_artifact_sha256=(
            sources.rerun_isolation_record.sha256
        ),
        original_environment_fingerprint=str(
            sources.original_environment["environment_fingerprint"]
        ),
        rerun_environment_fingerprint=str(
            sources.rerun_environment["environment_fingerprint"]
        ),
        original_host_instance_id=str(
            sources.original_environment["host_instance_id"]
        ),
        rerun_host_instance_id=str(
            sources.rerun_environment["host_instance_id"]
        ),
        original_boot_session_id=str(
            sources.original_environment["boot_session_id"]
        ),
        rerun_boot_session_id=str(
            sources.rerun_environment["boot_session_id"]
        ),
        original_writable_storage_id=str(
            sources.original_environment["writable_storage_id"]
        ),
        rerun_writable_storage_id=str(
            sources.rerun_environment["writable_storage_id"]
        ),
        original_backend_namespace_sha256=hashlib.sha256(
            canonical_json_bytes(
                sources.original_execution.backend_profile.to_dict()
            )
        ).hexdigest(),
        rerun_backend_namespace_sha256=hashlib.sha256(
            canonical_json_bytes(sources.rerun_execution.backend_profile.to_dict())
        ).hexdigest(),
        original_backend_job_id=sources.original_execution.backend_job_id,
        rerun_backend_job_id=sources.rerun_execution.backend_job_id,
        original_provider_invocation_id=(
            sources.original_execution.provider_invocation_id
        ),
        rerun_provider_invocation_id=(
            sources.rerun_execution.provider_invocation_id
        ),
        original_cache_used=bool(sources.original_isolation["cache_used"]),
        original_checkpoint_used=bool(
            sources.original_isolation["checkpoint_used"]
        ),
        original_resumed_from_checkpoint=bool(
            sources.original_isolation["resumed_from_checkpoint"]
        ),
        rerun_cache_used=bool(sources.rerun_isolation["cache_used"]),
        rerun_checkpoint_used=bool(
            sources.rerun_isolation["checkpoint_used"]
        ),
        rerun_resumed_from_checkpoint=bool(
            sources.rerun_isolation["resumed_from_checkpoint"]
        ),
        original_challenge_nonce=sources.original_execution.challenge_nonce,
        rerun_challenge_nonce=sources.rerun_execution.challenge_nonce,
        exact_mismatches=sources.comparison.exact_mismatches,
        differences=sources.comparison.differences,
        outcome=sources.comparison.outcome,
        verification_event_id=event.event_id,
        verification_event_hash=event.event_hash,
        verification_event_index=event_index,
        **(_clean_rerun_profile_dict(sources.plan) if sources.plan.is_bounded_mean else {}),
        grid_comparisons=(sources.comparison.grid_comparisons if sources.plan.is_bounded_mean else ()),
    )


def _validate_scientific_clean_rerun_authority_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    sources: _CleanRerunAuthoritySources,
    binding: Mapping[str, Any],
) -> None:
    _require_clean_rerun_event_bound(event)
    if (
        event.event_hash is None
        or event.actor_role is not Role.REPRODUCTION_VERIFIER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes
        != tuple(item.sha256 for item in sources.source_records)
        or event.code_version != f"sha256:{sources.rerun_spec.code_sha256}"
        or event.configuration_hash != sources.rerun_spec.configuration_sha256
        or event.dataset_identifiers != (sources.rerun_spec.data_sha256,)
        or event.random_seeds != sources.rerun_spec.seeds
        or event.evaluator_outputs
        or event.reason
        != "verified two prospectively bound isolated scientific executions"
        or thaw_json(event.metadata)
        != {"scientific_clean_rerun_authority": dict(binding)}
        or event_index
        <= max(
            sources.plan.ledger_event_index,
            sources.original_execution.ledger_event_index,
            sources.rerun_execution.ledger_event_index,
        )
        or type(sources.rerun_domain_event_index) is not int
        or not 0 <= sources.rerun_domain_event_index < event_index
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ReproductionError(
            "scientific clean-rerun verification event is stale or substituted"
        )
    _require_clean_rerun_source_chronology(event, sources.source_records)


def _scientific_clean_rerun_publication_metadata(
    record: ArtifactRecord,
    authority: ScientificCleanRerunAuthority,
) -> dict[str, Any]:
    return {
        "artifact_types": [record.logical_type],
        "artifact_record_hashes": [str(record.record_hash)],
        "scientific_clean_rerun_authority_publication": {
            "schema_version": (SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_EVENT_SCHEMA if authority.is_bounded_mean
                               else SCIENTIFIC_CLEAN_RERUN_AUTHORITY_EVENT_SCHEMA),
            **(_clean_rerun_profile_dict(authority) if authority.is_bounded_mean else {}),
            "authority_id": authority.authority_id,
            "plan_artifact_sha256": authority.plan_artifact_sha256,
            "outcome": authority.outcome.value,
            "authority_scope": authority.authority_scope,
            "scientific_evidence": True,
        },
    }


def _validate_scientific_clean_rerun_publication_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    record: ArtifactRecord,
    authority: ScientificCleanRerunAuthority,
    rerun_spec: FrozenRunSpec,
) -> None:
    _require_clean_rerun_event_bound(event)
    if (
        event.event_hash is None
        or event.actor_role is not Role.REPRODUCTION_VERIFIER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes != (record.sha256,)
        or event.code_version != f"sha256:{rerun_spec.code_sha256}"
        or event.configuration_hash != rerun_spec.configuration_sha256
        or event.dataset_identifiers != (rerun_spec.data_sha256,)
        or event.random_seeds != rerun_spec.seeds
        or event.evaluator_outputs
        or event.reason != "admitted source-owned scientific clean-rerun authority"
        or thaw_json(event.metadata)
        != _scientific_clean_rerun_publication_metadata(record, authority)
        or event_index <= authority.verification_event_index
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ReproductionError(
            "scientific clean-rerun publication event is stale or substituted"
        )
    _require_clean_rerun_source_chronology(event, (record,))


def register_scientific_clean_rerun_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    rerun_result_assessment_artifact_sha256: str,
    rerun_domain_validity_receipt_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_original_execution_run_id: str,
    expected_rerun_execution_run_id: str,
) -> ArtifactRecord:
    """Issue authority only for two freshly replayed scientific executions."""

    entry_registry, entry_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        expected_ledger_run_id,
    )
    sources = _resolve_clean_rerun_authority_sources(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        rerun_result_assessment_artifact_sha256=(
            rerun_result_assessment_artifact_sha256
        ),
        rerun_domain_validity_receipt_artifact_sha256=(
            rerun_domain_validity_receipt_artifact_sha256
        ),
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    authority_id = _scientific_clean_rerun_authority_id(sources)
    binding = _scientific_clean_rerun_authority_binding(
        sources,
        authority_id=authority_id,
    )
    slot_records = _matching_clean_rerun_authority_records(
        registry, entry_registry.records, plan_artifact_sha256=plan_artifact_sha256, plan=sources.plan,
    )
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                locked_registry != entry_registry
                or locked_ledger != entry_ledger
                or not locked_ledger.valid
            ):
                raise ReproductionError(
                    "clean-rerun authority sources changed before admission"
                )
            admitted = tuple(
                (index, item)
                for index, item in enumerate(locked_ledger.events)
                if isinstance(
                    candidate := thaw_json(item.metadata).get(
                        "scientific_clean_rerun_authority"
                    ),
                    Mapping,
                )
                and _clean_rerun_authority_slot_matches(
                    candidate, plan_artifact_sha256=sources.plan_record.sha256,
                    rerun_result_id=sources.plan.rerun_result_id,
                    rerun_assessment_id=sources.plan.rerun_assessment_id,
                    rerun_execution_run_id=expected_rerun_execution_run_id,
                )
            )
            if len(admitted) > 1:
                raise ReproductionError(
                    "scientific clean-rerun verification slot is ambiguous"
                )
            if admitted:
                event_index, verification_event = admitted[0]
                if (
                    thaw_json(verification_event.metadata).get(
                        "scientific_clean_rerun_authority"
                    )
                    != binding
                ):
                    raise ReproductionError(
                        "clean-rerun recovery differs from the admitted verification"
                    )
            else:
                current_state = (
                    locked_ledger.events[-1].state_after
                    if locked_ledger.events
                    else MacroState.PREFLIGHT
                )
                verification_event = LedgerEvent.create(
                    run_id=expected_ledger_run_id,
                    actor_role=Role.REPRODUCTION_VERIFIER,
                    state_before=current_state,
                    requested_state_after=current_state,
                    artifact_hashes=tuple(
                        item.sha256 for item in sources.source_records
                    ),
                    code_version=f"sha256:{sources.rerun_spec.code_sha256}",
                    configuration_hash=sources.rerun_spec.configuration_sha256,
                    dataset_identifiers=(sources.rerun_spec.data_sha256,),
                    random_seeds=sources.rerun_spec.seeds,
                    evaluator_outputs=(),
                    reason=(
                        "verified two prospectively bound isolated "
                        "scientific executions"
                    ),
                    prior_event_hash=locked_ledger.head_hash,
                    event_type="CHECKPOINT",
                    metadata={"scientific_clean_rerun_authority": binding},
                )
                _require_clean_rerun_event_bound(verification_event)
                event_index = len(locked_ledger.events)
            authority = _scientific_clean_rerun_authority_from_event(
                sources,
                authority_id=authority_id,
                event=verification_event,
                event_index=event_index,
            )
            authority_bytes = canonical_json_bytes(authority.to_dict()) + b"\n"
            expected_authority_sha256 = hashlib.sha256(authority_bytes).hexdigest()
            existing = slot_records
            if len(existing) > 1 or (
                existing and existing[0].sha256 != expected_authority_sha256
            ):
                raise ReproductionError(
                    "scientific clean-rerun authority artifact slot is ambiguous"
                )
            publication_matches = tuple(
                (index, item)
                for index, item in enumerate(locked_ledger.events)
                if isinstance(
                    candidate := thaw_json(item.metadata).get(
                        "scientific_clean_rerun_authority_publication"
                    ),
                    Mapping,
                )
                and (expected_authority_sha256 in item.artifact_hashes
                     or candidate.get("plan_artifact_sha256") == sources.plan_record.sha256)
            )
            if len(publication_matches) > 1:
                raise ReproductionError(
                    "scientific clean-rerun authority has ambiguous ledger admissions"
                )
            prospective_events = locked_ledger.events if admitted else (*locked_ledger.events, verification_event)
            _validate_scientific_clean_rerun_authority_event(
                verification_event, event_index, prospective_events,
                sources=sources, binding=binding,
            )
            prospective_record = _preflight_clean_rerun_record(
                registry, locked_registry, authority_bytes,
                logical_type=SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
                origin=_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_ORIGIN,
                creator_role=Role.REPRODUCTION_VERIFIER,
                creation_command=_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_COMMAND,
                parent_artifacts=authority.source_artifact_hashes,
                schema_version="2.0" if authority.is_bounded_mean else "1.0",
                created_at=utc_now(),
            )
            if publication_matches:
                publication_index, publication_event = publication_matches[0]
                publication_events = prospective_events
            else:
                latest = prospective_events[-1]
                publication_event = LedgerEvent.create(
                    run_id=expected_ledger_run_id,
                    actor_role=Role.REPRODUCTION_VERIFIER,
                    state_before=latest.state_after,
                    requested_state_after=latest.state_after,
                    artifact_hashes=(prospective_record.sha256,),
                    code_version=f"sha256:{sources.rerun_spec.code_sha256}",
                    configuration_hash=sources.rerun_spec.configuration_sha256,
                    dataset_identifiers=(sources.rerun_spec.data_sha256,),
                    random_seeds=sources.rerun_spec.seeds, evaluator_outputs=(),
                    reason="admitted source-owned scientific clean-rerun authority",
                    prior_event_hash=latest.event_hash, event_type="CHECKPOINT",
                    metadata=_scientific_clean_rerun_publication_metadata(prospective_record, authority),
                )
                publication_index = len(prospective_events)
                publication_events = (*prospective_events, publication_event)
            _require_clean_rerun_event_bound(verification_event)
            _require_clean_rerun_event_bound(publication_event)
            _validate_scientific_clean_rerun_publication_event(
                publication_event, publication_index, publication_events,
                record=prospective_record, authority=authority, rerun_spec=sources.rerun_spec,
            )
            _require_clean_rerun_capacity(
                locked_registry,
                locked_ledger,
                registry_records_needed=int(not existing),
                ledger_events_needed=int(not admitted)
                + int(not publication_matches),
            )
            if admitted:
                verification_ledger = locked_ledger
            else:

                def append_verification(
                    current: LedgerValidationResult,
                ) -> LedgerEvent:
                    if current != locked_ledger:
                        raise ReproductionError(
                            "clean-rerun verification ledger changed before admission"
                        )
                    return verification_event

                ledger._append_locked(ledger_guard, append_verification)
                verification_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if not verification_ledger.valid or verification_ledger.events != prospective_events:
                    raise ReproductionError(
                        "clean-rerun verification corrupted the ledger"
                    )
            _validate_scientific_clean_rerun_authority_event(
                verification_event,
                event_index,
                verification_ledger.events,
                sources=sources,
                binding=binding,
            )
            record = registry._put_bytes_locked(
                registry_guard,
                authority_bytes,
                logical_type=SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
                origin=_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_ORIGIN,
                creator_role=Role.REPRODUCTION_VERIFIER,
                creation_command=_SCIENTIFIC_CLEAN_RERUN_AUTHORITY_COMMAND,
                parent_artifacts=authority.source_artifact_hashes,
                schema_version=prospective_record.schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=prospective_record.created_at,
            )
            if record != prospective_record:
                raise ReproductionError("clean-rerun authority differs from its prospective metadata")
            if publication_matches:
                publication_ledger = verification_ledger
            else:

                def build_publication_event(
                    current: LedgerValidationResult,
                ) -> LedgerEvent:
                    if current != verification_ledger:
                        raise ReproductionError(
                            "clean-rerun publication ledger changed before admission"
                        )
                    return publication_event

                publication_event = ledger._append_locked(
                    ledger_guard,
                    build_publication_event,
                )
                publication_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if not publication_ledger.valid or publication_ledger.events != publication_events:
                    raise ReproductionError(
                        "clean-rerun publication corrupted the ledger"
                    )
                publication_index = len(publication_ledger.events) - 1
            _validate_scientific_clean_rerun_publication_event(
                publication_event,
                publication_index,
                publication_ledger.events,
                record=record,
                authority=authority,
                rerun_spec=sources.rerun_spec,
            )
            final_locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            final_locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            expected_records = (
                locked_registry.records
                if existing
                else tuple(
                    sorted(
                        (*locked_registry.records, record),
                        key=lambda item: item.sha256,
                    )
                )
            )
            if (
                final_locked_registry.records != expected_records
                or final_locked_registry.errors != locked_registry.errors
                or final_locked_registry.orphan_paths
                != locked_registry.orphan_paths
                or final_locked_ledger != publication_ledger
            ):
                raise ReproductionError(
                    "clean-rerun authority publication changed unexpectedly"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    require_scientific_clean_rerun_authority(
        registry,
        ledger,
        authority_artifact_sha256=record.sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    return record


def require_scientific_clean_rerun_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_original_execution_run_id: str,
    expected_rerun_execution_run_id: str,
) -> ScientificCleanRerunAuthority:
    """Freshly replay a persisted scientific clean-rerun authority."""

    entry_registry, entry_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        expected_ledger_run_id,
    )
    events = entry_ledger.events
    record, value = _load_clean_rerun_json(
        registry,
        authority_artifact_sha256,
        logical_type=SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
        creator_role=Role.REPRODUCTION_VERIFIER,
        schema_version=("1.0", "2.0"),
    )
    if (
        record.origin != _SCIENTIFIC_CLEAN_RERUN_AUTHORITY_ORIGIN
        or record.creation_command != _SCIENTIFIC_CLEAN_RERUN_AUTHORITY_COMMAND
    ):
        raise ReproductionError(
            "scientific clean-rerun authority metadata is not source-owned"
        )
    authority = ScientificCleanRerunAuthority.from_mapping(value)
    if (
        record.schema_version != ("2.0" if authority.is_bounded_mean else "1.0")
        or authority.ledger_run_id != expected_ledger_run_id
        or authority.original_execution_run_id
        != expected_original_execution_run_id
        or authority.rerun_execution_run_id != expected_rerun_execution_run_id
        or record.parent_artifacts != authority.source_artifact_hashes
    ):
        raise ReproductionError(
            "scientific clean-rerun authority names another source closure"
        )
    sources = _resolve_clean_rerun_authority_sources(
        registry,
        ledger,
        plan_artifact_sha256=authority.plan_artifact_sha256,
        rerun_result_assessment_artifact_sha256=(
            authority.rerun_result_assessment_artifact_sha256
        ),
        rerun_domain_validity_receipt_artifact_sha256=(
            authority.rerun_domain_validity_receipt_artifact_sha256
        ),
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    if _matching_clean_rerun_authority_records(
        registry, entry_registry.records,
        plan_artifact_sha256=authority.plan_artifact_sha256, plan=sources.plan,
    ) != (record,):
        raise ReproductionError("scientific clean-rerun authority artifact slot is ambiguous")
    authority_id = _scientific_clean_rerun_authority_id(sources)
    binding = _scientific_clean_rerun_authority_binding(
        sources,
        authority_id=authority_id,
    )
    verification_matches = tuple(
        (index, event)
        for index, event in enumerate(events)
        if isinstance(
            candidate := thaw_json(event.metadata).get(
                "scientific_clean_rerun_authority"
            ),
            Mapping,
        )
        and _clean_rerun_authority_slot_matches(
            candidate, plan_artifact_sha256=sources.plan_record.sha256,
            rerun_result_id=sources.plan.rerun_result_id,
            rerun_assessment_id=sources.plan.rerun_assessment_id,
            rerun_execution_run_id=expected_rerun_execution_run_id,
        )
    )
    if len(verification_matches) != 1:
        raise ReproductionError(
            "scientific clean-rerun authority lacks one verification event"
        )
    event_index, verification_event = verification_matches[0]
    _validate_scientific_clean_rerun_authority_event(
        verification_event,
        event_index,
        events,
        sources=sources,
        binding=binding,
    )
    expected = _scientific_clean_rerun_authority_from_event(
        sources,
        authority_id=authority_id,
        event=verification_event,
        event_index=event_index,
    )
    if authority != expected:
        raise ReproductionError(
            "scientific clean-rerun authority differs from fresh source replay"
        )
    publication_matches = tuple(
        (index, event)
        for index, event in enumerate(events)
        if isinstance(
            candidate := thaw_json(event.metadata).get(
                "scientific_clean_rerun_authority_publication"
            ),
            Mapping,
        )
        and (record.sha256 in event.artifact_hashes
             or candidate.get("plan_artifact_sha256") == sources.plan_record.sha256)
    )
    if len(publication_matches) != 1:
        raise ReproductionError(
            "scientific clean-rerun authority lacks one publication admission"
        )
    publication_index, publication_event = publication_matches[0]
    _validate_scientific_clean_rerun_publication_event(
        publication_event,
        publication_index,
        events,
        record=record,
        authority=authority,
        rerun_spec=sources.rerun_spec,
    )
    _require_clean_rerun_snapshot_unchanged(
        registry,
        ledger,
        expected_ledger_run_id,
        entry_registry,
        entry_ledger,
    )
    return authority


def resolve_scientific_clean_rerun_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_original_execution_run_id: str,
    expected_rerun_execution_run_id: str,
) -> ScientificCleanRerunAuthorityResolution:
    """Resolve absence as external blocking; malformed candidates raise."""

    entry_registry, entry_ledger = _locked_clean_rerun_snapshot(
        registry,
        ledger,
        expected_ledger_run_id,
    )
    plan = require_scientific_clean_rerun_plan(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    matches = _matching_clean_rerun_authority_records(
        registry, entry_registry.records, plan_artifact_sha256=plan_artifact_sha256, plan=plan,
    )
    if len(matches) > 1:
        raise ReproductionError(
            "scientific clean-rerun authority artifact slot is ambiguous"
        )
    if not matches:
        incomplete_events = tuple(
            event
            for event in entry_ledger.events
            if (
                isinstance(
                    candidate := thaw_json(event.metadata).get(
                        "scientific_clean_rerun_authority"
                    ),
                    Mapping,
                )
                and _clean_rerun_authority_slot_matches(
                    candidate, plan_artifact_sha256=plan_artifact_sha256,
                    rerun_result_id=plan.rerun_result_id,
                    rerun_assessment_id=plan.rerun_assessment_id,
                    rerun_execution_run_id=expected_rerun_execution_run_id,
                )
            )
            or (
                isinstance(
                    publication := thaw_json(event.metadata).get(
                        "scientific_clean_rerun_authority_publication"
                    ),
                    Mapping,
                )
                and publication.get("plan_artifact_sha256")
                == plan_artifact_sha256
            )
        )
        if incomplete_events:
            raise ReproductionError(
                "scientific clean-rerun admission is incomplete and requires "
                "source-owner recovery"
            )
        resolution = ScientificCleanRerunAuthorityResolution(
            status=ScientificCleanRerunResolutionStatus.BLOCKED_EXTERNAL,
            reason_code="SCIENTIFIC_CLEAN_RERUN_NOT_COMPLETED",
            reason=(
                "No source-owned authority for a distinct second scientific "
                "execution has been registered."
            ),
            plan_artifact_sha256=plan_artifact_sha256,
        )
        _require_clean_rerun_snapshot_unchanged(
            registry,
            ledger,
            expected_ledger_run_id,
            entry_registry,
            entry_ledger,
        )
        return resolution
    authority = require_scientific_clean_rerun_authority(
        registry,
        ledger,
        authority_artifact_sha256=matches[0].sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_original_execution_run_id=(
            expected_original_execution_run_id
        ),
        expected_rerun_execution_run_id=expected_rerun_execution_run_id,
    )
    if authority.plan_artifact_sha256 != plan_artifact_sha256 or (
        authority.ledger_run_id != plan.ledger_run_id
    ):
        raise ReproductionError(
            "scientific clean-rerun authority differs from its plan"
        )
    resolution = ScientificCleanRerunAuthorityResolution(
        status=ScientificCleanRerunResolutionStatus.AUTHORIZED,
        reason_code="SCIENTIFIC_CLEAN_RERUN_AUTHORIZED",
        reason=(
            "Two distinct source-owned scientific executions and their exact "
            "result comparison completed fresh authority replay."
        ),
        plan_artifact_sha256=plan_artifact_sha256,
        authority_artifact_sha256=matches[0].sha256,
        authority=authority,
    )
    _require_clean_rerun_snapshot_unchanged(
        registry,
        ledger,
        expected_ledger_run_id,
        entry_registry,
        entry_ledger,
    )
    return resolution


def _architecture_control_boundary() -> dict[str, Any]:
    return {
        "evidence_class": ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
        "replay_scope": ARCHITECTURE_CONTROL_REPLAY_SCOPE,
        "scientific_evidence": False,
        "independent_confirmation": False,
        "publication_eligible": False,
    }


def _require_replay_source_classification(
    source: Mapping[str, Any],
    custody: Mapping[str, Any],
    *,
    expected_evidence_class: str,
) -> None:
    if expected_evidence_class == SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS:
        # Preserve the existing scientific replay admission contract exactly.
        if source.get("evidence_class") != expected_evidence_class:
            raise ReproductionError("no local replay adapter for this evidence class")
        return
    if expected_evidence_class != ARCHITECTURE_CONTROL_EVIDENCE_CLASS:
        raise ReproductionError("unsupported frozen replay evidence class")
    if (
        source.get("evidence_class") != ARCHITECTURE_CONTROL_EVIDENCE_CLASS
        or source.get("scientific_evidence") is not False
        or custody.get("kind") != "SIMULATED_HOLDOUT_CUSTODY"
        or custody.get("custody_independence") != "SIMULATED_NON_INDEPENDENT"
        or custody.get("evidence_class") != ARCHITECTURE_CONTROL_EVIDENCE_CLASS
        or custody.get("execution_kind") != ARCHITECTURE_CONTROL_EXECUTION_KIND
        or custody.get("scientific_evidence") is not False
        or custody.get("confirmatory_claims_valid") is not False
        or custody.get("genuine_independence_claimed") is not False
        or custody.get("authorized_access_count") != 1
    ):
        raise ReproductionError(
            "architecture-control replay source is not exact and non-evidentiary"
        )


def _canonical_json(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value) + b"\n"
    except UnsafeSerializationError as exc:
        raise ReproductionError("reproduction value is not safe canonical JSON") from exc


def _read_scientific_domain_trust_root(
    registry: ArtifactRegistry,
) -> bytes | None:
    """Read the local admission key only to prove replay outputs exclude it."""

    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        directory_fd = open_confined_directory_fd(
            registry.policy.root,
            registry.base_path,
            create=False,
        )
        try:
            descriptor = os.open(
                SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        metadata = os.fstat(descriptor)
        named = os.stat(
            SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o777) != 0o600
            or metadata.st_size != _SCIENTIFIC_DOMAIN_TRUST_ROOT_BYTES
            or identity != (named.st_dev, named.st_ino)
        ):
            raise ReproductionError(
                "scientific-domain trust root is unsafe during replay secrecy check"
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(
            descriptor,
            _SCIENTIFIC_DOMAIN_TRUST_ROOT_BYTES + 1 - total,
        ):
            chunks.append(chunk)
            total += len(chunk)
            if total > _SCIENTIFIC_DOMAIN_TRUST_ROOT_BYTES:
                raise ReproductionError(
                    "scientific-domain trust root has an invalid size"
                )
        value = b"".join(chunks)
        final = os.fstat(descriptor)
        final_named = os.stat(
            SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        stable = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        final_stable = (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if (
            len(value) != _SCIENTIFIC_DOMAIN_TRUST_ROOT_BYTES
            or stable != final_stable
            or identity != (final_named.st_dev, final_named.st_ino)
        ):
            raise ReproductionError(
                "scientific-domain trust root changed during replay secrecy check"
            )
        return value
    except ReproductionError:
        raise
    except (OSError, PathSecurityError) as exc:
        raise ReproductionError(
            "scientific-domain trust root cannot be checked safely"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _assert_scientific_domain_trust_root_not_serialized(
    registry: ArtifactRegistry,
    members: Mapping[str, bytes],
) -> None:
    """Reject reproduction input/output that names or contains the local key."""

    key_material = _read_scientific_domain_trust_root(registry)
    marker = SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME.encode("utf-8")
    encoded_forms: tuple[bytes, ...] = ()
    if key_material is not None:
        standard_b64 = base64.b64encode(key_material)
        urlsafe_b64 = base64.urlsafe_b64encode(key_material)
        encoded_forms = tuple(
            dict.fromkeys(
                (
                    key_material,
                    key_material.hex().encode("ascii"),
                    key_material.hex().upper().encode("ascii"),
                    standard_b64,
                    standard_b64.rstrip(b"="),
                    urlsafe_b64,
                    urlsafe_b64.rstrip(b"="),
                )
            )
        )
    for name, content in members.items():
        if (
            not isinstance(name, str)
            or not isinstance(content, bytes)
            or SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME in name
            or marker in content
            or any(value in content for value in encoded_forms)
        ):
            raise ReproductionError(
                "scientific-domain trust root must not appear in reproduction"
            )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path, root: Path | None = None) -> dict[str, Any]:
    trust_root = root or path.parent
    try:
        canonical_root = trust_root.resolve(strict=True)
        candidate = path if path.is_absolute() else canonical_root / path
        relative = candidate.relative_to(canonical_root)
        payload = read_confined_bytes(
            canonical_root,
            relative,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        if payload is None:
            raise ReproductionError("JSON evidence disappeared")
        value = safe_json_loads(payload)
    except (OSError, ValueError, PathSecurityError, UnsafeSerializationError) as exc:
        raise ReproductionError(f"cannot read JSON evidence {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"expected a JSON object in {path.name}")
    return value


def _secure_directory(root: Path, path: Path, *, create: bool) -> Path:
    """Resolve a directory beneath *root* without following directory links."""

    root = root.resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ReproductionError("output directory escapes project root") from exc
    current = root
    for component in relative.parts:
        if component in {"", ".", ".."}:
            raise ReproductionError("unsafe output directory component")
        candidate = current / component
        try:
            candidate.lstat()
        except FileNotFoundError:
            if not create:
                raise ReproductionError("required output directory is absent")
            candidate.mkdir()
        if candidate.is_symlink() or not candidate.is_dir():
            raise ReproductionError("output directory contains a link or non-directory")
        current = candidate
    resolved = current.resolve(strict=True)
    if root not in resolved.parents and resolved != root:
        raise ReproductionError("output directory resolves outside project root")
    return resolved


def _read_regular_at(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ReproductionError("reproduction output is not an unlinked regular file")
        if metadata.st_size > max_bytes:
            raise ReproductionError("reproduction output exceeds its deterministic bound")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ReproductionError("reproduction output exceeds its deterministic bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _atomic_write(root: Path, path: Path, data: bytes) -> None:
    """Create a deterministic file, accepting an identical prior result."""

    root = root.resolve(strict=True)
    try:
        parent_relative = path.parent.relative_to(root)
        directory_fd = open_confined_directory_fd(
            root, parent_relative, create=True
        )
    except (ValueError, PathSecurityError) as exc:
        raise ReproductionError("reproduction output directory is unsafe") from exc
    partial_name = (
        f".{path.name}.{_sha256(data)[:16]}.{os.urandom(8).hex()}.partial"
    )
    descriptor: int | None = None
    try:
        try:
            existing = _read_regular_at(directory_fd, path.name, max_bytes=len(data))
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ReproductionError("unsafe existing reproduction artifact") from exc
        if existing is not None:
            if existing != data:
                raise ReproductionError(f"immutable reproduction collision: {path.name}")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(partial_name, flags, 0o600, dir_fd=directory_fd)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise ReproductionError("short reproduction write")
            offset += written
        os.fsync(descriptor)
        held = os.fstat(descriptor)
        named = os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or (held.st_dev, held.st_ino, held.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
        ):
            raise ReproductionError(
                "reproduction partial identity changed before publication"
            )
        try:
            os.link(
                partial_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _read_regular_at(directory_fd, path.name, max_bytes=len(data)) != data:
                raise ReproductionError(f"immutable reproduction collision: {path.name}")
        published_fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            published = os.fstat(published_fd)
            if (
                (published.st_dev, published.st_ino, published.st_size)
                != (held.st_dev, held.st_ino, len(data))
            ):
                raise ReproductionError(
                    "published reproduction identity differs from held bytes"
                )
        finally:
            os.close(published_fd)
        os.unlink(partial_name, dir_fd=directory_fd)
        os.close(descriptor)
        descriptor = None
        if _read_regular_at(directory_fd, path.name, max_bytes=len(data)) != data:
            raise ReproductionError(
                "published reproduction failed final byte verification"
            )
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(partial_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _safe_run_dir(root: Path, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ReproductionError("invalid run ID")
    try:
        return secure_directory(root, Path("runs") / run_id, create=False)
    except PathSecurityError as exc:
        raise ReproductionError("unsafe run directory") from exc


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = safe_json_loads(payload)
    except (UnsafeSerializationError, UnicodeDecodeError, ValueError) as exc:
        raise ReproductionError(f"malformed frozen {label}") from exc
    if not isinstance(value, dict):
        raise ReproductionError(f"frozen {label} must be a JSON object")
    return value


def _registry_artifact(
    project_root: Path,
    registry: ArtifactRegistry,
    record: Mapping[str, Any],
    logical_type: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    """Resolve one manifest record to a bounded immutable registry snapshot."""

    digest = record.get("sha256")
    if not isinstance(digest, str):
        raise ReproductionError(f"{logical_type} has no content digest")
    try:
        metadata = registry.get_metadata(digest)
        if metadata.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError(f"{logical_type} exceeds the replay size bound")
        payload = read_confined_bytes(
            project_root,
            metadata.path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except (ArtifactError, PathSecurityError) as exc:
        raise ReproductionError(f"{logical_type} registry evidence is absent or unsafe") from exc
    if payload is None:
        raise ReproductionError(f"{logical_type} registry evidence disappeared")
    if (
        metadata.logical_type != logical_type
        or metadata.path != record.get("registry_path")
        or metadata.metadata_path != record.get("registry_metadata_path")
        or metadata.record_hash != record.get("registry_record_hash")
        or metadata.size != len(payload)
        or metadata.sha256 != _sha256(payload)
        or metadata.frozen is not True
        or metadata.validation_result != "PASS"
    ):
        raise ReproductionError(f"{logical_type} registry binding is invalid")
    descriptor = {
        "sha256": metadata.sha256,
        "logical_type": metadata.logical_type,
        "size": metadata.size,
        "registry_path": metadata.path,
        "registry_metadata_path": metadata.metadata_path,
        "registry_record_hash": metadata.record_hash,
    }
    return descriptor, payload, _json_object(payload, logical_type)


def _descriptor_artifact(
    project_root: Path,
    registry: ArtifactRegistry,
    descriptor: Mapping[str, Any],
    logical_type: str,
) -> tuple[bytes, dict[str, Any]]:
    """Reopen frozen bytes solely through a published source descriptor."""

    digest = descriptor.get("sha256")
    if not isinstance(digest, str):
        raise ReproductionError(f"published {logical_type} descriptor is incomplete")
    try:
        metadata = registry.get_metadata(digest)
        if metadata.size > DEFAULT_MAX_JSON_BYTES:
            raise ReproductionError(f"published {logical_type} exceeds its bound")
        payload = read_confined_bytes(
            project_root,
            metadata.path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except (ArtifactError, PathSecurityError) as exc:
        raise ReproductionError(f"published {logical_type} evidence is unavailable") from exc
    expected = {
        "sha256": metadata.sha256,
        "logical_type": metadata.logical_type,
        "size": metadata.size,
        "registry_path": metadata.path,
        "registry_metadata_path": metadata.metadata_path,
        "registry_record_hash": metadata.record_hash,
    }
    if payload is None or dict(descriptor) != expected or _sha256(payload) != digest:
        raise ReproductionError(f"published {logical_type} descriptor no longer resolves")
    return payload, _json_object(payload, logical_type)


def _inventory_matches_live(project_root: Path, payload: Mapping[str, Any]) -> bool:
    """Compare a frozen source/config inventory to one fd-pinned live snapshot."""

    kind = payload.get("kind")
    if kind == "FROZEN_SOURCE_INVENTORY":
        directory, suffix = Path("src/scientist_one"), ".py"
        expected_launcher = next(
            (
                item
                for item in payload.get("entries", ())
                if isinstance(item, Mapping)
                and item.get("path") == "scripts/scientist_one_cli.py"
            ),
            None,
        )
        if not isinstance(expected_launcher, Mapping):
            return False
    elif kind == "FROZEN_CONFIGURATION_INVENTORY":
        directory, suffix = Path("configs"), ".json"
    else:
        return False
    entries = payload.get("entries")
    if (
        payload.get("schema_version") != "1.0"
        or not isinstance(entries, list)
        or not entries
        or payload.get("aggregate_sha256")
        != _sha256(canonical_json_bytes(entries) + b"\n")
    ):
        return False
    try:
        directory_fd = open_confined_directory_fd(
            project_root, directory, create=False
        )
        try:
            collected: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if entry.name.endswith(suffix):
                        if len(collected) >= MAX_INVENTORY_ENTRIES:
                            return False
                        collected.append(entry.name)
            names = tuple(sorted(collected))
            directory_entries = [
                item
                for item in entries
                if isinstance(item, Mapping)
                and Path(str(item.get("path", ""))).parent == directory
            ]
            if names != tuple(Path(str(item.get("path", ""))).name for item in directory_entries):
                return False
            observed: list[dict[str, Any]] = []
            aggregate_bytes = 0
            for name in names:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_size > 4 * 1024 * 1024
                    ):
                        return False
                    chunks: list[bytes] = []
                    total = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        total += len(chunk)
                        if total > 4 * 1024 * 1024:
                            return False
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    aggregate_bytes += len(data)
                    if aggregate_bytes > MAX_INVENTORY_TOTAL_BYTES:
                        return False
                finally:
                    os.close(descriptor)
                observed.append(
                    {
                        "path": (directory / name).as_posix(),
                        "sha256": _sha256(data),
                        "size": len(data),
                    }
                )
        finally:
            os.close(directory_fd)
    except (OSError, PathSecurityError, TypeError, ValueError):
        return False
    if kind == "FROZEN_SOURCE_INVENTORY":
        try:
            launcher = read_confined_bytes(
                project_root,
                "scripts/scientist_one_cli.py",
                reject_hardlinks=True,
                max_bytes=4 * 1024 * 1024,
            )
        except PathSecurityError:
            return False
        if launcher is None:
            return False
        observed.append(
            {
                "path": "scripts/scientist_one_cli.py",
                "sha256": _sha256(launcher),
                "size": len(launcher),
            }
        )
        observed.sort(key=lambda item: item["path"])
    return observed == entries


def _mean(values: Sequence[Any], label: str) -> float:
    if not values:
        raise ReproductionError(f"{label} values are empty")
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in values):
        raise ReproductionError(f"{label} contains a non-numeric value")
    converted: list[float] = []
    try:
        for item in values:
            numeric = float(item)
            if not math.isfinite(numeric):
                raise ReproductionError(f"{label} contains a non-finite value")
            converted.append(numeric)
        result = math.fsum(converted) / len(converted)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError(f"{label} cannot be represented finitely") from exc
    if not math.isfinite(result):
        raise ReproductionError(f"{label} mean is non-finite")
    return result


def reproduce_run(
    root: str | Path,
    run_id: str,
    *,
    timestamp: str | None = None,
) -> ReproductionResult:
    """Replay a scientifically classified frozen synthetic result.

    This entry point retains the original scientific replay admission and
    result schema.  Non-evidentiary simulated controls must use the separately
    named :func:`reproduce_architecture_control_run` boundary.
    """

    return _reproduce_local_fixture(
        root,
        run_id,
        timestamp=timestamp,
        expected_evidence_class=SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS,
    )


def reproduce_architecture_control_run(
    root: str | Path,
    run_id: str,
    *,
    timestamp: str | None = None,
) -> ReproductionResult:
    """Replay a review-only, explicitly non-evidentiary architecture control."""

    return _reproduce_local_fixture(
        root,
        run_id,
        timestamp=timestamp,
        expected_evidence_class=ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
    )


def _reproduce_local_fixture(
    root: str | Path,
    run_id: str,
    *,
    timestamp: str | None,
    expected_evidence_class: str,
) -> ReproductionResult:
    """Replay the exact admitted local fixture in a clean local directory.

    The reproduction identifier is derived from source evidence, so repeated
    calls are idempotent.  The original run artifacts are only read.
    """

    project_root = Path(root).resolve(strict=True)
    run_dir = _safe_run_dir(project_root, run_id)
    manifest = _read_json(run_dir / "manifest.json", project_root)
    if manifest.get("run_id") != run_id:
        raise ReproductionError("run manifest identity mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReproductionError("run manifest has no artifact registry")
    ledger = EventLedger(project_root, Path("runs") / run_id / "events.jsonl").validate()
    if not ledger.valid or not ledger.events:
        raise ReproductionError("authoritative event ledger is invalid or empty")
    if (
        manifest.get("ledger_head_hash") != ledger.head_hash
        or manifest.get("event_count") != len(ledger.events)
    ):
        raise ReproductionError("run manifest is not anchored to the authoritative ledger")
    ledger_artifacts: dict[str, str] = {}
    ledger_record_hashes: dict[str, str] = {}
    for event in ledger.events:
        artifact_types = event.metadata.get("artifact_types", [])
        record_hashes = event.metadata.get("artifact_record_hashes", [])
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            artifact_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", record_hash)
            ):
                raise ReproductionError("ledger artifact type is malformed")
            prior = ledger_artifacts.get(logical_type)
            prior_record = ledger_record_hashes.get(logical_type)
            if (
                (prior is not None and prior != digest)
                or (prior_record is not None and prior_record != record_hash)
            ):
                raise ReproductionError("ledger contains conflicting logical artifact identities")
            ledger_artifacts[logical_type] = digest
            ledger_record_hashes[logical_type] = record_hash

    required_sources = (
        "machine_results",
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    )
    source_records: dict[str, Mapping[str, Any]] = {}
    for logical_type in required_sources:
        record = artifacts.get(logical_type)
        if (
            not isinstance(record, dict)
            or record.get("sha256") != ledger_artifacts.get(logical_type)
            or record.get("registry_record_hash")
            != ledger_record_hashes.get(logical_type)
        ):
            raise ReproductionError(
                f"mutable manifest projection disagrees with ledger: {logical_type}"
            )
        source_records[logical_type] = record
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    frozen_descriptors: dict[str, dict[str, Any]] = {}
    frozen_payloads: dict[str, dict[str, Any]] = {}
    frozen_source_bytes: dict[str, bytes] = {}
    for logical_type in required_sources:
        descriptor, source_bytes, parsed = _registry_artifact(
            project_root, registry, source_records[logical_type], logical_type
        )
        frozen_descriptors[logical_type] = descriptor
        frozen_payloads[logical_type] = parsed
        frozen_source_bytes[f"source/{logical_type}.json"] = source_bytes
    _assert_scientific_domain_trust_root_not_serialized(
        registry,
        frozen_source_bytes,
    )
    source_record = source_records["machine_results"]
    protocol_record = source_records["frozen_protocol"]
    source = frozen_payloads["machine_results"]
    protocol = frozen_payloads["frozen_protocol"]
    if not _inventory_matches_live(
        project_root, frozen_payloads["frozen_source_inventory"]
    ) or not _inventory_matches_live(
        project_root, frozen_payloads["frozen_configuration_inventory"]
    ):
        raise ReproductionError("live code or configuration differs from the frozen replay inputs")

    _require_replay_source_classification(
        source,
        frozen_payloads["custody_record"],
        expected_evidence_class=expected_evidence_class,
    )
    code_fingerprint = source.get("code_fingerprint")
    configuration_hash = source.get("configuration_sha256")
    if code_fingerprint != manifest.get("code_fingerprint"):
        raise ReproductionError("source result code fingerprint does not match run manifest")
    if configuration_hash != manifest.get("configuration_sha256"):
        raise ReproductionError("source result configuration hash does not match run manifest")
    for label, value in (("code fingerprint", code_fingerprint), ("configuration hash", configuration_hash)):
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ReproductionError(f"invalid {label}")
    if (
        frozen_payloads["frozen_source_inventory"].get("aggregate_sha256")
        != code_fingerprint
        or frozen_payloads["frozen_configuration_inventory"].get(
            "aggregate_sha256"
        )
        != configuration_hash
    ):
        raise ReproductionError(
            "frozen inventory aggregates do not bind the recorded code/configuration"
        )
    input_hashes = source.get("input_hashes")
    expected_input_types = {
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    if (
        not isinstance(input_hashes, dict)
        or set(input_hashes) != expected_input_types
        or input_hashes.get("frozen_protocol") != protocol_record["sha256"]
    ):
        raise ReproductionError("source result is not bound to the frozen protocol")
    for logical_type, digest in input_hashes.items():
        if not isinstance(logical_type, str) or not isinstance(digest, str):
            raise ReproductionError("malformed source input hashes")
        corresponding = {
            "frozen_protocol": "frozen_protocol",
            "blind_interpretation": "blind_interpretation",
            "custody_record": "custody_record",
            "frozen_source_inventory": "frozen_source_inventory",
            "frozen_configuration_inventory": "frozen_configuration_inventory",
        }.get(logical_type)
        if corresponding is None:
            raise ReproductionError(f"unsupported frozen input: {logical_type}")
        record = source_records.get(corresponding)
        if not isinstance(record, Mapping) or record.get("sha256") != digest:
            raise ReproductionError(f"frozen input binding mismatch: {logical_type}")
    fixture_ids = source.get("dataset_fixture_ids")
    seeds = source.get("random_seeds")
    if not isinstance(fixture_ids, list) or not fixture_ids or not all(isinstance(item, str) and item for item in fixture_ids):
        raise ReproductionError("dataset or fixture identifiers are required")
    if not isinstance(seeds, list) or not seeds or any(isinstance(item, bool) or not isinstance(item, int) for item in seeds):
        raise ReproductionError("frozen random seeds are required")
    fixture = source.get("frozen_fixture")
    if not isinstance(fixture, dict):
        raise ReproductionError("machine results omit the frozen fixture")
    control = fixture.get("control")
    treatment = fixture.get("treatment")
    if not isinstance(control, list) or not isinstance(treatment, list):
        raise ReproductionError("frozen fixture groups must be arrays")
    expected_raw = source.get("primary_estimate")
    if isinstance(expected_raw, bool) or not isinstance(expected_raw, (int, float)):
        raise ReproductionError("primary estimate is not numeric")
    try:
        expected = float(expected_raw)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("primary estimate cannot be represented finitely") from exc
    if not math.isfinite(expected):
        raise ReproductionError("primary estimate must be finite")
    tolerance_raw = protocol.get("reproduction_tolerance", 1e-12)
    if isinstance(tolerance_raw, bool) or not isinstance(tolerance_raw, (int, float)):
        raise ReproductionError("reproduction tolerance is not numeric")
    try:
        tolerance = float(tolerance_raw)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("reproduction tolerance cannot be represented finitely") from exc
    if not math.isfinite(tolerance) or tolerance < 0:
        raise ReproductionError("reproduction tolerance cannot be negative")
    source_output_hashes = source.get("output_hashes")
    if not isinstance(source_output_hashes, dict) or not isinstance(
        source_output_hashes.get("result_core"), str
    ):
        raise ReproductionError("frozen source output hash is missing")

    architecture_control = (
        expected_evidence_class == ARCHITECTURE_CONTROL_EVIDENCE_CLASS
    )
    result_status = (
        ARCHITECTURE_CONTROL_REPLAY_STATUS
        if architecture_control
        else "PASS"
    )

    identity_payload = {
        "run_id": run_id,
        "source_result_sha256": source_record["sha256"],
        "protocol_sha256": protocol_record["sha256"],
        "code_fingerprint": code_fingerprint,
        "configuration_hash": configuration_hash,
        "input_hashes": input_hashes,
        "dataset_fixture_ids": fixture_ids,
        "random_seeds": seeds,
        "source_output_hashes": source_output_hashes,
        "algorithm": "difference_of_arithmetic_means_v1",
        "tolerance": tolerance,
    }
    if architecture_control:
        identity_payload.update(
            {
                "evidence_class": ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
                "replay_scope": ARCHITECTURE_CONTROL_REPLAY_SCOPE,
            }
        )
    reproduction_id = _sha256(_canonical_json(identity_payload))[:20]
    reproduction_dir = run_dir / "reproductions" / reproduction_id
    created_at = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    frozen_manifest = {
        "schema_version": (
            "architecture-control-reproduction/v1"
            if architecture_control
            else "1.0"
        ),
        "kind": (
            "FROZEN_ARCHITECTURE_CONTROL_REPRODUCTION_MANIFEST"
            if architecture_control
            else "FROZEN_REPRODUCTION_MANIFEST"
        ),
        "run_id": run_id,
        "reproduction_id": reproduction_id,
        "created_at": created_at,
        "offline": True,
        "command": [
            "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
            "reproduce", run_id
        ],
        "algorithm": "difference_of_arithmetic_means_v1",
        "source_artifacts": {
            key: frozen_descriptors[key] for key in sorted(frozen_descriptors)
        },
        "source_ledger": {
            "head_hash": ledger.head_hash,
            "event_count": len(ledger.events),
        },
        "environment": {
            "python_version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "architecture": platform.machine(),
            "platform": sys.platform,
            "python_executable_name": Path(sys.executable).name,
        },
        "device_execution": {
            "selected_device": "cpu",
            "dtype": "float32",
            "operation": "difference_of_arithmetic_means_v1",
            "mps_used": False,
            "parity_required": False,
            "parity_evidence": "CPU deterministic standard-library replay; no accelerator invoked",
        },
        "code_fingerprint": code_fingerprint,
        "configuration_sha256": configuration_hash,
        "dataset_fixture_ids": list(fixture_ids),
        "random_seeds": list(seeds),
        "input_hashes": dict(sorted(input_hashes.items())),
        "expected_source_output_hashes": dict(sorted(source_output_hashes.items())),
        "accepted_tolerance": tolerance,
        "expected_primary_estimate": expected,
        "provider": (
            "BUILTIN_LOCAL_ARCHITECTURE_CONTROL_FIXTURE"
            if architecture_control
            else "BUILTIN_LOCAL_SYNTHETIC_FIXTURE"
        ),
        "external_integrations_used": [],
    }
    if architecture_control:
        frozen_manifest.update(_architecture_control_boundary())
    manifest_name = f"manifest-{_sha256(_canonical_json(frozen_manifest))[:16]}.json"
    manifest_bytes = _canonical_json(frozen_manifest)
    _assert_scientific_domain_trust_root_not_serialized(
        registry,
        {manifest_name: manifest_bytes},
    )
    _atomic_write(project_root, reproduction_dir / manifest_name, manifest_bytes)

    # Replay strictly from the just-published immutable manifest and re-opened
    # content-addressed inputs, never from mutable in-memory run metadata.
    replay_manifest = _read_json(reproduction_dir / manifest_name, project_root)
    if replay_manifest != frozen_manifest:
        raise ReproductionError("frozen reproduction manifest changed after publication")
    replay_run_id = replay_manifest.get("run_id")
    replay_sources = replay_manifest.get("source_artifacts")
    replay_ledger_anchor = replay_manifest.get("source_ledger")
    if (
        replay_run_id != run_id
        or not isinstance(replay_sources, dict)
        or not isinstance(replay_ledger_anchor, dict)
    ):
        raise ReproductionError("published reproduction identity is malformed")
    replay_ledger = EventLedger(
        project_root, Path("runs") / replay_run_id / "events.jsonl"
    ).validate()
    if (
        not replay_ledger.valid
        or replay_ledger.head_hash != replay_ledger_anchor.get("head_hash")
        or len(replay_ledger.events) != replay_ledger_anchor.get("event_count")
    ):
        raise ReproductionError("published reproduction ledger anchor no longer verifies")
    replay_ledger_artifacts: dict[str, str] = {}
    replay_ledger_record_hashes: dict[str, str] = {}
    for event in replay_ledger.events:
        artifact_types = event.metadata.get("artifact_types", [])
        record_hashes = event.metadata.get("artifact_record_hashes", [])
        if (
            not isinstance(artifact_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(artifact_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("published ledger artifact projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            artifact_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", record_hash)
            ):
                raise ReproductionError("published ledger artifact record hash is malformed")
            prior = replay_ledger_artifacts.get(logical_type)
            prior_record = replay_ledger_record_hashes.get(logical_type)
            if (
                (prior is not None and prior != digest)
                or (prior_record is not None and prior_record != record_hash)
            ):
                raise ReproductionError("published ledger contains conflicting artifact bindings")
            replay_ledger_artifacts[logical_type] = digest
            replay_ledger_record_hashes[logical_type] = record_hash
    replay_registry = ArtifactRegistry(
        project_root, Path("runs") / replay_run_id / "registry"
    )
    replay_payloads: dict[str, dict[str, Any]] = {}
    replay_source_bytes: dict[str, bytes] = {}
    for logical_type in required_sources:
        descriptor = replay_sources.get(logical_type)
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("sha256") != replay_ledger_artifacts.get(logical_type)
            or descriptor.get("registry_record_hash")
            != replay_ledger_record_hashes.get(logical_type)
        ):
            raise ReproductionError(
                f"published {logical_type} is not anchored in the ledger"
            )
        source_bytes, parsed = _descriptor_artifact(
            project_root, replay_registry, descriptor, logical_type
        )
        replay_payloads[logical_type] = parsed
        replay_source_bytes[f"source/{logical_type}.json"] = source_bytes
    _assert_scientific_domain_trust_root_not_serialized(
        replay_registry,
        replay_source_bytes,
    )
    replay_source = replay_payloads["machine_results"]
    _require_replay_source_classification(
        replay_source,
        replay_payloads["custody_record"],
        expected_evidence_class=expected_evidence_class,
    )
    if not _inventory_matches_live(
        project_root, replay_payloads["frozen_source_inventory"]
    ) or not _inventory_matches_live(
        project_root, replay_payloads["frozen_configuration_inventory"]
    ):
        raise ReproductionError("published replay inventories no longer match the workspace")
    replay_code = replay_manifest.get("code_fingerprint")
    replay_configuration = replay_manifest.get("configuration_sha256")
    if (
        replay_source.get("code_fingerprint") != replay_code
        or replay_source.get("configuration_sha256") != replay_configuration
        or replay_payloads["frozen_source_inventory"].get("aggregate_sha256")
        != replay_code
        or replay_payloads["frozen_configuration_inventory"].get(
            "aggregate_sha256"
        )
        != replay_configuration
    ):
        raise ReproductionError(
            "published replay inventories do not bind the code/configuration identity"
        )
    replay_fixture = replay_source.get("frozen_fixture")
    if not isinstance(replay_fixture, dict):
        raise ReproductionError("frozen replay fixture is missing")
    replay_control = replay_fixture.get("control")
    replay_treatment = replay_fixture.get("treatment")
    if not isinstance(replay_control, list) or not isinstance(replay_treatment, list):
        raise ReproductionError("frozen replay fixture groups are invalid")
    replay_expected = replay_manifest.get("expected_primary_estimate")
    replay_tolerance = replay_manifest.get("accepted_tolerance")
    if (
        isinstance(replay_expected, bool)
        or not isinstance(replay_expected, (int, float))
        or isinstance(replay_tolerance, bool)
        or not isinstance(replay_tolerance, (int, float))
        or replay_tolerance < 0
    ):
        raise ReproductionError("published numeric replay contract is malformed")
    try:
        replay_expected = float(replay_expected)
        replay_tolerance = float(replay_tolerance)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("published numeric replay contract is not finite") from exc
    if not math.isfinite(replay_expected) or not math.isfinite(replay_tolerance):
        raise ReproductionError("published numeric replay contract is not finite")
    observed = _mean(replay_treatment, "treatment") - _mean(replay_control, "control")
    difference = abs(observed - replay_expected)
    if not math.isfinite(observed) or not math.isfinite(difference):
        raise ReproductionError("replayed numeric result is non-finite")
    passed = difference <= replay_tolerance
    reproduced_core = {
        "primary_estimate": observed,
        "control_mean": _mean(replay_control, "control"),
        "treatment_mean": _mean(replay_treatment, "treatment"),
        "n_control": len(replay_control),
        "n_treatment": len(replay_treatment),
    }
    reproduced_core_hash = _sha256(_canonical_json(reproduced_core))
    replay_output_hashes = replay_manifest.get("expected_source_output_hashes")
    replay_input_hashes = replay_manifest.get("input_hashes")
    replay_fixture_ids = replay_manifest.get("dataset_fixture_ids")
    replay_seeds = replay_manifest.get("random_seeds")
    if not isinstance(replay_output_hashes, dict) or replay_output_hashes.get("result_core") != reproduced_core_hash:
        raise ReproductionError("replayed output hash differs from the frozen source output")
    if (
        not isinstance(replay_input_hashes, dict)
        or set(replay_input_hashes) != expected_input_types
        or replay_source.get("input_hashes") != replay_input_hashes
        or any(
            replay_sources[name].get("sha256") != replay_input_hashes[name]
            for name in expected_input_types
        )
        or not isinstance(replay_fixture_ids, list)
        or not isinstance(replay_seeds, list)
    ):
        raise ReproductionError("published replay provenance is malformed")
    replay_source_sha = replay_sources["machine_results"]["sha256"]
    result_payload = {
        "schema_version": (
            "architecture-control-reproduction/v1"
            if architecture_control
            else "1.0"
        ),
        "kind": (
            "ARCHITECTURE_CONTROL_REPRODUCTION_RESULT"
            if architecture_control
            else "REPRODUCTION_RESULT"
        ),
        "run_id": run_id,
        "reproduction_id": reproduction_id,
        "status": result_status if passed else "FAIL",
        "expected_primary_estimate": replay_expected,
        "observed_primary_estimate": observed,
        "absolute_difference": difference,
        "accepted_tolerance": replay_tolerance,
        "numeric_comparison_passed": passed,
        "reproduced_output_hashes": {"result_core": reproduced_core_hash},
        "expected_source_output_hashes": dict(sorted(replay_output_hashes.items())),
        "input_hashes": dict(sorted(replay_input_hashes.items())),
        "code_fingerprint": replay_manifest.get("code_fingerprint"),
        "configuration_sha256": replay_manifest.get("configuration_sha256"),
        "dataset_fixture_ids": list(replay_fixture_ids),
        "random_seeds": list(replay_seeds),
        "source_result_sha256": replay_source_sha,
        "frozen_manifest_sha256": _sha256(_canonical_json(replay_manifest)),
        "discrepancies": [] if passed else ["primary estimate differs beyond tolerance"],
    }
    if architecture_control:
        result_payload.update(_architecture_control_boundary())
    result_name = f"result-{_sha256(_canonical_json(result_payload))[:16]}.json"
    result_bytes = _canonical_json(result_payload)
    _assert_scientific_domain_trust_root_not_serialized(
        replay_registry,
        {result_name: result_bytes},
    )
    _atomic_write(project_root, reproduction_dir / result_name, result_bytes)
    if not passed:
        raise ReproductionError("primary-result reproduction failed")

    return ReproductionResult(
        run_id=run_id,
        status=result_status,
        reproduction_id=reproduction_id,
        expected=replay_expected,
        observed=observed,
        absolute_difference=difference,
        tolerance=replay_tolerance,
        manifest_path=(reproduction_dir / manifest_name).relative_to(project_root).as_posix(),
        result_path=(reproduction_dir / result_name).relative_to(project_root).as_posix(),
        source_result_sha256=replay_source_sha,
    )


def verify_frozen_reproduction(
    root: str | Path,
    run_id: str,
    frozen_record: Mapping[str, Any],
) -> ReproductionResult:
    """Verify a scientifically classified frozen reproduction packet."""

    return _verify_frozen_local_fixture(
        root,
        run_id,
        frozen_record,
        expected_evidence_class=SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS,
    )


def verify_frozen_architecture_control_reproduction(
    root: str | Path,
    run_id: str,
    frozen_record: Mapping[str, Any],
) -> ReproductionResult:
    """Verify a review-only non-evidentiary architecture-control replay."""

    return _verify_frozen_local_fixture(
        root,
        run_id,
        frozen_record,
        expected_evidence_class=ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
    )


def _verify_frozen_local_fixture(
    root: str | Path,
    run_id: str,
    frozen_record: Mapping[str, Any],
    *,
    expected_evidence_class: str,
) -> ReproductionResult:
    """Recompute and verify an already-published local replay packet.

    The replay consumes only the immutable manifest, its run-scoped registry
    descriptors, and the ledger prefix named by that manifest.  It never
    creates a new manifest from the later mutable run projection.
    """

    architecture_control = (
        expected_evidence_class == ARCHITECTURE_CONTROL_EVIDENCE_CLASS
    )
    if expected_evidence_class not in {
        SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS,
        ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
    }:
        raise ReproductionError("unsupported frozen replay evidence class")
    manifest_keys = (
        ARCHITECTURE_CONTROL_FROZEN_MANIFEST_KEYS
        if architecture_control
        else FROZEN_MANIFEST_KEYS
    )
    result_keys = (
        ARCHITECTURE_CONTROL_REPRODUCTION_RESULT_KEYS
        if architecture_control
        else REPRODUCTION_RESULT_KEYS
    )
    expected_schema = (
        "architecture-control-reproduction/v1"
        if architecture_control
        else "1.0"
    )
    expected_manifest_kind = (
        "FROZEN_ARCHITECTURE_CONTROL_REPRODUCTION_MANIFEST"
        if architecture_control
        else "FROZEN_REPRODUCTION_MANIFEST"
    )
    expected_result_kind = (
        "ARCHITECTURE_CONTROL_REPRODUCTION_RESULT"
        if architecture_control
        else "REPRODUCTION_RESULT"
    )
    expected_status = (
        ARCHITECTURE_CONTROL_REPLAY_STATUS
        if architecture_control
        else "PASS"
    )
    expected_provider = (
        "BUILTIN_LOCAL_ARCHITECTURE_CONTROL_FIXTURE"
        if architecture_control
        else "BUILTIN_LOCAL_SYNTHETIC_FIXTURE"
    )

    project_root = Path(root).resolve(strict=True)
    _safe_run_dir(project_root, run_id)
    if set(frozen_record) != FROZEN_RECORD_KEYS:
        raise ReproductionError("frozen reproduction summary schema is malformed")
    manifest_path = frozen_record.get("manifest_path")
    result_path = frozen_record.get("result_path")
    if (
        not isinstance(manifest_path, str)
        or not isinstance(result_path, str)
        or Path(manifest_path).is_absolute()
        or Path(result_path).is_absolute()
    ):
        raise ReproductionError("frozen reproduction paths are malformed")
    try:
        manifest_bytes = read_confined_bytes(
            project_root,
            manifest_path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        result_bytes = read_confined_bytes(
            project_root,
            result_path,
            reject_hardlinks=True,
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
    except PathSecurityError as exc:
        raise ReproductionError("frozen reproduction packet is unsafe") from exc
    if manifest_bytes is None or result_bytes is None:
        raise ReproductionError("frozen reproduction packet is absent")
    if (
        _sha256(manifest_bytes) != frozen_record.get("manifest_sha256")
        or _sha256(result_bytes) != frozen_record.get("result_sha256")
    ):
        raise ReproductionError("frozen reproduction packet digest mismatch")
    replay_manifest = _json_object(manifest_bytes, "reproduction manifest")
    replay_result = _json_object(result_bytes, "reproduction result")
    reproduction_id = replay_manifest.get("reproduction_id")
    if (
        set(replay_manifest) != manifest_keys
        or set(replay_result) != result_keys
        or replay_manifest.get("schema_version") != expected_schema
        or replay_result.get("schema_version") != expected_schema
        or replay_manifest.get("kind") != expected_manifest_kind
        or replay_result.get("kind") != expected_result_kind
        or replay_manifest.get("run_id") != run_id
        or replay_result.get("run_id") != run_id
        or replay_result.get("reproduction_id") != reproduction_id
        or frozen_record.get("reproduction_id") != reproduction_id
        or replay_result.get("frozen_manifest_sha256") != _sha256(manifest_bytes)
    ):
        raise ReproductionError("frozen reproduction identity is malformed")

    anchor = replay_manifest.get("source_ledger")
    if not isinstance(anchor, Mapping) or set(anchor) != {"head_hash", "event_count"}:
        raise ReproductionError("frozen reproduction ledger anchor is absent")
    ledger = EventLedger(
        project_root, Path("runs") / run_id / "events.jsonl"
    ).validate()
    anchor_count = anchor.get("event_count")
    if (
        not ledger.valid
        or isinstance(anchor_count, bool)
        or not isinstance(anchor_count, int)
        or anchor_count < 1
        or anchor_count > len(ledger.events)
        or ledger.events[anchor_count - 1].event_hash != anchor.get("head_hash")
    ):
        raise ReproductionError("frozen reproduction ledger prefix is invalid")
    prefix = ledger.events[:anchor_count]
    ledger_hashes: dict[str, str] = {}
    ledger_records: dict[str, str] = {}
    for event in prefix:
        logical_types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        if (
            not isinstance(logical_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(logical_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            if event.artifact_hashes:
                raise ReproductionError("frozen ledger projection is malformed")
            continue
        for logical_type, digest, record_hash in zip(
            logical_types, event.artifact_hashes, record_hashes, strict=True
        ):
            if (
                not isinstance(logical_type, str)
                or not isinstance(record_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_hash) is None
            ):
                raise ReproductionError("frozen ledger provenance is malformed")
            if (
                logical_type in ledger_hashes
                and (
                    ledger_hashes[logical_type] != digest
                    or ledger_records[logical_type] != record_hash
                )
            ):
                raise ReproductionError("frozen ledger provenance conflicts")
            ledger_hashes[logical_type] = digest
            ledger_records[logical_type] = record_hash

    required = {
        "machine_results",
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    descriptors = replay_manifest.get("source_artifacts")
    if not isinstance(descriptors, Mapping) or set(descriptors) != required:
        raise ReproductionError("frozen reproduction source set is incomplete")
    registry = ArtifactRegistry(project_root, Path("runs") / run_id / "registry")
    _assert_scientific_domain_trust_root_not_serialized(
        registry,
        {
            manifest_path: manifest_bytes,
            result_path: result_bytes,
        },
    )
    payloads: dict[str, dict[str, Any]] = {}
    source_bytes_by_type: dict[str, bytes] = {}
    for logical_type in required:
        descriptor = descriptors.get(logical_type)
        if (
            not isinstance(descriptor, Mapping)
            or descriptor.get("sha256") != ledger_hashes.get(logical_type)
            or descriptor.get("registry_record_hash")
            != ledger_records.get(logical_type)
        ):
            raise ReproductionError(
                f"frozen reproduction source is not ledger-bound: {logical_type}"
            )
        source_bytes, payloads[logical_type] = _descriptor_artifact(
            project_root, registry, descriptor, logical_type
        )
        source_bytes_by_type[f"source/{logical_type}.json"] = source_bytes
    _assert_scientific_domain_trust_root_not_serialized(
        registry,
        source_bytes_by_type,
    )
    packet_metadata: dict[str, Any] = {}
    for logical_type in ("reproduction_manifest", "reproduction_result"):
        digest_key = "manifest_sha256" if logical_type.endswith("manifest") else "result_sha256"
        record_key = "manifest_record_hash" if logical_type.endswith("manifest") else "result_record_hash"
        try:
            metadata = registry.get_metadata(str(frozen_record.get(digest_key)))
            registered_bytes = registry.get_bytes(metadata.sha256)
        except ArtifactError as exc:
            raise ReproductionError("registered reproduction packet is absent") from exc
        expected_bytes = (
            manifest_bytes if logical_type.endswith("manifest") else result_bytes
        )
        if (
            metadata.logical_type != logical_type
            or metadata.record_hash != frozen_record.get(record_key)
            or metadata.sha256 != frozen_record.get(digest_key)
            or metadata.frozen is not True
            or registered_bytes != expected_bytes
            or not registry.verify(metadata.sha256)
        ):
            raise ReproductionError("registered reproduction packet binding differs")
        packet_metadata[logical_type] = metadata
    if (
        tuple(packet_metadata["reproduction_manifest"].parent_artifacts)
        != (str(descriptors["machine_results"].get("sha256")),)
        or tuple(packet_metadata["reproduction_result"].parent_artifacts)
        != (str(frozen_record.get("manifest_sha256")),)
    ):
        raise ReproductionError("registered reproduction packet parent lineage differs")

    full_projection: dict[str, tuple[str, str]] = {}
    for event in ledger.events:
        logical_types = event.metadata.get("artifact_types", ())
        record_hashes = event.metadata.get("artifact_record_hashes", ())
        if (
            not isinstance(logical_types, (list, tuple))
            or not isinstance(record_hashes, (list, tuple))
            or len(logical_types) != len(event.artifact_hashes)
            or len(record_hashes) != len(event.artifact_hashes)
        ):
            continue
        for logical_type, digest, record_hash in zip(
            logical_types, event.artifact_hashes, record_hashes, strict=True
        ):
            prior = full_projection.get(str(logical_type))
            current = (str(digest), str(record_hash))
            if prior is not None and prior != current:
                raise ReproductionError("full ledger reproduction projection conflicts")
            full_projection[str(logical_type)] = current
    if "reproduction_report" in full_projection:
        try:
            report_metadata = registry.get_metadata(
                full_projection["reproduction_report"][0]
            )
            report_payload = _json_object(
                registry.get_bytes(report_metadata.sha256), "reproduction report"
            )
        except ArtifactError as exc:
            raise ReproductionError("ledger-bound reproduction report is absent") from exc
        if (
            report_metadata.record_hash
            != full_projection["reproduction_report"][1]
            or report_payload != dict(frozen_record)
            or tuple(report_metadata.parent_artifacts)
            != (
                str(descriptors["machine_results"].get("sha256")),
                str(frozen_record.get("manifest_sha256")),
                str(frozen_record.get("result_sha256")),
            )
        ):
            raise ReproductionError("supplied reproduction record is not ledger-bound")

    code_hash = replay_manifest.get("code_fingerprint")
    configuration_hash = replay_manifest.get("configuration_sha256")
    expected_command = [
        "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py",
        "reproduce", run_id,
    ]
    expected_environment = {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "architecture": platform.machine(),
        "platform": sys.platform,
        "python_executable_name": Path(sys.executable).name,
    }
    expected_device = {
        "selected_device": "cpu",
        "dtype": "float32",
        "operation": "difference_of_arithmetic_means_v1",
        "mps_used": False,
        "parity_required": False,
        "parity_evidence": (
            "CPU deterministic standard-library replay; no accelerator invoked"
        ),
    }
    if (
        replay_manifest.get("created_at") is None
        or not isinstance(replay_manifest.get("created_at"), str)
        or re.fullmatch(r"[0-9a-f]{20}", str(reproduction_id)) is None
        or replay_manifest.get("offline") is not True
        or replay_manifest.get("command") != expected_command
        or replay_manifest.get("algorithm")
        != "difference_of_arithmetic_means_v1"
        or replay_manifest.get("provider") != expected_provider
        or replay_manifest.get("external_integrations_used") != []
        or replay_manifest.get("environment") != expected_environment
        or replay_manifest.get("device_execution") != expected_device
        or re.fullmatch(r"[0-9a-f]{64}", str(code_hash)) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(configuration_hash)) is None
        or payloads["frozen_source_inventory"].get("aggregate_sha256") != code_hash
        or payloads["frozen_configuration_inventory"].get("aggregate_sha256")
        != configuration_hash
        or not _inventory_matches_live(
            project_root, payloads["frozen_source_inventory"]
        )
        or not _inventory_matches_live(
            project_root, payloads["frozen_configuration_inventory"]
        )
    ):
        raise ReproductionError("frozen reproduction inventory no longer verifies")
    machine = payloads["machine_results"]
    expected_input_types = {
        "frozen_protocol",
        "blind_interpretation",
        "custody_record",
        "frozen_source_inventory",
        "frozen_configuration_inventory",
    }
    machine_inputs = machine.get("input_hashes")
    protocol = payloads["frozen_protocol"]
    _require_replay_source_classification(
        machine,
        payloads["custody_record"],
        expected_evidence_class=expected_evidence_class,
    )
    if architecture_control and (
        any(
            replay_manifest.get(key) != value
            for key, value in _architecture_control_boundary().items()
        )
        or any(
            replay_result.get(key) != value
            for key, value in _architecture_control_boundary().items()
        )
    ):
        raise ReproductionError(
            "architecture-control replay boundary differs from its exact schema"
        )
    if (
        machine.get("code_fingerprint") != code_hash
        or machine.get("configuration_sha256") != configuration_hash
        or not isinstance(machine_inputs, Mapping)
        or set(machine_inputs) != expected_input_types
        or any(
            machine_inputs[name] != descriptors[name].get("sha256")
            for name in expected_input_types
        )
        or replay_manifest.get("input_hashes") != machine_inputs
        or machine.get("dataset_fixture_ids")
        != replay_manifest.get("dataset_fixture_ids")
        or machine.get("random_seeds") != replay_manifest.get("random_seeds")
    ):
        raise ReproductionError("frozen machine-result lineage is malformed")
    fixture = machine.get("frozen_fixture")
    if not isinstance(fixture, Mapping):
        raise ReproductionError("frozen reproduction fixture is absent")
    control = fixture.get("control")
    treatment = fixture.get("treatment")
    if not isinstance(control, list) or not isinstance(treatment, list):
        raise ReproductionError("frozen reproduction fixture is malformed")
    observed = _mean(treatment, "treatment") - _mean(control, "control")
    expected = replay_manifest.get("expected_primary_estimate")
    tolerance = replay_manifest.get("accepted_tolerance")
    if (
        isinstance(expected, bool)
        or not isinstance(expected, (int, float))
        or isinstance(tolerance, bool)
        or not isinstance(tolerance, (int, float))
    ):
        raise ReproductionError("frozen reproduction numeric contract is malformed")
    try:
        expected = float(expected)
        tolerance = float(tolerance)
    except (OverflowError, ValueError) as exc:
        raise ReproductionError("frozen reproduction numeric contract is non-finite") from exc
    difference = abs(observed - expected)
    reproduced_core = {
        "primary_estimate": observed,
        "control_mean": _mean(control, "control"),
        "treatment_mean": _mean(treatment, "treatment"),
        "n_control": len(control),
        "n_treatment": len(treatment),
    }
    expected_output_hashes = replay_manifest.get("expected_source_output_hashes")
    machine_output_hashes = machine.get("output_hashes")
    reproduced_hash = _sha256(_canonical_json(reproduced_core))
    fixture_ids = replay_manifest.get("dataset_fixture_ids")
    seeds = replay_manifest.get("random_seeds")
    protocol_tolerance = protocol.get("reproduction_tolerance")
    try:
        normalized_protocol_tolerance = float(protocol_tolerance)
    except (TypeError, OverflowError, ValueError) as exc:
        raise ReproductionError("frozen protocol tolerance is malformed") from exc
    identity = {
        "run_id": run_id,
        "source_result_sha256": descriptors["machine_results"].get("sha256"),
        "protocol_sha256": descriptors["frozen_protocol"].get("sha256"),
        "code_fingerprint": code_hash,
        "configuration_hash": configuration_hash,
        "input_hashes": dict(machine_inputs),
        "dataset_fixture_ids": fixture_ids,
        "random_seeds": seeds,
        "source_output_hashes": expected_output_hashes,
        "algorithm": replay_manifest.get("algorithm"),
        "tolerance": tolerance,
    }
    if architecture_control:
        identity.update(
            {
                "evidence_class": ARCHITECTURE_CONTROL_EVIDENCE_CLASS,
                "replay_scope": ARCHITECTURE_CONTROL_REPLAY_SCOPE,
            }
        )
    result_reproduced_hashes = replay_result.get("reproduced_output_hashes")
    result_expected_hashes = replay_result.get("expected_source_output_hashes")
    if (
        not all(math.isfinite(value) for value in (observed, expected, tolerance, difference))
        or tolerance < 0
        or not math.isfinite(normalized_protocol_tolerance)
        or normalized_protocol_tolerance != tolerance
        or difference > tolerance
        or machine.get("primary_estimate") != expected
        or machine.get("scientific_protocol_sha256")
        != protocol.get("protocol_sha256")
        or not isinstance(fixture_ids, list)
        or not fixture_ids
        or any(not isinstance(item, str) or not item for item in fixture_ids)
        or not isinstance(seeds, list)
        or not seeds
        or any(isinstance(item, bool) or not isinstance(item, int) for item in seeds)
        or not isinstance(machine_output_hashes, Mapping)
        or not isinstance(expected_output_hashes, Mapping)
        or set(machine_output_hashes) != {"result_core"}
        or set(expected_output_hashes) != {"result_core"}
        or machine_output_hashes != expected_output_hashes
        or expected_output_hashes.get("result_core") != reproduced_hash
        or _sha256(_canonical_json(identity))[:20] != reproduction_id
        or replay_result.get("status") != expected_status
        or replay_result.get("expected_primary_estimate") != expected
        or replay_result.get("observed_primary_estimate") != observed
        or replay_result.get("absolute_difference") != difference
        or replay_result.get("accepted_tolerance") != tolerance
        or replay_result.get("numeric_comparison_passed") is not True
        or not isinstance(result_reproduced_hashes, Mapping)
        or not isinstance(result_expected_hashes, Mapping)
        or set(result_reproduced_hashes) != {"result_core"}
        or result_reproduced_hashes.get("result_core") != reproduced_hash
        or result_expected_hashes != expected_output_hashes
        or replay_result.get("input_hashes") != machine_inputs
        or replay_result.get("code_fingerprint") != code_hash
        or replay_result.get("configuration_sha256") != configuration_hash
        or replay_result.get("dataset_fixture_ids") != fixture_ids
        or replay_result.get("random_seeds") != seeds
        or replay_result.get("discrepancies") != []
        or replay_result.get("source_result_sha256")
        != descriptors["machine_results"].get("sha256")
    ):
        raise ReproductionError("frozen reproduction result does not recompute")
    base = ReproductionResult(
        run_id=run_id,
        status=expected_status,
        reproduction_id=str(reproduction_id),
        expected=expected,
        observed=observed,
        absolute_difference=difference,
        tolerance=tolerance,
        manifest_path=manifest_path,
        result_path=result_path,
        source_result_sha256=str(descriptors["machine_results"].get("sha256")),
    )
    if any(frozen_record.get(key) != value for key, value in base.to_dict().items()):
        raise ReproductionError("frozen reproduction summary differs from replayed bytes")
    return base


__all__ = [
    "BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID",
    "BoundedMeanCleanRerunComparison",
    "BoundedMeanCleanRerunDifference",
    "BoundedMeanCleanRerunGridComparison",
    "ARCHITECTURE_CONTROL_EVIDENCE_CLASS",
    "ARCHITECTURE_CONTROL_EXECUTION_KIND",
    "ARCHITECTURE_CONTROL_REPLAY_SCOPE",
    "ARCHITECTURE_CONTROL_REPLAY_STATUS",
    "ExperimentReplayProvider",
    "ReproductionError",
    "ReproductionResult",
    "SCIENTIFIC_CLEAN_RERUN_AUTHORITY_EVENT_SCHEMA",
    "SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE",
    "SCIENTIFIC_CLEAN_RERUN_AUTHORITY_SCHEMA",
    "SCIENTIFIC_CLEAN_RERUN_PLAN_EVENT_SCHEMA",
    "SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE",
    "SCIENTIFIC_CLEAN_RERUN_PLAN_SCHEMA",
    "SCIENTIFIC_REPRODUCTION_EVIDENCE_CLASS",
    "ScientificCleanRerunAuthority",
    "ScientificCleanRerunAuthorityResolution",
    "ScientificCleanRerunComparison",
    "ScientificCleanRerunDifference",
    "ScientificCleanRerunOutcome",
    "ScientificCleanRerunPlan",
    "ScientificCleanRerunResolutionStatus",
    "derive_scientific_clean_rerun_comparison",
    "derive_bounded_mean_clean_rerun_comparison",
    "register_scientific_clean_rerun_authority",
    "register_scientific_clean_rerun_plan",
    "reproduce_architecture_control_run",
    "reproduce_run",
    "require_scientific_clean_rerun_authority",
    "require_scientific_clean_rerun_plan",
    "resolve_scientific_clean_rerun_authority",
    "verify_frozen_architecture_control_reproduction",
    "verify_frozen_reproduction",
]
