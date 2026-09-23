"""Source-owned scientific execution admissibility.

This module deliberately supports one closed procedure.  It separates the
question "was the frozen procedure executed without adaptive result access?"
from the scientific outcome of that procedure.  A negative, null, or
falsified result can therefore be admissible; caller-authored prose, role
labels, and ``PASS`` booleans cannot make it so.

The shared policy DTO lives here so ``scientific_design`` can use it without
this module importing that owner at module import time.  Backend activity
remains owned by ``experiments``.  Source-owner imports in the resolver are
intentionally local to avoid a dependency cycle.

The confirmatory-timeline owner is staged ahead of this leaf.  Its pre-issuance
resolver is responsible for distinguishing missing local support from absent
external custody evidence.  This module accepts only its registered positive
receipt; an absent receipt here is therefore a local source-closure absence,
not evidence about why upstream issuance was blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
from typing import Any, Mapping, Sequence

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
)
from .errors import ArtifactError, ValidationError
from .ledger import MAX_LEDGER_BYTES, MAX_LEDGER_EVENTS, EventLedger, LedgerEvent
from .models import MacroState, thaw_json, utc_now, validate_identifier, validate_sha256
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads


SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA = (
    "SCIENTIST_ONE_EXECUTION_ADMISSIBILITY_POLICY_V1"
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA = (
    "SCIENTIST_ONE_EXECUTION_ADMISSIBILITY_AUTHORITY_V1"
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE = (
    "scientific_execution_admissibility_authority"
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN = (
    "source-owned fixed-grid scientific execution admissibility replay"
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND = (
    "scientist-one",
    "verify-scientific-execution-admissibility",
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_PUBLICATION_KEY = (
    "scientific_execution_admissibility_authority_publication"
)
SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE = (
    "FIXED_COMPLETE_GENERIC_ML_EXECUTION_ADMISSIBILITY"
)
_FIXED_GENERIC_ML_COMPARISON_SCOPE = (
    "FROZEN_MODEL_CONFIRMATORY_INFERENCE_ONLY"
)

CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V3 = "checked-superiority-contract/v3"
EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V3 = "3.0"

RESULT_ADMISSIBILITY_STOPPING_DISPLAY = (
    "RESULT_ADMISSIBILITY: complete every frozen seed and required ablation "
    "exactly once without adaptive selection."
)
RELEASE_READINESS_STOPPING_DISPLAY = (
    "RELEASE_READINESS: complete a clean rerun, canonical reproducibility "
    "package, and reproduction audit before release."
)
FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA = (
    RESULT_ADMISSIBILITY_STOPPING_DISPLAY,
    RELEASE_READINESS_STOPPING_DISPLAY,
)

_AUTHORITY_RECORD_SCHEMA_VERSION = "1.0"
_MAX_REASON_CODES = 64
_MAX_AUTHORITY_BYTES = 1024 * 1024
_PUBLICATION_REASON = (
    "published source-owned fixed-grid scientific execution admissibility"
)


class ScientificExecutionAdmissibilityError(RuntimeError):
    """Admissibility evidence is malformed, ambiguous, stale, or unavailable."""


class ScientificExecutionAdmissibilityProfile(StrEnum):
    FIXED_COMPLETE_GENERIC_ML_V1 = "FIXED_COMPLETE_GENERIC_ML_V1"


class DecisionStoppingRule(StrEnum):
    COMPLETE_EXACT_FROZEN_GRID = "COMPLETE_EXACT_FROZEN_GRID"


class EvaluatorRule(StrEnum):
    SOURCE_OWNED_GENERIC_ML_PAIRED_METRIC = (
        "SOURCE_OWNED_GENERIC_ML_PAIRED_METRIC"
    )


class ReleaseStoppingRule(StrEnum):
    CLEAN_RERUN_PACKAGE_AND_REPRODUCTION_AUDIT = (
        "CLEAN_RERUN_PACKAGE_AND_REPRODUCTION_AUDIT"
    )


class ScientificExecutionAdmissibilityStatus(StrEnum):
    ADMISSIBLE = "ADMISSIBLE"
    INADMISSIBLE = "INADMISSIBLE"


class ScientificDecisionStoppingStatus(StrEnum):
    MET = "MET"
    NOT_MET = "NOT_MET"


class ScientificEvaluatorIntegrityStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class ScientificExecutionAdmissibilityResolutionStatus(StrEnum):
    ADMISSIBLE = "ADMISSIBLE"
    INADMISSIBLE = "INADMISSIBLE"
    BLOCKED_LOCAL = "BLOCKED_LOCAL"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"


def _enum_value(value: Any, enum_type: type[StrEnum], label: str) -> StrEnum:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ScientificExecutionAdmissibilityError(f"{label} is invalid") from exc


def _utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ScientificExecutionAdmissibilityError(
            f"{label} must be a UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, OSError, ValueError) as exc:
        raise ScientificExecutionAdmissibilityError(
            f"{label} is malformed"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ScientificExecutionAdmissibilityError(f"{label} must be UTC")
    return parsed


def _exact_mapping(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ScientificExecutionAdmissibilityError(f"{label} schema is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ScientificExecutionAdmissibilityPolicy:
    profile: ScientificExecutionAdmissibilityProfile = (
        ScientificExecutionAdmissibilityProfile.FIXED_COMPLETE_GENERIC_ML_V1
    )
    decision_stopping_rule: DecisionStoppingRule = (
        DecisionStoppingRule.COMPLETE_EXACT_FROZEN_GRID
    )
    evaluator_rule: EvaluatorRule = (
        EvaluatorRule.SOURCE_OWNED_GENERIC_ML_PAIRED_METRIC
    )
    release_stopping_rule: ReleaseStoppingRule = (
        ReleaseStoppingRule.CLEAN_RERUN_PACKAGE_AND_REPRODUCTION_AUDIT
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "profile",
            _enum_value(
                self.profile,
                ScientificExecutionAdmissibilityProfile,
                "admissibility profile",
            ),
        )
        object.__setattr__(
            self,
            "decision_stopping_rule",
            _enum_value(
                self.decision_stopping_rule,
                DecisionStoppingRule,
                "decision stopping rule",
            ),
        )
        object.__setattr__(
            self,
            "evaluator_rule",
            _enum_value(self.evaluator_rule, EvaluatorRule, "evaluator rule"),
        )
        object.__setattr__(
            self,
            "release_stopping_rule",
            _enum_value(
                self.release_stopping_rule,
                ReleaseStoppingRule,
                "release stopping rule",
            ),
        )
        if (
            self.profile
            is not ScientificExecutionAdmissibilityProfile.FIXED_COMPLETE_GENERIC_ML_V1
            or self.decision_stopping_rule
            is not DecisionStoppingRule.COMPLETE_EXACT_FROZEN_GRID
            or self.evaluator_rule
            is not EvaluatorRule.SOURCE_OWNED_GENERIC_ML_PAIRED_METRIC
            or self.release_stopping_rule
            is not ReleaseStoppingRule.CLEAN_RERUN_PACKAGE_AND_REPRODUCTION_AUDIT
        ):
            raise ScientificExecutionAdmissibilityError(
                "unsupported scientific execution admissibility policy"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA,
            "profile": self.profile.value,
            "decision_stopping_rule": self.decision_stopping_rule.value,
            "evaluator_rule": self.evaluator_rule.value,
            "release_stopping_rule": self.release_stopping_rule.value,
        }

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> "ScientificExecutionAdmissibilityPolicy":
        value = _exact_mapping(
            value,
            {
                "schema_version",
                "profile",
                "decision_stopping_rule",
                "evaluator_rule",
                "release_stopping_rule",
            },
            "scientific execution admissibility policy",
        )
        if value["schema_version"] != SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA:
            raise ScientificExecutionAdmissibilityError(
                "unsupported scientific execution admissibility policy schema"
            )
        return cls(
            profile=value["profile"],
            decision_stopping_rule=value["decision_stopping_rule"],
            evaluator_rule=value["evaluator_rule"],
            release_stopping_rule=value["release_stopping_rule"],
        )


@dataclass(frozen=True, slots=True)
class ScientificExecutionAdmissibilityAuthority:
    """One deterministic decision about one exact scientific execution.

    This can qualify a result for outcome-neutral assessment.  It never grants
    release readiness, which still requires the separately replayed clean run,
    reproducibility package, and REPRODUCTION audit named by the frozen policy.

    The publication event is intentionally not embedded here.  The artifact
    binds the ledger head immediately before publication; replay separately
    verifies the unique publication event.  This avoids a circular
    event/artifact identity and makes an artifact-only crash inert and
    recoverable.
    """

    authority_id: str
    ledger_run_id: str
    execution_run_id: str
    scientific_binding_sha256: str
    policy: ScientificExecutionAdmissibilityPolicy
    status: ScientificExecutionAdmissibilityStatus
    decision_stopping_status: ScientificDecisionStoppingStatus
    evaluator_integrity_status: ScientificEvaluatorIntegrityStatus
    reason_codes: tuple[str, ...]
    evaluation_contract_freeze_receipt_artifact_sha256: str
    evaluation_contract_freeze_receipt_record_hash: str
    contract_artifact_sha256: str
    contract_record_hash: str
    scientific_execution_preparation_artifact_sha256: str
    scientific_execution_preparation_record_hash: str
    scientific_execution_authority_artifact_sha256: str
    scientific_execution_authority_record_hash: str
    scientific_execution_activity_artifact_sha256: str
    scientific_execution_activity_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    scientific_domain_evidence_source_artifact_sha256: str
    scientific_domain_evidence_source_record_hash: str
    generic_ml_paired_metric_projection_authority_artifact_sha256: str
    generic_ml_paired_metric_projection_authority_record_hash: str
    scientific_confirmatory_timeline_receipt_artifact_sha256: str
    scientific_confirmatory_timeline_receipt_record_hash: str
    source_artifact_sha256s: tuple[str, ...]
    source_artifact_record_hashes: tuple[str, ...]
    source_ledger_prefix_head_hash: str
    authority_scope: str = SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE

    def __post_init__(self) -> None:
        for name in ("authority_id", "ledger_run_id", "execution_run_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        if not isinstance(self.policy, ScientificExecutionAdmissibilityPolicy):
            raise ScientificExecutionAdmissibilityError(
                "admissibility authority requires the closed typed policy"
            )
        for name, enum_type in (
            ("status", ScientificExecutionAdmissibilityStatus),
            ("decision_stopping_status", ScientificDecisionStoppingStatus),
            ("evaluator_integrity_status", ScientificEvaluatorIntegrityStatus),
        ):
            object.__setattr__(
                self,
                name,
                _enum_value(getattr(self, name), enum_type, name.replace("_", " ")),
            )
        if not isinstance(self.reason_codes, tuple):
            object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        if (
            not self.reason_codes
            or len(self.reason_codes) > _MAX_REASON_CODES
            or len(set(self.reason_codes)) != len(self.reason_codes)
        ):
            raise ScientificExecutionAdmissibilityError(
                "admissibility reason-code closure is invalid"
            )
        for value in self.reason_codes:
            validate_identifier(value, "admissibility reason code")
        hash_names = (
            "evaluation_contract_freeze_receipt_artifact_sha256",
            "evaluation_contract_freeze_receipt_record_hash",
            "contract_artifact_sha256",
            "contract_record_hash",
            "scientific_execution_preparation_artifact_sha256",
            "scientific_execution_preparation_record_hash",
            "scientific_execution_authority_artifact_sha256",
            "scientific_execution_authority_record_hash",
            "scientific_execution_activity_artifact_sha256",
            "scientific_execution_activity_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "output_manifest_artifact_sha256",
            "output_manifest_record_hash",
            "scientific_domain_evidence_source_artifact_sha256",
            "scientific_domain_evidence_source_record_hash",
            "generic_ml_paired_metric_projection_authority_artifact_sha256",
            "generic_ml_paired_metric_projection_authority_record_hash",
            "scientific_confirmatory_timeline_receipt_artifact_sha256",
            "scientific_confirmatory_timeline_receipt_record_hash",
            "source_ledger_prefix_head_hash",
            "scientific_binding_sha256",
        )
        for name in hash_names:
            validate_sha256(getattr(self, name), name.replace("_", " "))
        for name in ("source_artifact_sha256s", "source_artifact_record_hashes"):
            values = getattr(self, name)
            if not isinstance(values, tuple):
                values = tuple(values)
                object.__setattr__(self, name, values)
            if not values or len(values) > MAX_ARTIFACT_PARENTS:
                raise ScientificExecutionAdmissibilityError(
                    "admissibility source closure exceeds its bound"
                )
            for value in values:
                validate_sha256(value, "admissibility source identity")
        if (
            len(self.source_artifact_sha256s)
            != len(self.source_artifact_record_hashes)
            or len(set(self.source_artifact_sha256s))
            != len(self.source_artifact_sha256s)
            or self.source_artifact_sha256s
            != self.direct_source_artifact_sha256s
            or self.source_artifact_record_hashes
            != self.direct_source_artifact_record_hashes
            or self.authority_scope != SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE
        ):
            raise ScientificExecutionAdmissibilityError(
                "admissibility authority has a substituted source closure"
            )
        admissible = (
            self.status is ScientificExecutionAdmissibilityStatus.ADMISSIBLE
            and self.decision_stopping_status
            is ScientificDecisionStoppingStatus.MET
            and self.evaluator_integrity_status
            is ScientificEvaluatorIntegrityStatus.PASS
            and self.reason_codes == ("FIXED_COMPLETE_GENERIC_ML_ADMISSIBLE",)
        )
        if self.status is ScientificExecutionAdmissibilityStatus.ADMISSIBLE:
            if not admissible:
                raise ScientificExecutionAdmissibilityError(
                    "admissible execution lacks stopping and evaluator closure"
                )
        elif (
            self.decision_stopping_status is ScientificDecisionStoppingStatus.MET
            and self.evaluator_integrity_status
            is ScientificEvaluatorIntegrityStatus.PASS
        ):
            raise ScientificExecutionAdmissibilityError(
                "inadmissible execution has no derived failure"
            )

    @property
    def direct_source_artifact_sha256s(self) -> tuple[str, ...]:
        return (
            self.evaluation_contract_freeze_receipt_artifact_sha256,
            self.scientific_execution_authority_artifact_sha256,
            self.scientific_domain_evidence_source_artifact_sha256,
            self.generic_ml_paired_metric_projection_authority_artifact_sha256,
            self.scientific_confirmatory_timeline_receipt_artifact_sha256,
        )

    @property
    def direct_source_artifact_record_hashes(self) -> tuple[str, ...]:
        return (
            self.evaluation_contract_freeze_receipt_record_hash,
            self.scientific_execution_authority_record_hash,
            self.scientific_domain_evidence_source_record_hash,
            self.generic_ml_paired_metric_projection_authority_record_hash,
            self.scientific_confirmatory_timeline_receipt_record_hash,
        )

    @property
    def scientific_evidence_eligible(self) -> bool:
        return self.status is ScientificExecutionAdmissibilityStatus.ADMISSIBLE

    def to_dict(self) -> dict[str, Any]:
        result = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {
                "policy",
                "status",
                "decision_stopping_status",
                "evaluator_integrity_status",
            }
        }
        result["schema_version"] = SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA
        result["policy"] = self.policy.to_dict()
        result["status"] = self.status.value
        result["decision_stopping_status"] = self.decision_stopping_status.value
        result["evaluator_integrity_status"] = self.evaluator_integrity_status.value
        result["reason_codes"] = list(self.reason_codes)
        result["source_artifact_sha256s"] = list(self.source_artifact_sha256s)
        result["source_artifact_record_hashes"] = list(
            self.source_artifact_record_hashes
        )
        return result

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> "ScientificExecutionAdmissibilityAuthority":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        value = _exact_mapping(
            value, expected, "scientific execution admissibility authority"
        )
        if value["schema_version"] != SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA:
            raise ScientificExecutionAdmissibilityError(
                "unsupported scientific execution admissibility schema"
            )
        try:
            arguments = {name: value[name] for name in cls.__dataclass_fields__}
            arguments["policy"] = ScientificExecutionAdmissibilityPolicy.from_mapping(
                arguments["policy"]
            )
            arguments["status"] = ScientificExecutionAdmissibilityStatus(
                arguments["status"]
            )
            arguments["decision_stopping_status"] = ScientificDecisionStoppingStatus(
                arguments["decision_stopping_status"]
            )
            arguments["evaluator_integrity_status"] = (
                ScientificEvaluatorIntegrityStatus(
                    arguments["evaluator_integrity_status"]
                )
            )
            arguments["reason_codes"] = tuple(arguments["reason_codes"])
            arguments["source_artifact_sha256s"] = tuple(
                arguments["source_artifact_sha256s"]
            )
            arguments["source_artifact_record_hashes"] = tuple(
                arguments["source_artifact_record_hashes"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ScientificExecutionAdmissibilityError(
                "scientific execution admissibility authority is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionAdmissibilityResolution:
    status: ScientificExecutionAdmissibilityResolutionStatus
    reason_code: str
    authority_artifact_sha256: str | None = None
    authority: ScientificExecutionAdmissibilityAuthority | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "status",
            _enum_value(
                self.status,
                ScientificExecutionAdmissibilityResolutionStatus,
                "admissibility resolution status",
            ),
        )
        validate_identifier(self.reason_code, "admissibility resolution reason code")
        if self.status in {
            ScientificExecutionAdmissibilityResolutionStatus.ADMISSIBLE,
            ScientificExecutionAdmissibilityResolutionStatus.INADMISSIBLE,
        }:
            if self.authority is not None and self.authority_artifact_sha256 is None:
                raise ScientificExecutionAdmissibilityError(
                    "registered admissibility resolution lacks its artifact"
                )
            if self.authority is not None:
                expected = (
                    ScientificExecutionAdmissibilityStatus.ADMISSIBLE
                    if self.status
                    is ScientificExecutionAdmissibilityResolutionStatus.ADMISSIBLE
                    else ScientificExecutionAdmissibilityStatus.INADMISSIBLE
                )
                if self.authority.status is not expected:
                    raise ScientificExecutionAdmissibilityError(
                        "resolution and authority status differ"
                    )
        elif self.authority is not None or self.authority_artifact_sha256 is not None:
            raise ScientificExecutionAdmissibilityError(
                "blocked admissibility resolution cannot carry authority"
            )


@dataclass(frozen=True, slots=True)
class _AdmissibilityDetermination:
    status: ScientificExecutionAdmissibilityStatus
    stopping: ScientificDecisionStoppingStatus
    evaluator: ScientificEvaluatorIntegrityStatus
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _AdmissibilitySources:
    freeze_record: ArtifactRecord
    freeze: Any
    contract_record: ArtifactRecord
    contract: Any
    preparation_record: ArtifactRecord
    preparation: Any
    execution_record: ArtifactRecord
    execution: Any
    activity_record: ArtifactRecord
    activity: Any
    spec_record: ArtifactRecord
    spec: Any
    manifest_record: ArtifactRecord
    manifest: Any
    domain_source_record: ArtifactRecord
    domain_source: Any
    projection_record: ArtifactRecord
    projection: Any
    timeline_record: ArtifactRecord
    timeline: Any
    timeline_publication_head_hash: str
    determination: _AdmissibilityDetermination | None
    registry_snapshot: Any
    ledger_snapshot: Any

    @property
    def direct_records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.freeze_record,
            self.execution_record,
            self.domain_source_record,
            self.projection_record,
            self.timeline_record,
        )


def _validate_runtime(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> None:
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ScientificExecutionAdmissibilityError(
            "admissibility requires exact ArtifactRegistry and EventLedger"
        )
    validate_identifier(run_id, "admissibility ledger run ID")
    if (
        registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise ScientificExecutionAdmissibilityError(
            "admissibility requires the canonical paired registry and ledger"
        )


def _locked_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> tuple[Any, Any]:
    """Capture registry then ledger under the repository's canonical lock order."""

    _validate_runtime(registry, ledger, run_id)
    try:
        registry.verify_all(raise_on_error=True)
        ledger.assert_valid()
    except Exception as exc:
        raise ScientificExecutionAdmissibilityError(
            "admissibility registry or ledger cannot be verified"
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
                raise ScientificExecutionAdmissibilityError(
                    "admissibility ledger is invalid"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    if any(event.run_id != run_id for event in ledger_snapshot.events):
        raise ScientificExecutionAdmissibilityError(
            "admissibility ledger contains another run identity"
        )
    return registry_snapshot, ledger_snapshot


def _source_record(registry: ArtifactRegistry, digest: str, label: str) -> ArtifactRecord:
    validate_sha256(digest, f"{label} artifact SHA-256")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
    except (ArtifactError, ValidationError) as exc:
        raise ScientificExecutionAdmissibilityError(
            f"{label} cannot be reopened"
        ) from exc
    if (
        record.record_hash is None
        or record.validation_result != "PASS"
        or record.frozen is not True
    ):
        raise ScientificExecutionAdmissibilityError(
            f"{label} is not frozen registry authority"
        )
    return record


def _record_hash(record: ArtifactRecord) -> str:
    if record.record_hash is None:  # pragma: no cover - guarded at load
        raise ScientificExecutionAdmissibilityError("source record hash is absent")
    return str(record.record_hash)


def _string_value(value: Any) -> str:
    return value.value if isinstance(value, StrEnum) else str(value)


def _required_contract_ablation_ids(contract: Any) -> tuple[str, ...]:
    try:
        return tuple(item.ablation_id for item in contract.ablations if item.required)
    except (AttributeError, TypeError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "evaluation contract ablation closure is malformed"
        ) from exc


def _duration_seconds(started_at: str, completed_at: str) -> float:
    started = _utc_timestamp(started_at, "attested execution start")
    completed = _utc_timestamp(completed_at, "attested execution completion")
    duration = (completed - started).total_seconds()
    if duration < 0:
        raise ScientificExecutionAdmissibilityError(
            "attested execution timestamps are reversed"
        )
    return duration


def _projection_production_bindings(
    projection: Any,
) -> tuple[
    tuple[
        str,
        int,
        str,
        tuple[tuple[str, str], ...],
        tuple[tuple[str, str], ...],
    ],
    ...,
]:
    """Return the one closed activity convention from the typed projection."""

    rows = getattr(projection, "seed_projections", None)
    if not isinstance(rows, tuple) or not rows:
        raise ScientificExecutionAdmissibilityError(
            "generic-ML projection lacks typed per-seed production bindings"
        )
    result: list[
        tuple[
            str,
            int,
            str,
            tuple[tuple[str, str], ...],
            tuple[tuple[str, str], ...],
        ]
    ] = []
    for row in rows:
        try:
            seed = row.seed
            candidate_condition = row.candidate_condition_id
            baseline_condition = row.baseline_condition_id
            candidate_model = row.candidate_model_artifact_sha256
            candidate_model_record = row.candidate_model_record_hash
            baseline_model = row.baseline_model_artifact_sha256
            baseline_model_record = row.baseline_model_record_hash
            paired_predictions = row.paired_predictions_artifact_sha256
            paired_predictions_record = row.paired_predictions_record_hash
            robustness = row.robustness_artifact_sha256
            robustness_record = row.robustness_record_hash
        except AttributeError as exc:
            raise ScientificExecutionAdmissibilityError(
                "generic-ML projection seed binding is malformed"
            ) from exc
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ScientificExecutionAdmissibilityError(
                "generic-ML projection seed is invalid"
            )
        validate_identifier(candidate_condition, "candidate condition ID")
        validate_identifier(baseline_condition, "baseline condition ID")
        for digest, record_hash, label in (
            (candidate_model, candidate_model_record, "candidate model"),
            (baseline_model, baseline_model_record, "baseline model"),
            (
                paired_predictions,
                paired_predictions_record,
                "paired predictions",
            ),
            (robustness, robustness_record, "robustness"),
        ):
            validate_sha256(digest, f"{label} artifact SHA-256")
            validate_sha256(record_hash, f"{label} artifact record hash")
        candidate_model_identity = (candidate_model, candidate_model_record)
        baseline_model_identity = (baseline_model, baseline_model_record)
        paired_predictions_identity = (
            paired_predictions,
            paired_predictions_record,
        )
        robustness_identity = (robustness, robustness_record)
        result.extend(
            (
                (
                    "MODEL_INVOCATION",
                    seed,
                    candidate_condition,
                    (),
                    (candidate_model_identity,),
                ),
                (
                    "MODEL_INVOCATION",
                    seed,
                    baseline_condition,
                    (),
                    (baseline_model_identity,),
                ),
                (
                    "PREDICTION_GENERATION",
                    seed,
                    candidate_condition,
                    (candidate_model_identity, baseline_model_identity),
                    (paired_predictions_identity,),
                ),
                (
                    "OUTPUT_COMMIT",
                    seed,
                    candidate_condition,
                    (paired_predictions_identity,),
                    (robustness_identity,),
                ),
            )
        )
    output_hashes = tuple(
        identity[0]
        for _kind, _seed, _condition, _inputs, outputs in result
        for identity in outputs
    )
    if len(set(output_hashes)) != len(output_hashes):
        raise ScientificExecutionAdmissibilityError(
            "generic-ML projection aliases model or prediction artifacts"
        )
    return tuple(result)


def _derive_determination(sources: _AdmissibilitySources) -> _AdmissibilityDetermination:
    """Derive procedure admissibility without interpreting scientific outcome."""

    contract = sources.contract
    spec = sources.spec
    execution = sources.execution
    activity = sources.activity
    projection = sources.projection
    manifest = sources.manifest
    policy = getattr(contract, "scientific_execution_admissibility_policy", None)
    if not isinstance(policy, ScientificExecutionAdmissibilityPolicy):
        raise ScientificExecutionAdmissibilityError(
            "v3 evaluation contract lacks the closed admissibility policy"
        )
    if tuple(contract.stopping_criteria) != FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA:
        raise ScientificExecutionAdmissibilityError(
            "v3 stopping display differs from its typed policy"
        )

    stopping_failures: list[str] = []
    evaluator_failures: list[str] = []
    try:
        spec_metadata = thaw_json(spec.metadata)
        domain_policy = spec_metadata.get("scientific_domain_policy")
        active_baselines = tuple(
            item
            for item in contract.baseline_registry.entries
            if _string_value(item.status) not in {"CONTEXT_ONLY", "INCOMPATIBLE"}
        )
        candidate_conditions = contract.candidate_conditions
        sole_baseline_conditions = (
            active_baselines[0].conditions if len(active_baselines) == 1 else None
        )
    except (AttributeError, TypeError, ValidationError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "fixed Generic-ML comparison policy is malformed"
        ) from exc
    if (
        not isinstance(domain_policy, Mapping)
        or domain_policy.get("comparison_scope")
        != _FIXED_GENERIC_ML_COMPARISON_SCOPE
        or getattr(projection, "comparison_scope", None)
        != _FIXED_GENERIC_ML_COMPARISON_SCOPE
        or sole_baseline_conditions is None
        or candidate_conditions.tuning_trials != 0
        or sole_baseline_conditions.tuning_trials != 0
        or candidate_conditions.hyperparameter_search.strip().casefold() != "none"
        or sole_baseline_conditions.hyperparameter_search.strip().casefold() != "none"
    ):
        evaluator_failures.append("UNSUPPORTED_COMPARISON_OR_TUNING_SCOPE")
    expected_seeds = tuple(contract.seed_reporting.seeds)
    expected_ablations = _required_contract_ablation_ids(contract)
    if tuple(spec.seeds) != expected_seeds:
        stopping_failures.append("FROZEN_SEED_GRID_MISMATCH")
    if tuple(spec.required_ablations) != expected_ablations:
        stopping_failures.append("FROZEN_ABLATION_GRID_MISMATCH")
    if spec.attempt != 1 or spec.retry_of_run_id is not None:
        stopping_failures.append("CONFIRMATORY_RETRY_OR_REUSED_ATTEMPT")
    if _string_value(spec.phase) != "CONFIRMATORY":
        stopping_failures.append("NON_CONFIRMATORY_EXECUTION")
    if spec.seed_policy != "EXPLICIT_FIXED_SEEDS_NO_SELECTION":
        stopping_failures.append("UNSUPPORTED_SEED_SELECTION_POLICY")
    if tuple(spec.termination_conditions) != (
        "wall_clock_timeout",
        "all_planned_seeds_reported",
    ):
        stopping_failures.append("UNSUPPORTED_TERMINATION_POLICY")
    if _string_value(execution.outcome) != "COMPLETED":
        stopping_failures.append("EXECUTION_DID_NOT_COMPLETE")
    if _string_value(activity.terminal.kind) != "ALL_PLANNED_WORK_COMPLETED":
        stopping_failures.append("ACTIVITY_TERMINAL_NOT_COMPLETE")
    if activity.terminal.occurred_at != execution.attested_completed_at:
        stopping_failures.append("ACTIVITY_TERMINAL_TIME_MISMATCH")
    duration = _duration_seconds(
        execution.attested_started_at,
        execution.attested_completed_at,
    )
    if duration > min(float(spec.timeout_seconds), float(contract.compute_budget.max_wall_seconds)):
        stopping_failures.append("EXECUTION_EXCEEDED_FROZEN_WALL_LIMIT")

    activity_rows = tuple(activity.activity_rows)
    forbidden_kinds = {"EVALUATOR_QUERY", "SELECTION_TRIAL", "ADAPTIVE_BRANCH"}
    if any(_string_value(row.kind) in forbidden_kinds for row in activity_rows):
        evaluator_failures.append("ADAPTIVE_OR_EVALUATOR_ACTIVITY_OBSERVED")
    if any(
        _string_value(row.dataset_access_purpose) == "CONFIRMATORY_LABELS"
        for row in activity_rows
        if row.dataset_access_purpose is not None
    ):
        evaluator_failures.append("BACKEND_ACCESSED_PROTECTED_CONFIRMATORY_LABELS")

    dataset_sha = getattr(projection, "dataset_authority_artifact_sha256", None)
    split_shas = tuple(
        getattr(projection, "split_authority_artifact_sha256s", ())
    )
    try:
        validate_sha256(dataset_sha, "projection Dataset authority SHA-256")
        for digest in split_shas:
            validate_sha256(digest, "projection split authority SHA-256")
    except (TypeError, ValidationError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "generic-ML projection dataset closure is malformed"
        ) from exc
    if len(split_shas) != 4 or len(set(split_shas)) != 4:
        evaluator_failures.append("PROJECTION_SPLIT_CLOSURE_INCOMPLETE")
    if tuple(getattr(projection, "seed_order", ())) != expected_seeds:
        evaluator_failures.append("PROJECTION_SEED_GRID_MISMATCH")
    common_unit_ids = tuple(getattr(projection, "paired_unit_ids", ()))
    common_unit_hashes = tuple(getattr(projection, "paired_unit_hashes", ()))
    common_labels = tuple(getattr(projection, "reference_labels", ()))
    seed_projections = tuple(getattr(projection, "seed_projections", ()))
    if (
        not common_unit_ids
        or len(common_unit_ids) != len(common_unit_hashes)
        or len(common_unit_ids) != len(common_labels)
        or len(set(common_unit_ids)) != len(common_unit_ids)
        or len(set(common_unit_hashes)) != len(common_unit_hashes)
        or tuple(getattr(row, "seed", None) for row in seed_projections)
        != expected_seeds
        or any(
            tuple(getattr(row, "paired_unit_ids", ())) != common_unit_ids
            or tuple(getattr(row, "paired_unit_hashes", ()))
            != common_unit_hashes
            or tuple(getattr(row, "reference_labels", ())) != common_labels
            or len(tuple(getattr(row, "candidate_values", ())))
            != len(common_unit_ids)
            or len(tuple(getattr(row, "baseline_values", ())))
            != len(common_unit_ids)
            for row in seed_projections
        )
    ):
        evaluator_failures.append("PROJECTION_UNIT_GRID_MISMATCH")
    for row in activity_rows:
        if _string_value(row.kind) != "DATASET_READ":
            continue
        if (
            row.dataset_artifact_binding is None
            or row.split_artifact_binding is None
            or row.dataset_artifact_binding.artifact_sha256 != dataset_sha
            or row.split_artifact_binding.artifact_sha256 not in split_shas
        ):
            evaluator_failures.append("DATASET_READ_OUTSIDE_FROZEN_SPLITS")
            break
    if not any(
        _string_value(row.dataset_access_purpose) == "CONFIRMATORY_FEATURES"
        for row in activity_rows
        if row.dataset_access_purpose is not None
    ):
        evaluator_failures.append("CONFIRMATORY_FEATURE_ACCESS_NOT_ATTESTED")

    expected_productions = _projection_production_bindings(projection)
    observed_productions = tuple(
        (
            _string_value(row.kind),
            row.seed,
            row.condition_id,
            tuple(
                (binding.artifact_sha256, binding.artifact_record_hash)
                for binding in row.input_artifact_bindings
            ),
            tuple(
                (binding.artifact_sha256, binding.artifact_record_hash)
                for binding in row.output_artifact_bindings
            ),
        )
        for row in activity_rows
        if _string_value(row.kind)
        in {"MODEL_INVOCATION", "PREDICTION_GENERATION", "OUTPUT_COMMIT"}
    )
    if tuple(seed for _kind, seed, _condition, _inputs, _outputs in observed_productions) != tuple(
        seed for seed in expected_seeds for _ in range(4)
    ):
        stopping_failures.append("MODEL_ACTIVITY_GRID_INCOMPLETE")
    if observed_productions != expected_productions:
        evaluator_failures.append("MODEL_PREDICTION_ACTIVITY_GRID_MISMATCH")

    manifest_ablation_ids = tuple(item.ablation_id for item in manifest.ablations)
    manifest_ablation_hashes = tuple(
        item.artifact_sha256 for item in manifest.ablations
    )
    if (
        manifest_ablation_ids != expected_ablations
        or any(item.status != "PASS" for item in manifest.ablations)
    ):
        stopping_failures.append("MANIFEST_ABLATION_GRID_INCOMPLETE")
    projection_ablation_hashes = tuple(
        getattr(projection, "ablation_output_artifact_sha256s", ())
    )
    projection_ablation_records = tuple(
        getattr(projection, "ablation_output_record_hashes", ())
    )
    if (
        projection_ablation_hashes != manifest_ablation_hashes
        or len(projection_ablation_records) != len(projection_ablation_hashes)
    ):
        stopping_failures.append("PROJECTION_ABLATION_CLOSURE_MISMATCH")
    observed_ablation_rows = tuple(
        (
            row.ablation_id,
            tuple(
                (binding.artifact_sha256, binding.artifact_record_hash)
                for binding in row.output_artifact_bindings
            ),
        )
        for row in activity_rows
        if _string_value(row.kind) == "ABLATION_EXECUTION"
    )
    expected_ablation_rows = tuple(
        (ablation_id, ((digest, record_hash),))
        for ablation_id, digest, record_hash in zip(
            expected_ablations,
            projection_ablation_hashes,
            projection_ablation_records,
            strict=False,
        )
    )
    if observed_ablation_rows != expected_ablation_rows:
        stopping_failures.append("ABLATION_ACTIVITY_GRID_MISMATCH")

    domain_consumed = tuple(
        getattr(projection, "domain_consumed_output_artifact_sha256s", ())
    )
    manifest_outputs = tuple(item.sha256 for item in manifest.artifacts)
    manifest_ablation_set = set(manifest_ablation_hashes)
    expected_domain_consumed = tuple(
        digest for digest in manifest_outputs if digest not in manifest_ablation_set
    )
    if (
        not domain_consumed
        or len(set(domain_consumed)) != len(domain_consumed)
        or domain_consumed != expected_domain_consumed
        or len(manifest_ablation_set) != len(manifest_ablation_hashes)
        or not manifest_ablation_set.issubset(set(manifest_outputs))
        or set(domain_consumed).intersection(manifest_ablation_set)
        or set(domain_consumed) | manifest_ablation_set
        != set(manifest_outputs)
    ):
        evaluator_failures.append("MANIFEST_OUTPUT_CONSUMPTION_INCOMPLETE")

    if stopping_failures or evaluator_failures:
        reason_codes = tuple(dict.fromkeys((*stopping_failures, *evaluator_failures)))
        return _AdmissibilityDetermination(
            status=ScientificExecutionAdmissibilityStatus.INADMISSIBLE,
            stopping=(
                ScientificDecisionStoppingStatus.NOT_MET
                if stopping_failures
                else ScientificDecisionStoppingStatus.MET
            ),
            evaluator=(
                ScientificEvaluatorIntegrityStatus.FAIL
                if evaluator_failures
                else ScientificEvaluatorIntegrityStatus.PASS
            ),
            reason_codes=reason_codes,
        )
    return _AdmissibilityDetermination(
        status=ScientificExecutionAdmissibilityStatus.ADMISSIBLE,
        stopping=ScientificDecisionStoppingStatus.MET,
        evaluator=ScientificEvaluatorIntegrityStatus.PASS,
        reason_codes=("FIXED_COMPLETE_GENERIC_ML_ADMISSIBLE",),
    )


def _missing_source(
    registry: ArtifactRegistry,
    selectors: Sequence[tuple[str, str]],
) -> str | None:
    for digest, label in selectors:
        try:
            validate_sha256(digest, f"{label} SHA-256")
            registry.get_metadata(digest)
        except ArtifactError:
            return label
    return None


def _derive_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    scientific_confirmatory_timeline_receipt_artifact_sha256: str,
    scientific_domain_evidence_source_artifact_sha256: str,
    generic_ml_paired_metric_projection_authority_artifact_sha256: str,
) -> tuple[
    ScientificExecutionAdmissibilityResolutionStatus,
    str,
    _AdmissibilitySources | None,
]:
    """Bracket every resolution, including absence, in one paired view."""

    entry_registry, entry_ledger = _locked_snapshot(
        registry, ledger, expected_ledger_run_id
    )
    result = _derive_sources_at_snapshot(
        registry,
        ledger,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=(
            evaluation_contract_freeze_receipt_artifact_sha256
        ),
        scientific_execution_authority_artifact_sha256=(
            scientific_execution_authority_artifact_sha256
        ),
        scientific_confirmatory_timeline_receipt_artifact_sha256=(
            scientific_confirmatory_timeline_receipt_artifact_sha256
        ),
        scientific_domain_evidence_source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
        generic_ml_paired_metric_projection_authority_artifact_sha256=(
            generic_ml_paired_metric_projection_authority_artifact_sha256
        ),
        entry_registry=entry_registry,
        entry_ledger=entry_ledger,
    )
    if _locked_snapshot(registry, ledger, expected_ledger_run_id) != (
        entry_registry, entry_ledger
    ):
        raise ScientificExecutionAdmissibilityError(
            "admissibility sources changed during fresh replay"
        )
    return result


def _derive_sources_at_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    scientific_confirmatory_timeline_receipt_artifact_sha256: str,
    scientific_domain_evidence_source_artifact_sha256: str,
    generic_ml_paired_metric_projection_authority_artifact_sha256: str,
    entry_registry: Any,
    entry_ledger: Any,
) -> tuple[
    ScientificExecutionAdmissibilityResolutionStatus,
    str,
    _AdmissibilitySources | None,
]:
    """Private source derivation; only the outer paired wrapper consumes it."""

    _validate_runtime(registry, ledger, expected_ledger_run_id)
    validate_identifier(expected_execution_run_id, "expected execution run ID")
    missing = _missing_source(
        registry,
        (
            (
                evaluation_contract_freeze_receipt_artifact_sha256,
                "evaluation-contract freeze receipt",
            ),
            (
                scientific_execution_authority_artifact_sha256,
                "scientific execution authority",
            ),
            (
                scientific_domain_evidence_source_artifact_sha256,
                "scientific domain evidence source",
            ),
            (
                generic_ml_paired_metric_projection_authority_artifact_sha256,
                "generic-ML paired metric projection",
            ),
            (
                scientific_confirmatory_timeline_receipt_artifact_sha256,
                "scientific confirmatory timeline receipt",
            ),
        ),
    )
    if missing is not None:
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
            "LOCAL_SOURCE_AUTHORITY_ABSENT",
            None,
        )

    try:
        from . import scientific_design as design_module
        from .domains import (
            DomainKind,
            ScientificDomainAdmissionStatus,
            ScientificDomainAdmissionUnavailable,
            require_scientific_domain_evidence_source,
        )
        from .experiments import (
            COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
            ExperimentError,
            OutputManifest,
            ScientificExecutionAuthorityUnavailable,
            require_scientific_execution_activity,
            require_scientific_execution_authority,
            require_scientific_execution_preparation,
            require_scientific_execution_run_spec,
        )
        from .generic_ml_projection import (
            require_generic_ml_paired_metric_projection_authority,
        )
    except (ImportError, AttributeError):
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
            "SUPPORTED_SOURCE_OWNER_NOT_IMPLEMENTED",
            None,
        )

    timeline_require = getattr(
        design_module,
        "require_scientific_confirmatory_timeline_receipt_v2",
        None,
    )
    if timeline_require is None:
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
            "CONFIRMATORY_TIMELINE_BRIDGE_NOT_IMPLEMENTED",
            None,
        )
    try:
        freeze_record = _source_record(
            registry,
            evaluation_contract_freeze_receipt_artifact_sha256,
            "evaluation-contract freeze receipt",
        )
        freeze_value = safe_json_loads(registry.get_bytes(freeze_record.sha256))
        freeze_candidate = design_module.EvaluationContractFreezeGateReceipt.from_dict(
            freeze_value
        )
        freeze = design_module.require_evaluation_contract_freeze_gate_receipt(
            registry,
            ledger,
            receipt_artifact_sha256=freeze_record.sha256,
            expected_run_id=expected_ledger_run_id,
            expected_contract_id=freeze_candidate.object_id,
        )
        contract = design_module.require_frozen_evaluation_contract(
            registry,
            contract_artifact_sha256=freeze.contract_artifact_sha256,
        )
        contract_record = _source_record(
            registry,
            freeze.contract_artifact_sha256,
            "frozen evaluation contract",
        )
        policy = getattr(
            contract,
            "scientific_execution_admissibility_policy",
            None,
        )
        if policy is None:
            return (
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
                "LEGACY_CONTRACT_HAS_NO_TYPED_ADMISSIBILITY_POLICY",
                None,
            )
        if not isinstance(policy, ScientificExecutionAdmissibilityPolicy):
            raise ScientificExecutionAdmissibilityError(
                "evaluation contract has a substituted admissibility policy"
            )
        if contract_record.schema_version != EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V3:
            raise ScientificExecutionAdmissibilityError(
                "typed admissibility policy is not carried by a v3 contract artifact"
            )
        execution = require_scientific_execution_authority(
            registry,
            ledger,
            authority_artifact_sha256=(
                scientific_execution_authority_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        execution_record = _source_record(
            registry,
            scientific_execution_authority_artifact_sha256,
            "scientific execution authority",
        )
    except ScientificExecutionAuthorityUnavailable:
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
            "SCIENTIFIC_BACKEND_AUTHORITY_UNAVAILABLE",
            None,
        )
    except (ArtifactError, ValidationError, ExperimentError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "prospective contract or execution authority failed fresh replay"
        ) from exc

    activity_sha256 = execution.execution_activity_artifact_sha256
    activity_record_hash = execution.execution_activity_record_hash
    if activity_sha256 is None or activity_record_hash is None:
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
            "LEGACY_EXECUTION_LACKS_AUTHENTICATED_COMPLETE_ACTIVITY",
            None,
        )
    try:
        preparation = require_scientific_execution_preparation(
            registry,
            ledger,
            preparation_artifact_sha256=execution.preparation_artifact_sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        preparation_record = _source_record(
            registry,
            execution.preparation_artifact_sha256,
            "scientific execution preparation",
        )
        spec = require_scientific_execution_run_spec(
            registry,
            frozen_run_spec_artifact_sha256=(
                execution.frozen_run_spec_artifact_sha256
            ),
        )
        spec_record = _source_record(
            registry,
            execution.frozen_run_spec_artifact_sha256,
            "frozen scientific run spec",
        )
        configuration_record = _source_record(
            registry, spec.configuration_sha256, "frozen model configuration"
        )
        evaluator_record = _source_record(
            registry, spec.evaluator_sha256, "frozen evaluator implementation"
        )
        activity = require_scientific_execution_activity(
            registry,
            activity_artifact_sha256=activity_sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            expected_preparation_artifact_sha256=preparation_record.sha256,
            expected_frozen_run_spec_artifact_sha256=spec_record.sha256,
            expected_output_manifest_artifact_sha256=(
                execution.output_manifest_artifact_sha256
            ),
        )
        activity_record = _source_record(
            registry,
            activity_sha256,
            "authenticated scientific execution activity",
        )
        manifest_record = _source_record(
            registry,
            execution.output_manifest_artifact_sha256,
            "scientific output manifest",
        )
        manifest_value = safe_json_loads(registry.get_bytes(manifest_record.sha256))
        manifest = OutputManifest.from_mapping(manifest_value)
        projection = require_generic_ml_paired_metric_projection_authority(
            registry,
            ledger,
            projection_artifact_sha256=(
                generic_ml_paired_metric_projection_authority_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            expected_domain_evidence_source_artifact_sha256=(
                scientific_domain_evidence_source_artifact_sha256
            ),
            expected_contract_artifact_sha256=contract_record.sha256,
            expected_output_manifest_artifact_sha256=manifest_record.sha256,
        )
        projection_record = _source_record(
            registry,
            generic_ml_paired_metric_projection_authority_artifact_sha256,
            "generic-ML paired metric projection",
        )
        from .scientific_numeric_ablation import SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY
        from .scientific_numeric_ablation_execution import require_scientific_numeric_ablation_execution

        if SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY in thaw_json(spec.metadata):
            # Full prospective replay already rejects malformed presence and
            # missing required new-profile policy. Never replace this with a
            # producer PASS flag or a caller-constructed numeric companion.
            numeric_ablations = require_scientific_numeric_ablation_execution(
                registry, ledger,
                expected_ledger_run_id=expected_ledger_run_id,
                expected_execution_run_id=expected_execution_run_id,
                generic_ml_projection_artifact_sha256=projection_record.sha256,
                scientific_execution_authority_artifact_sha256=execution_record.sha256,
                scientific_domain_evidence_source_artifact_sha256=scientific_domain_evidence_source_artifact_sha256,
                expected_contract_artifact_sha256=contract_record.sha256,
                expected_output_manifest_artifact_sha256=manifest_record.sha256,
            )
            if (numeric_ablations.execution != execution or numeric_ablations.projection != projection
                    or numeric_ablations.spec != spec or numeric_ablations.execution_record != execution_record
                    or numeric_ablations.projection_record != projection_record
                    or numeric_ablations.spec_record != spec_record
                    or numeric_ablations.manifest_record != manifest_record
                    or numeric_ablations.activity_record != activity_record):
                raise ScientificExecutionAdmissibilityError(
                    "numeric ablation replay differs from the exact admissibility sources"
                )
        domain_source = require_scientific_domain_evidence_source(
            registry,
            ledger,
            source_artifact_sha256=scientific_domain_evidence_source_artifact_sha256,
            expected_run_id=expected_ledger_run_id,
            expected_domain=DomainKind.GENERIC_ML,
            expected_object_id=projection.object_id,
            expected_task_id=projection.task_id,
        )
        domain_source_record = _source_record(
            registry,
            scientific_domain_evidence_source_artifact_sha256,
            "scientific domain evidence source",
        )
    except ScientificDomainAdmissionUnavailable as exc:
        if exc.status is ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL:
            return (
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
                exc.reason_code,
                None,
            )
        if exc.status in {
            ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
            ScientificDomainAdmissionStatus.UNSUPPORTED,
        }:
            return (
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
                exc.reason_code,
                None,
            )
        raise ScientificExecutionAdmissibilityError(
            "verified domain source was reported unavailable"
        ) from exc
    except ScientificExecutionAuthorityUnavailable:
        return (
            ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
            "SCIENTIFIC_BACKEND_AUTHORITY_UNAVAILABLE",
            None,
        )
    except (ArtifactError, ValidationError, ExperimentError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "admissibility execution or domain source failed fresh replay"
        ) from exc

    try:
        timeline = timeline_require(
            registry,
            ledger,
            receipt_artifact_sha256=(
                scientific_confirmatory_timeline_receipt_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            expected_contract_artifact_sha256=contract_record.sha256,
            expected_preparation_artifact_sha256=preparation_record.sha256,
            expected_execution_authority_artifact_sha256=execution_record.sha256,
            expected_output_manifest_artifact_sha256=manifest_record.sha256,
            expected_generic_ml_projection_artifact_sha256=projection_record.sha256,
        )
        timeline_record = _source_record(
            registry,
            scientific_confirmatory_timeline_receipt_artifact_sha256,
            "scientific confirmatory timeline receipt",
        )
        # A receipt's internal prefix is the earlier metric projection event.
        # Dependents must instead follow the actual, source-owned publication.
        publications = design_module._matching_scientific_confirmatory_timeline_events(
            entry_ledger.events, receipt=timeline
        )
        if len(publications) != 1:
            raise ScientificExecutionAdmissibilityError(
                "confirmatory timeline publication is absent or ambiguous"
            )
        publication_index, publication_event, _binding = publications[0]
        design_module._validate_scientific_confirmatory_timeline_event(
            publication_event,
            publication_index,
            entry_ledger.events,
            record=timeline_record,
            receipt=timeline,
            source_records=tuple(
                registry.get_metadata(digest)
                for digest in timeline.direct_source_artifact_sha256s
            ),
        )
        timeline_publication_head_hash = publication_event.event_hash
        validate_sha256(
            timeline_publication_head_hash, "confirmatory timeline publication"
        )
    except design_module.ScientificConfirmatoryTimelineUnavailable as exc:
        status_value = _string_value(exc.resolution_status)
        if status_value == "BLOCKED_EXTERNAL":
            return (
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
                exc.reason_code,
                None,
            )
        if status_value == "BLOCKED_LOCAL":
            return (
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
                exc.reason_code,
                None,
            )
        raise ScientificExecutionAdmissibilityError(
            "verified confirmatory timeline was reported unavailable"
        ) from exc
    except Exception as exc:
        raise ScientificExecutionAdmissibilityError(
            "confirmatory timeline source failed fresh replay"
        ) from exc

    projection_source_sha = getattr(
        projection, "scientific_domain_evidence_source_artifact_sha256", None
    )
    if projection_source_sha is None:
        projection_source_sha = getattr(projection, "source_artifact_sha256", None)
    prepared_input_pairs = tuple(zip(
        preparation.input_artifact_sha256s,
        preparation.input_artifact_record_hashes,
        strict=True,
    ))
    source_mismatches = (
        freeze.run_id != expected_ledger_run_id,
        spec.run_id != expected_execution_run_id,
        preparation.ledger_run_id != expected_ledger_run_id,
        preparation.execution_run_id != expected_execution_run_id,
        preparation.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        preparation.frozen_run_spec_record_hash != _record_hash(spec_record),
        preparation.frozen_run_spec_sha256 != spec.sha256,
        preparation.scientific_binding_sha256 != spec.scientific_binding_sha256,
        prepared_input_pairs.count((
            configuration_record.sha256, _record_hash(configuration_record)
        )) != 1,
        prepared_input_pairs.count((
            evaluator_record.sha256, _record_hash(evaluator_record)
        )) != 1,
        execution.ledger_run_id != expected_ledger_run_id,
        execution.execution_run_id != expected_execution_run_id,
        execution.preparation_artifact_sha256 != preparation_record.sha256,
        execution.preparation_record_hash != _record_hash(preparation_record),
        execution.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        execution.frozen_run_spec_sha256 != spec.sha256,
        execution.scientific_binding_sha256 != spec.scientific_binding_sha256,
        execution.output_manifest_artifact_sha256 != manifest_record.sha256,
        execution.output_manifest_record_hash != _record_hash(manifest_record),
        execution.execution_activity_artifact_sha256 != activity_record.sha256,
        execution.execution_activity_record_hash != _record_hash(activity_record),
        activity.ledger_run_id != expected_ledger_run_id,
        activity.execution_run_id != expected_execution_run_id,
        activity.preparation_artifact_sha256 != preparation_record.sha256,
        activity.preparation_record_hash != _record_hash(preparation_record),
        activity.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        activity.frozen_run_spec_record_hash != _record_hash(spec_record),
        activity.output_manifest_artifact_sha256 != manifest_record.sha256,
        activity.output_manifest_record_hash != _record_hash(manifest_record),
        activity.capture_profile != COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
        freeze.contract_artifact_sha256 != contract_record.sha256,
        freeze.contract_record_hash != _record_hash(contract_record),
        freeze.contract_sha256 != contract.sha256,
        freeze.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        freeze.frozen_run_spec_record_hash != _record_hash(spec_record),
        freeze.frozen_run_spec_sha256 != spec.sha256,
        tuple(contract.seed_reporting.seeds) != tuple(spec.seeds),
        domain_source.run_id != expected_ledger_run_id,
        domain_source.execution_run_id != expected_execution_run_id,
        domain_source.evaluation_contract_artifact_sha256 != contract_record.sha256,
        domain_source.evaluation_contract_record_hash
        != _record_hash(contract_record),
        domain_source.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        domain_source.frozen_run_spec_record_hash != _record_hash(spec_record),
        domain_source.scientific_execution_authority_artifact_sha256
        != execution_record.sha256,
        domain_source.scientific_execution_authority_record_hash
        != _record_hash(execution_record),
        domain_source.source_artifact_sha256 != domain_source_record.sha256,
        domain_source.source_record_hash != _record_hash(domain_source_record),
        projection.run_id != expected_ledger_run_id,
        projection.execution_run_id != expected_execution_run_id,
        projection.object_id != domain_source.object_id,
        projection.task_id != domain_source.task_id,
        projection_source_sha != domain_source_record.sha256,
        projection.scientific_domain_evidence_source_record_hash
        != _record_hash(domain_source_record),
        projection.plan_artifact_sha256 != domain_source.plan_artifact_sha256,
        projection.plan_record_hash != domain_source.plan_record_hash,
        projection.raw_source_artifact_sha256
        != domain_source.raw_source_artifact_sha256,
        projection.raw_source_record_hash != domain_source.raw_source_record_hash,
        projection.canonical_run_artifact_sha256
        != domain_source.canonical_run_artifact_sha256,
        projection.canonical_run_record_hash
        != domain_source.canonical_run_record_hash,
        projection.canonical_run_content_hash
        != domain_source.canonical_run_content_hash,
        projection.output_manifest_artifact_sha256 != manifest_record.sha256,
        projection.output_manifest_record_hash != _record_hash(manifest_record),
        projection.evaluation_contract_artifact_sha256 != contract_record.sha256,
        projection.evaluation_contract_record_hash != _record_hash(contract_record),
        projection.frozen_run_spec_artifact_sha256 != spec_record.sha256,
        projection.frozen_run_spec_record_hash != _record_hash(spec_record),
        projection.frozen_model_configuration_artifact_sha256
        != configuration_record.sha256,
        projection.frozen_model_configuration_record_hash
        != _record_hash(configuration_record),
        projection.scientific_execution_authority_artifact_sha256
        != execution_record.sha256,
        projection.scientific_execution_authority_record_hash
        != _record_hash(execution_record),
        projection.scientific_execution_activity_artifact_sha256
        != activity_record.sha256,
        projection.scientific_execution_activity_record_hash
        != _record_hash(activity_record),
        projection.evaluator_artifact_sha256 != spec.evaluator_sha256,
        projection.evaluator_record_hash != _record_hash(evaluator_record),
        projection.environment_artifact_sha256
        != execution.environment_artifact_sha256,
        projection.environment_record_hash != execution.environment_record_hash,
        projection.projection_artifact_sha256 != projection_record.sha256,
        projection.projection_record_hash != _record_hash(projection_record),
        projection.status != "PROJECTED",
        projection.scientific_evidence_eligible is not True,
        tuple(projection.split_authority_artifact_sha256s)
        != tuple(domain_source.split_authority_artifact_sha256s),
        tuple(projection.split_authority_record_hashes)
        != tuple(domain_source.split_authority_record_hashes),
        projection.dataset_authority_artifact_sha256
        != domain_source.dataset_authority_artifact_sha256,
        projection.dataset_authority_record_hash
        != domain_source.dataset_authority_record_hash,
        timeline.ledger_run_id != expected_ledger_run_id,
        timeline.execution_run_id != expected_execution_run_id,
        timeline.contract_artifact_sha256 != contract_record.sha256,
        timeline.contract_record_hash != _record_hash(contract_record),
        timeline.scientific_execution_preparation_artifact_sha256
        != preparation_record.sha256,
        timeline.scientific_execution_preparation_record_hash
        != _record_hash(preparation_record),
        timeline.scientific_execution_authority_artifact_sha256
        != execution_record.sha256,
        timeline.scientific_execution_authority_record_hash
        != _record_hash(execution_record),
        timeline.output_manifest_artifact_sha256 != manifest_record.sha256,
        timeline.output_manifest_record_hash != _record_hash(manifest_record),
        timeline.generic_ml_projection_artifact_sha256
        != projection_record.sha256,
        timeline.generic_ml_projection_record_hash
        != _record_hash(projection_record),
    )
    if any(source_mismatches):
        raise ScientificExecutionAdmissibilityError(
            "admissibility sources do not form one exact execution closure"
        )
    if getattr(timeline, "scientific_gate_passed", False) is not True:
        raise ScientificExecutionAdmissibilityError(
            "confirmatory timeline lacks positive independent custody authority"
        )
    provisional = _AdmissibilitySources(
        freeze_record=freeze_record,
        freeze=freeze,
        contract_record=contract_record,
        contract=contract,
        preparation_record=preparation_record,
        preparation=preparation,
        execution_record=execution_record,
        execution=execution,
        activity_record=activity_record,
        activity=activity,
        spec_record=spec_record,
        spec=spec,
        manifest_record=manifest_record,
        manifest=manifest,
        domain_source_record=domain_source_record,
        domain_source=domain_source,
        projection_record=projection_record,
        projection=projection,
        timeline_record=timeline_record,
        timeline=timeline,
        timeline_publication_head_hash=timeline_publication_head_hash,
        determination=None,
        registry_snapshot=entry_registry,
        ledger_snapshot=entry_ledger,
    )
    determination = _derive_determination(provisional)
    sources = replace(provisional, determination=determination)
    resolution_status = (
        ScientificExecutionAdmissibilityResolutionStatus.ADMISSIBLE
        if determination.status is ScientificExecutionAdmissibilityStatus.ADMISSIBLE
        else ScientificExecutionAdmissibilityResolutionStatus.INADMISSIBLE
    )
    return resolution_status, determination.reason_codes[0], sources


def resolve_scientific_execution_admissibility(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    scientific_confirmatory_timeline_receipt_artifact_sha256: str,
    scientific_domain_evidence_source_artifact_sha256: str,
    generic_ml_paired_metric_projection_authority_artifact_sha256: str,
) -> ScientificExecutionAdmissibilityResolution:
    """Resolve the closed leaf after upstream positive authorities exist.

    Callers must first use the confirmatory-timeline pre-issuance resolver when
    they need a truthful ``BLOCKED_LOCAL`` versus ``BLOCKED_EXTERNAL`` custody
    diagnosis.  This leaf never guesses that diagnosis from a missing receipt.
    """

    status, reason, _sources = _derive_sources(
        registry,
        ledger,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=(
            evaluation_contract_freeze_receipt_artifact_sha256
        ),
        scientific_execution_authority_artifact_sha256=(
            scientific_execution_authority_artifact_sha256
        ),
        scientific_confirmatory_timeline_receipt_artifact_sha256=(
            scientific_confirmatory_timeline_receipt_artifact_sha256
        ),
        scientific_domain_evidence_source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
        generic_ml_paired_metric_projection_authority_artifact_sha256=(
            generic_ml_paired_metric_projection_authority_artifact_sha256
        ),
    )
    return ScientificExecutionAdmissibilityResolution(
        status=status,
        reason_code=reason,
    )


def _authority_slot_binding(sources: _AdmissibilitySources) -> dict[str, Any]:
    return {
        "schema_version": SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA,
        "ledger_run_id": sources.execution.ledger_run_id,
        "execution_run_id": sources.execution.execution_run_id,
        "contract_artifact_sha256": sources.contract_record.sha256,
        "contract_record_hash": _record_hash(sources.contract_record),
        "preparation_artifact_sha256": sources.preparation_record.sha256,
        "preparation_record_hash": _record_hash(sources.preparation_record),
        "challenge_nonce": sources.preparation.challenge_nonce,
        "scientific_execution_authority_artifact_sha256": (
            sources.execution_record.sha256
        ),
        "scientific_execution_authority_record_hash": _record_hash(
            sources.execution_record
        ),
        "scientific_binding_sha256": sources.spec.scientific_binding_sha256,
        "generic_ml_paired_metric_projection_authority_artifact_sha256": (
            sources.projection_record.sha256
        ),
        "generic_ml_paired_metric_projection_authority_record_hash": _record_hash(
            sources.projection_record
        ),
    }


def _authority_id(sources: _AdmissibilitySources) -> str:
    return "execution-admissibility-" + hashlib.sha256(
        canonical_json_bytes(_authority_slot_binding(sources))
    ).hexdigest()[:24]


def _authority_from_sources(
    sources: _AdmissibilitySources,
) -> ScientificExecutionAdmissibilityAuthority:
    determination = sources.determination
    if determination is None:  # pragma: no cover - internal construction guard
        raise ScientificExecutionAdmissibilityError(
            "admissibility determination is absent"
        )
    direct = sources.direct_records
    prefix_hash = sources.timeline_publication_head_hash
    validate_sha256(prefix_hash, "confirmatory timeline publication prefix")
    return ScientificExecutionAdmissibilityAuthority(
        authority_id=_authority_id(sources),
        ledger_run_id=sources.execution.ledger_run_id,
        execution_run_id=sources.execution.execution_run_id,
        scientific_binding_sha256=sources.spec.scientific_binding_sha256,
        policy=sources.contract.scientific_execution_admissibility_policy,
        status=determination.status,
        decision_stopping_status=determination.stopping,
        evaluator_integrity_status=determination.evaluator,
        reason_codes=determination.reason_codes,
        evaluation_contract_freeze_receipt_artifact_sha256=(
            sources.freeze_record.sha256
        ),
        evaluation_contract_freeze_receipt_record_hash=_record_hash(
            sources.freeze_record
        ),
        contract_artifact_sha256=sources.contract_record.sha256,
        contract_record_hash=_record_hash(sources.contract_record),
        scientific_execution_preparation_artifact_sha256=(
            sources.preparation_record.sha256
        ),
        scientific_execution_preparation_record_hash=_record_hash(
            sources.preparation_record
        ),
        scientific_execution_authority_artifact_sha256=(
            sources.execution_record.sha256
        ),
        scientific_execution_authority_record_hash=_record_hash(
            sources.execution_record
        ),
        scientific_execution_activity_artifact_sha256=sources.activity_record.sha256,
        scientific_execution_activity_record_hash=_record_hash(
            sources.activity_record
        ),
        frozen_run_spec_artifact_sha256=sources.spec_record.sha256,
        frozen_run_spec_record_hash=_record_hash(sources.spec_record),
        output_manifest_artifact_sha256=sources.manifest_record.sha256,
        output_manifest_record_hash=_record_hash(sources.manifest_record),
        scientific_domain_evidence_source_artifact_sha256=(
            sources.domain_source_record.sha256
        ),
        scientific_domain_evidence_source_record_hash=_record_hash(
            sources.domain_source_record
        ),
        generic_ml_paired_metric_projection_authority_artifact_sha256=(
            sources.projection_record.sha256
        ),
        generic_ml_paired_metric_projection_authority_record_hash=_record_hash(
            sources.projection_record
        ),
        scientific_confirmatory_timeline_receipt_artifact_sha256=(
            sources.timeline_record.sha256
        ),
        scientific_confirmatory_timeline_receipt_record_hash=_record_hash(
            sources.timeline_record
        ),
        source_artifact_sha256s=tuple(item.sha256 for item in direct),
        source_artifact_record_hashes=tuple(_record_hash(item) for item in direct),
        source_ledger_prefix_head_hash=prefix_hash,
    )


def _load_authority_record(
    registry: ArtifactRegistry,
    digest: str,
) -> tuple[ArtifactRecord, ScientificExecutionAdmissibilityAuthority]:
    validate_sha256(digest, "admissibility authority SHA-256")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
    except (ArtifactError, ValidationError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority cannot be reopened"
        ) from exc
    if record.size > _MAX_AUTHORITY_BYTES:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority exceeds its byte bound"
        )
    try:
        raw = registry.get_bytes(digest)
        value = safe_json_loads(raw, max_bytes=_MAX_AUTHORITY_BYTES)
        authority = ScientificExecutionAdmissibilityAuthority.from_mapping(value)
    except (ArtifactError, ValidationError, TypeError, ValueError) as exc:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority content is malformed"
        ) from exc
    if (
        record.logical_type != SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE
        or record.schema_version != _AUTHORITY_RECORD_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin != SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN
        or record.creator_role is not Role.CLAIM_VERIFIER
        or record.creation_command != SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND
        or record.parent_artifacts != authority.source_artifact_sha256s
        or record.validation_result != "PASS"
        or record.frozen is not True
        or record.record_hash is None
        or raw != canonical_json_bytes(authority.to_dict()) + b"\n"
    ):
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority registry metadata is substituted"
        )
    return record, authority


def _matching_authority_records(
    registry: ArtifactRegistry,
    records: Sequence[ArtifactRecord],
    prospective: ScientificExecutionAdmissibilityAuthority,
) -> tuple[tuple[ArtifactRecord, ScientificExecutionAdmissibilityAuthority], ...]:
    matches: list[
        tuple[ArtifactRecord, ScientificExecutionAdmissibilityAuthority]
    ] = []
    for record in records:
        if record.logical_type != SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE:
            continue
        candidate_record, candidate = _load_authority_record(registry, record.sha256)
        same_slot = any(
            (
                candidate.authority_id == prospective.authority_id,
                candidate.execution_run_id == prospective.execution_run_id,
                candidate.scientific_execution_preparation_artifact_sha256
                == prospective.scientific_execution_preparation_artifact_sha256,
                candidate.scientific_execution_authority_artifact_sha256
                == prospective.scientific_execution_authority_artifact_sha256,
                candidate.generic_ml_paired_metric_projection_authority_artifact_sha256
                == prospective.generic_ml_paired_metric_projection_authority_artifact_sha256,
            )
        )
        if same_slot:
            matches.append((candidate_record, candidate))
    if len(matches) > 1:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority slot is ambiguous"
        )
    return tuple(matches)


def _publication_binding(
    record: ArtifactRecord,
    authority: ScientificExecutionAdmissibilityAuthority,
) -> dict[str, Any]:
    return {
        "schema_version": SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA,
        "authority_id": authority.authority_id,
        "ledger_run_id": authority.ledger_run_id,
        "execution_run_id": authority.execution_run_id,
        "authority_artifact_sha256": record.sha256,
        "authority_record_hash": _record_hash(record),
        "contract_artifact_sha256": authority.contract_artifact_sha256,
        "scientific_execution_preparation_artifact_sha256": (
            authority.scientific_execution_preparation_artifact_sha256
        ),
        "scientific_execution_authority_artifact_sha256": (
            authority.scientific_execution_authority_artifact_sha256
        ),
        "generic_ml_paired_metric_projection_authority_artifact_sha256": (
            authority.generic_ml_paired_metric_projection_authority_artifact_sha256
        ),
        "status": authority.status.value,
        "source_ledger_prefix_head_hash": (
            authority.source_ledger_prefix_head_hash
        ),
    }


def _publication_event_id(binding: Mapping[str, Any]) -> str:
    return "execution-admissibility-publication-" + hashlib.sha256(
        canonical_json_bytes(binding)
    ).hexdigest()[:24]


def _publication_matches_slot(
    binding: Any,
    authority: ScientificExecutionAdmissibilityAuthority,
) -> bool:
    if not isinstance(binding, Mapping):
        return False
    return any(
        (
            binding.get("authority_id") == authority.authority_id,
            binding.get("execution_run_id") == authority.execution_run_id,
            binding.get("scientific_execution_preparation_artifact_sha256")
            == authority.scientific_execution_preparation_artifact_sha256,
            binding.get("scientific_execution_authority_artifact_sha256")
            == authority.scientific_execution_authority_artifact_sha256,
            binding.get(
                "generic_ml_paired_metric_projection_authority_artifact_sha256"
            )
            == authority.generic_ml_paired_metric_projection_authority_artifact_sha256,
        )
    )


def _matching_publications(
    events: tuple[LedgerEvent, ...],
    authority: ScientificExecutionAdmissibilityAuthority,
) -> tuple[tuple[int, LedgerEvent, Mapping[str, Any]], ...]:
    matches: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
    for index, event in enumerate(events):
        metadata = thaw_json(event.metadata)
        binding = metadata.get(
            SCIENTIFIC_EXECUTION_ADMISSIBILITY_PUBLICATION_KEY
        )
        if binding is None:
            continue
        if not isinstance(binding, Mapping):
            raise ScientificExecutionAdmissibilityError(
                "admissibility publication metadata is malformed"
            )
        if _publication_matches_slot(binding, authority):
            matches.append((index, event, binding))
    if len(matches) > 1:
        raise ScientificExecutionAdmissibilityError(
            "admissibility publication slot is ambiguous"
        )
    return tuple(matches)


def _validate_publication_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    record: ArtifactRecord,
    authority: ScientificExecutionAdmissibilityAuthority,
    contract: Any,
    spec: Any,
) -> None:
    binding = _publication_binding(record, authority)
    event_time = _utc_timestamp(event.timestamp, "admissibility publication time")
    record_time = _utc_timestamp(record.created_at, "admissibility artifact time")
    expected_metadata = {
        "artifact_types": [record.logical_type],
        "artifact_record_hashes": [_record_hash(record)],
        SCIENTIFIC_EXECUTION_ADMISSIBILITY_PUBLICATION_KEY: binding,
    }
    invalid = (
        event_index <= 0
        or event_index >= len(events)
        or event.event_hash is None
        or event.event_id != _publication_event_id(binding)
        or event.event_type != "CHECKPOINT"
        or event.actor_role is not Role.CLAIM_VERIFIER
        or not isinstance(event.state_before, MacroState)
        or event.state_before != event.requested_state_after
        or event.state_before != events[event_index - 1].requested_state_after
        or event.prior_event_hash != events[event_index - 1].event_hash
        or event_time < record_time
        or not any(
            prior.event_hash == authority.source_ledger_prefix_head_hash
            for prior in events[:event_index]
        )
        or event.artifact_hashes != (record.sha256,)
        or event.code_version != events[event_index - 1].code_version
        or event.configuration_hash != events[event_index - 1].configuration_hash
        or event.dataset_identifiers != (contract.dataset.dataset_id,)
        or event.random_seeds != tuple(spec.seeds)
        or bool(event.evaluator_outputs)
        or event.reason != _PUBLICATION_REASON
        or thaw_json(event.metadata) != expected_metadata
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in events[event_index + 1 :]
        )
    )
    if invalid:
        raise ScientificExecutionAdmissibilityError(
            "admissibility publication event is stale or substituted"
        )


def _build_publication_event(
    snapshot: Any,
    *,
    timestamp: str,
    record: ArtifactRecord,
    authority: ScientificExecutionAdmissibilityAuthority,
    contract: Any,
    spec: Any,
) -> LedgerEvent:
    if not snapshot.valid or not snapshot.events:
        raise ScientificExecutionAdmissibilityError(
            "admissibility publication requires an existing valid ledger"
        )
    prior = snapshot.events[-1]
    state = prior.requested_state_after
    if not isinstance(state, MacroState):
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority cannot publish after terminal state"
        )
    binding = _publication_binding(record, authority)
    return LedgerEvent.create(
        run_id=authority.ledger_run_id,
        event_id=_publication_event_id(binding),
        timestamp=timestamp,
        actor_role=Role.CLAIM_VERIFIER,
        state_before=state,
        requested_state_after=state,
        artifact_hashes=(record.sha256,),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(contract.dataset.dataset_id,),
        random_seeds=tuple(spec.seeds),
        evaluator_outputs=(),
        reason=_PUBLICATION_REASON,
        prior_event_hash=snapshot.head_hash,
        event_type="CHECKPOINT",
        metadata={
            "artifact_types": [record.logical_type],
            "artifact_record_hashes": [_record_hash(record)],
            SCIENTIFIC_EXECUTION_ADMISSIBILITY_PUBLICATION_KEY: binding,
        },
    )


def register_scientific_execution_admissibility_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    scientific_confirmatory_timeline_receipt_artifact_sha256: str,
    scientific_domain_evidence_source_artifact_sha256: str,
    generic_ml_paired_metric_projection_authority_artifact_sha256: str,
) -> ArtifactRecord:
    status, reason, sources = _derive_sources(
        registry,
        ledger,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=(
            evaluation_contract_freeze_receipt_artifact_sha256
        ),
        scientific_execution_authority_artifact_sha256=(
            scientific_execution_authority_artifact_sha256
        ),
        scientific_confirmatory_timeline_receipt_artifact_sha256=(
            scientific_confirmatory_timeline_receipt_artifact_sha256
        ),
        scientific_domain_evidence_source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
        generic_ml_paired_metric_projection_authority_artifact_sha256=(
            generic_ml_paired_metric_projection_authority_artifact_sha256
        ),
    )
    if status in {
        ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
        ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
    } or sources is None:
        raise ScientificExecutionAdmissibilityError(
            f"scientific execution admissibility is unavailable: {reason}"
        )
    authority = _authority_from_sources(sources)
    data = canonical_json_bytes(authority.to_dict()) + b"\n"
    if len(data) > _MAX_AUTHORITY_BYTES:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority exceeds its byte bound"
        )
    prospective_sha256 = hashlib.sha256(data).hexdigest()

    # Every expensive/nested replay and every candidate parse happens before
    # the non-reentrant co-lock.  The locked phase below is a bounded CAS only.
    matches = _matching_authority_records(
        registry,
        sources.registry_snapshot.records,
        authority,
    )
    record: ArtifactRecord | None = None
    if matches:
        record, existing = matches[0]
        if record.sha256 != prospective_sha256 or existing != authority:
            raise ScientificExecutionAdmissibilityError(
                "admissibility execution slot is already occupied"
            )
    digest_collision = next(
        (
            candidate
            for candidate in sources.registry_snapshot.records
            if candidate.sha256 == prospective_sha256
        ),
        None,
    )
    if digest_collision is not None:
        if not registry._semantic_match(
            digest_collision,
            logical_type=SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE,
            schema_version=_AUTHORITY_RECORD_SCHEMA_VERSION,
            mime_type="application/json",
            origin=SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN,
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND,
            parents=authority.source_artifact_sha256s,
            validation_result="PASS",
            frozen=True,
        ):
            raise ScientificExecutionAdmissibilityError(
                "admissibility content digest has competing registry metadata"
            )
        if record is None or record != digest_collision:
            raise ScientificExecutionAdmissibilityError(
                "admissibility digest aliases another publication slot"
            )
    publications = _matching_publications(sources.ledger_snapshot.events, authority)
    if publications:
        if record is None:
            raise ScientificExecutionAdmissibilityError(
                "admissibility publication names an absent authority artifact"
            )
        publication_index, publication_event, stated = publications[0]
        if dict(stated) != _publication_binding(record, authority):
            raise ScientificExecutionAdmissibilityError(
                "admissibility publication slot is competing"
            )
        _validate_publication_event(
            publication_event,
            publication_index,
            sources.ledger_snapshot.events,
            record=record,
            authority=authority,
            contract=sources.contract,
            spec=sources.spec,
        )

    records_needed = int(record is None)
    events_needed = int(not publications)
    if sources.registry_snapshot.count + records_needed > MAX_REGISTRY_RECORDS:
        raise ScientificExecutionAdmissibilityError(
            "admissibility registry capacity is insufficient"
        )
    if sources.ledger_snapshot.event_count + events_needed > MAX_LEDGER_EVENTS:
        raise ScientificExecutionAdmissibilityError(
            "admissibility ledger event capacity is insufficient"
        )
    if (
        events_needed
        and sources.ledger_snapshot.valid_prefix_bytes + _MAX_AUTHORITY_BYTES
        > MAX_LEDGER_BYTES
    ):
        raise ScientificExecutionAdmissibilityError(
            "admissibility ledger byte capacity is insufficient"
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
                not locked_ledger.valid
                or locked_registry != sources.registry_snapshot
                or locked_ledger != sources.ledger_snapshot
            ):
                raise ScientificExecutionAdmissibilityError(
                    "admissibility sources changed before publication"
                )
            publication_timestamp = utc_now()
            if record is None:
                record = registry._put_bytes_locked(
                    registry_guard,
                    data,
                    logical_type=SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE,
                    origin=SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN,
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND,
                    parent_artifacts=authority.source_artifact_sha256s,
                    schema_version=_AUTHORITY_RECORD_SCHEMA_VERSION,
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                    created_at=publication_timestamp,
                )
            if record.sha256 != prospective_sha256:
                raise ScientificExecutionAdmissibilityError(
                    "admissibility artifact changed during publication"
                )
            if publications:
                committed_ledger = locked_ledger
            else:
                def build(current: Any) -> LedgerEvent:
                    if current != locked_ledger:
                        raise ScientificExecutionAdmissibilityError(
                            "admissibility ledger changed before publication"
                        )
                    assert record is not None
                    return _build_publication_event(
                        current,
                        timestamp=publication_timestamp,
                        record=record,
                        authority=authority,
                        contract=sources.contract,
                        spec=sources.spec,
                    )

                prospective_event = build(locked_ledger)
                _validate_publication_event(
                    prospective_event,
                    locked_ledger.event_count,
                    (*locked_ledger.events, prospective_event),
                    record=record,
                    authority=authority,
                    contract=sources.contract,
                    spec=sources.spec,
                )
                encoded_event = canonical_json_bytes(prospective_event.to_dict()) + b"\n"
                if (
                    len(encoded_event) > _MAX_AUTHORITY_BYTES
                    or locked_ledger.valid_prefix_bytes + len(encoded_event)
                    > MAX_LEDGER_BYTES
                ):
                    raise ScientificExecutionAdmissibilityError(
                        "admissibility publication exceeds ledger byte capacity"
                    )
                appended = ledger._append_locked(ledger_guard, build)
                if appended != prospective_event:
                    raise ScientificExecutionAdmissibilityError(
                        "admissibility publication event changed identity"
                    )
                committed_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if not committed_ledger.valid:
                    raise ScientificExecutionAdmissibilityError(
                        "admissibility publication corrupted the ledger"
                    )
                _validate_publication_event(
                    appended,
                    locked_ledger.event_count,
                    committed_ledger.events,
                    record=record,
                    authority=authority,
                    contract=sources.contract,
                    spec=sources.spec,
                )
            final_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            final_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                final_registry.count
                != locked_registry.count + records_needed
                or final_ledger != committed_ledger
                or final_ledger.event_count
                != locked_ledger.event_count + events_needed
            ):
                raise ScientificExecutionAdmissibilityError(
                    "admissibility publication changed outside its exact delta"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)

    return_record = _source_record(registry, record.sha256, "admissibility authority")
    require_scientific_execution_admissibility_authority(
        registry,
        ledger,
        authority_artifact_sha256=return_record.sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        expected_contract_artifact_sha256=sources.contract_record.sha256,
        expected_scientific_execution_authority_artifact_sha256=(
            sources.execution_record.sha256
        ),
    )
    return return_record


def require_scientific_execution_admissibility_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_contract_artifact_sha256: str,
    expected_scientific_execution_authority_artifact_sha256: str,
) -> ScientificExecutionAdmissibilityAuthority:
    _validate_runtime(registry, ledger, expected_ledger_run_id)
    validate_identifier(expected_execution_run_id, "expected execution run ID")
    validate_sha256(
        expected_contract_artifact_sha256,
        "expected evaluation contract artifact SHA-256",
    )
    validate_sha256(
        expected_scientific_execution_authority_artifact_sha256,
        "expected scientific execution authority artifact SHA-256",
    )
    entry_registry, entry_ledger = _locked_snapshot(
        registry, ledger, expected_ledger_run_id
    )
    record, authority = _load_authority_record(
        registry, authority_artifact_sha256
    )
    if (
        authority.ledger_run_id != expected_ledger_run_id
        or authority.execution_run_id != expected_execution_run_id
        or authority.contract_artifact_sha256
        != expected_contract_artifact_sha256
        or authority.scientific_execution_authority_artifact_sha256
        != expected_scientific_execution_authority_artifact_sha256
    ):
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority names another expected closure"
        )
    status, reason, sources = _derive_sources(
        registry,
        ledger,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=(
            authority.evaluation_contract_freeze_receipt_artifact_sha256
        ),
        scientific_execution_authority_artifact_sha256=(
            authority.scientific_execution_authority_artifact_sha256
        ),
        scientific_confirmatory_timeline_receipt_artifact_sha256=(
            authority.scientific_confirmatory_timeline_receipt_artifact_sha256
        ),
        scientific_domain_evidence_source_artifact_sha256=(
            authority.scientific_domain_evidence_source_artifact_sha256
        ),
        generic_ml_paired_metric_projection_authority_artifact_sha256=(
            authority.generic_ml_paired_metric_projection_authority_artifact_sha256
        ),
    )
    if status in {
        ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
        ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_EXTERNAL,
    } or sources is None:
        raise ScientificExecutionAdmissibilityError(
            f"admissibility authority source replay is unavailable: {reason}"
        )
    expected = _authority_from_sources(sources)
    if authority != expected:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority differs from deterministic source replay"
        )
    matches = _matching_authority_records(
        registry,
        entry_registry.records,
        authority,
    )
    if matches != ((record, authority),):
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority execution slot is ambiguous"
        )
    publications = _matching_publications(entry_ledger.events, authority)
    if len(publications) != 1:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority lacks one exact publication"
        )
    event_index, event, binding = publications[0]
    if dict(binding) != _publication_binding(record, authority):
        raise ScientificExecutionAdmissibilityError(
            "admissibility publication differs from its artifact"
        )
    _validate_publication_event(
        event,
        event_index,
        entry_ledger.events,
        record=record,
        authority=authority,
        contract=sources.contract,
        spec=sources.spec,
    )
    final_registry, final_ledger = _locked_snapshot(
        registry, ledger, expected_ledger_run_id
    )
    if final_registry != entry_registry or final_ledger != entry_ledger:
        raise ScientificExecutionAdmissibilityError(
            "admissibility authority sources changed during replay"
        )
    return authority


__all__ = [
    "CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V3",
    "DecisionStoppingRule",
    "EVALUATION_CONTRACT_ARTIFACT_SCHEMA_V3",
    "EvaluatorRule",
    "FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA",
    "RELEASE_READINESS_STOPPING_DISPLAY",
    "RESULT_ADMISSIBILITY_STOPPING_DISPLAY",
    "ReleaseStoppingRule",
    "SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA",
    "SCIENTIFIC_EXECUTION_ADMISSIBILITY_PUBLICATION_KEY",
    "SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCHEMA",
    "SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE",
    "ScientificDecisionStoppingStatus",
    "ScientificEvaluatorIntegrityStatus",
    "ScientificExecutionAdmissibilityAuthority",
    "ScientificExecutionAdmissibilityError",
    "ScientificExecutionAdmissibilityPolicy",
    "ScientificExecutionAdmissibilityProfile",
    "ScientificExecutionAdmissibilityResolution",
    "ScientificExecutionAdmissibilityResolutionStatus",
    "ScientificExecutionAdmissibilityStatus",
    "register_scientific_execution_admissibility_authority",
    "require_scientific_execution_admissibility_authority",
    "resolve_scientific_execution_admissibility",
]
