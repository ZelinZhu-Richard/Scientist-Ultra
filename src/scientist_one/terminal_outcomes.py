"""Typed, append-only Research OS terminal outcomes.

This vocabulary is deliberately separate from the trusted kernel's legacy
``TerminalState`` enum.  A Research OS outcome record is an immutable
scientific/operational fact; materializing one never drives the legacy macro
state machine.  Existing typed statuses are translated by deterministic
diagnostic adapters.  They cannot authorize materialization without a fresh,
registry-resolved source binding.  Passing or otherwise nonterminal statuses
map to ``None`` rather than inventing a success terminal outcome.

The raw record is persisted in the existing ``ArtifactRegistry`` with its
evidence artifacts as parents.  A canonical ``Decision`` then binds that raw
record into ``ResearchStateRepository`` and its ``EventLedger``.  This keeps
the registry and ledger as the only authorities and avoids a parallel state
system.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
import hashlib
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .artifacts import ArtifactRecord, ArtifactRegistry
from .compute_terminal import (
    COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
    GPU_PROTOCOL_REQUIRED_STATUS,
    WALL_BUDGET_EXHAUSTED_STATUS,
    ComputeTerminalError,
    require_compute_terminal_assessment,
)
from .discovery import BranchStatus
from .errors import ArtifactError, UnsafeSerializationError, ValidationError
from .experiments import (
    ComputeMode,
    ComputeProfile as ExecutionComputeProfile,
    ReproductionStatus as ExperimentReproductionStatus,
    ValidationStatus as ComputeValidationStatus,
)
from .gates import (
    DimensionStatus,
    SOUNDNESS_ASSESSMENT_SCHEMA_VERSION,
    SoundnessAssessment,
    SoundnessDimension,
    SoundnessVerdict,
    _resolve_claim_graph_authority,
    register_scientific_soundness_assessment,
    require_scientific_soundness_assessment,
)
from .models import TerminalState, utc_now, validate_identifier, validate_sha256
from .paper_pipeline import (
    HardBlocker,
    PaperVerification,
    require_paper_verification,
)
from .research_state import (
    MAX_CANONICAL_OBJECT_BYTES,
    RESEARCH_STATE_SCHEMA_VERSION,
    CanonicalResearchObject,
    Decision,
    HypothesisStatus as CanonicalHypothesisStatus,
    MaterializedResearchObject,
    RecordStatus,
    ReproductionStatus as CanonicalReproductionStatus,
    ResearchStateRepository,
)
from .reproduction import (
    SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
    ReproductionError,
    ScientificCleanRerunAuthority,
    ScientificCleanRerunOutcome,
    require_scientific_clean_rerun_authority,
)
from .roles import Role
from .scientific_design import (
    HypothesisStatus as DesignHypothesisStatus,
    RESEARCH_QUESTION_GATE_ASSESSMENT_LOGICAL_TYPE,
    ResearchGateOutcome,
    SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
    ScientificGateVerificationStatus,
    ScientificPromotionError,
    ScientificResultPromotionReceiptV3,
    ScientificResultOutcome,
    require_research_question_gate_assessment,
    require_scientific_result_promotion_authority_v3,
)
from .security import canonical_json_bytes, safe_json_loads


LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION = "2.0"
TERMINAL_OUTCOME_SCHEMA_VERSION = "3.0"
LEGACY_TERMINAL_OUTCOME_MAPPING_ID = "research-os-terminal-outcome-map/v1"
TERMINAL_OUTCOME_MAPPING_ID = "research-os-terminal-outcome-map/v2"
PAPER_PUBLICATION_TERMINAL_MAPPING_ID = "research-os-paper-publication-eligibility/v1"
TERMINAL_OUTCOME_LOGICAL_TYPE = "research_terminal_outcome"
TERMINAL_DECISION_TYPE = "RESEARCH_TERMINAL_OUTCOME"
# Compatibility names for callers that previously consumed a terminal-only
# wrapper. The authoritative source is now the gate owner's canonical,
# freshly replayable assessment artifact rather than a second receipt schema.
TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE = "scientific_soundness_assessment"
TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION = SOUNDNESS_ASSESSMENT_SCHEMA_VERSION
TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE = "paper_verification"
MAX_REASON_BYTES = 32 * 1024
MAX_EVIDENCE_ARTIFACTS = 256

_SUPPORTED_TERMINAL_OUTCOME_SCHEMA_VERSIONS = frozenset(
    {LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION, TERMINAL_OUTCOME_SCHEMA_VERSION}
)
_SUPPORTED_TERMINAL_OUTCOME_MAPPING_IDS = frozenset(
    {
        LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
        TERMINAL_OUTCOME_MAPPING_ID,
        PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
    }
)
_CURRENT_FORMAT_TERMINAL_MAPPING_IDS = frozenset(
    {TERMINAL_OUTCOME_MAPPING_ID, PAPER_PUBLICATION_TERMINAL_MAPPING_ID}
)


class ResearchTerminalOutcome(StrEnum):
    """Truthful terminal outcomes, including the meta-spec's required vocabulary."""

    NOT_PUBLISHABLE = "NOT_PUBLISHABLE"
    INSUFFICIENT_NOVELTY = "INSUFFICIENT_NOVELTY"
    INCONCLUSIVE = "INCONCLUSIVE"
    HYPOTHESIS_FALSIFIED = "HYPOTHESIS_FALSIFIED"
    NEGATIVE_RESULT = "NEGATIVE_RESULT"
    NO_MEANINGFUL_GAIN = "NO_MEANINGFUL_GAIN"
    RESULT_NOT_ROBUST = "RESULT_NOT_ROBUST"
    REPRODUCIBILITY_FAILED = "REPRODUCIBILITY_FAILED"
    INSUFFICIENT_COMPUTE = "INSUFFICIENT_COMPUTE"
    FULL_VALIDATION_REQUIRES_GPU_CLOUD = "FULL_VALIDATION_REQUIRES_GPU_CLOUD"
    MORE_EXPERIMENTS_REQUIRED = "MORE_EXPERIMENTS_REQUIRED"


class TerminalAuthorityScope(StrEnum):
    """What an exact source owner authorizes the terminal record to claim."""

    SCIENTIFIC_EVIDENCE = "SCIENTIFIC_EVIDENCE"
    NON_EVIDENTIARY_MECHANICAL = "NON_EVIDENTIARY_MECHANICAL"
    OPERATIONAL_BLOCKER = "OPERATIONAL_BLOCKER"


class TerminalPhase(StrEnum):
    RESEARCH_QUESTION_GATE = "RESEARCH_QUESTION_GATE"
    HYPOTHESIS_EVALUATION = "HYPOTHESIS_EVALUATION"
    DISCOVERY = "DISCOVERY"
    REPRODUCTION = "REPRODUCTION"
    COMPUTE = "COMPUTE"
    ROBUSTNESS = "ROBUSTNESS"
    SCIENTIFIC_SOUNDNESS = "SCIENTIFIC_SOUNDNESS"
    PAPER_READINESS = "PAPER_READINESS"
    LEGACY_FINALIZATION = "LEGACY_FINALIZATION"


class TerminalSourceKind(StrEnum):
    RESEARCH_GATE = "RESEARCH_GATE"
    HYPOTHESIS_REGISTER = "HYPOTHESIS_REGISTER"
    SCIENTIFIC_RESULT = "SCIENTIFIC_RESULT"
    DISCOVERY_BRANCH = "DISCOVERY_BRANCH"
    EXPERIMENT_REPRODUCTION = "EXPERIMENT_REPRODUCTION"
    CANONICAL_REPRODUCTION = "CANONICAL_REPRODUCTION"
    COMPUTE_STATUS = "COMPUTE_STATUS"
    SOUNDNESS_GATE = "SOUNDNESS_GATE"
    PAPER_VERIFICATION = "PAPER_VERIFICATION"
    LEGACY_TERMINAL_ADAPTER = "LEGACY_TERMINAL_ADAPTER"


def _bounded_reason(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > MAX_REASON_BYTES
    ):
        raise ValidationError("terminal outcome reason must be non-empty bounded text")
    return value


def _utc_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError("terminal outcome timestamp must be UTC ISO-8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("terminal outcome timestamp is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValidationError("terminal outcome timestamp must be UTC")
    return value


def _status_tuple(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValidationError("terminal source statuses must be a tuple")
    try:
        statuses = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValidationError("terminal source statuses must be a tuple") from exc
    if not statuses or len(statuses) > 64:
        raise ValidationError("terminal source statuses have invalid cardinality")
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > 256
        or "\x00" in item
        for item in statuses
    ):
        raise ValidationError("terminal source status is malformed")
    if len(set(statuses)) != len(statuses):
        raise ValidationError("terminal source statuses must be unique")
    return statuses


@dataclass(frozen=True, slots=True)
class _ExpectedDerivation:
    phase: TerminalPhase
    outcome: ResearchTerminalOutcome


_CURRENT_SIMPLE_RULES: Mapping[
    tuple[TerminalSourceKind, tuple[str, ...]], _ExpectedDerivation
] = MappingProxyType({
    (
        TerminalSourceKind.RESEARCH_GATE,
        (ResearchGateOutcome.INSUFFICIENT_NOVELTY.value,),
    ): _ExpectedDerivation(
        TerminalPhase.RESEARCH_QUESTION_GATE,
        ResearchTerminalOutcome.INSUFFICIENT_NOVELTY,
    ),
    (
        TerminalSourceKind.RESEARCH_GATE,
        (ResearchGateOutcome.INFEASIBLE_WITH_CURRENT_RESOURCES.value,),
    ): _ExpectedDerivation(
        TerminalPhase.COMPUTE,
        ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
    ),
    (
        TerminalSourceKind.RESEARCH_GATE,
        (ResearchGateOutcome.TERMINATE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.RESEARCH_QUESTION_GATE,
        ResearchTerminalOutcome.NOT_PUBLISHABLE,
    ),
    (
        TerminalSourceKind.HYPOTHESIS_REGISTER,
        (DesignHypothesisStatus.FALSIFIED.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.HYPOTHESIS_FALSIFIED,
    ),
    (
        TerminalSourceKind.HYPOTHESIS_REGISTER,
        (DesignHypothesisStatus.INCONCLUSIVE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.INCONCLUSIVE,
    ),
    (
        TerminalSourceKind.HYPOTHESIS_REGISTER,
        (DesignHypothesisStatus.NOT_SUPPORTED.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.INCONCLUSIVE,
    ),
    (
        TerminalSourceKind.SCIENTIFIC_RESULT,
        (ScientificResultOutcome.NEGATIVE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.NEGATIVE_RESULT,
    ),
    (
        TerminalSourceKind.SCIENTIFIC_RESULT,
        (ScientificResultOutcome.NULL.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
    ),
    (
        TerminalSourceKind.SCIENTIFIC_RESULT,
        (ScientificResultOutcome.INCONCLUSIVE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.INCONCLUSIVE,
    ),
    (
        TerminalSourceKind.SCIENTIFIC_RESULT,
        (ScientificResultOutcome.FALSIFIED.value,),
    ): _ExpectedDerivation(
        TerminalPhase.HYPOTHESIS_EVALUATION,
        ResearchTerminalOutcome.HYPOTHESIS_FALSIFIED,
    ),
    (
        TerminalSourceKind.DISCOVERY_BRANCH,
        (BranchStatus.NEGATIVE_RESULT.value,),
    ): _ExpectedDerivation(
        TerminalPhase.DISCOVERY,
        ResearchTerminalOutcome.NEGATIVE_RESULT,
    ),
    (
        TerminalSourceKind.DISCOVERY_BRANCH,
        (BranchStatus.NULL_RESULT.value,),
    ): _ExpectedDerivation(
        TerminalPhase.DISCOVERY,
        ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
    ),
    (
        TerminalSourceKind.EXPERIMENT_REPRODUCTION,
        (ExperimentReproductionStatus.OUTSIDE_TOLERANCE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
    ),
    (
        TerminalSourceKind.EXPERIMENT_REPRODUCTION,
        (ExperimentReproductionStatus.IDENTITY_MISMATCH.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
    ),
    (
        TerminalSourceKind.EXPERIMENT_REPRODUCTION,
        (ExperimentReproductionStatus.NON_EVIDENTIARY.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
    ),
    (
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (CanonicalReproductionStatus.FAIL.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
    ),
    (
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (CanonicalReproductionStatus.OUTSIDE_TOLERANCE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
    ),
    (
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (CanonicalReproductionStatus.NOT_RUN.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
    ),
    (
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (CanonicalReproductionStatus.BLOCKED_EXTERNAL.value,),
    ): _ExpectedDerivation(
        TerminalPhase.REPRODUCTION,
        ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
    ),
    (
        TerminalSourceKind.COMPUTE_STATUS,
        (ComputeMode.GPU_CLOUD.value, ComputeValidationStatus.UNTESTED.value),
    ): _ExpectedDerivation(
        TerminalPhase.COMPUTE,
        ResearchTerminalOutcome.FULL_VALIDATION_REQUIRES_GPU_CLOUD,
    ),
    (
        TerminalSourceKind.COMPUTE_STATUS,
        (WALL_BUDGET_EXHAUSTED_STATUS,),
    ): _ExpectedDerivation(
        TerminalPhase.COMPUTE,
        ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
    ),
    (
        TerminalSourceKind.COMPUTE_STATUS,
        (GPU_PROTOCOL_REQUIRED_STATUS,),
    ): _ExpectedDerivation(
        TerminalPhase.COMPUTE,
        ResearchTerminalOutcome.FULL_VALIDATION_REQUIRES_GPU_CLOUD,
    ),
    (
        TerminalSourceKind.LEGACY_TERMINAL_ADAPTER,
        (TerminalState.NEGATIVE_RESULT.value,),
    ): _ExpectedDerivation(
        TerminalPhase.LEGACY_FINALIZATION,
        ResearchTerminalOutcome.NEGATIVE_RESULT,
    ),
    (
        TerminalSourceKind.LEGACY_TERMINAL_ADAPTER,
        (TerminalState.INCONCLUSIVE.value,),
    ): _ExpectedDerivation(
        TerminalPhase.LEGACY_FINALIZATION,
        ResearchTerminalOutcome.INCONCLUSIVE,
    ),
    (
        TerminalSourceKind.LEGACY_TERMINAL_ADAPTER,
        (TerminalState.STOP_BUDGET.value,),
    ): _ExpectedDerivation(
        TerminalPhase.LEGACY_FINALIZATION,
        ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
    ),
    (
        TerminalSourceKind.LEGACY_TERMINAL_ADAPTER,
        (TerminalState.STOP_SCIENTIFIC_INVALIDITY.value,),
    ): _ExpectedDerivation(
        TerminalPhase.LEGACY_FINALIZATION,
        ResearchTerminalOutcome.NOT_PUBLISHABLE,
    ),
})

_LEGACY_SIMPLE_RULES: Mapping[
    tuple[TerminalSourceKind, tuple[str, ...]], _ExpectedDerivation
] = MappingProxyType(
    {
        **{
            key: value
            for key, value in _CURRENT_SIMPLE_RULES.items()
            if key[0] is not TerminalSourceKind.SCIENTIFIC_RESULT
            and key
            != (
                TerminalSourceKind.COMPUTE_STATUS,
                (WALL_BUDGET_EXHAUSTED_STATUS,),
            )
            and key
            != (
                TerminalSourceKind.COMPUTE_STATUS,
                (GPU_PROTOCOL_REQUIRED_STATUS,),
            )
        },
        (
            TerminalSourceKind.HYPOTHESIS_REGISTER,
            (DesignHypothesisStatus.NOT_SUPPORTED.value,),
        ): _ExpectedDerivation(
            TerminalPhase.HYPOTHESIS_EVALUATION,
            ResearchTerminalOutcome.NO_MEANINGFUL_GAIN,
        ),
    }
)

_SIMPLE_RULES_BY_MAPPING: Mapping[
    str,
    Mapping[tuple[TerminalSourceKind, tuple[str, ...]], _ExpectedDerivation],
] = MappingProxyType(
    {
        LEGACY_TERMINAL_OUTCOME_MAPPING_ID: _LEGACY_SIMPLE_RULES,
        TERMINAL_OUTCOME_MAPPING_ID: _CURRENT_SIMPLE_RULES,
        PAPER_PUBLICATION_TERMINAL_MAPPING_ID: MappingProxyType({}),
    }
)


def _expected_derivation(
    source_kind: TerminalSourceKind,
    source_statuses: tuple[str, ...],
    *,
    mapping_id: str,
) -> _ExpectedDerivation:
    if (
        mapping_id == PAPER_PUBLICATION_TERMINAL_MAPPING_ID
        and source_kind is not TerminalSourceKind.PAPER_VERIFICATION
    ):
        raise ValidationError("paper publication mapping requires paper verification")
    try:
        simple_rules = _SIMPLE_RULES_BY_MAPPING[mapping_id]
    except KeyError as exc:
        raise ValidationError("unknown terminal outcome mapping policy") from exc
    simple = simple_rules.get((source_kind, source_statuses))
    if simple is not None:
        return simple
    if source_kind is TerminalSourceKind.SOUNDNESS_GATE:
        if len(source_statuses) != 2:
            raise ValidationError("soundness derivation requires verdict and robustness status")
        verdict_label, robustness_label = source_statuses
        if not verdict_label.startswith("VERDICT:") or not robustness_label.startswith(
            "ROBUSTNESS:"
        ):
            raise ValidationError("soundness source statuses are malformed")
        try:
            verdict = SoundnessVerdict(verdict_label.removeprefix("VERDICT:"))
            robustness = DimensionStatus(
                robustness_label.removeprefix("ROBUSTNESS:")
            )
        except ValueError as exc:
            raise ValidationError("soundness source status is unknown") from exc
        if robustness is DimensionStatus.FAIL:
            return _ExpectedDerivation(
                TerminalPhase.ROBUSTNESS,
                ResearchTerminalOutcome.RESULT_NOT_ROBUST,
            )
        if verdict in {
            SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
            SoundnessVerdict.MAJOR_REVISION,
        }:
            return _ExpectedDerivation(
                TerminalPhase.SCIENTIFIC_SOUNDNESS,
                ResearchTerminalOutcome.MORE_EXPERIMENTS_REQUIRED,
            )
        if verdict is SoundnessVerdict.REJECT_RESEARCH_DIRECTION:
            return _ExpectedDerivation(
                TerminalPhase.SCIENTIFIC_SOUNDNESS,
                ResearchTerminalOutcome.NOT_PUBLISHABLE,
            )
        raise ValidationError("soundness status is not terminal")
    if source_kind is TerminalSourceKind.PAPER_VERIFICATION:
        if not source_statuses or source_statuses[0] != "FAILED":
            raise ValidationError("paper source status is not terminal")
        try:
            blockers = tuple(HardBlocker(item) for item in source_statuses[1:])
        except ValueError as exc:
            raise ValidationError("paper blocker status is unknown") from exc
        if len(set(blockers)) != len(blockers):
            raise ValidationError("paper blocker statuses must be unique")
        if blockers != tuple(item for item in HardBlocker if item in blockers):
            raise ValidationError("paper blocker statuses are not in canonical order")
        if mapping_id == PAPER_PUBLICATION_TERMINAL_MAPPING_ID:
            # Preserve every observed blocker, but do not mistake inability to
            # publish for source-owned novelty or reproduction conclusions.
            return _ExpectedDerivation(
                TerminalPhase.PAPER_READINESS,
                ResearchTerminalOutcome.NOT_PUBLISHABLE,
            )
        if HardBlocker.FAILED_CLEAN_REPRODUCTION in blockers:
            return _ExpectedDerivation(
                TerminalPhase.REPRODUCTION,
                ResearchTerminalOutcome.REPRODUCIBILITY_FAILED,
            )
        if HardBlocker.UNSUPPORTED_NOVELTY in blockers:
            return _ExpectedDerivation(
                TerminalPhase.PAPER_READINESS,
                ResearchTerminalOutcome.INSUFFICIENT_NOVELTY,
            )
        return _ExpectedDerivation(
            TerminalPhase.PAPER_READINESS,
            ResearchTerminalOutcome.NOT_PUBLISHABLE,
        )
    raise ValidationError("source status does not map to a terminal outcome")


@dataclass(frozen=True, slots=True)
class TerminalSourceBinding:
    """Registry/ledger-resolved source identity for an authoritative derivation."""

    source_kind: TerminalSourceKind
    source_artifact_sha256: str
    source_record_hash: str | None
    source_logical_type: str
    source_creator_role: Role
    source_run_id: str
    source_object_id: str
    source_claim_ids: tuple[str, ...]
    source_statuses: tuple[str, ...]
    source_parent_artifact_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            source_kind = TerminalSourceKind(self.source_kind)
        except (TypeError, ValueError) as exc:
            raise ValidationError("terminal source binding kind is invalid") from exc
        validate_sha256(
            self.source_artifact_sha256,
            "terminal source artifact SHA-256",
        )
        if self.source_record_hash is not None:
            validate_sha256(
                self.source_record_hash,
                "terminal source metadata record SHA-256",
            )
        if (
            not isinstance(self.source_logical_type, str)
            or not self.source_logical_type.strip()
            or len(self.source_logical_type) > 256
            or "\x00" in self.source_logical_type
        ):
            raise ValidationError("terminal source logical type is invalid")
        if not isinstance(self.source_creator_role, Role):
            raise ValidationError("terminal source creator role must be typed")
        if self.source_creator_role is Role.HUMAN_RELEASE:
            raise ValidationError("terminal sources cannot synthesize human release authority")
        validate_identifier(self.source_run_id, "terminal source run ID")
        validate_identifier(self.source_object_id, "terminal source object ID")
        if isinstance(self.source_claim_ids, (str, bytes)):
            raise ValidationError("terminal source claim IDs must be a tuple")
        claims = tuple(self.source_claim_ids)
        if len(claims) > 256 or len(set(claims)) != len(claims):
            raise ValidationError("terminal source claim IDs must be bounded and unique")
        for claim_id in claims:
            validate_identifier(claim_id, "terminal source claim ID")
        statuses = _status_tuple(self.source_statuses)
        if isinstance(self.source_parent_artifact_hashes, (str, bytes)):
            raise ValidationError("terminal source parents must be an ordered tuple")
        parents = tuple(self.source_parent_artifact_hashes)
        if len(parents) > MAX_EVIDENCE_ARTIFACTS or len(set(parents)) != len(parents):
            raise ValidationError("terminal source parents must be bounded and unique")
        for digest in parents:
            validate_sha256(digest, "terminal source parent SHA-256")
        if self.source_artifact_sha256 in parents:
            raise ValidationError("terminal source cannot parent itself")
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(self, "source_claim_ids", claims)
        object.__setattr__(self, "source_statuses", statuses)
        object.__setattr__(self, "source_parent_artifact_hashes", parents)

    @property
    def required_evidence_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    self.source_artifact_sha256,
                    *self.source_parent_artifact_hashes,
                )
            )
        )

    def to_dict(self, *, include_source_record_hash: bool = True) -> dict[str, Any]:
        result = {
            "source_kind": self.source_kind.value,
            "source_artifact_sha256": self.source_artifact_sha256,
            "source_logical_type": self.source_logical_type,
            "source_creator_role": self.source_creator_role.value,
            "source_run_id": self.source_run_id,
            "source_object_id": self.source_object_id,
            "source_claim_ids": list(self.source_claim_ids),
            "source_statuses": list(self.source_statuses),
            "source_parent_artifact_hashes": list(
                self.source_parent_artifact_hashes
            ),
        }
        if include_source_record_hash:
            result["source_record_hash"] = self.source_record_hash
        return result

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        require_source_record_hash: bool,
    ) -> "TerminalSourceBinding":
        legacy_required = {
            "source_kind",
            "source_artifact_sha256",
            "source_logical_type",
            "source_creator_role",
            "source_run_id",
            "source_object_id",
            "source_claim_ids",
            "source_statuses",
            "source_parent_artifact_hashes",
        }
        required = (
            legacy_required | {"source_record_hash"}
            if require_source_record_hash
            else legacy_required
        )
        if not isinstance(value, Mapping) or set(value) != required:
            raise ValidationError("terminal source binding schema is incomplete or unknown")
        try:
            return cls(
                source_kind=TerminalSourceKind(value["source_kind"]),
                source_artifact_sha256=value["source_artifact_sha256"],
                source_record_hash=(
                    value["source_record_hash"]
                    if require_source_record_hash
                    else None
                ),
                source_logical_type=value["source_logical_type"],
                source_creator_role=Role(value["source_creator_role"]),
                source_run_id=value["source_run_id"],
                source_object_id=value["source_object_id"],
                source_claim_ids=tuple(value["source_claim_ids"]),
                source_statuses=tuple(value["source_statuses"]),
                source_parent_artifact_hashes=tuple(
                    value["source_parent_artifact_hashes"]
                ),
            )
        except ValidationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("malformed terminal source binding") from exc


@dataclass(frozen=True, slots=True)
class TerminalOutcomeDerivation:
    """Auditable mapping; authoritative only with a resolved source binding."""

    source_kind: TerminalSourceKind
    source_statuses: tuple[str, ...]
    phase: TerminalPhase
    outcome: ResearchTerminalOutcome
    mapping_id: str = TERMINAL_OUTCOME_MAPPING_ID
    source_binding: TerminalSourceBinding | None = None
    authority_scope: TerminalAuthorityScope | None = None

    def __post_init__(self) -> None:
        try:
            source_kind = TerminalSourceKind(self.source_kind)
            phase = TerminalPhase(self.phase)
            outcome = ResearchTerminalOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise ValidationError("terminal outcome derivation enum is invalid") from exc
        statuses = _status_tuple(self.source_statuses)
        if self.mapping_id not in _SUPPORTED_TERMINAL_OUTCOME_MAPPING_IDS:
            raise ValidationError("unknown terminal outcome mapping policy")
        authority_scope = self.authority_scope
        if authority_scope is not None:
            try:
                authority_scope = TerminalAuthorityScope(authority_scope)
            except (TypeError, ValueError) as exc:
                raise ValidationError("terminal authority scope is invalid") from exc
        if self.mapping_id == LEGACY_TERMINAL_OUTCOME_MAPPING_ID:
            if authority_scope is not None:
                raise ValidationError(
                    "legacy terminal derivations cannot carry an authority scope"
                )
            if (
                self.source_binding is not None
                and self.source_binding.source_record_hash is not None
            ):
                raise ValidationError(
                    "legacy terminal derivations cannot carry a source record hash"
                )
        elif self.source_binding is not None and authority_scope is None:
            raise ValidationError(
                "authoritative terminal derivations require a source-derived scope"
            )
        elif (
            self.source_binding is not None
            and self.source_binding.source_record_hash is None
        ):
            raise ValidationError(
                "authoritative terminal derivations require the source metadata record hash"
            )
        elif self.source_binding is None and authority_scope is not None:
            raise ValidationError(
                "diagnostic terminal derivations cannot claim an authority scope"
            )
        if (
            self.mapping_id == PAPER_PUBLICATION_TERMINAL_MAPPING_ID
            and self.source_binding is not None
            and authority_scope is not TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL
        ):
            raise ValidationError("paper publication authority is mechanical only")
        expected = _expected_derivation(
            source_kind,
            statuses,
            mapping_id=self.mapping_id,
        )
        if phase is not expected.phase or outcome is not expected.outcome:
            raise ValidationError("terminal outcome contradicts its typed source status")
        if self.source_binding is not None:
            if not isinstance(self.source_binding, TerminalSourceBinding):
                raise ValidationError("terminal source binding must be typed")
            if (
                self.source_binding.source_kind is not source_kind
                or self.source_binding.source_statuses != statuses
            ):
                raise ValidationError(
                    "terminal source binding contradicts the mapped source status"
                )
        object.__setattr__(self, "source_kind", source_kind)
        object.__setattr__(self, "source_statuses", statuses)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "authority_scope", authority_scope)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "mapping_id": self.mapping_id,
            "source_kind": self.source_kind.value,
            "source_statuses": list(self.source_statuses),
            "phase": self.phase.value,
            "outcome": self.outcome.value,
            "source_binding": (
                self.source_binding.to_dict(
                    include_source_record_hash=(
                        self.mapping_id in _CURRENT_FORMAT_TERMINAL_MAPPING_IDS
                    )
                )
                if self.source_binding is not None
                else None
            ),
        }
        if self.mapping_id in _CURRENT_FORMAT_TERMINAL_MAPPING_IDS:
            result["authority_scope"] = (
                self.authority_scope.value
                if self.authority_scope is not None
                else None
            )
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TerminalOutcomeDerivation":
        legacy_required = {
            "mapping_id",
            "source_kind",
            "source_statuses",
            "phase",
            "outcome",
            "source_binding",
        }
        pre_binding_legacy = legacy_required - {"source_binding"}
        current_required = legacy_required | {"authority_scope"}
        if not isinstance(value, Mapping):
            raise ValidationError("terminal derivation schema is incomplete or unknown")
        mapping_id = value.get("mapping_id")
        allowed_shapes = (
            (legacy_required, pre_binding_legacy)
            if mapping_id == LEGACY_TERMINAL_OUTCOME_MAPPING_ID
            else (current_required,)
        )
        if not any(set(value) == shape for shape in allowed_shapes):
            raise ValidationError("terminal derivation schema is incomplete or unknown")
        try:
            source_value = value.get("source_binding")
            scope_value = value.get("authority_scope")
            return cls(
                mapping_id=value["mapping_id"],
                source_kind=TerminalSourceKind(value["source_kind"]),
                source_statuses=tuple(value["source_statuses"]),
                phase=TerminalPhase(value["phase"]),
                outcome=ResearchTerminalOutcome(value["outcome"]),
                source_binding=(
                    TerminalSourceBinding.from_dict(
                        source_value,
                        require_source_record_hash=(
                            mapping_id in _CURRENT_FORMAT_TERMINAL_MAPPING_IDS
                        ),
                    )
                    if source_value is not None
                    else None
                ),
                authority_scope=(
                    TerminalAuthorityScope(scope_value)
                    if scope_value is not None
                    else None
                ),
            )
        except ValidationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("malformed terminal outcome derivation") from exc


def _derivation(
    source_kind: TerminalSourceKind,
    source_statuses: tuple[str, ...],
    *,
    source_binding: TerminalSourceBinding | None = None,
    authority_scope: TerminalAuthorityScope | None = None,
    mapping_id: str = TERMINAL_OUTCOME_MAPPING_ID,
) -> TerminalOutcomeDerivation:
    expected = _expected_derivation(
        source_kind,
        source_statuses,
        mapping_id=mapping_id,
    )
    return TerminalOutcomeDerivation(
        source_kind=source_kind,
        source_statuses=source_statuses,
        phase=expected.phase,
        outcome=expected.outcome,
        mapping_id=mapping_id,
        source_binding=source_binding,
        authority_scope=authority_scope,
    )


def derive_from_research_gate(
    status: ResearchGateOutcome,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(status, ResearchGateOutcome):
        raise ValidationError("research gate status must be typed")
    if status in {
        ResearchGateOutcome.PROCEED,
        ResearchGateOutcome.REFORMULATE,
        ResearchGateOutcome.MORE_LITERATURE_REQUIRED,
    }:
        return None
    return _derivation(TerminalSourceKind.RESEARCH_GATE, (status.value,))


def derive_from_hypothesis_status(
    status: DesignHypothesisStatus | CanonicalHypothesisStatus,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(status, (DesignHypothesisStatus, CanonicalHypothesisStatus)):
        raise ValidationError("hypothesis status must be typed")
    if status.value in {
        DesignHypothesisStatus.UNTESTED.value,
        DesignHypothesisStatus.SUPPORTED.value,
        DesignHypothesisStatus.PARTIALLY_SUPPORTED.value,
        CanonicalHypothesisStatus.POST_HOC.value,
    }:
        return None
    return _derivation(
        TerminalSourceKind.HYPOTHESIS_REGISTER,
        (status.value,),
    )


def derive_from_scientific_result_outcome(
    outcome: ScientificResultOutcome,
) -> TerminalOutcomeDerivation | None:
    """Map only source-derived outcome-neutral result semantics."""

    if not isinstance(outcome, ScientificResultOutcome):
        raise ValidationError("scientific result outcome must be typed")
    if outcome in {
        ScientificResultOutcome.POSITIVE,
        ScientificResultOutcome.TECHNICAL_FAILURE,
    }:
        return None
    return _derivation(
        TerminalSourceKind.SCIENTIFIC_RESULT,
        (outcome.value,),
    )


def derive_from_discovery_branch(
    status: BranchStatus,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(status, BranchStatus):
        raise ValidationError("discovery branch status must be typed")
    if status not in {BranchStatus.NEGATIVE_RESULT, BranchStatus.NULL_RESULT}:
        return None
    return _derivation(TerminalSourceKind.DISCOVERY_BRANCH, (status.value,))


def derive_from_experiment_reproduction(
    status: ExperimentReproductionStatus,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(status, ExperimentReproductionStatus):
        raise ValidationError("experiment reproduction status must be typed")
    if status is ExperimentReproductionStatus.PASS:
        return None
    return _derivation(
        TerminalSourceKind.EXPERIMENT_REPRODUCTION,
        (status.value,),
    )


def derive_from_canonical_reproduction(
    status: CanonicalReproductionStatus,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(status, CanonicalReproductionStatus):
        raise ValidationError("canonical reproduction status must be typed")
    if status is CanonicalReproductionStatus.PASS:
        return None
    return _derivation(
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (status.value,),
    )


def derive_from_compute_status(
    mode: ComputeMode,
    validation_status: ComputeValidationStatus,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(mode, ComputeMode) or not isinstance(
        validation_status, ComputeValidationStatus
    ):
        raise ValidationError("compute mode and validation status must be typed")
    if (
        mode is ComputeMode.LOCAL_MAC
        and validation_status is ComputeValidationStatus.VALIDATED_LOCAL
    ):
        return None
    if (
        mode is ComputeMode.GPU_CLOUD
        and validation_status is ComputeValidationStatus.UNTESTED
    ):
        return _derivation(
            TerminalSourceKind.COMPUTE_STATUS,
            (mode.value, validation_status.value),
        )
    raise ValidationError("compute mode and validation status are inconsistent")


def derive_from_compute_profile(
    profile: ExecutionComputeProfile,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(profile, ExecutionComputeProfile):
        raise ValidationError("compute profile must be typed")
    return derive_from_compute_status(profile.mode, profile.validation_status)


def derive_from_soundness(
    assessment: SoundnessAssessment,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(assessment, SoundnessAssessment):
        raise ValidationError("soundness assessment must be typed")
    robustness = dict(assessment.dimensions)[SoundnessDimension.ROBUSTNESS]
    if (
        robustness is not DimensionStatus.FAIL
        and assessment.verdict
        in {SoundnessVerdict.PASS, SoundnessVerdict.CONDITIONAL_PASS}
    ):
        return None
    return _derivation(
        TerminalSourceKind.SOUNDNESS_GATE,
        (
            f"VERDICT:{assessment.verdict.value}",
            f"ROBUSTNESS:{robustness.value}",
        ),
    )


def derive_from_paper_verification(
    verification: PaperVerification,
) -> TerminalOutcomeDerivation | None:
    if not isinstance(verification, PaperVerification):
        raise ValidationError("paper verification must be typed")
    if verification.passed:
        return None
    statuses = ("FAILED",) + tuple(
        item.value for item in HardBlocker if item in verification.blockers
    )
    return _derivation(TerminalSourceKind.PAPER_VERIFICATION, statuses)


def derive_from_legacy_terminal(
    status: TerminalState,
) -> TerminalOutcomeDerivation | None:
    """Read-only compatibility adapter; it never requests a state transition."""

    if not isinstance(status, TerminalState):
        raise ValidationError("legacy terminal status must be typed")
    if status in {
        TerminalState.READY_FOR_HUMAN_REVIEW,
        TerminalState.BLOCKED_EXTERNAL,
        TerminalState.STOP_SECURITY,
    }:
        return None
    return _derivation(
        TerminalSourceKind.LEGACY_TERMINAL_ADAPTER,
        (status.value,),
    )


def _load_canonical_research_artifact(
    repository: ResearchStateRepository,
    artifact_sha256: str,
    *,
    require_latest: bool,
) -> tuple[ArtifactRecord, CanonicalResearchObject]:
    """Resolve exact canonical bytes plus their same-run materialization event."""

    validate_sha256(artifact_sha256, "canonical terminal source SHA-256")
    registry = repository.registry
    try:
        registry.verify(artifact_sha256, raise_on_error=True)
        metadata = registry.get_metadata(artifact_sha256)
        raw = registry.get_bytes(artifact_sha256)
    except ArtifactError as exc:
        raise ValidationError(
            "terminal source artifact is absent or corrupt"
        ) from exc
    if (
        not metadata.logical_type.startswith("research_state.")
        or metadata.schema_version != RESEARCH_STATE_SCHEMA_VERSION
        or metadata.mime_type != "application/json"
        or metadata.validation_result != "PASS"
        or metadata.frozen is not True
    ):
        raise ValidationError(
            "terminal source is not a frozen canonical research-state artifact"
        )
    try:
        payload = safe_json_loads(
            raw,
            max_bytes=MAX_CANONICAL_OBJECT_BYTES + 1,
        )
        research_object = CanonicalResearchObject.from_dict(payload)
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("terminal source canonical payload is malformed") from exc
    if (
        research_object.canonical_bytes() != raw
        or research_object.logical_type != metadata.logical_type
        or research_object.schema_version != metadata.schema_version
        or research_object.producer is not metadata.creator_role
        or research_object.created_at != metadata.created_at
        or metadata.origin
        != (
            f"research-state:{research_object.object_type}:"
            f"{research_object.object_id}:r{research_object.revision}"
        )
    ):
        raise ValidationError("terminal source canonical artifact binding is inconsistent")
    event_id = f"rs-{artifact_sha256[:48]}"
    events = tuple(
        event for event in repository.ledger.events() if event.event_id == event_id
    )
    if len(events) != 1:
        raise ValidationError(
            "terminal source has no unique canonical materialization event"
        )
    event = events[0]
    event_metadata = event.metadata
    if (
        event.run_id != repository.run_id
        or event.actor_role is not research_object.producer
        or event.timestamp != research_object.created_at
        or event.code_version != repository.code_version
        or event.configuration_hash != repository.configuration_hash
        or tuple(event.artifact_hashes) != (artifact_sha256,)
        or event_metadata.get("research_state_operation")
        not in {"MATERIALIZED", "SUPERSEDED"}
        or event_metadata.get("object_type") != research_object.object_type
        or event_metadata.get("object_id") != research_object.object_id
        or event_metadata.get("revision") != research_object.revision
        or event_metadata.get("content_hash") != research_object.content_hash
        or event_metadata.get("artifact_hash") != artifact_sha256
    ):
        raise ValidationError(
            "terminal source materialization event is not bound to this run and object"
        )
    if require_latest:
        revisions = tuple(
            item
            for item in repository.objects()
            if item.object_type == research_object.object_type
            and item.object_id == research_object.object_id
        )
        if not revisions or max(revisions, key=lambda item: item.revision).content_hash != (
            research_object.content_hash
        ):
            raise ValidationError("terminal source is not the latest canonical revision")
    return metadata, research_object


def register_soundness_terminal_source(
    repository: ResearchStateRepository,
    assessment: SoundnessAssessment,
) -> ArtifactRecord:
    """Compatibility delegate to the gate owner's canonical assessment writer."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "soundness terminal-source registration requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    if not isinstance(assessment, SoundnessAssessment):
        raise ValidationError("soundness terminal source requires a typed assessment")
    if assessment.run_id not in {None, repository.run_id}:
        raise ValidationError("soundness terminal source belongs to a different run")
    return register_scientific_soundness_assessment(
        repository.registry,
        assessment,
        ledger=repository.ledger,
    )


def _require_run_scoped_repository(repository: ResearchStateRepository) -> None:
    """Bind terminal authority to the repository's canonical run namespace."""

    if (
        repository.registry.base_path.parts
        != ("runs", repository.run_id, "registry")
        or repository.ledger.relative_path.parts
        != ("runs", repository.run_id, "events.jsonl")
    ):
        raise ValidationError(
            "terminal authority requires the exact run-scoped registry and ledger"
        )


def derive_from_registered_soundness(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_assessment_id: str,
    expected_claim_ids: tuple[str, ...],
) -> TerminalOutcomeDerivation | None:
    """Derive from one exact assessment freshly replayed by the gate owner."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered soundness derivation requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_identifier(expected_assessment_id, "expected soundness assessment ID")
    if isinstance(expected_claim_ids, (str, bytes)):
        raise ValidationError("expected terminal claim IDs must be a tuple")
    claims = tuple(expected_claim_ids)
    if len(claims) > 256 or len(set(claims)) != len(claims):
        raise ValidationError("expected terminal claim IDs must be bounded and unique")
    for claim_id in claims:
        validate_identifier(claim_id, "expected terminal claim ID")

    registry = repository.registry
    try:
        assessment: SoundnessAssessment | None = None
        last_error: ValidationError | None = None
        # A v2 assessment either carries the repository run ID and exact
        # confirmatory-paper authorities, or is explicitly non-confirmatory
        # with no run ID.  Resolve both shapes through the gate owner's fresh
        # replay API; never infer the shape from a caller-provided flag.
        for expected_run_id in (repository.run_id, None):
            try:
                assessment = require_scientific_soundness_assessment(
                    registry,
                    assessment_artifact_hash=source_artifact_sha256,
                    expected_assessment_id=expected_assessment_id,
                    ledger=repository.ledger,
                    expected_run_id=expected_run_id,
                )
                break
            except ValidationError as exc:
                last_error = exc
        if assessment is None:
            assert last_error is not None
            raise last_error
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise ValidationError("soundness terminal source is absent or corrupt") from exc
    return _derive_from_replayed_soundness(
        repository,
        source_artifact_sha256,
        assessment,
        expected_assessment_id=expected_assessment_id,
        expected_claim_ids=claims,
    )


def _derive_from_replayed_soundness(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    assessment: SoundnessAssessment,
    *,
    expected_assessment_id: str,
    expected_claim_ids: tuple[str, ...],
) -> TerminalOutcomeDerivation | None:
    """Shared projection after the gate owner has replayed the whole assessment.

    This private seam avoids re-entering the current semantic audit when its
    already-replayed soundness is used to verify a downstream terminal view.
    It is not a replacement for source replay or a public authority issuer.
    """

    if not isinstance(repository, ResearchStateRepository) or not isinstance(
        assessment, SoundnessAssessment
    ):
        raise ValidationError("soundness terminal projection requires typed sources")
    _require_run_scoped_repository(repository)
    registry = repository.registry
    try:
        metadata = registry.get_metadata(source_artifact_sha256)
    except ArtifactError as exc:
        raise ValidationError("soundness terminal source is absent or corrupt") from exc
    claims = tuple(expected_claim_ids)
    if (
        assessment.assessment_id != expected_assessment_id
        or assessment.run_id not in {None, repository.run_id}
        or metadata.logical_type != TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE
        or metadata.schema_version != TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION
        or metadata.creator_role is not Role.SCIENTIFIC_REVIEWER
        or metadata.origin != "registry-rederived complete scientific soundness assessment"
        or metadata.creation_command
        != ("scientist-one", "record-scientific-soundness-assessment")
        or metadata.frozen is not True
        or metadata.validation_result != "PASS"
        or metadata.parent_artifacts != assessment.evidence_hashes
    ):
        raise ValidationError("soundness terminal projection source binding changed")
    if assessment.central_claim_ids != claims:
        raise ValidationError("soundness terminal source claim IDs were substituted")
    value_derivation = derive_from_soundness(assessment)
    if value_derivation is None:
        return None
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.SOUNDNESS_GATE,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=assessment.assessment_id,
        source_claim_ids=claims,
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    try:
        scientifically_authorized_claim_ids = _resolve_claim_graph_authority(
            registry,
            assessment.claim_graph_artifact_hash,
            ledger=repository.ledger,
            run_id=assessment.run_id,
            confirmatory_claim_authority_hashes=(
                assessment.confirmatory_claim_authority_hashes
            ),
            require_scientific_claims=True,
        )
    except ValidationError:
        authority_scope = TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL
    else:
        if scientifically_authorized_claim_ids != frozenset(claims):
            raise ValidationError(
                "soundness scientific authority resolved another claim set"
            )
        authority_scope = TerminalAuthorityScope.SCIENTIFIC_EVIDENCE
    return _derivation(
        TerminalSourceKind.SOUNDNESS_GATE,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=authority_scope,
    )


def derive_from_registered_scientific_result(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_result_id: str,
) -> TerminalOutcomeDerivation | None:
    """Derive only after the result-v3 owner freshly replays its full closure."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered scientific result derivation requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_sha256(
        source_artifact_sha256,
        "scientific result-promotion source artifact SHA-256",
    )
    validate_identifier(expected_result_id, "expected scientific result ID")
    registry = repository.registry
    try:
        registry.verify(source_artifact_sha256, raise_on_error=True)
        metadata = registry.get_metadata(source_artifact_sha256)
        value = safe_json_loads(registry.get_bytes(source_artifact_sha256))
        receipt = ScientificResultPromotionReceiptV3.from_dict(value)
        resolution = require_scientific_result_promotion_authority_v3(
            registry,
            repository.ledger,
            promotion_receipt_artifact_sha256=source_artifact_sha256,
            expected_ledger_run_id=repository.run_id,
            expected_execution_run_id=receipt.execution_run_id,
            expected_result_id=expected_result_id,
        )
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise ValidationError(
            "scientific result terminal source is absent, corrupt, or unauthorized"
        ) from exc
    if (
        resolution.assessment.ledger_run_id != repository.run_id
        or not resolution.scientific_evidence_eligible
    ):
        raise ValidationError(
            "scientific result terminal source lacks evidence authority"
        )
    value_derivation = derive_from_scientific_result_outcome(resolution.outcome)
    if value_derivation is None:
        return None
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.SCIENTIFIC_RESULT,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=resolution.result_id,
        source_claim_ids=(),
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    return _derivation(
        TerminalSourceKind.SCIENTIFIC_RESULT,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
    )


def derive_from_registered_research_gate_assessment(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_object_id: str,
) -> TerminalOutcomeDerivation | None:
    """Derive only terminal outcomes owned by an outcome-neutral gate replay."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered research-gate derivation requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_sha256(
        source_artifact_sha256,
        "research-question gate assessment source SHA-256",
    )
    validate_identifier(expected_object_id, "expected research-question gate object ID")
    registry = repository.registry
    try:
        registry.verify(source_artifact_sha256, raise_on_error=True)
        metadata = registry.get_metadata(source_artifact_sha256)
        assessment = require_research_question_gate_assessment(
            registry,
            repository.ledger,
            assessment_artifact_sha256=source_artifact_sha256,
            expected_run_id=repository.run_id,
            expected_object_id=expected_object_id,
        )
    except (ArtifactError, ScientificPromotionError, ValidationError) as exc:
        raise ValidationError(
            "research-question gate terminal source is absent, corrupt, "
            "or unauthorized"
        ) from exc
    if assessment.outcome is not ResearchGateOutcome.INSUFFICIENT_NOVELTY:
        if (
            assessment.outcome
            is not ResearchGateOutcome.INFEASIBLE_WITH_CURRENT_RESOURCES
        ):
            return None
        raise ValidationError(
            "research-question gate cannot own a compute-specific terminal outcome"
        )
    if assessment.verification_status is ScientificGateVerificationStatus.UNTESTED:
        raise ValidationError(
            "untested research-question criteria cannot authorize a terminal outcome"
        )
    value_derivation = derive_from_research_gate(assessment.outcome)
    if value_derivation is None:  # pragma: no cover - closed outcomes above
        return None
    authority_scope = (
        TerminalAuthorityScope.SCIENTIFIC_EVIDENCE
        if assessment.scientific_evidence_eligible
        else TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL
    )
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.RESEARCH_GATE,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=assessment.object_id,
        source_claim_ids=(),
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    return _derivation(
        TerminalSourceKind.RESEARCH_GATE,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=authority_scope,
    )


def derive_from_registered_paper_verification(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_candidate_id: str,
) -> TerminalOutcomeDerivation | None:
    """Derive conservative paper ineligibility after exact owner replay."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered paper verification derivation requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_sha256(
        source_artifact_sha256,
        "paper verification source artifact SHA-256",
    )
    validate_identifier(expected_candidate_id, "expected paper candidate ID")
    registry = repository.registry
    try:
        registry.verify(source_artifact_sha256, raise_on_error=True)
        verification = require_paper_verification(
            registry,
            repository.ledger,
            run_id=repository.run_id,
            verification_artifact_hash=source_artifact_sha256,
            expected_candidate_id=expected_candidate_id,
        )
    except (ArtifactError, ValidationError) as exc:
        raise ValidationError(
            "paper verification terminal source is absent, corrupt, or unauthorized"
        ) from exc
    return _derive_from_replayed_paper_verification(
        repository,
        source_artifact_sha256,
        verification,
        expected_candidate_id=expected_candidate_id,
    )


def _derive_from_replayed_paper_verification(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    verification: PaperVerification,
    *,
    expected_candidate_id: str,
) -> TerminalOutcomeDerivation | None:
    """Project a terminal only after the complete paper owner has replayed.

    Shared with the private same-round owner so a completed paper replay need
    not recursively invoke Soundness again.  This helper owns only the exact
    mechanical terminal mapping, not paper or scientific authority.
    """

    if not isinstance(repository, ResearchStateRepository) or not isinstance(
        verification, PaperVerification
    ):
        raise ValidationError("paper terminal projection requires typed sources")
    _require_run_scoped_repository(repository)
    validate_sha256(source_artifact_sha256, "paper verification source artifact SHA-256")
    validate_identifier(expected_candidate_id, "expected paper candidate ID")
    try:
        metadata = repository.registry.get_metadata(source_artifact_sha256)
    except ArtifactError as exc:
        raise ValidationError("paper verification terminal source is absent or corrupt") from exc
    if (
        metadata.logical_type != TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE
        or metadata.schema_version != "1.0"
        or metadata.creator_role is not Role.SCIENTIFIC_REVIEWER
        or metadata.origin != "fresh registry-and-ledger replay of exact paper authority"
        or metadata.creation_command != ("scientist-one", "verify-paper-authority")
        or metadata.frozen is not True
        or metadata.validation_result != "PASS"
        or len(metadata.parent_artifacts) != 2
    ):
        raise ValidationError("paper terminal projection source binding changed")
    value_derivation = derive_from_paper_verification(verification)
    if value_derivation is None:
        return None
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.PAPER_VERIFICATION,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=expected_candidate_id,
        source_claim_ids=verification.verified_claim_ids,
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    return _derivation(
        TerminalSourceKind.PAPER_VERIFICATION,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL,
        mapping_id=PAPER_PUBLICATION_TERMINAL_MAPPING_ID,
    )


def derive_from_registered_scientific_clean_rerun(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_authority_id: str,
) -> TerminalOutcomeDerivation | None:
    """Derive only from a freshly replayed authorized scientific clean rerun."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered scientific clean-rerun derivation requires "
            "ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_sha256(
        source_artifact_sha256,
        "scientific clean-rerun source artifact SHA-256",
    )
    validate_identifier(expected_authority_id, "expected clean-rerun authority ID")
    registry = repository.registry
    try:
        registry.verify(source_artifact_sha256, raise_on_error=True)
        metadata = registry.get_metadata(source_artifact_sha256)
        value = safe_json_loads(registry.get_bytes(source_artifact_sha256))
        stated = ScientificCleanRerunAuthority.from_mapping(value)
        authority = require_scientific_clean_rerun_authority(
            registry,
            repository.ledger,
            authority_artifact_sha256=source_artifact_sha256,
            expected_ledger_run_id=repository.run_id,
            expected_original_execution_run_id=(
                stated.original_execution_run_id
            ),
            expected_rerun_execution_run_id=stated.rerun_execution_run_id,
        )
    except (
        ArtifactError,
        ReproductionError,
        UnsafeSerializationError,
        ValidationError,
    ) as exc:
        raise ValidationError(
            "scientific clean-rerun terminal source is absent, corrupt, "
            "or unauthorized"
        ) from exc
    if authority.authority_id != expected_authority_id:
        raise ValidationError(
            "scientific clean-rerun terminal source authority ID was substituted"
        )
    if authority.outcome is ScientificCleanRerunOutcome.PASS:
        return None
    if authority.outcome not in {
        ScientificCleanRerunOutcome.FAIL,
        ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE,
    }:
        raise ValidationError(
            "scientific clean-rerun authority has no terminal comparison outcome"
        )
    value_derivation = _derivation(
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        (authority.outcome.value,),
    )
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.CANONICAL_REPRODUCTION,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=authority.authority_id,
        source_claim_ids=(),
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    return _derivation(
        TerminalSourceKind.CANONICAL_REPRODUCTION,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=TerminalAuthorityScope.SCIENTIFIC_EVIDENCE,
    )


def derive_from_registered_compute_terminal_assessment(
    repository: ResearchStateRepository,
    source_artifact_sha256: str,
    *,
    expected_assessment_id: str,
) -> TerminalOutcomeDerivation:
    """Derive an operational fact from the full source-selected compute owner.

    The CUDA protocol route means one mandatory device-timing obligation is
    unperformed and outside admitted LOCAL_MAC capabilities. It does not
    establish cloud availability, physical incapacity or scientific adequacy.
    """

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError(
            "registered compute derivation requires ResearchStateRepository"
        )
    _require_run_scoped_repository(repository)
    validate_sha256(
        source_artifact_sha256,
        "compute terminal assessment source SHA-256",
    )
    validate_identifier(expected_assessment_id, "expected compute assessment ID")
    try:
        repository.registry.verify(source_artifact_sha256, raise_on_error=True)
        metadata = repository.registry.get_metadata(source_artifact_sha256)
        value = safe_json_loads(
            repository.registry.get_bytes(source_artifact_sha256)
        )
        if not isinstance(value, Mapping):
            raise ValidationError("compute terminal assessment payload is malformed")
        execution_run_id = value.get("execution_run_id")
        if not isinstance(execution_run_id, str):
            raise ValidationError("compute terminal execution run ID is absent")
        assessment = require_compute_terminal_assessment(
            repository.registry,
            repository.ledger,
            assessment_artifact_sha256=source_artifact_sha256,
            expected_ledger_run_id=repository.run_id,
            expected_execution_run_id=execution_run_id,
        )
    except (
        ArtifactError,
        ComputeTerminalError,
        UnsafeSerializationError,
        ValidationError,
    ) as exc:
        raise ValidationError(
            "compute terminal source is absent, corrupt, or unauthorized"
        ) from exc
    if assessment.assessment_id != expected_assessment_id:
        raise ValidationError("compute terminal assessment ID was substituted")
    value_derivation = _derivation(
        TerminalSourceKind.COMPUTE_STATUS,
        (assessment.factual_status,),
    )
    binding = TerminalSourceBinding(
        source_kind=TerminalSourceKind.COMPUTE_STATUS,
        source_artifact_sha256=source_artifact_sha256,
        source_record_hash=metadata.record_hash,
        source_logical_type=metadata.logical_type,
        source_creator_role=metadata.creator_role,
        source_run_id=repository.run_id,
        source_object_id=assessment.assessment_id,
        source_claim_ids=(),
        source_statuses=value_derivation.source_statuses,
        source_parent_artifact_hashes=metadata.parent_artifacts,
    )
    return _derivation(
        TerminalSourceKind.COMPUTE_STATUS,
        value_derivation.source_statuses,
        source_binding=binding,
        authority_scope=TerminalAuthorityScope.OPERATIONAL_BLOCKER,
    )


@dataclass(frozen=True, slots=True)
class _ResolvedTerminalAuthority:
    derivation: TerminalOutcomeDerivation
    authority_scope: TerminalAuthorityScope

    def __post_init__(self) -> None:
        if not isinstance(self.derivation, TerminalOutcomeDerivation):
            raise ValidationError(
                "resolved terminal authority requires a typed derivation"
            )
        if self.derivation.source_binding is None:
            raise ValidationError(
                "resolved terminal authority requires an exact source binding"
            )
        if not isinstance(self.authority_scope, TerminalAuthorityScope):
            raise ValidationError("resolved terminal authority scope is invalid")


_TerminalOwnerResolver = Callable[
    [ResearchStateRepository, TerminalOutcomeDerivation],
    _ResolvedTerminalAuthority,
]


def _resolve_soundness_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError("soundness terminal owner requires a source binding")
    current = derive_from_registered_soundness(
        repository,
        binding.source_artifact_sha256,
        expected_assessment_id=binding.source_object_id,
        expected_claim_ids=binding.source_claim_ids,
    )
    return _normalize_replayed_soundness_terminal(current, derivation)


def _normalize_replayed_soundness_terminal(
    current: TerminalOutcomeDerivation | None,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    """Keep exact historical normalization shared by both soundness readers."""

    if current is None or current.authority_scope is None:
        raise ValidationError("soundness source is no longer terminal")
    scope = current.authority_scope
    resolved = (
        current
        if derivation.mapping_id == TERMINAL_OUTCOME_MAPPING_ID
        else replace(
            current,
            mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            source_binding=replace(
                current.source_binding,
                source_record_hash=None,
            ),
            authority_scope=None,
        )
    )
    return _ResolvedTerminalAuthority(resolved, scope)


def _resolve_scientific_result_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError("scientific result terminal owner requires a source binding")
    if binding.source_claim_ids:
        raise ValidationError(
            "scientific result terminal source cannot relabel a hypothesis as a claim"
        )
    current = derive_from_registered_scientific_result(
        repository,
        binding.source_artifact_sha256,
        expected_result_id=binding.source_object_id,
    )
    if current is None or current.authority_scope is None:
        raise ValidationError("scientific result source is not terminal")
    return _ResolvedTerminalAuthority(current, current.authority_scope)


def _resolve_research_gate_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError("research-gate terminal owner requires a source binding")
    if binding.source_claim_ids:
        raise ValidationError(
            "research-gate terminal source cannot manufacture claim IDs"
        )
    current = derive_from_registered_research_gate_assessment(
        repository,
        binding.source_artifact_sha256,
        expected_object_id=binding.source_object_id,
    )
    if current is None or current.authority_scope is None:
        raise ValidationError("research-gate source is not terminal")
    return _ResolvedTerminalAuthority(current, current.authority_scope)


def _resolve_paper_verification_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError("paper terminal owner requires a source binding")
    current = derive_from_registered_paper_verification(
        repository,
        binding.source_artifact_sha256,
        expected_candidate_id=binding.source_object_id,
    )
    if current is None or current.authority_scope is None:
        raise ValidationError("paper verification source is not terminal")
    return _normalize_replayed_paper_terminal(current, derivation)


def _normalize_replayed_paper_terminal(
    current: TerminalOutcomeDerivation,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    """Preserve only historically admissible v2 paper terminal projections."""

    if (
        current.mapping_id != PAPER_PUBLICATION_TERMINAL_MAPPING_ID
        or current.source_kind is not TerminalSourceKind.PAPER_VERIFICATION
        or current.authority_scope is not TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL
    ):
        raise ValidationError("paper terminal replay requires mechanical publication scope")
    if derivation.mapping_id == PAPER_PUBLICATION_TERMINAL_MAPPING_ID:
        resolved = current
    elif derivation.mapping_id == TERMINAL_OUTCOME_MAPPING_ID:
        historical = _expected_derivation(
            current.source_kind,
            current.source_statuses,
            mapping_id=TERMINAL_OUTCOME_MAPPING_ID,
        )
        if historical.outcome is not ResearchTerminalOutcome.NOT_PUBLISHABLE:
            raise ValidationError(
                "historical paper mapping cannot own a source-specific scientific outcome"
            )
        resolved = replace(current, mapping_id=TERMINAL_OUTCOME_MAPPING_ID)
    else:
        # Prior paper replay never normalized v1 into a bound current owner.
        raise ValidationError("paper terminal mapping has no historical authority owner")
    return _ResolvedTerminalAuthority(resolved, current.authority_scope)


def _resolve_scientific_clean_rerun_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError(
            "scientific clean-rerun terminal owner requires a source binding"
        )
    if binding.source_claim_ids:
        raise ValidationError(
            "scientific clean-rerun terminal source cannot manufacture claim IDs"
        )
    current = derive_from_registered_scientific_clean_rerun(
        repository,
        binding.source_artifact_sha256,
        expected_authority_id=binding.source_object_id,
    )
    if current is None or current.authority_scope is None:
        raise ValidationError("scientific clean-rerun source is not terminal")
    return _ResolvedTerminalAuthority(current, current.authority_scope)


def _resolve_compute_terminal_owner(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:  # pragma: no cover - dispatch requires a bound source
        raise ValidationError("compute terminal owner requires a source binding")
    if binding.source_claim_ids:
        raise ValidationError("compute terminal source cannot manufacture claim IDs")
    current = derive_from_registered_compute_terminal_assessment(
        repository,
        binding.source_artifact_sha256,
        expected_assessment_id=binding.source_object_id,
    )
    if current.authority_scope is not TerminalAuthorityScope.OPERATIONAL_BLOCKER:
        raise ValidationError("compute terminal owner has an invalid authority scope")
    return _ResolvedTerminalAuthority(current, current.authority_scope)


_TERMINAL_OWNER_RESOLVERS: Mapping[
    tuple[TerminalSourceKind, str], _TerminalOwnerResolver
] = MappingProxyType(
    {
        (
            TerminalSourceKind.RESEARCH_GATE,
            RESEARCH_QUESTION_GATE_ASSESSMENT_LOGICAL_TYPE,
        ): _resolve_research_gate_terminal_owner,
        (
            TerminalSourceKind.SOUNDNESS_GATE,
            TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE,
        ): _resolve_soundness_terminal_owner,
        (
            TerminalSourceKind.SCIENTIFIC_RESULT,
            SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
        ): _resolve_scientific_result_terminal_owner,
        (
            TerminalSourceKind.PAPER_VERIFICATION,
            TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE,
        ): _resolve_paper_verification_terminal_owner,
        (
            TerminalSourceKind.CANONICAL_REPRODUCTION,
            SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
        ): _resolve_scientific_clean_rerun_terminal_owner,
        (
            TerminalSourceKind.COMPUTE_STATUS,
            COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
        ): _resolve_compute_terminal_owner,
    }
)


def _terminal_owner_resolver(
    key: tuple[TerminalSourceKind, str],
    *,
    _closed_resolvers: Mapping[
        tuple[TerminalSourceKind, str], _TerminalOwnerResolver
    ] = _TERMINAL_OWNER_RESOLVERS,
) -> _TerminalOwnerResolver:
    resolver = _closed_resolvers.get(key)
    if resolver is None:
        raise ValidationError(
            "terminal source kind and logical type have no closed source-owner resolver"
        )
    return resolver


def _resolve_authoritative_derivation(
    repository: ResearchStateRepository,
    derivation: TerminalOutcomeDerivation,
) -> _ResolvedTerminalAuthority:
    binding = derivation.source_binding
    if binding is None:
        raise ValidationError(
            "value-only terminal derivations are diagnostic and cannot authorize materialization"
        )
    try:
        repository.registry.verify(
            binding.source_artifact_sha256,
            raise_on_error=True,
        )
        metadata = repository.registry.get_metadata(
            binding.source_artifact_sha256
        )
    except ArtifactError as exc:
        raise ValidationError(
            "terminal source artifact is absent or corrupt"
        ) from exc
    if (
        binding.source_logical_type != metadata.logical_type
        or (
            derivation.mapping_id in _CURRENT_FORMAT_TERMINAL_MAPPING_IDS
            and binding.source_record_hash != metadata.record_hash
        )
        or binding.source_creator_role is not metadata.creator_role
        or binding.source_parent_artifact_hashes != metadata.parent_artifacts
    ):
        raise ValidationError(
            "terminal source binding differs from actual registry metadata"
        )
    resolver = _terminal_owner_resolver(
        (binding.source_kind, metadata.logical_type)
    )
    resolved = resolver(repository, derivation)
    if resolved.derivation != derivation:
        raise ValidationError(
            "terminal source no longer resolves to the recorded authoritative derivation"
        )
    return resolved


@dataclass(frozen=True, slots=True)
class ResearchTerminalRecord:
    """Immutable terminal fact bound to one run and exact evidence artifacts."""

    record_id: str
    run_id: str
    phase: TerminalPhase
    outcome: ResearchTerminalOutcome
    reason: str
    evidence_artifact_hashes: tuple[str, ...]
    derivation: TerminalOutcomeDerivation
    producer: Role
    authority_scope: TerminalAuthorityScope | None = None
    source_object_id: str | None = None
    source_claim_ids: tuple[str, ...] = ()
    uncertainty: float = 0.0
    created_at: str = ""
    schema_version: str = TERMINAL_OUTCOME_SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.record_id, "terminal record ID")
        validate_identifier(self.run_id, "terminal run ID")
        try:
            phase = TerminalPhase(self.phase)
            outcome = ResearchTerminalOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise ValidationError("terminal record enum is invalid") from exc
        if not isinstance(self.derivation, TerminalOutcomeDerivation):
            raise ValidationError("terminal record requires a typed derivation")
        if phase is not self.derivation.phase or outcome is not self.derivation.outcome:
            raise ValidationError("terminal record contradicts its source derivation")
        if not isinstance(self.producer, Role):
            raise ValidationError("terminal record producer must be a typed role")
        if self.producer is not Role.SCIENTIFIC_REVIEWER:
            raise ValidationError(
                "terminal records require the exact scientific-reviewer role"
            )
        if self.source_object_id is not None:
            validate_identifier(self.source_object_id, "terminal source object ID")
        if isinstance(self.source_claim_ids, (str, bytes)):
            raise ValidationError("terminal source claim IDs must be a tuple")
        claims = tuple(self.source_claim_ids)
        if len(claims) > 256 or len(set(claims)) != len(claims):
            raise ValidationError("terminal source claim IDs must be bounded and unique")
        for claim_id in claims:
            validate_identifier(claim_id, "terminal source claim ID")
        reason = _bounded_reason(self.reason)
        if isinstance(self.evidence_artifact_hashes, (str, bytes)):
            raise ValidationError("terminal evidence artifacts must be a tuple")
        evidence = tuple(self.evidence_artifact_hashes)
        if not evidence or len(evidence) > MAX_EVIDENCE_ARTIFACTS:
            raise ValidationError("terminal record requires bounded evidence artifacts")
        for digest in evidence:
            validate_sha256(digest, "terminal evidence artifact SHA-256")
        if len(set(evidence)) != len(evidence):
            raise ValidationError("terminal evidence artifacts must be unique")
        evidence = tuple(sorted(evidence))
        binding = self.derivation.source_binding
        authority_scope = self.authority_scope
        if authority_scope is not None:
            try:
                authority_scope = TerminalAuthorityScope(authority_scope)
            except (TypeError, ValueError) as exc:
                raise ValidationError("terminal record authority scope is invalid") from exc
        if binding is None:
            if (
                self.source_object_id is not None
                or claims
                or authority_scope is not None
            ):
                raise ValidationError(
                    "diagnostic terminal derivations cannot claim source authority"
                )
        else:
            if authority_scope is None:
                authority_scope = self.derivation.authority_scope
            binding_mismatch = (
                self.source_object_id != binding.source_object_id
                or claims != binding.source_claim_ids
                or self.run_id != binding.source_run_id
                or evidence != binding.required_evidence_artifact_hashes
            )
            if self.schema_version == LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION:
                binding_mismatch = binding_mismatch or authority_scope is not None
            else:
                binding_mismatch = (
                    binding_mismatch
                    or authority_scope is None
                    or authority_scope is not self.derivation.authority_scope
                )
            if binding_mismatch:
                raise ValidationError(
                    "terminal record differs from its exact authoritative source binding"
                )
        if isinstance(self.uncertainty, bool) or not isinstance(
            self.uncertainty, (int, float)
        ):
            raise ValidationError("terminal outcome uncertainty must be numeric")
        uncertainty = float(self.uncertainty)
        if not 0.0 <= uncertainty <= 1.0:
            raise ValidationError("terminal outcome uncertainty must be within [0,1]")
        created_at = self.created_at or utc_now()
        _utc_timestamp(created_at)
        if self.schema_version not in _SUPPORTED_TERMINAL_OUTCOME_SCHEMA_VERSIONS:
            raise ValidationError("unsupported terminal outcome schema")
        if self.schema_version == LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION:
            if (
                self.derivation.mapping_id != LEGACY_TERMINAL_OUTCOME_MAPPING_ID
                or authority_scope is not None
            ):
                raise ValidationError(
                    "legacy terminal records cannot carry current mapping or scope"
                )
        elif self.derivation.mapping_id not in _CURRENT_FORMAT_TERMINAL_MAPPING_IDS:
            raise ValidationError(
                "current terminal records require the current mapping policy"
            )
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "evidence_artifact_hashes", evidence)
        object.__setattr__(self, "source_claim_ids", claims)
        object.__setattr__(self, "authority_scope", authority_scope)
        object.__setattr__(self, "uncertainty", uncertainty)
        object.__setattr__(self, "created_at", created_at)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "run_id": self.run_id,
            "phase": self.phase.value,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "evidence_artifact_hashes": list(self.evidence_artifact_hashes),
            "derivation": self.derivation.to_dict(),
            "producer": self.producer.value,
            "source_object_id": self.source_object_id,
            "source_claim_ids": list(self.source_claim_ids),
            "uncertainty": self.uncertainty,
            "created_at": self.created_at,
        }
        if self.schema_version == TERMINAL_OUTCOME_SCHEMA_VERSION:
            result["authority_scope"] = (
                self.authority_scope.value
                if self.authority_scope is not None
                else None
            )
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResearchTerminalRecord":
        legacy_required = {
            "schema_version",
            "record_id",
            "run_id",
            "phase",
            "outcome",
            "reason",
            "evidence_artifact_hashes",
            "derivation",
            "producer",
            "source_object_id",
            "source_claim_ids",
            "uncertainty",
            "created_at",
        }
        current_required = legacy_required | {"authority_scope"}
        if not isinstance(value, Mapping):
            raise ValidationError("terminal record schema is incomplete or unknown")
        schema_version = value.get("schema_version")
        required = (
            legacy_required
            if schema_version == LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION
            else current_required
        )
        if set(value) != required:
            raise ValidationError("terminal record schema is incomplete or unknown")
        try:
            scope_value = value.get("authority_scope")
            return cls(
                schema_version=value["schema_version"],
                record_id=value["record_id"],
                run_id=value["run_id"],
                phase=TerminalPhase(value["phase"]),
                outcome=ResearchTerminalOutcome(value["outcome"]),
                reason=value["reason"],
                evidence_artifact_hashes=tuple(value["evidence_artifact_hashes"]),
                derivation=TerminalOutcomeDerivation.from_dict(value["derivation"]),
                producer=Role(value["producer"]),
                authority_scope=(
                    TerminalAuthorityScope(scope_value)
                    if scope_value is not None
                    else None
                ),
                source_object_id=value["source_object_id"],
                source_claim_ids=tuple(value["source_claim_ids"]),
                uncertainty=value["uncertainty"],
                created_at=value["created_at"],
            )
        except ValidationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("malformed terminal outcome record") from exc

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict()) + b"\n"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class MaterializedTerminalOutcome:
    terminal_record: ResearchTerminalRecord
    terminal_artifact: ArtifactRecord
    canonical_decision: MaterializedResearchObject


def _load_terminal_record_from_registry(
    registry: ArtifactRegistry,
    artifact_sha256: str,
) -> ResearchTerminalRecord:
    if not isinstance(registry, ArtifactRegistry):
        raise ValidationError("terminal readback requires an ArtifactRegistry")
    validate_sha256(artifact_sha256, "terminal artifact SHA-256")
    registry.verify(artifact_sha256, raise_on_error=True)
    metadata = registry.get_metadata(artifact_sha256)
    if (
        metadata.logical_type != TERMINAL_OUTCOME_LOGICAL_TYPE
        or metadata.schema_version not in _SUPPORTED_TERMINAL_OUTCOME_SCHEMA_VERSIONS
        or metadata.mime_type != "application/json"
        or metadata.validation_result != "PASS"
        or metadata.frozen is not True
    ):
        raise ValidationError("artifact is not an authoritative terminal outcome")
    raw = registry.get_bytes(artifact_sha256)
    try:
        value = safe_json_loads(raw, max_bytes=MAX_REASON_BYTES + 64 * 1024)
    except Exception as exc:
        raise ValidationError("terminal outcome artifact is malformed") from exc
    record = ResearchTerminalRecord.from_dict(value)
    if (
        record.canonical_bytes() != raw
        or record.schema_version != metadata.schema_version
        or record.sha256 != artifact_sha256
        or record.producer is not metadata.creator_role
        or record.created_at != metadata.created_at
        or record.evidence_artifact_hashes != metadata.parent_artifacts
    ):
        raise ValidationError("terminal outcome artifact binding is inconsistent")
    return record


def _terminal_decision(
    record: ResearchTerminalRecord,
    repository: ResearchStateRepository,
    terminal_artifact_sha256: str,
) -> Decision:
    binding = record.derivation.source_binding
    if binding is None:
        raise ValidationError("diagnostic terminal records cannot create decisions")
    authority_hashes = (terminal_artifact_sha256,)
    metadata = {
        "terminal_record_artifact_sha256": terminal_artifact_sha256,
        "terminal_phase": record.phase.value,
        "terminal_source_kind": record.derivation.source_kind.value,
        "terminal_mapping_id": record.derivation.mapping_id,
        "terminal_run_id": record.run_id,
        "terminal_source_artifact_sha256": binding.source_artifact_sha256,
        "terminal_source_object_id": record.source_object_id,
        "terminal_source_claim_ids": list(record.source_claim_ids),
    }
    if record.schema_version == TERMINAL_OUTCOME_SCHEMA_VERSION:
        if record.authority_scope is None:  # pragma: no cover - record validates
            raise ValidationError("current terminal Decision lacks authority scope")
        metadata["terminal_authority_scope"] = record.authority_scope.value
    return Decision(
        object_id=record.record_id,
        producer=record.producer,
        status=RecordStatus.COMPLETE,
        created_at=record.created_at,
        code_version=repository.code_version,
        authority_artifact_hashes=authority_hashes,
        decision_type=TERMINAL_DECISION_TYPE,
        outcome=record.outcome.value,
        alternatives=(),
        evidence_ids=(),
        source_artifact_hashes=authority_hashes,
        governing_rule=record.derivation.mapping_id,
        uncertainty=record.uncertainty,
        reason=record.reason,
        consequences=(
            f"Close Research OS phase {record.phase.value} with a truthful outcome.",
            "Preserve negative, null, inconclusive, or falsified evidence without narrative rewriting.",
            "Do not infer or request a legacy macro-state transition from this record.",
        ),
        metadata=metadata,
    )


def _require_materialized_terminal_decision(
    repository: ResearchStateRepository,
    record: ResearchTerminalRecord,
    terminal_artifact_sha256: str,
) -> MaterializedResearchObject:
    expected = _terminal_decision(record, repository, terminal_artifact_sha256)
    matches = tuple(
        item
        for item in repository.objects()
        if isinstance(item, Decision) and item.object_id == record.record_id
    )
    if len(matches) != 1 or matches[0] != expected:
        raise ValidationError(
            "terminal artifact lacks its exact same-run canonical Decision authority"
        )
    decision_sha256 = hashlib.sha256(expected.canonical_bytes()).hexdigest()
    metadata, loaded = _load_canonical_research_artifact(
        repository,
        decision_sha256,
        require_latest=True,
    )
    if (
        loaded != expected
        or metadata.logical_type != "research_state.decision"
        or metadata.parent_artifacts
        != tuple(sorted(expected.source_artifact_hashes))
    ):
        raise ValidationError("canonical terminal Decision binding is inconsistent")
    event_id = f"rs-{decision_sha256[:48]}"
    event = next(
        (item for item in repository.ledger.events() if item.event_id == event_id),
        None,
    )
    if event is None:
        raise ValidationError("canonical terminal Decision event is missing")
    return MaterializedResearchObject(expected, metadata, event)


def load_terminal_outcome(
    registry: ArtifactRegistry,
    artifact_sha256: str,
    *,
    repository: ResearchStateRepository,
) -> ResearchTerminalRecord:
    """Load an authoritative terminal fact through registry and same-run ledger."""

    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError("terminal readback requires ResearchStateRepository")
    if (
        registry.policy.root != repository.registry.policy.root
        or registry.base_path != repository.registry.base_path
    ):
        raise ValidationError("terminal readback registry differs from the repository")
    record = _load_terminal_record_from_registry(registry, artifact_sha256)
    if record.run_id != repository.run_id:
        raise ValidationError("terminal artifact belongs to a different run")
    metadata = registry.get_metadata(artifact_sha256)
    if (
        metadata.origin
        != f"research-terminal:{record.run_id}:{record.record_id}"
        or metadata.creation_command != repository.creation_command
    ):
        raise ValidationError("terminal artifact metadata differs from its run binding")
    resolved = _resolve_authoritative_derivation(repository, record.derivation)
    if (
        record.schema_version == TERMINAL_OUTCOME_SCHEMA_VERSION
        and record.authority_scope is not resolved.authority_scope
    ):
        raise ValidationError(
            "terminal record scope differs from its freshly resolved source owner"
        )
    _require_materialized_terminal_decision(repository, record, artifact_sha256)
    return record


def materialize_terminal_outcome(
    record: ResearchTerminalRecord,
    repository: ResearchStateRepository,
) -> MaterializedTerminalOutcome:
    """Persist a terminal fact without changing ``repository.state``.

    The returned canonical ``Decision`` is the root integration hook for the
    Research OS controller.  Its materialization ledger event has identical
    ``state_before`` and ``requested_state_after`` values.
    """

    if not isinstance(record, ResearchTerminalRecord):
        raise ValidationError("terminal materialization requires a typed record")
    if not isinstance(repository, ResearchStateRepository):
        raise ValidationError("terminal materialization requires ResearchStateRepository")
    if repository.run_id != record.run_id:
        raise ValidationError("terminal record run differs from repository run")
    resolved = _resolve_authoritative_derivation(repository, record.derivation)
    if (
        record.schema_version == TERMINAL_OUTCOME_SCHEMA_VERSION
        and record.authority_scope is not resolved.authority_scope
    ):
        raise ValidationError(
            "terminal record scope differs from its freshly resolved source owner"
        )
    registry = repository.registry
    for digest in record.evidence_artifact_hashes:
        registry.verify(digest, raise_on_error=True)
        evidence = registry.get_metadata(digest)
        if evidence.validation_result != "PASS" or evidence.frozen is not True:
            raise ValidationError("terminal evidence must be a frozen PASS artifact")

    existing = tuple(
        item
        for item in repository.objects()
        if isinstance(item, Decision) and item.object_id == record.record_id
    )
    if existing and (
        len(existing) != 1
        or existing[0] != _terminal_decision(record, repository, record.sha256)
    ):
        raise ValidationError("terminal record ID already names a different decision")

    terminal_artifact = registry.put_bytes(
        record.canonical_bytes(),
        logical_type=TERMINAL_OUTCOME_LOGICAL_TYPE,
        origin=f"research-terminal:{record.run_id}:{record.record_id}",
        creator_role=record.producer,
        creation_command=repository.creation_command,
        parent_artifacts=record.evidence_artifact_hashes,
        schema_version=record.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=record.created_at,
    )
    if _load_terminal_record_from_registry(registry, terminal_artifact.sha256) != record:
        raise ValidationError("terminal outcome failed immediate authoritative readback")

    decision = _terminal_decision(record, repository, terminal_artifact.sha256)
    materialized = repository.materialize(
        decision,
        reason=(
            f"materialized Research OS terminal outcome {record.outcome.value}; "
            "legacy macro state unchanged"
        ),
    )
    if (
        load_terminal_outcome(
            registry,
            terminal_artifact.sha256,
            repository=repository,
        )
        != record
    ):
        raise ValidationError("terminal outcome failed authoritative decision readback")
    return MaterializedTerminalOutcome(record, terminal_artifact, materialized)


__all__ = [
    "MaterializedTerminalOutcome",
    "LEGACY_TERMINAL_OUTCOME_MAPPING_ID",
    "LEGACY_TERMINAL_OUTCOME_SCHEMA_VERSION",
    "PAPER_PUBLICATION_TERMINAL_MAPPING_ID",
    "ResearchTerminalOutcome",
    "ResearchTerminalRecord",
    "TERMINAL_DECISION_TYPE",
    "TERMINAL_OUTCOME_LOGICAL_TYPE",
    "TERMINAL_OUTCOME_MAPPING_ID",
    "TERMINAL_OUTCOME_SCHEMA_VERSION",
    "TERMINAL_PAPER_VERIFICATION_SOURCE_LOGICAL_TYPE",
    "TERMINAL_SOUNDNESS_SOURCE_LOGICAL_TYPE",
    "TERMINAL_SOUNDNESS_SOURCE_SCHEMA_VERSION",
    "TerminalAuthorityScope",
    "TerminalOutcomeDerivation",
    "TerminalPhase",
    "TerminalSourceBinding",
    "TerminalSourceKind",
    "derive_from_canonical_reproduction",
    "derive_from_compute_profile",
    "derive_from_compute_status",
    "derive_from_discovery_branch",
    "derive_from_experiment_reproduction",
    "derive_from_hypothesis_status",
    "derive_from_legacy_terminal",
    "derive_from_paper_verification",
    "derive_from_registered_paper_verification",
    "derive_from_registered_compute_terminal_assessment",
    "derive_from_registered_research_gate_assessment",
    "derive_from_registered_scientific_clean_rerun",
    "derive_from_registered_scientific_result",
    "derive_from_registered_soundness",
    "derive_from_research_gate",
    "derive_from_scientific_result_outcome",
    "derive_from_soundness",
    "load_terminal_outcome",
    "materialize_terminal_outcome",
    "register_soundness_terminal_source",
]
