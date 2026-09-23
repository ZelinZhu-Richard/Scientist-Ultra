"""Evidence-only paper verification, multidimensional readiness, and venue fit.

Composition is downstream of verified research state.  This module does not
generate scientific facts; it checks that a paper candidate is a faithful view
of authoritative claims, metrics, code, references, limitations, and reviews.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
import hashlib
import math
from typing import Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .claims import (
    ClaimDecision,
    ClaimEvidenceGraph,
    ClaimEvidenceUse,
    EvidenceKind,
    EvidenceVerificationReceipt,
    artifact_registry_resolver,
)
from .errors import ValidationError
from .external import (
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA,
    require_audited_live_transport_execution,
)
from .gates import (
    ChallengeCategory,
    ChallengeStatus,
    ChallengerExecutionStatus,
    DimensionStatus,
    JudgmentSubjectKind,
    SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE,
    SEMANTIC_JUDGMENT_RECEIPT_SCHEMA_VERSION,
    SemanticJudgmentReceipt,
    SoundnessAssessment,
    SoundnessDimension,
    SoundnessDimensionEvidenceReceipt,
    SoundnessVerdict,
    _SemanticChallengerAuditRoundSoundness,
    _require_audited_live_semantic_transport,
    _semantic_challenger_audit_parse_soundness,
    require_scientific_semantic_judgment_receipt,
    require_scientific_soundness_assessment,
)
from .models import utc_now, validate_identifier, validate_sha256
from .holdout import (
    AccessOutcome,
    CustodyIndependence,
    HoldoutAccessRecord,
    HoldoutRelease,
    HoldoutSeal,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .literature import CitationGraphNode, ScholarlyRecord
from .protocol import (
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ResearchProtocol,
    SeedPolicy,
    StatisticalTestSpec,
    validate_protocol,
)
from .research_state import (
    CLAIM_SEMANTICS_RECEIPT_LOGICAL_TYPE,
    Claim as StateClaim,
    ClaimSemanticsEvidenceScope,
    ClaimSemanticsReceipt,
    ClaimStrength,
    ClaimType,
    Implementation as StateImplementation,
    Method as StateMethod,
    ResearchStateAuthorityBinding,
    ResearchStateAuthoritySnapshot,
    Result as StateResult,
    VerificationStatus,
    _SameRoundReviewReplay,
    _locked_research_state_source_snapshot,
    _require_same_round_review_snapshot,
    _resolve_bound_research_state_authority,
    require_claim_semantics_receipt,
    resolve_bound_research_state_authority,
    resolve_research_state_authority,
)
from .roles import Role
from .scientific_design import (
    ScientificDesignError,
    require_audited_claim_bound_reference_authority,
    require_confirmatory_timeline_receipt,
)
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


MAX_TEXT_BYTES = 64 * 1024
MAX_ITEMS = 2048
MAX_AUTHORITATIVE_BUNDLE_BYTES = 8 * 1024 * 1024
AUTHORITATIVE_BUNDLE_PAYLOAD_SCHEMA = "authoritative-research-bundle/v2"
AUTHORITATIVE_BUNDLE_ARTIFACT_SCHEMA_VERSION = "2.0"
AUTHORITATIVE_BUNDLE_CREATION_COMMAND = (
    "scientist-one",
    "paper",
    "issue-authoritative-bundle",
)
_CLAIM_STRENGTH_RANK = {
    ClaimStrength.UNSUPPORTED: 0,
    ClaimStrength.LIMITED: 1,
    ClaimStrength.QUALIFIED: 2,
    ClaimStrength.SUPPORTED: 3,
    ClaimStrength.STRONG: 4,
}


class HardBlocker(StrEnum):
    UNRESOLVED_AUTHORITY = "UNRESOLVED_AUTHORITY"
    FABRICATED_OR_UNSUPPORTED_REFERENCE = "FABRICATED_OR_UNSUPPORTED_REFERENCE"
    IRREPRODUCIBLE_HEADLINE_RESULT = "IRREPRODUCIBLE_HEADLINE_RESULT"
    UNRESOLVED_LEAKAGE = "UNRESOLVED_LEAKAGE"
    EVALUATOR_EXPLOITATION = "EVALUATOR_EXPLOITATION"
    OMITTED_REQUIRED_BASELINE = "OMITTED_REQUIRED_BASELINE"
    METHOD_CODE_CONTRADICTION = "METHOD_CODE_CONTRADICTION"
    TABLE_PROSE_CONTRADICTION = "TABLE_PROSE_CONTRADICTION"
    INVALID_STATISTICS = "INVALID_STATISTICS"
    UNSUPPORTED_NOVELTY = "UNSUPPORTED_NOVELTY"
    SELECTION_BIAS = "SELECTION_BIAS"
    FAILED_CLEAN_REPRODUCTION = "FAILED_CLEAN_REPRODUCTION"
    UNSUPPORTED_CENTRAL_CLAIM = "UNSUPPORTED_CENTRAL_CLAIM"
    UNRESOLVED_BLOCKING_CHALLENGE = "UNRESOLVED_BLOCKING_CHALLENGE"
    VENUE_REQUIREMENTS_UNRESOLVED = "VENUE_REQUIREMENTS_UNRESOLVED"


class VenueFamily(StrEnum):
    ML_AI = "ML_AI"
    MEDICAL_IMAGING = "MEDICAL_IMAGING"
    OPERATIONS_RESEARCH = "OPERATIONS_RESEARCH"
    SYSTEMS = "SYSTEMS"


class VenueFit(StrEnum):
    NOT_READY = "NOT_READY"
    WORKSHOP_FIT = "WORKSHOP_FIT"
    SPECIALIZED_CONFERENCE_FIT = "SPECIALIZED_CONFERENCE_FIT"
    SOLID_CONFERENCE_FIT = "SOLID_CONFERENCE_FIT"
    STRONG_CONFERENCE_CANDIDATE = "STRONG_CONFERENCE_CANDIDATE"
    UNCERTAIN = "UNCERTAIN"


class MetricDirection(StrEnum):
    HIGHER_IS_BETTER = "HIGHER_IS_BETTER"
    LOWER_IS_BETTER = "LOWER_IS_BETTER"
    TARGET_IS_BETTER = "TARGET_IS_BETTER"


class MetricEvidenceStatus(StrEnum):
    """Fresh research-state disposition; never selected by the paper caller."""

    SCIENTIFIC_ELIGIBLE = "SCIENTIFIC_ELIGIBLE"
    NON_EVIDENTIARY = "NON_EVIDENTIARY"


class ConfirmatoryAuthorityScope(StrEnum):
    NON_EVIDENTIARY_FIXTURE = "NON_EVIDENTIARY_FIXTURE"
    SCIENTIFIC_EVIDENCE = "SCIENTIFIC_EVIDENCE"


class ReferenceDepth(StrEnum):
    LEVEL_0 = "LEVEL_0"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"
    LEVEL_4 = "LEVEL_4"
    LEVEL_5 = "LEVEL_5"

    @property
    def ordinal(self) -> int:
        return int(self.value.rsplit("_", 1)[1])


@dataclass(frozen=True, slots=True)
class StateAuthoritySourceBinding:
    """Exact registry record consumed by the research-state semantic resolver."""

    artifact_hash: str
    artifact_record_hash: str
    logical_type: str
    creator_role: Role

    def __post_init__(self) -> None:
        validate_sha256(self.artifact_hash, "state authority artifact")
        validate_sha256(self.artifact_record_hash, "state authority record hash")
        _text(self.logical_type, "state authority logical type", maximum=512)
        if not isinstance(self.creator_role, Role):
            raise ValidationError("state authority creator role must be typed")


@dataclass(frozen=True, slots=True)
class AuthoritativeMetric:
    metric_id: str
    value: float
    unit: str
    direction: MetricDirection
    result_artifact_hash: str
    result_state_artifact_hash: str
    canonical_metric_id: str
    result_value_key: str | None = None
    tolerance: float = 0.0
    metric_state_artifact_hash: str | None = None
    scientific_evidence_status: MetricEvidenceStatus = (
        MetricEvidenceStatus.NON_EVIDENTIARY
    )
    result_authority_sources: tuple[StateAuthoritySourceBinding, ...] = ()
    metric_authority_sources: tuple[StateAuthoritySourceBinding, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.metric_id, "metric ID")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise ValidationError("metric value must be numeric")
        if not math.isfinite(float(self.value)):
            raise ValidationError("metric value must be finite")
        _text(self.unit, "metric unit", maximum=128)
        if not isinstance(self.direction, MetricDirection):
            raise ValidationError("metric direction must be typed")
        validate_sha256(self.result_artifact_hash, "metric result artifact")
        validate_sha256(self.result_state_artifact_hash, "canonical result-state artifact")
        validate_identifier(self.canonical_metric_id, "canonical metric ID")
        if self.result_value_key is not None:
            validate_identifier(self.result_value_key, "result value key")
        if (
            isinstance(self.tolerance, bool)
            or not isinstance(self.tolerance, (int, float))
            or not math.isfinite(float(self.tolerance))
            or self.tolerance < 0
        ):
            raise ValidationError("metric tolerance must be finite and non-negative")
        if self.metric_state_artifact_hash is not None:
            validate_sha256(
                self.metric_state_artifact_hash,
                "canonical metric-state artifact",
            )
        if not isinstance(self.scientific_evidence_status, MetricEvidenceStatus):
            raise ValidationError("metric scientific-evidence status must be typed")
        for name in ("result_authority_sources", "metric_authority_sources"):
            values = getattr(self, name)
            if (
                not isinstance(values, tuple)
                or len(values) > MAX_ITEMS
                or any(
                    not isinstance(item, StateAuthoritySourceBinding)
                    for item in values
                )
                or len({item.artifact_hash for item in values}) != len(values)
            ):
                raise ValidationError(
                    "metric state-authority sources must be bounded and unique"
                )


@dataclass(frozen=True, slots=True)
class PaperNumericAssertion:
    assertion_id: str
    claim_id: str
    metric_id: str
    value: float
    unit: str
    direction: MetricDirection
    source_artifact_hash: str

    def __post_init__(self) -> None:
        validate_identifier(self.assertion_id, "numeric assertion ID")
        validate_identifier(self.claim_id, "numeric assertion claim ID")
        validate_identifier(self.metric_id, "numeric assertion metric ID")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise ValidationError("numeric assertion value must be numeric")
        if not math.isfinite(float(self.value)):
            raise ValidationError("numeric assertion value must be finite")
        _text(self.unit, "numeric assertion unit", maximum=128)
        if not isinstance(self.direction, MetricDirection):
            raise ValidationError("numeric assertion direction must be typed")
        validate_sha256(self.source_artifact_hash, "numeric assertion source")


@dataclass(frozen=True, slots=True)
class PaperClaim:
    claim_id: str
    text: str
    strength: ClaimStrength
    evidence_hashes: tuple[str, ...]
    citation_ids: tuple[str, ...] = ()
    central: bool = False
    claim_type: ClaimType = ClaimType.QUALITATIVE
    scope: str = ""
    confidence: float = 0.0
    verification_method: str = ""
    permitted_strength: ClaimStrength = ClaimStrength.UNSUPPORTED
    dependency_claim_ids: tuple[str, ...] = ()
    evidence_sources: tuple["EvidenceSourceBinding", ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.claim_id, "paper claim ID")
        _text(self.text, "paper claim text")
        if not isinstance(self.strength, ClaimStrength):
            raise ValidationError("paper claim strength must be typed")
        _hashes(self.evidence_hashes, "paper claim evidence", allow_empty=False)
        _identifiers(self.citation_ids, "paper claim citations", allow_empty=True)
        if not isinstance(self.central, bool):
            raise ValidationError("paper claim central flag must be boolean")
        if not isinstance(self.claim_type, ClaimType):
            raise ValidationError("paper claim type must be typed")
        if not isinstance(self.scope, str) or len(self.scope.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValidationError("paper claim scope must be bounded text")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValidationError("paper claim confidence must be bounded")
        object.__setattr__(self, "confidence", float(self.confidence))
        if (
            not isinstance(self.verification_method, str)
            or len(self.verification_method.encode("utf-8")) > MAX_TEXT_BYTES
        ):
            raise ValidationError("paper claim verification method must be bounded text")
        if not isinstance(self.permitted_strength, ClaimStrength):
            raise ValidationError("paper claim permitted strength must be typed")
        _identifiers(
            self.dependency_claim_ids,
            "paper claim dependencies",
            allow_empty=True,
        )
        if (
            not isinstance(self.evidence_sources, tuple)
            or len(self.evidence_sources) > MAX_ITEMS
            or any(
                not isinstance(item, EvidenceSourceBinding)
                for item in self.evidence_sources
            )
            or len(
                {
                    (item.kind, item.evidence_artifact_hash)
                    for item in self.evidence_sources
                }
            )
            != len(self.evidence_sources)
        ):
            raise ValidationError("paper claim evidence-source mapping is malformed")
        if self.evidence_sources and {
            item.evidence_artifact_hash for item in self.evidence_sources
        } != set(self.evidence_hashes):
            raise ValidationError(
                "paper claim evidence-source mapping is incomplete"
            )


@dataclass(frozen=True, slots=True)
class ReferenceUse:
    citation_id: str
    reference_artifact_hash: str
    verification_depth: ReferenceDepth
    supported_claim_ids: tuple[str, ...]
    contradictory_context: bool = False
    source_citation_evidence_artifact_hash: str | None = None
    citation_node_id: str | None = None
    passage_sha256: str | None = None
    passage_locator_sha256: str | None = None
    context_sha256: str | None = None
    semantic_judgment_artifact_hash: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.citation_id, "citation ID")
        validate_sha256(self.reference_artifact_hash, "reference artifact")
        if not isinstance(self.verification_depth, ReferenceDepth):
            raise ValidationError("reference depth must be typed")
        _identifiers(self.supported_claim_ids, "reference supported claims", allow_empty=True)
        if not isinstance(self.contradictory_context, bool):
            raise ValidationError("contradictory-context flag must be boolean")
        authority_fields = (
            self.source_citation_evidence_artifact_hash,
            self.citation_node_id,
            self.passage_sha256,
            self.passage_locator_sha256,
            self.context_sha256,
            self.semantic_judgment_artifact_hash,
        )
        if any(value is not None for value in authority_fields):
            if any(value is None for value in authority_fields):
                raise ValidationError(
                    "claim-bound reference authority must be supplied as one exact projection"
                )
            validate_sha256(
                self.source_citation_evidence_artifact_hash,
                "source-citation evidence artifact",
            )
            validate_identifier(self.citation_node_id, "reference citation node ID")
            for value, label in (
                (self.passage_sha256, "reference passage SHA-256"),
                (self.passage_locator_sha256, "reference passage locator SHA-256"),
                (self.context_sha256, "reference context SHA-256"),
                (
                    self.semantic_judgment_artifact_hash,
                    "reference semantic-judgment artifact",
                ),
            ):
                validate_sha256(value, label)


@dataclass(frozen=True, slots=True)
class GeneratedAsset:
    asset_id: str
    kind: str
    artifact_hash: str
    authoritative_parent_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.asset_id, "generated asset ID")
        if self.kind not in {"TABLE", "FIGURE"}:
            raise ValidationError("generated asset kind must be TABLE or FIGURE")
        validate_sha256(self.artifact_hash, "generated asset")
        _hashes(self.authoritative_parent_hashes, "asset parents", allow_empty=False)


@dataclass(frozen=True, slots=True)
class EvidenceSourceBinding:
    """Registry parents that give one typed claim-evidence edge its meaning."""

    kind: EvidenceKind
    evidence_artifact_hash: str
    source_artifact_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceKind):
            raise ValidationError("evidence-source binding kind must be typed")
        validate_sha256(self.evidence_artifact_hash, "claim evidence artifact")
        _hashes(
            self.source_artifact_hashes,
            "claim evidence source artifacts",
            allow_empty=True,
        )
        if (
            self.kind is EvidenceKind.SOURCE_CITATION
            and len(self.source_artifact_hashes) not in {1, 3}
        ):
            raise ValidationError(
                "SOURCE_CITATION evidence requires one diagnostic source or "
                "exactly three scientific source artifacts"
            )


@dataclass(frozen=True, slots=True)
class GeneratedAssetRequirement:
    """A table or figure that canonical claim evidence requires the paper to expose."""

    kind: str
    artifact_hash: str
    authoritative_parent_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.kind not in {"TABLE", "FIGURE"}:
            raise ValidationError("generated-asset requirement must be TABLE or FIGURE")
        validate_sha256(self.artifact_hash, "required generated asset")
        _hashes(
            self.authoritative_parent_hashes,
            "required generated-asset parents",
            allow_empty=False,
        )


@dataclass(frozen=True, slots=True)
class ConfirmatoryClaimAuthority:
    """Exact trusted-kernel protocol/custody/reveal/result chain for one claim."""

    claim_id: str
    run_id: str
    timeline_receipt_hash: str
    protocol_artifact_hash: str
    fresh_custody_receipt_hash: str
    custody_record_hash: str
    result_artifact_hash: str
    protocol_hash: str
    study_id: str
    study_version: int
    holdout_identity_hash: str
    seal_hash: str
    release_id: str
    scope: ConfirmatoryAuthorityScope
    scientific_gate_passed: bool

    def __post_init__(self) -> None:
        validate_identifier(self.claim_id, "confirmatory claim ID")
        validate_identifier(self.run_id, "confirmatory run ID")
        for name in (
            "timeline_receipt_hash",
            "protocol_artifact_hash",
            "fresh_custody_receipt_hash",
            "custody_record_hash",
            "result_artifact_hash",
            "protocol_hash",
            "holdout_identity_hash",
            "seal_hash",
            "release_id",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        validate_identifier(self.study_id, "confirmatory study ID")
        if (
            isinstance(self.study_version, bool)
            or not isinstance(self.study_version, int)
            or self.study_version < 1
        ):
            raise ValidationError("confirmatory study version must be positive")
        if not isinstance(self.scope, ConfirmatoryAuthorityScope):
            raise ValidationError("confirmatory authority scope must be typed")
        if not isinstance(self.scientific_gate_passed, bool):
            raise ValidationError("confirmatory scientific-gate result must be boolean")
        if self.scientific_gate_passed is not (
            self.scope is ConfirmatoryAuthorityScope.SCIENTIFIC_EVIDENCE
        ):
            raise ValidationError(
                "confirmatory scientific status conflicts with its derived scope"
            )


@dataclass(frozen=True, slots=True)
class ReferenceAuthorityBinding:
    """Compact paper projection of one freshly replayed claim-bound citation."""

    run_id: str
    claim_id: str
    claim_text: str
    claim_scope: str
    claim_graph_artifact_hash: str
    claim_semantics_proposal_artifact_hash: str
    source_citation_evidence_id: str
    source_citation_evidence_artifact_hash: str
    source_citation_evidence_record_hash: str
    citation_graph_artifact_hash: str
    citation_graph_record_hash: str
    citation_node_id: str
    citation_node_record_sha256: str
    citation_id: str
    reference_artifact_hash: str
    reference_record_hash: str
    passage_sha256: str
    passage_locator_sha256: str
    context_sha256: str
    transport_execution_authority_artifact_hash: str
    semantic_judgment_artifact_hash: str
    semantic_judgment_record_hash: str
    semantic_judgment_evidence_artifact_hashes: tuple[str, ...]
    semantic_judgment_context_artifact_hashes: tuple[str, ...]
    semantic_judgment_custody_artifact_hashes: tuple[str, ...]
    semantic_projection_sha256: str
    permitted_strength: ClaimStrength
    evidence_artifact_hashes: tuple[str, ...]
    evidence_record_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "reference authority run ID")
        validate_identifier(self.claim_id, "reference authority claim ID")
        validate_identifier(
            self.source_citation_evidence_id,
            "reference authority evidence ID",
        )
        validate_identifier(self.citation_node_id, "reference authority citation node ID")
        validate_identifier(self.citation_id, "reference authority citation ID")
        _text(self.claim_text, "reference authority claim text")
        _text(self.claim_scope, "reference authority claim scope")
        for name in (
            "claim_graph_artifact_hash",
            "claim_semantics_proposal_artifact_hash",
            "source_citation_evidence_artifact_hash",
            "source_citation_evidence_record_hash",
            "citation_graph_artifact_hash",
            "citation_graph_record_hash",
            "citation_node_record_sha256",
            "reference_artifact_hash",
            "reference_record_hash",
            "passage_sha256",
            "passage_locator_sha256",
            "context_sha256",
            "transport_execution_authority_artifact_hash",
            "semantic_judgment_artifact_hash",
            "semantic_judgment_record_hash",
            "semantic_projection_sha256",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if not isinstance(self.permitted_strength, ClaimStrength):
            raise ValidationError("reference authority permitted strength must be typed")
        _hashes(
            self.evidence_artifact_hashes,
            "reference authority evidence artifacts",
            allow_empty=False,
        )
        _hashes(
            self.evidence_record_hashes,
            "reference authority evidence record hashes",
            allow_empty=False,
        )
        _hashes(
            self.semantic_judgment_evidence_artifact_hashes,
            "reference-support judgment evidence artifacts",
            allow_empty=False,
        )
        _hashes(
            self.semantic_judgment_context_artifact_hashes,
            "reference-support judgment context artifacts",
            allow_empty=False,
        )
        _hashes(
            self.semantic_judgment_custody_artifact_hashes,
            "reference-support judgment custody artifacts",
            allow_empty=False,
        )
        expected_closure = tuple(
            sorted(
                {
                    self.source_citation_evidence_artifact_hash,
                    self.claim_semantics_proposal_artifact_hash,
                    self.semantic_judgment_artifact_hash,
                    *self.semantic_judgment_evidence_artifact_hashes,
                    *self.semantic_judgment_context_artifact_hashes,
                    *self.semantic_judgment_custody_artifact_hashes,
                }
            )
        )
        if (
            len(self.evidence_artifact_hashes) != len(self.evidence_record_hashes)
            or self.evidence_artifact_hashes
            != tuple(sorted(self.evidence_artifact_hashes))
            or self.evidence_artifact_hashes != expected_closure
            or self.semantic_judgment_evidence_artifact_hashes
            != tuple(sorted(self.semantic_judgment_evidence_artifact_hashes))
            or self.semantic_judgment_context_artifact_hashes
            != (self.claim_semantics_proposal_artifact_hash,)
            or len(self.semantic_judgment_custody_artifact_hashes) != 7
            or len(set(self.semantic_judgment_custody_artifact_hashes)) != 7
            or not {
                self.claim_graph_artifact_hash,
                self.source_citation_evidence_artifact_hash,
                self.citation_graph_artifact_hash,
                self.reference_artifact_hash,
                self.transport_execution_authority_artifact_hash,
            }.issubset(self.semantic_judgment_evidence_artifact_hashes)
        ):
            raise ValidationError(
                "reference authority evidence bindings are incomplete or non-canonical"
            )


@dataclass(frozen=True, slots=True)
class ClaimPaperRequirements:
    """Deterministic writer obligations derived from one canonical claim."""

    claim_id: str
    claim_type: ClaimType
    evidence_sources: tuple[EvidenceSourceBinding, ...]
    required_metric_ids: tuple[str, ...]
    required_reference_artifact_hashes: tuple[str, ...]
    required_method_code_bindings: tuple["MethodCodeBinding", ...]
    required_generated_assets: tuple[GeneratedAssetRequirement, ...]
    required_reference_authorities: tuple[ReferenceAuthorityBinding, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.claim_id, "paper-requirement claim ID")
        if not isinstance(self.claim_type, ClaimType):
            raise ValidationError("paper-requirement claim type must be typed")
        if (
            not isinstance(self.evidence_sources, tuple)
            or len(self.evidence_sources) > MAX_ITEMS
            or any(not isinstance(item, EvidenceSourceBinding) for item in self.evidence_sources)
            or len(
                {(item.kind, item.evidence_artifact_hash) for item in self.evidence_sources}
            )
            != len(self.evidence_sources)
        ):
            raise ValidationError("claim evidence-source requirements must be unique and typed")
        _identifiers(self.required_metric_ids, "required metric IDs", allow_empty=True)
        _hashes(
            self.required_reference_artifact_hashes,
            "required reference artifacts",
            allow_empty=True,
        )
        if (
            not isinstance(self.required_method_code_bindings, tuple)
            or len(self.required_method_code_bindings) > MAX_ITEMS
            or any(
                not isinstance(item, MethodCodeBinding)
                for item in self.required_method_code_bindings
            )
            or len(set(self.required_method_code_bindings))
            != len(self.required_method_code_bindings)
        ):
            raise ValidationError("required method/code bindings must be unique and typed")
        if (
            not isinstance(self.required_generated_assets, tuple)
            or len(self.required_generated_assets) > MAX_ITEMS
            or any(
                not isinstance(item, GeneratedAssetRequirement)
                for item in self.required_generated_assets
            )
            or len({item.artifact_hash for item in self.required_generated_assets})
            != len(self.required_generated_assets)
        ):
            raise ValidationError("required generated assets must be unique and typed")
        if (
            not isinstance(self.required_reference_authorities, tuple)
            or len(self.required_reference_authorities) > MAX_ITEMS
            or any(
                not isinstance(item, ReferenceAuthorityBinding)
                for item in self.required_reference_authorities
            )
            or len(
                {
                    (
                        item.claim_id,
                        item.source_citation_evidence_artifact_hash,
                        item.reference_artifact_hash,
                    )
                    for item in self.required_reference_authorities
                }
            )
            != len(self.required_reference_authorities)
            or any(
                item.claim_id != self.claim_id
                or item.reference_artifact_hash
                not in self.required_reference_artifact_hashes
                for item in self.required_reference_authorities
            )
        ):
            raise ValidationError(
                "required reference authorities must be unique claim-bound projections"
            )


@dataclass(frozen=True, slots=True)
class AuthoritativeClaim:
    """Exact writer authority derived from state plus a freshly checked graph."""

    claim_id: str
    text: str
    expressed_strength: ClaimStrength
    permitted_strength: ClaimStrength
    evidence_hashes: tuple[str, ...]
    claim_state_artifact_hash: str
    graph_decision_hash: str
    claim_semantics_artifact_hash: str
    producer_role: Role
    claim_semantics_evidence_scope: ClaimSemanticsEvidenceScope
    confidence: float
    verification_method: str
    scientific_writer_eligible: bool
    evidence_use: ClaimEvidenceUse = ClaimEvidenceUse.SCIENTIFIC
    claim_type: ClaimType = ClaimType.QUALITATIVE
    scope: str = ""
    dependency_claim_ids: tuple[str, ...] = ()
    source_artifact_ids: tuple[str, ...] = ()
    requirements: ClaimPaperRequirements | None = None
    confirmatory: bool = False
    confirmatory_authority: ConfirmatoryClaimAuthority | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.claim_id, "authoritative claim ID")
        _text(self.text, "authoritative claim text")
        if not isinstance(self.expressed_strength, ClaimStrength) or not isinstance(
            self.permitted_strength, ClaimStrength
        ):
            raise ValidationError("authoritative claim strengths must be typed")
        _hashes(self.evidence_hashes, "authoritative claim evidence", allow_empty=False)
        validate_sha256(self.claim_state_artifact_hash, "claim-state artifact")
        validate_sha256(self.graph_decision_hash, "claim-graph decision")
        validate_sha256(
            self.claim_semantics_artifact_hash,
            "claim-semantics artifact",
        )
        if not isinstance(self.producer_role, Role):
            raise ValidationError("authoritative claim producer role must be typed")
        if self.producer_role is Role.CLAIM_VERIFIER:
            raise ValidationError(
                "claim verifier cannot produce the claim whose semantics it attests"
            )
        if not isinstance(
            self.claim_semantics_evidence_scope,
            ClaimSemanticsEvidenceScope,
        ):
            raise ValidationError(
                "authoritative claim-semantics evidence scope must be typed"
            )
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValidationError("authoritative claim confidence must be bounded")
        object.__setattr__(self, "confidence", float(self.confidence))
        _text(self.verification_method, "authoritative claim verification method")
        if not isinstance(self.scientific_writer_eligible, bool):
            raise ValidationError("scientific writer eligibility must be boolean")
        if not isinstance(self.evidence_use, ClaimEvidenceUse):
            raise ValidationError("authoritative claim evidence use must be typed")
        if (
            self.claim_semantics_evidence_scope
            is ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE
        ) != (self.evidence_use is ClaimEvidenceUse.SCIENTIFIC):
            raise ValidationError(
                "scientific claim semantics conflict with graph evidence use"
            )
        if self.scientific_writer_eligible and (
            self.evidence_use is not ClaimEvidenceUse.SCIENTIFIC
            or self.claim_semantics_evidence_scope
            is not ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE
        ):
            raise ValidationError("authoritative writer eligibility conflicts with evidence use")
        if not isinstance(self.claim_type, ClaimType):
            raise ValidationError("authoritative claim type must be typed")
        if not isinstance(self.scope, str) or len(self.scope.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValidationError("authoritative claim scope must be bounded text")
        _identifiers(
            self.dependency_claim_ids,
            "authoritative claim dependencies",
            allow_empty=True,
        )
        _hashes(
            self.source_artifact_ids,
            "authoritative claim source artifacts",
            allow_empty=True,
        )
        if self.requirements is not None and (
            not isinstance(self.requirements, ClaimPaperRequirements)
            or self.requirements.claim_id != self.claim_id
            or self.requirements.claim_type is not self.claim_type
        ):
            raise ValidationError("authoritative claim requirements conflict with claim identity")
        if self.scientific_writer_eligible:
            if self.requirements is None:
                raise ValidationError(
                    "scientific writer authority requires exact paper obligations"
                )
            reference_authorities = self.requirements.required_reference_authorities
            if (
                len(reference_authorities)
                != len(self.requirements.required_reference_artifact_hashes)
                or {item.reference_artifact_hash for item in reference_authorities}
                != set(self.requirements.required_reference_artifact_hashes)
                or any(
                    item.claim_id != self.claim_id
                    or item.claim_text != self.text
                    or item.claim_scope != self.scope
                    or _CLAIM_STRENGTH_RANK[item.permitted_strength]
                    < _CLAIM_STRENGTH_RANK[self.expressed_strength]
                    or _CLAIM_STRENGTH_RANK[item.permitted_strength]
                    > _CLAIM_STRENGTH_RANK[self.permitted_strength]
                    for item in reference_authorities
                )
            ):
                raise ValidationError(
                    "scientific claim reference authorities are incomplete or substituted"
                )
        elif (
            self.requirements is not None
            and self.requirements.required_reference_authorities
        ):
            raise ValidationError(
                "non-scientific claim cannot retain scientific reference authority"
            )
        if not isinstance(self.confirmatory, bool):
            raise ValidationError("authoritative confirmatory flag must be boolean")
        if self.confirmatory != (self.confirmatory_authority is not None):
            raise ValidationError(
                "confirmatory claims require exact protocol/custody/reveal authority"
            )
        if (
            self.confirmatory_authority is not None
            and self.confirmatory_authority.claim_id != self.claim_id
        ):
            raise ValidationError("confirmatory authority is bound to a different claim")


@dataclass(frozen=True, slots=True)
class MethodCodeBinding:
    """Raw method/code identity bound through canonical Method/Implementation state."""

    method_artifact_hash: str
    code_artifact_hash: str
    method_state_artifact_hash: str
    implementation_state_artifact_hash: str
    authority_sources: tuple[StateAuthoritySourceBinding, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "method_artifact_hash",
            "code_artifact_hash",
            "method_state_artifact_hash",
            "implementation_state_artifact_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if (
            not isinstance(self.authority_sources, tuple)
            or len(self.authority_sources) > MAX_ITEMS
            or any(
                not isinstance(item, StateAuthoritySourceBinding)
                for item in self.authority_sources
            )
            or len({item.artifact_hash for item in self.authority_sources})
            != len(self.authority_sources)
        ):
            raise ValidationError(
                "method/code authority sources must be bounded and unique"
            )


@dataclass(frozen=True, slots=True)
class AuthoritativeResearchBundle:
    research_state_hash: str
    claim_graph_hash: str
    claims: tuple[AuthoritativeClaim, ...]
    central_claim_ids: tuple[str, ...]
    authoritative_evidence_hashes: tuple[str, ...]
    metrics: tuple[AuthoritativeMetric, ...]
    method_code_bindings: tuple[MethodCodeBinding, ...]
    required_limitations: tuple[str, ...]
    required_baselines_complete: bool
    leakage_resolved: bool
    evaluator_exploitation_resolved: bool
    statistics_valid: bool
    novelty_supported: bool
    selection_integrity_valid: bool
    clean_reproduction_passed: bool
    soundness_verdict: SoundnessVerdict
    soundness_assessment_hash: str
    external_validation_complete: bool
    confirmatory_claim_authority_hashes: tuple[str, ...] = ()
    run_id: str | None = None
    research_state_artifact_hashes: tuple[str, ...] = ()
    research_state_ledger_head_hash: str | None = None
    research_state_ledger_event_count: int | None = None
    research_state_code_version: str | None = None
    research_state_configuration_hash: str | None = None

    def __post_init__(self) -> None:
        validate_sha256(self.research_state_hash, "research-state artifact")
        validate_sha256(self.claim_graph_hash, "claim-graph artifact")
        _typed_unique(self.claims, AuthoritativeClaim, "authoritative claims", lambda item: item.claim_id)
        _identifiers(self.central_claim_ids, "central claim IDs", allow_empty=False)
        if not set(self.central_claim_ids).issubset({item.claim_id for item in self.claims}):
            raise ValidationError("central claims must resolve in authoritative claim state")
        _hashes(self.authoritative_evidence_hashes, "authoritative evidence", allow_empty=False)
        if (
            not isinstance(self.metrics, tuple)
            or len(self.metrics) > MAX_ITEMS
            or any(not isinstance(item, AuthoritativeMetric) for item in self.metrics)
            or len({item.metric_id for item in self.metrics}) != len(self.metrics)
        ):
            raise ValidationError("authoritative metrics must be a bounded unique typed tuple")
        if (
            not isinstance(self.method_code_bindings, tuple)
            or len(self.method_code_bindings) > MAX_ITEMS
            or any(not isinstance(item, MethodCodeBinding) for item in self.method_code_bindings)
            or len(set(self.method_code_bindings)) != len(self.method_code_bindings)
        ):
            raise ValidationError("method/code bindings must be a bounded unique tuple")
        _texts(self.required_limitations, "required limitations", allow_empty=True)
        for name in (
            "required_baselines_complete",
            "leakage_resolved",
            "evaluator_exploitation_resolved",
            "statistics_valid",
            "novelty_supported",
            "selection_integrity_valid",
            "clean_reproduction_passed",
            "external_validation_complete",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"{name} must be boolean")
        if not isinstance(self.soundness_verdict, SoundnessVerdict):
            raise ValidationError("soundness verdict must be typed")
        validate_sha256(self.soundness_assessment_hash, "soundness assessment")
        _hashes(
            self.confirmatory_claim_authority_hashes,
            "confirmatory claim authority artifacts",
            allow_empty=True,
        )
        if self.confirmatory_claim_authority_hashes != tuple(
            sorted(self.confirmatory_claim_authority_hashes)
        ):
            raise ValidationError(
                "confirmatory claim authority artifacts must be canonical"
            )
        if set(self.authoritative_evidence_hashes).intersection(
            {
                self.research_state_hash,
                self.claim_graph_hash,
                self.soundness_assessment_hash,
                *self.confirmatory_claim_authority_hashes,
            }
        ):
            raise ValidationError(
                "authoritative evidence cannot duplicate a primary bundle parent"
            )
        if bool(self.confirmatory_claim_authority_hashes) != any(
            item.confirmatory for item in self.claims
        ):
            raise ValidationError(
                "confirmatory claims and claim-scoped authority artifacts must be paired"
            )
        state_authority_values = (
            self.run_id,
            self.research_state_ledger_head_hash,
            self.research_state_ledger_event_count,
            self.research_state_code_version,
            self.research_state_configuration_hash,
        )
        if any(value is not None for value in state_authority_values):
            if any(value is None for value in state_authority_values):
                raise ValidationError(
                    "authoritative bundle research-state binding is incomplete"
                )
            assert self.run_id is not None
            assert self.research_state_ledger_head_hash is not None
            assert self.research_state_ledger_event_count is not None
            assert self.research_state_code_version is not None
            assert self.research_state_configuration_hash is not None
            validate_identifier(self.run_id, "authoritative bundle run ID")
            _hashes(
                self.research_state_artifact_hashes,
                "authoritative research-state artifacts",
                allow_empty=False,
            )
            validate_sha256(
                self.research_state_ledger_head_hash,
                "research-state ledger head",
            )
            if (
                isinstance(self.research_state_ledger_event_count, bool)
                or not isinstance(self.research_state_ledger_event_count, int)
                or self.research_state_ledger_event_count <= 0
            ):
                raise ValidationError("research-state ledger event count is invalid")
            _text(
                self.research_state_code_version,
                "research-state code version",
                maximum=512,
            )
            validate_sha256(
                self.research_state_configuration_hash,
                "research-state configuration",
            )
        elif self.research_state_artifact_hashes:
            raise ValidationError(
                "research-state artifacts require exact live-ledger authority"
            )

    @property
    def eligible_claim_ids(self) -> tuple[str, ...]:
        return tuple(
            item.claim_id for item in self.claims if item.scientific_writer_eligible
        )


@dataclass(frozen=True, slots=True)
class PaperCandidate:
    candidate_id: str
    title: str
    claims: tuple[PaperClaim, ...]
    numeric_assertions: tuple[PaperNumericAssertion, ...]
    references: tuple[ReferenceUse, ...]
    assets: tuple[GeneratedAsset, ...]
    method_code_bindings: tuple[MethodCodeBinding, ...]
    limitations: tuple[str, ...]
    source_bundle_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.candidate_id, "paper candidate ID")
        _text(self.title, "paper title", maximum=1024)
        _typed_unique(self.claims, PaperClaim, "claims", lambda item: item.claim_id)
        _typed_unique(
            self.numeric_assertions,
            PaperNumericAssertion,
            "numeric assertions",
            lambda item: item.assertion_id,
            allow_empty=True,
        )
        _typed_unique(self.references, ReferenceUse, "references", lambda item: item.citation_id, allow_empty=True)
        _typed_unique(self.assets, GeneratedAsset, "assets", lambda item: item.asset_id, allow_empty=True)
        if (
            not isinstance(self.method_code_bindings, tuple)
            or len(self.method_code_bindings) > MAX_ITEMS
            or any(not isinstance(item, MethodCodeBinding) for item in self.method_code_bindings)
            or len(set(self.method_code_bindings)) != len(self.method_code_bindings)
        ):
            raise ValidationError("paper method/code bindings must be bounded")
        _texts(self.limitations, "paper limitations", allow_empty=True)
        _hashes(self.source_bundle_hashes, "paper source bundle", allow_empty=False)


@dataclass(frozen=True, slots=True)
class PaperVerification:
    passed: bool
    blockers: tuple[HardBlocker, ...]
    discrepancies: tuple[str, ...]
    verified_claim_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise ValidationError("paper verification pass flag must be boolean")
        if (
            not isinstance(self.blockers, tuple)
            or any(not isinstance(item, HardBlocker) for item in self.blockers)
            or len(set(self.blockers)) != len(self.blockers)
        ):
            raise ValidationError("paper blockers must be a unique typed tuple")
        _texts(self.discrepancies, "paper discrepancies", allow_empty=True)
        _identifiers(self.verified_claim_ids, "verified paper claim IDs", allow_empty=True)
        if self.passed != (not self.blockers and not self.discrepancies):
            raise ValidationError("paper verification status contradicts its findings")


@dataclass(frozen=True, slots=True)
class _PaperVerificationBundleSource:
    """Ephemeral full paper-bundle replay for downstream consumers."""

    state_authority: ResearchStateAuthoritySnapshot
    bundle: AuthoritativeResearchBundle
    issued_bundle: ArtifactRecord


@dataclass(frozen=True, slots=True)
class _PaperVerificationSource:
    """Exact stored paper structure; full scientific replay remains separate."""

    candidate: PaperCandidate
    bundle: AuthoritativeResearchBundle
    stored_verification: PaperVerification
    record: ArtifactRecord
    payload: Mapping[str, Any]
    candidate_record: ArtifactRecord
    candidate_wrapper: Mapping[str, Any]
    bundle_record: ArtifactRecord
    bundle_wrapper: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _PaperRoundReplay:
    """Completed upstream owners reused only inside one chronological readback."""

    audited_state: ResearchStateAuthoritySnapshot
    soundness: _SemanticChallengerAuditRoundSoundness
    reviews: _SameRoundReviewReplay


def _require_paper_round_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    replay: _PaperRoundReplay,
    *,
    run_id: str,
) -> None:
    """Bind already completed owners to this readback's unchanged source epoch."""

    if (
        type(replay) is not _PaperRoundReplay
        or type(replay.audited_state) is not ResearchStateAuthoritySnapshot
        or type(replay.soundness) is not _SemanticChallengerAuditRoundSoundness
        or type(replay.reviews) is not _SameRoundReviewReplay
        or replay.audited_state.run_id != run_id
        or replay.soundness.assessment.run_id != run_id
        or replay.audited_state.code_version != replay.reviews.code_version
        or replay.audited_state.configuration_hash != replay.reviews.configuration_hash
    ):
        raise ValidationError("paper round replay does not bind exact completed sources")
    _require_same_round_review_snapshot(
        registry, ledger, replay=replay.reviews, run_id=run_id,
    )
    if (
        registry.get_metadata(replay.audited_state.snapshot_artifact_sha256).record_hash
        != replay.audited_state.snapshot_artifact_record_hash
        or registry.get_metadata(replay.soundness.record.sha256) != replay.soundness.record
        or _semantic_challenger_audit_parse_soundness(registry, replay.soundness.record)
        != replay.soundness.assessment
    ):
        raise ValidationError("paper round source records changed after complete replay")


def _resolve_paper_bound_state(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    bundle: AuthoritativeResearchBundle,
    *,
    replay: _PaperRoundReplay | None = None,
) -> ResearchStateAuthoritySnapshot:
    """Route all three paper F checks through the same full bound-state owner."""

    selectors = dict(
        run_id=bundle.run_id,
        snapshot_artifact_hash=bundle.research_state_hash,
        state_artifact_hashes=bundle.research_state_artifact_hashes,
        ledger_head_hash=bundle.research_state_ledger_head_hash,
        ledger_event_count=bundle.research_state_ledger_event_count,
        expected_code_version=bundle.research_state_code_version,
        expected_configuration_hash=bundle.research_state_configuration_hash,
    )
    if replay is None:
        return resolve_bound_research_state_authority(registry, ledger, **selectors)
    _require_paper_round_sources(registry, ledger, replay, run_id=bundle.run_id)
    return _resolve_bound_research_state_authority(
        registry, ledger, **selectors, _review_replay=replay.reviews,
    )


def _require_paper_state_binding_join(
    initial: ResearchStateAuthoritySnapshot,
    final: ResearchStateAuthoritySnapshot,
) -> None:
    """Pure D059 identity comparison of two completed full state owners."""

    from .gates import _SEMANTIC_CHALLENGE_AUDIT_ALLOWED_POST_SNAPSHOT_TYPES

    by_identity = {(item.research_object.object_type, item.research_object.object_id): item for item in final.entries}
    if len(by_identity) != len(final.entries):
        raise ValueError("paper state contains competing canonical identities")
    initial_ids = set()
    for binding in initial.entries:
        identity = binding.research_object.object_type, binding.research_object.object_id
        initial_ids.add(identity)
        if by_identity.get(identity) != binding:
            raise ValueError("paper final state omits or changes an audited canonical binding")
    if any(identity not in initial_ids and identity[0] not in _SEMANTIC_CHALLENGE_AUDIT_ALLOWED_POST_SNAPSHOT_TYPES
           for identity in by_identity):
        raise ValueError("paper final state introduces unaudited scientific core")
    # Type membership restricts additions; their completed owners authenticate
    # them. F may precede S if its full bound prefix retains the identical core.


READINESS_DIMENSIONS = (
    "question_and_importance",
    "novelty",
    "technical_correctness",
    "evidence_quality",
    "statistics",
    "robustness_and_ablations",
    "reproducibility",
    "clarity",
    "limitations",
    "venue_fit",
)


@dataclass(frozen=True, slots=True)
class VenueProfile:
    profile_id: str
    family: VenueFamily
    required_sections: tuple[str, ...]
    artifact_requirements: tuple[str, ...]
    minimum_dimension_score: float = 0.6

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "venue profile ID")
        if not isinstance(self.family, VenueFamily):
            raise ValidationError("venue family must be typed")
        _identifiers(
            self.required_sections,
            "venue required sections",
            allow_empty=False,
        )
        _identifiers(
            self.artifact_requirements,
            "venue artifact requirements",
            allow_empty=False,
        )
        if (
            isinstance(self.minimum_dimension_score, bool)
            or not isinstance(self.minimum_dimension_score, (int, float))
            or not math.isfinite(float(self.minimum_dimension_score))
            or not 0 <= self.minimum_dimension_score <= 1
        ):
            raise ValidationError("venue minimum dimension score must be within [0,1]")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()


_VENUE_PROFILE_SCHEMA = "approved-venue-profile/v1"
_VENUE_PROFILE_COMMAND = ("scientist-one", "register-approved-venue-profile")


def _venue_classification_policy() -> dict[str, Any]:
    """Return a fresh immutable-by-construction projection of policy constants."""

    return {
        "schema_version": "venue-classification-policy/v1",
        "strong_conference_candidate": {
            "minimum_mean_score": 0.9,
            "minimum_dimension_score": 0.8,
        },
        "solid_conference_fit": {
            "minimum_mean_score": 0.8,
            "minimum_dimension_score": 0.7,
        },
        "specialized_conference_fit": {
            "minimum_mean_score": 0.0,
            "minimum_dimension_score": "profile.minimum_dimension_score",
        },
        "below_profile_minimum": VenueFit.WORKSHOP_FIT.value,
        "external_validation_incomplete": VenueFit.UNCERTAIN.value,
        "unresolved_authority": VenueFit.NOT_READY.value,
    }


def _approved_venue_profile(profile: VenueProfile) -> VenueProfile:
    if not isinstance(profile, VenueProfile):
        raise ValidationError("venue policy requires a typed approved profile")
    matches = tuple(
        candidate
        for candidate in default_venue_profiles()
        if candidate.profile_id == profile.profile_id
    )
    if len(matches) != 1 or matches[0] != profile:
        raise ValidationError("venue profile is not an approved source-owned policy")
    return matches[0]


def register_approved_venue_profile(
    registry: ArtifactRegistry,
    profile: VenueProfile,
) -> ArtifactRecord:
    """Freeze one code-approved venue policy; callers cannot alter its floors."""

    approved = _approved_venue_profile(profile)
    return registry.put_json(
        {
            "schema_version": _VENUE_PROFILE_SCHEMA,
            "profile": _plain_json(approved),
            "classification_policy": _venue_classification_policy(),
        },
        logical_type="approved_venue_profile",
        origin="source-owned bounded venue policy",
        creator_role=Role.PROTOCOL_DESIGNER,
        creation_command=_VENUE_PROFILE_COMMAND,
        parent_artifacts=(),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def require_approved_venue_profile(
    registry: ArtifactRegistry,
    profile_artifact_hash: str,
    *,
    expected_profile_id: str | None = None,
) -> VenueProfile:
    """Reopen one exact immutable approved profile from the registry."""

    record, value = _read_registry_json(
        registry,
        profile_artifact_hash,
        logical_type="approved_venue_profile",
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    payload = _require_exact_keys(
        value,
        {"schema_version", "profile", "classification_policy"},
        "approved venue profile",
    )
    profile_value = _require_exact_keys(
        payload["profile"],
        {
            "profile_id",
            "family",
            "required_sections",
            "artifact_requirements",
            "minimum_dimension_score",
        },
        "approved venue profile payload",
    )
    try:
        profile = VenueProfile(
            profile_id=profile_value["profile_id"],
            family=VenueFamily(profile_value["family"]),
            required_sections=_sequence(
                profile_value["required_sections"],
                "approved venue required sections",
            ),
            artifact_requirements=_sequence(
                profile_value["artifact_requirements"],
                "approved venue artifact requirements",
            ),
            minimum_dimension_score=profile_value["minimum_dimension_score"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("approved venue profile payload is malformed") from exc
    approved = _approved_venue_profile(profile)
    if (
        record.schema_version != "1.0"
        or record.origin != "source-owned bounded venue policy"
        or record.creation_command != _VENUE_PROFILE_COMMAND
        or record.parent_artifacts
        or payload["schema_version"] != _VENUE_PROFILE_SCHEMA
        or payload["profile"] != _plain_json(approved)
        or payload["classification_policy"] != _venue_classification_policy()
        or (
            expected_profile_id is not None
            and approved.profile_id != expected_profile_id
        )
    ):
        raise ValidationError("approved venue profile authority was substituted")
    return approved


@dataclass(frozen=True, slots=True)
class ManuscriptSection:
    section_id: str
    source_artifact_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.section_id, "manuscript section ID")
        _hashes(
            self.source_artifact_hashes,
            "manuscript section sources",
            allow_empty=False,
        )


@dataclass(frozen=True, slots=True)
class ArtifactReadinessBinding:
    requirement: str
    artifact_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.requirement, "venue artifact requirement")
        _hashes(
            self.artifact_hashes,
            "venue artifact-requirement sources",
            allow_empty=False,
        )


_VENUE_READINESS_V1_ORIGIN = (
    "structural venue inventory; no manuscript prose authority"
)
_VENUE_READINESS_V2_ORIGIN = (
    "scientific-reviewer venue requirement coverage over exact paper authority"
)
_VENUE_READINESS_COMMAND = ("scientist-one", "register-venue-readiness")


@dataclass(frozen=True, slots=True)
class VenueReadinessManifest:
    run_id: str
    candidate_id: str
    candidate_artifact_hash: str
    bundle_artifact_hash: str
    manuscript_artifact_hash: str
    profile_id: str
    profile_sha256: str
    profile_artifact_hash: str
    sections: tuple[ManuscriptSection, ...]
    artifact_bindings: tuple[ArtifactReadinessBinding, ...]
    source_artifact_hashes: tuple[str, ...]
    manuscript_revision_artifact_hash: str | None = None
    manuscript_content_artifact_hash: str | None = None
    composition_verification_artifact_hash: str | None = None
    schema_version: str = "venue-readiness/v2"

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "venue-readiness run ID")
        validate_identifier(self.candidate_id, "venue-readiness candidate ID")
        validate_identifier(self.profile_id, "venue-readiness profile ID")
        for name in (
            "candidate_artifact_hash",
            "bundle_artifact_hash",
            "manuscript_artifact_hash",
            "profile_sha256",
            "profile_artifact_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        revision_values = (
            self.manuscript_revision_artifact_hash,
            self.manuscript_content_artifact_hash,
            self.composition_verification_artifact_hash,
        )
        if any(item is not None for item in revision_values):
            if any(item is None for item in revision_values):
                raise ValidationError("venue-readiness revision binding is incomplete")
            for item in revision_values:
                assert item is not None
                validate_sha256(item, "venue-readiness revision artifact")
        if (
            not isinstance(self.sections, tuple)
            or not self.sections
            or len(self.sections) > MAX_ITEMS
            or any(not isinstance(item, ManuscriptSection) for item in self.sections)
            or len({item.section_id for item in self.sections}) != len(self.sections)
        ):
            raise ValidationError("venue-readiness sections must be bounded and unique")
        if (
            not isinstance(self.artifact_bindings, tuple)
            or not self.artifact_bindings
            or len(self.artifact_bindings) > MAX_ITEMS
            or any(
                not isinstance(item, ArtifactReadinessBinding)
                for item in self.artifact_bindings
            )
            or len({item.requirement for item in self.artifact_bindings})
            != len(self.artifact_bindings)
        ):
            raise ValidationError(
            "venue-readiness artifact bindings must be bounded and unique"
            )
        _hashes(
            self.source_artifact_hashes,
            "venue-readiness source artifacts",
            allow_empty=False,
        )
        derived_sources = tuple(
            dict.fromkeys(
                hash_value
                for collection in (
                    *(item.source_artifact_hashes for item in self.sections),
                    *(item.artifact_hashes for item in self.artifact_bindings),
                )
                for hash_value in collection
            )
        )
        expected_sources = tuple(dict.fromkeys((*derived_sources, *((self.manuscript_content_artifact_hash,) if self.manuscript_content_artifact_hash else ()))))
        if self.source_artifact_hashes != expected_sources:
            raise ValidationError(
                "venue-readiness source inventory is incomplete or reordered"
            )
        if self.schema_version not in {"venue-readiness/v1", "venue-readiness/v2"}:
            raise ValidationError("unsupported venue-readiness schema")
        if self.schema_version == "venue-readiness/v1":
            if any(item is not None for item in revision_values):
                raise ValidationError("legacy venue-readiness cannot bind manuscript prose")
        elif any(item is None for item in revision_values):
            raise ValidationError("venue-readiness/v2 requires issued manuscript prose")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


@dataclass(frozen=True, slots=True)
class VenueRequirementReceipt:
    """Exact authority that one profile requirement is actually satisfied."""

    receipt_id: str
    run_id: str
    requirement: str
    candidate_artifact_hash: str
    bundle_artifact_hash: str
    profile_id: str
    profile_sha256: str
    profile_artifact_hash: str
    readiness_manifest_hash: str
    source_artifact_hashes: tuple[str, ...]
    semantic_judgment_hash: str | None
    schema_version: str = "venue-requirement-receipt/v1"

    def __post_init__(self) -> None:
        for name in ("receipt_id", "run_id", "requirement", "profile_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        for name in (
            "candidate_artifact_hash",
            "bundle_artifact_hash",
            "profile_sha256",
            "profile_artifact_hash",
            "readiness_manifest_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        _hashes(
            self.source_artifact_hashes,
            "venue requirement source artifacts",
            allow_empty=False,
        )
        if self.semantic_judgment_hash is not None:
            validate_sha256(
                self.semantic_judgment_hash,
                "venue requirement semantic judgment",
            )
        if self.schema_version != "venue-requirement-receipt/v1":
            raise ValidationError("unsupported venue requirement-receipt schema")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


@dataclass(frozen=True, slots=True)
class VenueDimensionAssessmentReceipt:
    """One semantic readiness score over an exact candidate and requirement set."""

    assessment_id: str
    run_id: str
    dimension: str
    score: float
    candidate_artifact_hash: str
    bundle_artifact_hash: str
    profile_id: str
    profile_sha256: str
    profile_artifact_hash: str
    readiness_manifest_hash: str
    requirement_receipt_hashes: tuple[str, ...]
    semantic_judgment_hash: str
    schema_version: str = "venue-dimension-assessment/v1"

    def __post_init__(self) -> None:
        for name in ("assessment_id", "run_id", "dimension", "profile_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        if self.dimension not in READINESS_DIMENSIONS:
            raise ValidationError("venue dimension assessment names an unknown dimension")
        _validate_score(self.score)
        for name in (
            "candidate_artifact_hash",
            "bundle_artifact_hash",
            "profile_sha256",
            "profile_artifact_hash",
            "readiness_manifest_hash",
            "semantic_judgment_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        _hashes(
            self.requirement_receipt_hashes,
            "venue requirement receipt artifacts",
            allow_empty=False,
        )
        if self.schema_version != "venue-dimension-assessment/v1":
            raise ValidationError("unsupported venue dimension-assessment schema")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


@dataclass(frozen=True, slots=True)
class VenueAssessment:
    profile_id: str
    classification: VenueFit
    dimension_scores: tuple[tuple[str, float], ...]
    hard_blockers: tuple[HardBlocker, ...]
    rationale: str
    run_id: str | None = None
    candidate_artifact_hash: str | None = None
    bundle_artifact_hash: str | None = None
    readiness_manifest_hash: str | None = None
    profile_artifact_hash: str | None = None
    requirement_receipt_hashes: tuple[str, ...] = ()
    dimension_assessment_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "venue assessment profile ID")
        if not isinstance(self.classification, VenueFit):
            raise ValidationError("venue classification must be typed")
        _validate_dimension_scores(self.dimension_scores)
        if any(not isinstance(item, HardBlocker) for item in self.hard_blockers):
            raise ValidationError("venue hard blockers must be typed")
        _text(self.rationale, "venue rationale")
        if self.hard_blockers and self.classification is not VenueFit.NOT_READY:
            raise ValidationError("hard blockers force NOT_READY regardless of numeric score")
        authority_values = (
            self.run_id,
            self.candidate_artifact_hash,
            self.bundle_artifact_hash,
            self.readiness_manifest_hash,
            self.profile_artifact_hash,
        )
        if any(item is not None for item in authority_values):
            if any(item is None for item in authority_values):
                raise ValidationError("venue assessment authority binding is incomplete")
            assert self.run_id is not None
            validate_identifier(self.run_id, "venue assessment run ID")
            for value in authority_values[1:]:
                assert value is not None
                validate_sha256(value, "venue assessment authority artifact")
            _hashes(
                self.requirement_receipt_hashes,
                "venue assessment requirement receipts",
                allow_empty=False,
            )
            _hashes(
                self.dimension_assessment_hashes,
                "venue assessment dimension receipts",
                allow_empty=False,
            )
        elif self.requirement_receipt_hashes or self.dimension_assessment_hashes:
            raise ValidationError("venue assessment receipts require exact authority binding")
        if self.classification is not VenueFit.NOT_READY and self.run_id is None:
            raise ValidationError("positive or uncertain venue fit requires resolved authority")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


@dataclass(frozen=True, slots=True)
class VenueAssessmentAuthority:
    """Final source-owned venue view for one exact paper/profile branch."""

    assessment_id: str
    run_id: str
    candidate_id: str
    venue_family: VenueFamily
    evidence_ids: tuple[str, ...]
    assessed_at: str
    paper_verification_artifact_hash: str
    assessment: VenueAssessment
    schema_version: str = "venue-readiness-assessment/v1"

    def __post_init__(self) -> None:
        validate_identifier(self.assessment_id, "venue assessment authority ID")
        validate_identifier(self.run_id, "venue assessment authority run ID")
        validate_identifier(self.candidate_id, "venue assessment candidate ID")
        if not isinstance(self.venue_family, VenueFamily):
            raise ValidationError("venue assessment authority family must be typed")
        _identifiers(
            self.evidence_ids,
            "venue assessment canonical evidence IDs",
            allow_empty=False,
        )
        _text(self.assessed_at, "venue assessment authority timestamp")
        validate_sha256(
            self.paper_verification_artifact_hash,
            "venue assessment paper-verification artifact",
        )
        if not isinstance(self.assessment, VenueAssessment):
            raise ValidationError("venue assessment authority requires a typed assessment")
        if (
            self.assessment.run_id != self.run_id
            or self.assessment.profile_id == ""
            or self.assessment.candidate_artifact_hash is None
            or self.assessment.bundle_artifact_hash is None
            or self.assessment.profile_artifact_hash is None
            or self.assessment.readiness_manifest_hash is None
            or not self.assessment.requirement_receipt_hashes
            or not self.assessment.dimension_assessment_hashes
        ):
            raise ValidationError(
                "final venue assessment lacks complete source-owned authority"
            )
        if self.schema_version != "venue-readiness-assessment/v1":
            raise ValidationError("unsupported final venue-assessment schema")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


def _build_authoritative_research_bundle(
    registry: ArtifactRegistry,
    *,
    state_authority: ResearchStateAuthoritySnapshot | None = None,
    ledger: EventLedger | None = None,
    run_id: str | None = None,
    confirmatory_timeline_receipt_hashes: tuple[str, ...] = (),
    confirmatory_claim_authority_hashes: tuple[str, ...] = (),
    research_state_hash: str,
    claim_graph_hash: str,
    central_claim_ids: tuple[str, ...],
    authoritative_evidence_hashes: tuple[str, ...],
    metrics: tuple[AuthoritativeMetric, ...],
    method_code_bindings: tuple[MethodCodeBinding, ...],
    required_baselines_complete: bool,
    leakage_resolved: bool,
    evaluator_exploitation_resolved: bool,
    statistics_valid: bool,
    novelty_supported: bool,
    selection_integrity_valid: bool,
    clean_reproduction_passed: bool,
    soundness_assessment_hash: str,
    external_validation_complete: bool,
    _round_replay: _PaperRoundReplay | None = None,
) -> AuthoritativeResearchBundle:
    """Resolve paper authority from immutable registry content.

    The caller may choose the bounded evidence set and policy conservatism, but
    cannot supply claim text, strength, eligibility, result values, method/code
    relationships, or a soundness verdict.  Those are reconstructed from the
    exact frozen artifacts on every build and again on every paper check.
    """

    if not isinstance(registry, ArtifactRegistry):
        raise ValidationError("authoritative paper construction requires an ArtifactRegistry")
    if not isinstance(ledger, EventLedger):
        raise ValidationError(
            "paper authority requires the live research-state EventLedger"
        )
    if run_id is None:
        raise ValidationError("paper authority requires an exact run ID")
    validate_identifier(run_id, "paper authority run ID")
    _hashes(
        confirmatory_timeline_receipt_hashes,
        "confirmatory timeline receipt artifacts",
        allow_empty=True,
    )
    _hashes(
        confirmatory_claim_authority_hashes,
        "confirmatory claim authority artifacts",
        allow_empty=True,
    )
    canonical_confirmatory_claim_authorities = tuple(
        sorted(confirmatory_claim_authority_hashes)
    )
    if confirmatory_claim_authority_hashes != canonical_confirmatory_claim_authorities:
        raise ValidationError(
            "confirmatory claim authority artifacts must be canonical"
        )
    validate_sha256(research_state_hash, "research-state artifact")
    validate_sha256(claim_graph_hash, "claim-graph artifact")
    validate_sha256(soundness_assessment_hash, "soundness assessment")
    _identifiers(central_claim_ids, "central claim IDs", allow_empty=False)
    _hashes(authoritative_evidence_hashes, "authoritative evidence", allow_empty=False)
    _typed_unique(metrics, AuthoritativeMetric, "authoritative metrics", lambda item: item.metric_id)
    if (
        not isinstance(method_code_bindings, tuple)
        or len(method_code_bindings) > MAX_ITEMS
        or any(not isinstance(item, MethodCodeBinding) for item in method_code_bindings)
        or len(set(method_code_bindings)) != len(method_code_bindings)
    ):
        raise ValidationError("method/code bindings must be a bounded unique typed tuple")
    flag_values = {
        "required_baselines_complete": required_baselines_complete,
        "leakage_resolved": leakage_resolved,
        "evaluator_exploitation_resolved": evaluator_exploitation_resolved,
        "statistics_valid": statistics_valid,
        "novelty_supported": novelty_supported,
        "selection_integrity_valid": selection_integrity_valid,
        "clean_reproduction_passed": clean_reproduction_passed,
        "external_validation_complete": external_validation_complete,
    }
    if any(not isinstance(value, bool) for value in flag_values.values()):
        raise ValidationError("paper policy controls must be booleans")

    try:
        if state_authority is None:
            if _round_replay is not None:
                raise ValidationError("same-round paper construction requires fully replayed F")
            state_authority = _resolve_research_state(
                registry,
                ledger,
                research_state_hash,
                run_id=run_id,
            )
        elif type(state_authority) is not ResearchStateAuthoritySnapshot:
            raise ValidationError(
                "paper authority requires an exact research-state snapshot"
            )
        elif (
            state_authority.run_id != run_id
            or state_authority.snapshot_artifact_sha256 != research_state_hash
        ):
            raise ValidationError(
                "resolved research-state projection differs from paper inputs"
            )
        authority_set = set(authoritative_evidence_hashes)
        for digest in authoritative_evidence_hashes:
            _require_frozen_artifact(registry, digest)
        canonical_metrics = tuple(
            sorted(
                (
                    _verify_authoritative_metric(
                        registry,
                        metric,
                        state_authority,
                        authority_set,
                    )
                    for metric in metrics
                ),
                key=lambda item: item.metric_id,
            )
        )
        claims = _resolve_authoritative_claims(
            registry,
            claim_graph_hash,
            state_authority,
            authority_set,
            canonical_metrics,
            ledger=ledger,
            run_id=run_id,
            confirmatory_timeline_receipt_hashes=(
                confirmatory_timeline_receipt_hashes
            ),
        )
        used_timeline_receipts = {
            item.confirmatory_authority.timeline_receipt_hash
            for item in claims
            if item.confirmatory_authority is not None
        }
        if used_timeline_receipts != set(confirmatory_timeline_receipt_hashes):
            raise ValidationError(
                "confirmatory timeline receipts are missing, unused, or substituted"
            )
        if not set(central_claim_ids).issubset({item.claim_id for item in claims}):
            raise ValidationError("a central claim is absent from canonical verified state")
        required_metric_ids = {
            metric_id
            for claim in claims
            if claim.requirements is not None
            for metric_id in claim.requirements.required_metric_ids
        }
        if {item.metric_id for item in canonical_metrics} != required_metric_ids:
            raise ValidationError(
                "paper metrics differ from exact canonical claim requirements"
            )
        canonical_method_bindings = tuple(
            sorted(
                {
                    binding
                    for claim in claims
                    if claim.requirements is not None
                    for binding in claim.requirements.required_method_code_bindings
                },
                key=lambda item: (
                    item.method_state_artifact_hash,
                    item.implementation_state_artifact_hash,
                    item.code_artifact_hash,
                ),
            )
        )
        def method_identity(binding: MethodCodeBinding) -> tuple[str, ...]:
            return (
                binding.method_artifact_hash,
                binding.code_artifact_hash,
                binding.method_state_artifact_hash,
                binding.implementation_state_artifact_hash,
            )

        supplied_by_identity = {
            method_identity(binding): binding for binding in method_code_bindings
        }
        canonical_by_identity = {
            method_identity(binding): binding
            for binding in canonical_method_bindings
        }
        if (
            len(supplied_by_identity) != len(method_code_bindings)
            or set(supplied_by_identity) != set(canonical_by_identity)
            or any(
                supplied_by_identity[key].authority_sources
                and supplied_by_identity[key].authority_sources
                != canonical_by_identity[key].authority_sources
                for key in canonical_by_identity
            )
        ):
            raise ValidationError(
                "method/code bindings differ from canonical claim requirements"
            )
        for binding in canonical_method_bindings:
            if not {
                source.artifact_hash for source in binding.authority_sources
            }.issubset(authority_set):
                raise ValidationError(
                    "paper evidence omits method/code state authority"
                )
            _verify_method_code_binding(registry, binding, state_authority)
        use_live_soundness = (
            _round_replay is not None or bool(canonical_confirmatory_claim_authorities)
        )
        if not use_live_soundness:
            # An empty confirmation tuple does not imply a run-less source.
            # Inspect the exact stored shape only to route the full owner below;
            # never adopt the source's run or treat parsing as source authority.
            use_live_soundness = _semantic_challenger_audit_parse_soundness(
                registry, registry.get_metadata(soundness_assessment_hash)
            ).run_id is not None
        soundness = _resolve_soundness(
            registry,
            soundness_assessment_hash,
            claim_graph_hash=claim_graph_hash,
            central_claim_ids=central_claim_ids,
            ledger=(ledger if use_live_soundness else None),
            run_id=(run_id if use_live_soundness else None),
            confirmatory_claim_authority_hashes=(
                canonical_confirmatory_claim_authorities
            ),
            _round_replay=_round_replay,
        )
        _check_positive_policy_authority(soundness, flag_values)
        authority_closure = _artifact_ancestor_closure(
            registry,
            (
                research_state_hash,
                claim_graph_hash,
                soundness_assessment_hash,
                *canonical_confirmatory_claim_authorities,
            ),
        )
        required_authority_set = _required_paper_evidence_hashes(
            registry,
            claim_graph_hash=claim_graph_hash,
            claims=claims,
            metrics=canonical_metrics,
            method_code_bindings=canonical_method_bindings,
        )
        canonical_authoritative_evidence = tuple(sorted(required_authority_set))
        if authoritative_evidence_hashes != canonical_authoritative_evidence:
            raise ValidationError(
                "paper evidence differs from the exact consumed authority"
            )
        if not required_authority_set.issubset(authority_closure):
            raise ValidationError("consumed paper evidence escapes trusted authority roots")
        required_limitations = _derive_required_limitations(registry, soundness)
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("registry-resolved paper authority is unavailable or corrupt") from exc

    bundle = AuthoritativeResearchBundle(
        research_state_hash=research_state_hash,
        claim_graph_hash=claim_graph_hash,
        claims=claims,
        central_claim_ids=central_claim_ids,
        authoritative_evidence_hashes=authoritative_evidence_hashes,
        metrics=canonical_metrics,
        method_code_bindings=canonical_method_bindings,
        required_limitations=required_limitations,
        required_baselines_complete=required_baselines_complete,
        leakage_resolved=leakage_resolved,
        evaluator_exploitation_resolved=evaluator_exploitation_resolved,
        statistics_valid=statistics_valid,
        novelty_supported=novelty_supported,
        selection_integrity_valid=selection_integrity_valid,
        clean_reproduction_passed=clean_reproduction_passed,
        soundness_verdict=soundness.verdict,
        soundness_assessment_hash=soundness_assessment_hash,
        external_validation_complete=external_validation_complete,
        confirmatory_claim_authority_hashes=(
            canonical_confirmatory_claim_authorities
        ),
        run_id=run_id,
        research_state_artifact_hashes=tuple(
            sorted(item.artifact_sha256 for item in state_authority.entries)
        ),
        research_state_ledger_head_hash=state_authority.ledger_head_hash,
        research_state_ledger_event_count=state_authority.ledger_event_count,
        research_state_code_version=state_authority.code_version,
        research_state_configuration_hash=state_authority.configuration_hash,
    )
    final_state_authority = _resolve_paper_bound_state(
        registry, ledger, bundle, replay=_round_replay,
    )
    if final_state_authority != state_authority:
        raise ValidationError(
            "research-state authority changed during paper-bundle construction"
        )
    return bundle


def build_authoritative_research_bundle(
    registry: ArtifactRegistry,
    *,
    ledger: EventLedger | None = None,
    run_id: str | None = None,
    confirmatory_timeline_receipt_hashes: tuple[str, ...] = (),
    confirmatory_claim_authority_hashes: tuple[str, ...] = (),
    research_state_hash: str,
    claim_graph_hash: str,
    central_claim_ids: tuple[str, ...],
    authoritative_evidence_hashes: tuple[str, ...],
    metrics: tuple[AuthoritativeMetric, ...],
    method_code_bindings: tuple[MethodCodeBinding, ...],
    required_baselines_complete: bool,
    leakage_resolved: bool,
    evaluator_exploitation_resolved: bool,
    statistics_valid: bool,
    novelty_supported: bool,
    selection_integrity_valid: bool,
    clean_reproduction_passed: bool,
    soundness_assessment_hash: str,
    external_validation_complete: bool,
) -> AuthoritativeResearchBundle:
    """Issue a paper bundle from the complete live canonical state."""

    return _build_authoritative_research_bundle(
        registry,
        ledger=ledger,
        run_id=run_id,
        confirmatory_timeline_receipt_hashes=(
            confirmatory_timeline_receipt_hashes
        ),
        confirmatory_claim_authority_hashes=(
            confirmatory_claim_authority_hashes
        ),
        research_state_hash=research_state_hash,
        claim_graph_hash=claim_graph_hash,
        central_claim_ids=central_claim_ids,
        authoritative_evidence_hashes=authoritative_evidence_hashes,
        metrics=metrics,
        method_code_bindings=method_code_bindings,
        required_baselines_complete=required_baselines_complete,
        leakage_resolved=leakage_resolved,
        evaluator_exploitation_resolved=evaluator_exploitation_resolved,
        statistics_valid=statistics_valid,
        novelty_supported=novelty_supported,
        selection_integrity_valid=selection_integrity_valid,
        clean_reproduction_passed=clean_reproduction_passed,
        soundness_assessment_hash=soundness_assessment_hash,
        external_validation_complete=external_validation_complete,
    )


def _require_paper_verification_bundle_source(
    registry: ArtifactRegistry,
    ledger: EventLedger | None,
    bundle: AuthoritativeResearchBundle,
    *,
    _round_replay: _PaperRoundReplay | None = None,
) -> _PaperVerificationBundleSource:
    if (
        bundle.run_id is None
        or bundle.research_state_ledger_head_hash is None
        or bundle.research_state_ledger_event_count is None
        or bundle.research_state_code_version is None
        or bundle.research_state_configuration_hash is None
    ):
        raise ValidationError(
            "paper bundle lacks its frozen research-state projection"
        )
    state_authority = _resolve_paper_bound_state(
        registry, ledger, bundle, replay=_round_replay,
    )
    resolved = _build_authoritative_research_bundle(
        registry,
        state_authority=state_authority,
        ledger=ledger,
        run_id=bundle.run_id,
        confirmatory_timeline_receipt_hashes=tuple(
            item.confirmatory_authority.timeline_receipt_hash
            for item in bundle.claims
            if item.confirmatory_authority is not None
        ),
        confirmatory_claim_authority_hashes=(
            bundle.confirmatory_claim_authority_hashes
        ),
        research_state_hash=bundle.research_state_hash,
        claim_graph_hash=bundle.claim_graph_hash,
        central_claim_ids=bundle.central_claim_ids,
        authoritative_evidence_hashes=bundle.authoritative_evidence_hashes,
        metrics=bundle.metrics,
        method_code_bindings=bundle.method_code_bindings,
        required_baselines_complete=bundle.required_baselines_complete,
        leakage_resolved=bundle.leakage_resolved,
        evaluator_exploitation_resolved=bundle.evaluator_exploitation_resolved,
        statistics_valid=bundle.statistics_valid,
        novelty_supported=bundle.novelty_supported,
        selection_integrity_valid=bundle.selection_integrity_valid,
        clean_reproduction_passed=bundle.clean_reproduction_passed,
        soundness_assessment_hash=bundle.soundness_assessment_hash,
        external_validation_complete=bundle.external_validation_complete,
        _round_replay=_round_replay,
    )
    if resolved != bundle:
        raise ValidationError("supplied paper bundle differs from registry-derived authority")
    issued_bundle = _find_issued_authoritative_bundle(
        registry,
        ledger,
        bundle,
        _round_replay=_round_replay,
    )
    return _PaperVerificationBundleSource(
        state_authority=state_authority,
        bundle=resolved,
        issued_bundle=issued_bundle,
    )


def verify_paper(
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    registry: ArtifactRegistry | None = None,
    ledger: EventLedger | None = None,
) -> PaperVerification:
    if not isinstance(candidate, PaperCandidate) or not isinstance(bundle, AuthoritativeResearchBundle):
        raise ValidationError("paper verification requires typed candidate and bundle")
    if registry is None:
        return PaperVerification(
            passed=False,
            blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
            discrepancies=("authoritative_registry_required",),
            verified_claim_ids=(),
        )
    try:
        source = _require_paper_verification_bundle_source(
            registry,
            ledger,
            bundle,
        )
        # Retain source-field failures inside the historical diagnostic boundary.
        _resolved = source.bundle
        _issued_bundle = source.issued_bundle
    except Exception:
        return PaperVerification(
            passed=False,
            blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
            discrepancies=("authoritative_bundle_does_not_resolve",),
            verified_claim_ids=(),
        )

    return _verify_paper_from_replayed_bundle(candidate, source, registry, ledger)


def _verify_paper_from_replayed_bundle(
    candidate: PaperCandidate,
    source: _PaperVerificationBundleSource,
    registry: ArtifactRegistry,
    ledger: EventLedger | None,
) -> PaperVerification:
    """Run unchanged downstream checks after complete bundle-source replay.

    This private factoring neither authenticates a supplied source DTO nor
    replaces the public owner's complete source admission.
    """

    resolved = source.bundle
    issued_bundle = source.issued_bundle
    blockers: set[HardBlocker] = set()
    discrepancies: list[str] = []
    if not _candidate_source_bundle_resolves(
        registry,
        candidate,
        resolved,
        issued_bundle_artifact_hash=issued_bundle.sha256,
    ):
        blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
        discrepancies.append("paper_is_not_bound_to_complete_authoritative_bundle")
    claim_by_id = {item.claim_id: item for item in candidate.claims}
    authoritative_claims = {item.claim_id: item for item in resolved.claims}
    verified_claims: list[str] = []
    for claim in candidate.claims:
        authority = authoritative_claims.get(claim.claim_id)
        requirements = authority.requirements if authority is not None else None
        claim_supported = (
            authority is not None
            and authority.scientific_writer_eligible
            and claim.text == authority.text
            and claim.strength is authority.expressed_strength
            and set(claim.evidence_hashes) == set(authority.evidence_hashes)
            and claim.claim_type is authority.claim_type
            and claim.scope == authority.scope
            and claim.confidence == authority.confidence
            and claim.verification_method == authority.verification_method
            and claim.permitted_strength is authority.permitted_strength
            and claim.dependency_claim_ids == authority.dependency_claim_ids
            and requirements is not None
            and claim.evidence_sources == requirements.evidence_sources
        )
        if not claim_supported:
            blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
            discrepancies.append(f"unsupported_claim:{claim.claim_id}")
            if authority is not None:
                if not authority.scientific_writer_eligible:
                    blockers.add(HardBlocker.UNRESOLVED_AUTHORITY)
                    discrepancies.append(
                        f"claim_lacks_scientific_writer_authority:{claim.claim_id}"
                    )
                if claim.text != authority.text:
                    discrepancies.append(f"claim_text_mismatch:{claim.claim_id}")
                if claim.strength is not authority.expressed_strength:
                    discrepancies.append(f"claim_strength_mismatch:{claim.claim_id}")
                if set(claim.evidence_hashes) != set(authority.evidence_hashes):
                    discrepancies.append(f"claim_evidence_mismatch:{claim.claim_id}")
                if claim.claim_type is not authority.claim_type:
                    discrepancies.append(f"claim_type_mismatch:{claim.claim_id}")
                if claim.scope != authority.scope:
                    discrepancies.append(f"claim_scope_mismatch:{claim.claim_id}")
                if claim.confidence != authority.confidence:
                    discrepancies.append(f"claim_confidence_mismatch:{claim.claim_id}")
                if claim.verification_method != authority.verification_method:
                    discrepancies.append(
                        f"claim_verification_method_mismatch:{claim.claim_id}"
                    )
                if claim.permitted_strength is not authority.permitted_strength:
                    discrepancies.append(
                        f"claim_permitted_strength_mismatch:{claim.claim_id}"
                    )
                if claim.dependency_claim_ids != authority.dependency_claim_ids:
                    discrepancies.append(
                        f"claim_dependencies_mismatch:{claim.claim_id}"
                    )
                if requirements is None or (
                    claim.evidence_sources != requirements.evidence_sources
                ):
                    discrepancies.append(
                        f"claim_evidence_sources_mismatch:{claim.claim_id}"
                    )
        else:
            verified_claims.append(claim.claim_id)
        missing_dependencies = set(claim.dependency_claim_ids) - set(claim_by_id)
        if missing_dependencies:
            blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
            discrepancies.extend(
                f"missing_dependency_claim:{claim.claim_id}:{dependency_id}"
                for dependency_id in sorted(missing_dependencies)
            )
        should_be_central = claim.claim_id in resolved.central_claim_ids
        if claim.central is not should_be_central:
            blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
            discrepancies.append(f"central_claim_mislabeled:{claim.claim_id}")
    missing_central = set(resolved.central_claim_ids) - set(claim_by_id)
    if missing_central:
        blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
        discrepancies.extend(f"missing_central_claim:{item}" for item in sorted(missing_central))

    required_claims = {
        claim_id: authoritative_claims[claim_id].requirements
        for claim_id in claim_by_id
        if claim_id in authoritative_claims
    }
    if any(requirement is None for requirement in required_claims.values()):
        blockers.add(HardBlocker.UNRESOLVED_AUTHORITY)
        discrepancies.append("canonical_claim_requirements_are_missing")
    required_metric_ids = {
        metric_id
        for requirement in required_claims.values()
        if requirement is not None
        for metric_id in requirement.required_metric_ids
    }
    ineligible_required_metrics = tuple(
        sorted(
            metric.metric_id
            for metric in resolved.metrics
            if metric.metric_id in required_metric_ids
            and metric.scientific_evidence_status
            is not MetricEvidenceStatus.SCIENTIFIC_ELIGIBLE
        )
    )
    if ineligible_required_metrics:
        blockers.add(HardBlocker.IRREPRODUCIBLE_HEADLINE_RESULT)
        discrepancies.extend(
            f"metric_lacks_scientific_evidence_authority:{metric_id}"
            for metric_id in ineligible_required_metrics
        )

    references = {item.citation_id: item for item in candidate.references}
    required_reference_pairs = {
        (claim_id, reference_hash)
        for claim_id, requirement in required_claims.items()
        if requirement is not None
        for reference_hash in requirement.required_reference_artifact_hashes
    }
    supplied_reference_pairs = {
        (claim_id, reference.reference_artifact_hash)
        for reference in candidate.references
        for claim_id in reference.supported_claim_ids
    }
    if (
        any(not reference.supported_claim_ids for reference in candidate.references)
        or supplied_reference_pairs != required_reference_pairs
    ):
        blockers.add(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE)
        discrepancies.append("paper_reference_inventory_does_not_match")
    for claim in candidate.claims:
        for citation_id in claim.citation_ids:
            reference = references.get(citation_id)
            if reference is None or claim.claim_id not in reference.supported_claim_ids:
                blockers.add(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE)
                discrepancies.append(f"unsupported_reference:{claim.claim_id}:{citation_id}")
    for reference in candidate.references:
        try:
            _verify_reference_use(
                registry,
                reference,
                authoritative_claims,
                set(resolved.authoritative_evidence_hashes),
                ledger=ledger,
                run_id=resolved.run_id,
                claim_graph_artifact_hash=resolved.claim_graph_hash,
            )
        except Exception:
            blockers.add(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE)
            discrepancies.append(f"unresolved_reference:{reference.citation_id}")

    for claim_id, requirement in required_claims.items():
        if requirement is None:
            continue
        paper_claim = claim_by_id[claim_id]
        for reference_hash in requirement.required_reference_artifact_hashes:
            matches = tuple(
                reference
                for reference in candidate.references
                if reference.reference_artifact_hash == reference_hash
                and claim_id in reference.supported_claim_ids
                and reference.citation_id in paper_claim.citation_ids
            )
            if len(matches) != 1:
                blockers.add(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE)
                discrepancies.append(
                    f"missing_required_reference:{claim_id}:{reference_hash}"
                )
        supported_citation_ids = {
            reference.citation_id
            for reference in candidate.references
            if claim_id in reference.supported_claim_ids
        }
        if set(paper_claim.citation_ids) != supported_citation_ids:
            blockers.add(HardBlocker.FABRICATED_OR_UNSUPPORTED_REFERENCE)
            discrepancies.append(f"claim_reference_bindings_do_not_match:{claim_id}")

    metrics = {item.metric_id: item for item in resolved.metrics}
    for assertion in candidate.numeric_assertions:
        expected = metrics.get(assertion.metric_id)
        if assertion.claim_id not in claim_by_id:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"numeric_assertion_unknown_claim:{assertion.assertion_id}")
        if expected is None:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"unknown_metric:{assertion.metric_id}")
            continue
        requirement = required_claims.get(assertion.claim_id)
        if (
            requirement is not None
            and assertion.metric_id not in requirement.required_metric_ids
        ):
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(
                f"metric_not_required_by_claim:{assertion.assertion_id}"
            )
        if assertion.source_artifact_hash != expected.result_artifact_hash:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"metric_source_mismatch:{assertion.assertion_id}")
        if assertion.unit != expected.unit:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"metric_unit_mismatch:{assertion.assertion_id}")
        if assertion.direction is not expected.direction:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"metric_direction_mismatch:{assertion.assertion_id}")
        if not _exact_numeric_equal(assertion.value, expected.value):
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"metric_value_mismatch:{assertion.assertion_id}")

    for claim_id, requirement in required_claims.items():
        if requirement is None:
            continue
        for metric_id in requirement.required_metric_ids:
            matches = tuple(
                assertion
                for assertion in candidate.numeric_assertions
                if assertion.claim_id == claim_id and assertion.metric_id == metric_id
            )
            if len(matches) != 1:
                blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
                discrepancies.append(f"missing_required_metric:{claim_id}:{metric_id}")

    if set(candidate.method_code_bindings) != set(resolved.method_code_bindings):
        blockers.add(HardBlocker.METHOD_CODE_CONTRADICTION)
        discrepancies.append("method_code_bindings_do_not_match")
    asset_authority_roots = {
        item.result_artifact_hash for item in resolved.metrics
    } | {
        digest for claim in resolved.claims for digest in claim.evidence_hashes
    }
    required_asset_keys = {
        (
            asset.kind,
            asset.artifact_hash,
            asset.authoritative_parent_hashes,
        )
        for requirement in required_claims.values()
        if requirement is not None
        for asset in requirement.required_generated_assets
    }
    supplied_asset_keys = tuple(
        (
            asset.kind,
            asset.artifact_hash,
            asset.authoritative_parent_hashes,
        )
        for asset in candidate.assets
    )
    if (
        len(set(supplied_asset_keys)) != len(supplied_asset_keys)
        or set(supplied_asset_keys) != required_asset_keys
    ):
        blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
        discrepancies.append("paper_asset_inventory_does_not_match")
    for asset in candidate.assets:
        try:
            _verify_generated_asset(
                registry,
                asset,
                set(resolved.authoritative_evidence_hashes),
                asset_authority_roots,
            )
        except Exception:
            blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
            discrepancies.append(f"asset_parentage_does_not_resolve:{asset.asset_id}")
    for claim_id, requirement in required_claims.items():
        if requirement is None:
            continue
        if not set(requirement.required_method_code_bindings).issubset(
            set(candidate.method_code_bindings)
        ):
            blockers.add(HardBlocker.METHOD_CODE_CONTRADICTION)
            discrepancies.append(f"missing_required_method_code:{claim_id}")
        for required_asset in requirement.required_generated_assets:
            matches = tuple(
                asset
                for asset in candidate.assets
                if asset.kind == required_asset.kind
                and asset.artifact_hash == required_asset.artifact_hash
                and asset.authoritative_parent_hashes
                == required_asset.authoritative_parent_hashes
            )
            if len(matches) != 1:
                blockers.add(HardBlocker.TABLE_PROSE_CONTRADICTION)
                discrepancies.append(
                    f"missing_required_asset:{claim_id}:{required_asset.artifact_hash}"
                )
    missing_limitations = set(resolved.required_limitations) - set(candidate.limitations)
    if missing_limitations:
        blockers.add(HardBlocker.UNSUPPORTED_CENTRAL_CLAIM)
        discrepancies.extend(f"missing_limitation:{item}" for item in sorted(missing_limitations))

    policy_flags = (
        (resolved.required_baselines_complete, HardBlocker.OMITTED_REQUIRED_BASELINE),
        (resolved.leakage_resolved, HardBlocker.UNRESOLVED_LEAKAGE),
        (resolved.evaluator_exploitation_resolved, HardBlocker.EVALUATOR_EXPLOITATION),
        (resolved.statistics_valid, HardBlocker.INVALID_STATISTICS),
        (resolved.novelty_supported, HardBlocker.UNSUPPORTED_NOVELTY),
        (resolved.selection_integrity_valid, HardBlocker.SELECTION_BIAS),
        (resolved.clean_reproduction_passed, HardBlocker.FAILED_CLEAN_REPRODUCTION),
    )
    for passed, blocker in policy_flags:
        if not passed:
            blockers.add(blocker)
    if resolved.soundness_verdict not in {SoundnessVerdict.PASS, SoundnessVerdict.CONDITIONAL_PASS}:
        blockers.add(HardBlocker.UNRESOLVED_BLOCKING_CHALLENGE)

    ordered_blockers = tuple(item for item in HardBlocker if item in blockers)
    return PaperVerification(
        passed=not ordered_blockers and not discrepancies,
        blockers=ordered_blockers,
        discrepancies=tuple(discrepancies),
        verified_claim_ids=tuple(sorted(verified_claims)),
    )


def register_paper_verification(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
) -> ArtifactRecord:
    """Persist a paper verdict only after replaying all of its live authority."""

    if not isinstance(registry, ArtifactRegistry) or not isinstance(ledger, EventLedger):
        raise ValidationError("paper verification registration requires registry and ledger")
    validate_identifier(run_id, "paper verification run ID")
    if bundle.run_id != run_id:
        raise ValidationError("paper verification run differs from bundle authority")
    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    verification = verify_paper(candidate, bundle, registry, ledger)
    return registry.put_json(
        {
            "schema_version": "paper-verification/v1",
            "run_id": run_id,
            "candidate_artifact_hash": candidate_artifact_hash,
            "bundle_artifact_hash": bundle_artifact_hash,
            "verification": _plain_json(verification),
        },
        logical_type="paper_verification",
        origin="fresh registry-and-ledger replay of exact paper authority",
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=("scientist-one", "verify-paper-authority"),
        parent_artifacts=(candidate_artifact_hash, bundle_artifact_hash),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _read_paper_verification_source(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    verification_artifact_hash: str,
    expected_candidate_id: str | None = None,
) -> _PaperVerificationSource:
    """Read exact stored paper identities without granting fresh paper authority."""

    if not isinstance(registry, ArtifactRegistry) or not isinstance(ledger, EventLedger):
        raise ValidationError("paper verification readback requires registry and ledger")
    validate_identifier(run_id, "paper verification run ID")
    if expected_candidate_id is not None:
        validate_identifier(expected_candidate_id, "expected paper candidate ID")
    record, value = _read_registry_json(
        registry,
        verification_artifact_hash,
        logical_type="paper_verification",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    payload = _require_exact_keys(
        value,
        {
            "schema_version",
            "run_id",
            "candidate_artifact_hash",
            "bundle_artifact_hash",
            "verification",
        },
        "paper verification artifact",
    )
    if (
        record.schema_version != "1.0"
        or record.origin
        != "fresh registry-and-ledger replay of exact paper authority"
        or record.creation_command
        != ("scientist-one", "verify-paper-authority")
        or payload["schema_version"] != "paper-verification/v1"
        or payload["run_id"] != run_id
        or record.parent_artifacts
        != (
            payload["candidate_artifact_hash"],
            payload["bundle_artifact_hash"],
        )
    ):
        raise ValidationError("paper verification receipt is stale or substituted")
    candidate_hash, bundle_hash = record.parent_artifacts
    candidate_record, candidate_wrapper = _read_registry_json(
        registry,
        candidate_hash,
        logical_type="paper_candidate",
        creator_role=Role.PAPER_WRITER,
    )
    bundle_record, bundle_wrapper = _read_registry_json(
        registry,
        bundle_hash,
        logical_type="authoritative_research_bundle",
        creator_role=Role.ORCHESTRATOR,
    )
    candidate_value = candidate_wrapper.get("candidate")
    bundle_value = bundle_wrapper.get("bundle")
    if candidate_value is None or bundle_value is None:
        raise ValidationError("paper verification parents omit typed paper authority")
    try:
        candidate = _paper_candidate_from_json(candidate_value)
        bundle = _authoritative_bundle_from_json(bundle_value)
        if bundle.run_id != run_id:
            raise ValidationError("paper verification bundle belongs to another run")
        if (
            expected_candidate_id is not None
            and candidate.candidate_id != expected_candidate_id
        ):
            raise ValidationError(
                "paper verification names another paper candidate"
            )
        stored = _paper_verification_from_json(payload["verification"])
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("paper verification parents are malformed") from exc
    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_hash,
        bundle_hash,
    )
    return _PaperVerificationSource(
        candidate=candidate,
        bundle=bundle,
        stored_verification=stored,
        record=record,
        payload=payload,
        candidate_record=candidate_record,
        candidate_wrapper=candidate_wrapper,
        bundle_record=bundle_record,
        bundle_wrapper=bundle_wrapper,
    )


def require_paper_verification(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    verification_artifact_hash: str,
    expected_candidate_id: str | None = None,
) -> PaperVerification:
    """Rehydrate and freshly replay one registered paper verification artifact."""

    source = _read_paper_verification_source(
        registry,
        ledger,
        run_id=run_id,
        verification_artifact_hash=verification_artifact_hash,
        expected_candidate_id=expected_candidate_id,
    )
    candidate, bundle = source.candidate, source.bundle
    stored, payload = source.stored_verification, source.payload
    fresh = verify_paper(candidate, bundle, registry, ledger)
    if stored != fresh or payload["verification"] != _plain_json(fresh):
        raise ValidationError("stored paper verification differs from fresh replay")
    return fresh


def _require_paper_verification_with_round_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    verification_artifact_hash: str,
    expected_run_id: str,
    expected_candidate_id: str,
    audited_state: ResearchStateAuthoritySnapshot,
    soundness: _SemanticChallengerAuditRoundSoundness,
    review_replay: _SameRoundReviewReplay,
) -> tuple[PaperVerification, _PaperVerificationBundleSource]:
    """Strict full paper owner inside an already replayed chronological round.

    Unlike public diagnostic verification, failure of any bundle/source owner
    raises. Only a completely replayed paper discrepancy may own a mechanical
    terminal. No stored verdict, supplied DTO or hash ancestry is authority.
    """

    replay = _PaperRoundReplay(audited_state, soundness, review_replay)
    _require_paper_round_sources(registry, ledger, replay, run_id=expected_run_id)
    stored = _read_paper_verification_source(
        registry, ledger, run_id=expected_run_id,
        verification_artifact_hash=verification_artifact_hash,
        expected_candidate_id=expected_candidate_id,
    )
    bundle = stored.bundle
    if (
        bundle.soundness_assessment_hash != soundness.record.sha256
        or bundle.claim_graph_hash != soundness.assessment.claim_graph_artifact_hash
        or bundle.central_claim_ids != soundness.assessment.central_claim_ids
        or bundle.confirmatory_claim_authority_hashes
        != soundness.assessment.confirmatory_claim_authority_hashes
    ):
        raise ValidationError("paper source names another completed Soundness round")
    source = _require_paper_verification_bundle_source(
        registry, ledger, bundle, _round_replay=replay,
    )
    if source.issued_bundle != stored.bundle_record:
        raise ValidationError("paper verification does not consume the exact issued bundle")
    try:
        _require_paper_state_binding_join(audited_state, source.state_authority)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    events = review_replay.ledger_snapshot.events
    issuance = tuple(
        index for index, event in enumerate(events)
        if event.event_id == f"arb-{source.issued_bundle.sha256[:48]}"
    )
    if (
        len(issuance) != 1
        or not source.state_authority.ledger_event_count - 1
        < issuance[0] < review_replay.before_event_index < len(events)
        or any(peer.publication_event_index >= issuance[0] for peer in soundness.semantic_peers)
    ):
        raise ValidationError("paper round sources do not precede the canonical terminal")
    def timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    if not (
        timestamp(soundness.record.created_at)
        <= timestamp(stored.bundle_record.created_at)
        <= timestamp(stored.candidate_record.created_at)
        <= timestamp(stored.record.created_at)
    ):
        raise ValidationError("paper source record chronology was substituted")
    # The outer canonical owner authenticates this exact captured event type.
    # Venue assessed_at is the last canonical dimension's clock, not a paper
    # publication clock. Keep its causal ledger cutoff without importing the
    # terminal-specific timestamp ceiling, including in nested manuscript reads.
    cutoff = events[review_replay.before_event_index]
    if (
        cutoff.metadata.get("object_type") != "VenueAssessment"
        and timestamp(stored.record.created_at) > timestamp(cutoff.timestamp)
    ):
        raise ValidationError("paper source record chronology was substituted")
    fresh = _verify_paper_from_replayed_bundle(stored.candidate, source, registry, ledger)
    if (
        stored.stored_verification != fresh
        or stored.payload["verification"] != _plain_json(fresh)
    ):
        raise ValidationError("stored paper verification differs from full same-round replay")
    _require_paper_round_sources(registry, ledger, replay, run_id=expected_run_id)
    return fresh, source


def _require_frozen_artifact(
    registry: ArtifactRegistry,
    digest: str,
    *,
    logical_type: str | None = None,
    creator_role: Role | None = None,
):
    validate_sha256(digest, "registry artifact")
    if registry.verify(digest, raise_on_error=True) is not True:
        raise ValidationError("registry artifact did not verify")
    record = registry.get_metadata(digest)
    if record.sha256 != digest or record.validation_result != "PASS" or not record.frozen:
        raise ValidationError("paper authority requires a frozen PASS artifact")
    if logical_type is not None and record.logical_type != logical_type:
        raise ValidationError("registry artifact has the wrong logical type")
    if creator_role is not None and record.creator_role is not creator_role:
        raise ValidationError("registry artifact has the wrong creator authority")
    # Force content-address revalidation even when the caller only needs metadata.
    registry.get_bytes(digest)
    return record


def _read_registry_json(
    registry: ArtifactRegistry,
    digest: str,
    *,
    logical_type: str | None = None,
    creator_role: Role | None = None,
) -> tuple[Any, Mapping[str, Any]]:
    record = _require_frozen_artifact(
        registry,
        digest,
        logical_type=logical_type,
        creator_role=creator_role,
    )
    if record.mime_type != "application/json":
        raise ValidationError("authoritative structured artifact must be JSON")
    raw = registry.get_bytes(digest)
    value = safe_json_loads(raw)
    if not isinstance(value, Mapping):
        raise ValidationError("authoritative JSON artifact must contain an object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise ValidationError("authoritative JSON artifact is not canonical")
    return record, value


def _resolve_research_state(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    snapshot_hash: str,
    *,
    run_id: str,
) -> ResearchStateAuthoritySnapshot:
    """Delegate state truth to the repository's live semantic resolver."""

    try:
        return resolve_research_state_authority(
            registry,
            ledger,
            run_id=run_id,
            snapshot_artifact_hash=snapshot_hash,
        )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(
            "canonical research-state authority failed live semantic resolution"
        ) from exc


def _serialized_decisions(graph_value: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    decisions = graph_value.get("decisions")
    if not isinstance(decisions, list):
        raise ValidationError("claim graph omits serialized verifier decisions")
    result: dict[str, Mapping[str, Any]] = {}
    for value in decisions:
        if not isinstance(value, Mapping) or not isinstance(value.get("claim_id"), str):
            raise ValidationError("claim graph contains a malformed verifier decision")
        if value["claim_id"] in result:
            raise ValidationError("claim graph duplicates a verifier decision")
        result[value["claim_id"]] = value
    return result


def _decision_matches(value: Mapping[str, Any], decision: Any) -> bool:
    return (
        value.get("claim_id") == decision.claim_id
        and value.get("decision") == decision.decision.value
        and value.get("verifier_id") == decision.verifier_id
        and value.get("verifier_role") == decision.verifier_role.value
        and value.get("reason") == decision.reason
        and value.get("checked_evidence_hashes") == list(decision.checked_evidence_hashes)
        and value.get("evidence_receipt_hashes") == list(decision.evidence_receipt_hashes)
        and value.get("missing_kinds") == [item.value for item in decision.missing_kinds]
        and value.get("contradictions") == list(decision.contradictions)
        and value.get("sha256") == decision.sha256
    )


_NUMERIC_CLAIM_TYPES = frozenset(
    {
        ClaimType.NUMERICAL,
        ClaimType.COMPARATIVE,
        ClaimType.ROBUSTNESS,
        ClaimType.GENERALIZATION,
        ClaimType.EFFICIENCY,
        ClaimType.CAUSAL,
    }
)
_METHOD_BOUND_CLAIM_TYPES = frozenset(
    {
        ClaimType.NUMERICAL,
        ClaimType.METHODOLOGICAL,
        ClaimType.COMPARATIVE,
        ClaimType.ROBUSTNESS,
        ClaimType.GENERALIZATION,
        ClaimType.EFFICIENCY,
        ClaimType.CAUSAL,
        ClaimType.CONCLUSION,
    }
)


def _derive_evidence_source_bindings(
    registry: ArtifactRegistry,
    material_claim: Any,
    evidence_by_id: Mapping[str, Any],
) -> tuple[EvidenceSourceBinding, ...]:
    bindings: list[EvidenceSourceBinding] = []
    for link in material_claim.evidence_links:
        node = evidence_by_id.get(link.evidence_id)
        if node is None or node.kind is not link.kind:
            raise ValidationError("claim evidence-source binding is missing or mistyped")
        record, value = _read_registry_json(
            registry,
            node.artifact_hash,
            logical_type=f"claim_evidence.{node.kind.value}",
        )
        if value.get("claim_text") not in {None, material_claim.text}:
            raise ValidationError("claim evidence source is bound to different claim text")
        if value.get("evidence_kind") not in {None, node.kind.value}:
            raise ValidationError("claim evidence source declares a different evidence kind")
        declared_source = value.get("source_artifact_hash")
        if declared_source is not None and (
            not isinstance(declared_source, str)
            or record.parent_artifacts != (declared_source,)
        ):
            raise ValidationError("claim evidence source declaration conflicts with registry parents")
        for source_hash in record.parent_artifacts:
            _require_frozen_artifact(registry, source_hash)
        bindings.append(
            EvidenceSourceBinding(
                kind=node.kind,
                evidence_artifact_hash=node.artifact_hash,
                source_artifact_hashes=record.parent_artifacts,
            )
        )
    return tuple(
        sorted(
            bindings,
            key=lambda item: (item.kind.value, item.evidence_artifact_hash),
        )
    )


def _source_hashes_for_kind(
    bindings: tuple[EvidenceSourceBinding, ...],
    kind: EvidenceKind,
) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            source
            for binding in bindings
            if binding.kind is kind
            for source in binding.source_artifact_hashes
        )
    )


def _require_scientific_reference_source_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    claim_id: str,
    claim_text: str,
    claim_scope: str,
    claim_graph_artifact_hash: str,
    claim_semantics_proposal_artifact_hash: str,
    reference_support_semantic_judgment_artifact_hash: str,
    source_citation_evidence_artifact_hash: str,
    reference_artifact_hash: str,
) -> ReferenceAuthorityBinding:
    """Replay the source-owned claim-bound L5 citation authority."""

    source_record, source_value = _read_registry_json(
        registry,
        source_citation_evidence_artifact_hash,
        logical_type="claim_evidence.source_citation",
    )
    if (
        source_value.get("claim_id") != claim_id
        or source_value.get("claim_text") != claim_text
        or len(source_record.parent_artifacts) != 3
        or source_record.parent_artifacts[0] != reference_artifact_hash
    ):
        raise ValidationError(
            "scientific reference is not the exact claim-bound source projection"
        )
    reference_record, wrapper = _read_registry_json(
        registry,
        reference_artifact_hash,
        logical_type="reference_verification",
        creator_role=Role.CLAIM_VERIFIER,
    )
    scholarly_record_hash = wrapper.get("scholarly_record_artifact_hash")
    if not isinstance(scholarly_record_hash, str):
        raise ValidationError(
            "scientific reference omits its normalized scholarly source"
        )
    validate_sha256(
        scholarly_record_hash,
        "scientific reference scholarly-record artifact",
    )
    try:
        _, scholarly_value = _read_registry_json(
            registry,
            scholarly_record_hash,
            logical_type="normalized_scholarly_record",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        scholarly_record = ScholarlyRecord.from_dict(scholarly_value)
        expected_node = CitationGraphNode.from_record(scholarly_record)
        authority = require_audited_claim_bound_reference_authority(
            registry,
            ledger,
            expected_run_id=run_id,
            expected_claim_id=claim_id,
            expected_citation_node_id=expected_node.node_id,
            source_citation_evidence_artifact_sha256=(
                source_citation_evidence_artifact_hash
            ),
            claim_semantics_proposal_artifact_sha256=(
                claim_semantics_proposal_artifact_hash
            ),
            reference_support_semantic_judgment_artifact_sha256=(
                reference_support_semantic_judgment_artifact_hash
            ),
        )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(
            "scientific reference lacks audited-live claim-bound authority"
        ) from exc
    graph_record = _require_frozen_artifact(
        registry,
        claim_graph_artifact_hash,
        logical_type="claim_evidence_graph",
        creator_role=Role.CLAIM_VERIFIER,
    )
    if (
        authority.run_id != run_id
        or authority.claim_id != claim_id
        or authority.claim_text != claim_text
        or authority.claim_scope != claim_scope
        or authority.claim_graph_artifact_sha256 != claim_graph_artifact_hash
        or authority.claim_graph_record_hash != str(graph_record.record_hash)
        or authority.claim_semantics_proposal_artifact_sha256
        != claim_semantics_proposal_artifact_hash
        or authority.semantic_judgment_artifact_sha256
        != reference_support_semantic_judgment_artifact_hash
        or authority.source_citation_evidence_artifact_sha256
        != source_citation_evidence_artifact_hash
        or authority.source_citation_evidence_record_hash
        != str(source_record.record_hash)
        or authority.reference_verification_artifact_sha256
        != reference_artifact_hash
        or authority.reference_verification_record_hash
        != str(reference_record.record_hash)
        or authority.citation_node.to_dict() != expected_node.to_dict()
        or authority.semantic_support is not True
        or authority.material_contextual_contradiction is not False
    ):
        raise ValidationError(
            "scientific reference differs from the canonical claim, graph, or source"
        )
    try:
        permitted_strength = ClaimStrength(authority.permitted_strength)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "scientific reference returned an invalid bounded strength"
        ) from exc
    evidence_bindings = tuple(
        zip(
            authority.evidence_artifact_hashes,
            authority.evidence_record_hashes,
            strict=True,
        )
    )
    if (
        _CLAIM_STRENGTH_RANK[permitted_strength]
        < _CLAIM_STRENGTH_RANK[ClaimStrength.LIMITED]
        or any(
            str(_require_frozen_artifact(registry, digest).record_hash)
            != record_hash
            for digest, record_hash in evidence_bindings
        )
    ):
        raise ValidationError(
            "scientific reference has stale evidence or no positive claim strength"
        )
    return ReferenceAuthorityBinding(
        run_id=authority.run_id,
        claim_id=authority.claim_id,
        claim_text=authority.claim_text,
        claim_scope=authority.claim_scope,
        claim_graph_artifact_hash=authority.claim_graph_artifact_sha256,
        claim_semantics_proposal_artifact_hash=(
            authority.claim_semantics_proposal_artifact_sha256
        ),
        source_citation_evidence_id=authority.source_citation_evidence_id,
        source_citation_evidence_artifact_hash=(
            authority.source_citation_evidence_artifact_sha256
        ),
        source_citation_evidence_record_hash=(
            authority.source_citation_evidence_record_hash
        ),
        citation_graph_artifact_hash=authority.citation_graph_artifact_sha256,
        citation_graph_record_hash=authority.citation_graph_record_hash,
        citation_node_id=authority.citation_node.node_id,
        citation_node_record_sha256=authority.citation_node.record_sha256,
        citation_id=authority.citation_id,
        reference_artifact_hash=(
            authority.reference_verification_artifact_sha256
        ),
        reference_record_hash=authority.reference_verification_record_hash,
        passage_sha256=authority.passage.passage_sha256,
        passage_locator_sha256=authority.passage.locator_sha256,
        context_sha256=authority.passage.context_sha256,
        transport_execution_authority_artifact_hash=(
            authority.transport_execution_authority_artifact_sha256
        ),
        semantic_judgment_artifact_hash=(
            authority.semantic_judgment_artifact_sha256
        ),
        semantic_judgment_record_hash=authority.semantic_judgment_record_hash,
        semantic_judgment_evidence_artifact_hashes=(
            authority.semantic_judgment_evidence_artifact_hashes
        ),
        semantic_judgment_context_artifact_hashes=(
            authority.semantic_judgment_context_artifact_hashes
        ),
        semantic_judgment_custody_artifact_hashes=(
            authority.semantic_judgment_custody_artifact_hashes
        ),
        semantic_projection_sha256=authority.semantic_projection_sha256,
        permitted_strength=permitted_strength,
        evidence_artifact_hashes=authority.evidence_artifact_hashes,
        evidence_record_hashes=authority.evidence_record_hashes,
    )


def _state_authority_source_bindings(
    binding: ResearchStateAuthorityBinding,
) -> tuple[StateAuthoritySourceBinding, ...]:
    values = tuple(
        StateAuthoritySourceBinding(
            artifact_hash=artifact_hash,
            artifact_record_hash=record_hash,
            logical_type=logical_type,
            creator_role=creator_role,
        )
        for artifact_hash, record_hash, logical_type, creator_role in zip(
            binding.authority_artifact_hashes,
            binding.authority_artifact_record_hashes,
            binding.authority_logical_types,
            binding.authority_creator_roles,
        )
    )
    if len(values) != len(binding.authority_artifact_hashes):
        raise ValidationError("research-state authority source projection is incomplete")
    return values


def _resolved_claim_semantics(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
    binding: ResearchStateAuthorityBinding,
) -> tuple[ClaimSemanticsReceipt, StateAuthoritySourceBinding]:
    """Freshly replay the exact source-owned semantics receipt for one Claim."""

    if not isinstance(binding.research_object, StateClaim):
        raise ValidationError("claim semantics require a canonical Claim binding")
    resolved_semantics = binding.claim_semantics
    if not isinstance(resolved_semantics, ClaimSemanticsReceipt):
        raise ValidationError("verified canonical Claim lacks resolved semantics")
    matches = tuple(
        source
        for source in _state_authority_source_bindings(binding)
        if source.logical_type == CLAIM_SEMANTICS_RECEIPT_LOGICAL_TYPE
    )
    if len(matches) != 1 or matches[0].creator_role is not Role.CLAIM_VERIFIER:
        raise ValidationError(
            "canonical Claim does not bind one exact claim-semantics authority"
        )
    graph_sources = tuple(
        digest
        for digest in binding.research_object.source_artifact_ids
        if _require_frozen_artifact(registry, digest).logical_type
        == "claim_evidence_graph"
    )
    if len(graph_sources) != 1:
        raise ValidationError(
            "canonical Claim does not bind one exact claim-evidence graph"
        )
    semantics = require_claim_semantics_receipt(
        registry,
        ledger,
        receipt_artifact_hash=matches[0].artifact_hash,
        expected_run_id=run_id,
        expected_claim_graph_artifact_hash=graph_sources[0],
        expected_claim_id=binding.research_object.claim_id,
    )
    if semantics != resolved_semantics:
        raise ValidationError(
            "canonical Claim semantics differ from fresh source replay"
        )
    return semantics, matches[0]


def _require_scientific_claim_dependency_closure(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
    state_authority: ResearchStateAuthoritySnapshot,
    claim_semantics: ClaimSemanticsReceipt,
) -> None:
    """Reject scientific writing that depends on any non-scientific Claim."""

    pending = list(claim_semantics.dependency_bindings)
    visited: set[str] = set()
    while pending:
        dependency = pending.pop()
        if dependency.state_artifact_hash in visited:
            continue
        visited.add(dependency.state_artifact_hash)
        binding = state_authority.binding_for_artifact(
            dependency.state_artifact_hash
        )
        record = binding.research_object
        if (
            not isinstance(record, StateClaim)
            or record.claim_id != dependency.claim_id
            or record.content_hash != dependency.content_hash
            or binding.artifact_record_hash
            != dependency.state_artifact_record_hash
            or binding.materialization_event_id
            != dependency.materialization_event_id
            or binding.materialization_event_hash
            != dependency.materialization_event_hash
        ):
            raise ValidationError(
                "claim dependency differs from its exact resolved state authority"
            )
        if not binding.scientific_evidence_eligible:
            raise ValidationError(
                "scientific writer claim depends on a non-scientific Claim"
            )
        dependency_semantics, _ = _resolved_claim_semantics(
            registry,
            ledger,
            run_id,
            binding,
        )
        pending.extend(dependency_semantics.dependency_bindings)


def _derive_method_bindings(
    registry: ArtifactRegistry,
    code_artifact_hashes: tuple[str, ...],
    state_authority: ResearchStateAuthoritySnapshot,
) -> tuple[MethodCodeBinding, ...]:
    methods = {
        item.research_object.object_id: item
        for item in state_authority.entries
        if isinstance(item.research_object, StateMethod)
    }
    result: set[MethodCodeBinding] = set()
    for code_hash in code_artifact_hashes:
        code_record = _require_frozen_artifact(registry, code_hash)
        if (
            code_record.logical_type
            not in {
                "experiment_code",
                "autonomous_implementation.reviewed_worker_code",
            }
            or code_record.creator_role is not Role.IMPLEMENTER
        ):
            raise ValidationError("claim code evidence has the wrong type or role")
        matches = [
            item
            for item in state_authority.entries
            if isinstance(item.research_object, StateImplementation)
            and code_hash in item.research_object.code_artifact_hashes
            and any(
                authority_hash == code_hash
                and logical_type == code_record.logical_type
                and creator_role is Role.IMPLEMENTER
                and record_hash == str(code_record.record_hash)
                for authority_hash, record_hash, logical_type, creator_role in zip(
                    item.authority_artifact_hashes,
                    item.authority_artifact_record_hashes,
                    item.authority_logical_types,
                    item.authority_creator_roles,
                )
            )
        ]
        if not matches:
            raise ValidationError(
                "claim code evidence has no canonical Implementation authority"
            )
        method_ids = tuple(
            item.research_object.method_id
            for item in matches
            if isinstance(item.research_object, StateImplementation)
        )
        if (
            len(method_ids) != len(matches)
            or len(set(method_ids)) != len(method_ids)
        ):
            raise ValidationError(
                "claim code evidence has ambiguous same-method Implementation authority"
            )
        for implementation_binding in matches:
            implementation = implementation_binding.research_object
            assert isinstance(implementation, StateImplementation)
            method_binding = methods.get(implementation.method_id)
            if method_binding is None:
                raise ValidationError("canonical Implementation has no matching Method state")
            method = method_binding.research_object
            assert isinstance(method, StateMethod)
            raw_method_matches = tuple(
                authority_hash
                for authority_hash, logical_type, creator_role in zip(
                    method_binding.authority_artifact_hashes,
                    method_binding.authority_logical_types,
                    method_binding.authority_creator_roles,
                )
                if logical_type in {
                    "method_definition",
                    "baseline_method_definition",
                    "autonomous_implementation.admitted_descriptor",
                }
                and creator_role
                in {
                    Role.HYPOTHESIS_DESIGNER,
                    Role.PROTOCOL_DESIGNER,
                    Role.IMPLEMENTER,
                }
            )
            if len(raw_method_matches) != 1:
                raise ValidationError(
                    "canonical Method lacks one exact typed definition authority"
                )
            binding = MethodCodeBinding(
                method_artifact_hash=raw_method_matches[0],
                code_artifact_hash=code_hash,
                method_state_artifact_hash=method_binding.artifact_sha256,
                implementation_state_artifact_hash=(
                    implementation_binding.artifact_sha256
                ),
                authority_sources=tuple(
                    dict.fromkeys(
                        (
                            *_state_authority_source_bindings(method_binding),
                            *_state_authority_source_bindings(
                                implementation_binding
                            ),
                        )
                    )
                ),
            )
            _verify_method_code_binding(registry, binding, state_authority)
            result.add(binding)
    return tuple(
        sorted(
            result,
            key=lambda item: (
                item.method_state_artifact_hash,
                item.implementation_state_artifact_hash,
                item.code_artifact_hash,
            ),
        )
    )


def _derive_claim_paper_requirements(
    registry: ArtifactRegistry,
    claim_semantics: ClaimSemanticsReceipt,
    evidence_sources: tuple[EvidenceSourceBinding, ...],
    metrics: tuple[AuthoritativeMetric, ...],
    state_authority: ResearchStateAuthoritySnapshot,
    ledger: EventLedger | None = None,
    run_id: str | None = None,
) -> ClaimPaperRequirements:
    state_claim_ids = {
        item.research_object.claim_id
        for item in state_authority.entries
        if isinstance(item.research_object, StateClaim)
    }
    if not set(claim_semantics.dependency_claim_ids).issubset(state_claim_ids):
        raise ValidationError("canonical claim has an unresolved dependency claim")

    result_sources = set(
        _source_hashes_for_kind(evidence_sources, EvidenceKind.RESULT)
    )
    expected_metric_bindings: list[tuple[str, str, str, str | None]] = []
    matched_result_sources: set[str] = set()
    for entry in state_authority.entries:
        result = entry.research_object
        if not isinstance(result, StateResult):
            continue
        matching_sources = tuple(
            sorted(set(result.source_artifact_hashes).intersection(result_sources))
        )
        if not matching_sources:
            continue
        if len(matching_sources) != 1:
            raise ValidationError(
                "canonical Result maps one claim to ambiguous raw result sources"
            )
        source_hash = matching_sources[0]
        matched_result_sources.add(source_hash)
        if isinstance(result.value, Mapping):
            if not result.value:
                raise ValidationError("canonical Result mapping is empty")
            result_values = tuple(sorted(result.value.items()))
        else:
            result_values = ((None, result.value),)
        for result_value_key, raw_value in result_values:
            if (
                isinstance(raw_value, bool)
                or not isinstance(raw_value, (int, float))
                or not math.isfinite(float(raw_value))
            ):
                raise ValidationError(
                    "canonical numeric Result contains an unbound non-numeric value"
                )
            if result_value_key is not None:
                validate_identifier(
                    result_value_key,
                    "canonical Result metric value key",
                )
            expected_metric_bindings.append(
                (
                    (
                        result.metric_id
                        if result_value_key is None
                        else f"{result_value_key}-{result.metric_id}"
                    ),
                    entry.artifact_sha256,
                    source_hash,
                    result_value_key,
                )
            )
    if matched_result_sources != result_sources:
        raise ValidationError(
            "claim result evidence is not exactly represented in canonical Result state"
        )
    if len({item[0] for item in expected_metric_bindings}) != len(
        expected_metric_bindings
    ):
        raise ValidationError("canonical Result metrics have ambiguous paper identities")
    expected_metric_by_id = {
        item[0]: item for item in expected_metric_bindings
    }
    supplied_metric_by_id = {
        metric.metric_id: metric
        for metric in metrics
        if metric.metric_id in expected_metric_by_id
    }
    if set(supplied_metric_by_id) != set(expected_metric_by_id) or any(
        metric.result_state_artifact_hash != expected[1]
        or metric.result_artifact_hash != expected[2]
        or metric.result_value_key != expected[3]
        for metric_id, expected in expected_metric_by_id.items()
        for metric in (supplied_metric_by_id[metric_id],)
    ):
        raise ValidationError(
            "paper metrics differ from canonical Result value bindings"
        )
    required_metric_ids = tuple(sorted(expected_metric_by_id))
    if claim_semantics.claim_type in _NUMERIC_CLAIM_TYPES and not required_metric_ids:
        raise ValidationError("numeric canonical claim has no result-bound metric")

    citation_bindings = tuple(
        item
        for item in evidence_sources
        if item.kind is EvidenceKind.SOURCE_CITATION
    )
    reference_hashes: list[str] = []
    for binding in citation_bindings:
        sources = binding.source_artifact_hashes
        if len(sources) == 1:
            if (
                claim_semantics.scientific_writer_eligible
                or claim_semantics.claim_evidence_use
                is ClaimEvidenceUse.SCIENTIFIC
                or claim_semantics.evidence_scope
                is ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE
            ):
                raise ValidationError(
                    "scientific citation requires the exact three-source projection"
                )
            reference = _require_frozen_artifact(
                registry,
                sources[0],
                creator_role=Role.CLAIM_VERIFIER,
            )
            if reference.logical_type != "reference_verification":
                raise ValidationError(
                    "diagnostic citation source is not a reference verification"
                )
            reference_hashes.append(sources[0])
            continue
        if len(sources) != 3:
            raise ValidationError(
                "citation-backed canonical claim has an invalid source projection"
            )
        records = tuple(_require_frozen_artifact(registry, digest) for digest in sources)
        if (
            records[0].logical_type != "reference_verification"
            or records[0].creator_role is not Role.CLAIM_VERIFIER
            or records[1].logical_type != "citation_graph"
            or records[1].creator_role is not Role.EVIDENCE_CURATOR
            or records[2].logical_type
            != AUDITED_TRANSPORT_EXECUTION_AUTHORITY_LOGICAL_TYPE
            or records[2].creator_role is not Role.EVIDENCE_CURATOR
            or records[2].schema_version
            != AUDITED_TRANSPORT_EXECUTION_AUTHORITY_SCHEMA
            or len(records[2].parent_artifacts) != 1
        ):
            raise ValidationError(
                "citation-backed canonical claim reordered or substituted authority"
            )
        if ledger is None or run_id is None:
            raise ValidationError(
                "scientific citation requires live signed transport replay"
            )
        try:
            execution = require_audited_live_transport_execution(
                registry,
                ledger,
                run_id=run_id,
                authority_artifact_sha256=records[2].sha256,
                response_receipt_artifact_sha256=records[2].parent_artifacts[0],
            )
        except Exception as exc:
            raise ValidationError(
                "citation-backed canonical claim lacks current signed transport authority"
            ) from exc
        if (
            execution.response_receipt_artifact.sha256
            != records[2].parent_artifacts[0]
        ):
            raise ValidationError(
                "citation transport authority resolved another response receipt"
            )
        reference_hashes.append(sources[0])
    required_references = tuple(sorted(reference_hashes))
    if len(set(required_references)) != len(required_references):
        raise ValidationError("citation-backed canonical claim has ambiguous references")
    code_sources = _source_hashes_for_kind(evidence_sources, EvidenceKind.CODE)
    method_bindings = (
        _derive_method_bindings(registry, code_sources, state_authority)
        if code_sources
        else ()
    )
    if claim_semantics.claim_type in _METHOD_BOUND_CLAIM_TYPES and not method_bindings:
        raise ValidationError("method-bound canonical claim lacks canonical code provenance")

    asset_requirements: list[GeneratedAssetRequirement] = []
    for source_hash in _source_hashes_for_kind(
        evidence_sources, EvidenceKind.FIGURE_OR_TABLE
    ):
        source_record = _require_frozen_artifact(registry, source_hash)
        logical_type = source_record.logical_type.casefold()
        kind = None
        if "table" in logical_type and source_record.mime_type in {
            "text/csv",
            "application/json",
        }:
            kind = "TABLE"
        elif "figure" in logical_type and source_record.mime_type.startswith("image/"):
            kind = "FIGURE"
        if kind is not None:
            if not source_record.parent_artifacts:
                raise ValidationError("generated claim asset lacks authoritative parents")
            asset_requirements.append(
                GeneratedAssetRequirement(
                    kind,
                    source_hash,
                    source_record.parent_artifacts,
                )
            )
    if claim_semantics.claim_type in _NUMERIC_CLAIM_TYPES and not asset_requirements:
        raise ValidationError("numeric canonical claim lacks a generated result asset")

    return ClaimPaperRequirements(
        claim_id=claim_semantics.claim_id,
        claim_type=claim_semantics.claim_type,
        evidence_sources=evidence_sources,
        required_metric_ids=required_metric_ids,
        required_reference_artifact_hashes=required_references,
        required_method_code_bindings=method_bindings,
        required_generated_assets=tuple(
            sorted(asset_requirements, key=lambda item: item.artifact_hash)
        ),
        required_reference_authorities=(),
    )


def _require_exact_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValidationError(f"{label} schema is invalid")
    return value


def _sequence(value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValidationError(f"{label} must be a bounded JSON array")
    return tuple(value)


def _protocol_from_json(value: Any) -> ResearchProtocol:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(ResearchProtocol)},
        "frozen protocol",
    )

    def exact(model: type, raw: Any, label: str) -> Mapping[str, Any]:
        return _require_exact_keys(raw, {item.name for item in fields(model)}, label)

    data_roles_value = exact(DataRoles, payload["data_roles"], "protocol data roles")
    data_roles = DataRoles(
        **{
            name: _sequence(data_roles_value[name], f"protocol data role {name}")
            for name in ("train", "development", "validation", "holdout")
        }
    )
    candidate_value = exact(
        ExecutionConditions,
        payload["candidate_conditions"],
        "protocol candidate conditions",
    )
    candidate_conditions = ExecutionConditions(**dict(candidate_value))
    baselines = tuple(
        BaselineSpec(
            name=exact(BaselineSpec, item, "protocol baseline")["name"],
            conditions=ExecutionConditions(
                **dict(
                    exact(
                        ExecutionConditions,
                        exact(BaselineSpec, item, "protocol baseline")["conditions"],
                        "protocol baseline conditions",
                    )
                )
            ),
        )
        for item in _sequence(payload["baseline_set"], "protocol baselines")
    )
    domain_nulls = tuple(
        DomainNullSpec(
            **{
                **dict(exact(DomainNullSpec, item, "protocol domain null")),
                "structures_preserved": _sequence(
                    exact(DomainNullSpec, item, "protocol domain null")[
                        "structures_preserved"
                    ],
                    "protocol preserved structures",
                ),
                "assumptions": _sequence(
                    exact(DomainNullSpec, item, "protocol domain null")["assumptions"],
                    "protocol domain-null assumptions",
                ),
            }
        )
        for item in _sequence(payload["domain_nulls"], "protocol domain nulls")
    )
    statistical_tests = tuple(
        StatisticalTestSpec(
            **dict(exact(StatisticalTestSpec, item, "protocol statistical test"))
        )
        for item in _sequence(payload["statistical_tests"], "protocol statistical tests")
    )
    intervals = tuple(
        ConfidenceIntervalSpec(
            **dict(exact(ConfidenceIntervalSpec, item, "protocol confidence interval"))
        )
        for item in _sequence(payload["confidence_intervals"], "protocol confidence intervals")
    )
    seed_value = exact(SeedPolicy, payload["seed_policy"], "protocol seed policy")
    seed_policy = SeedPolicy(
        **{
            **dict(seed_value),
            "seeds": _sequence(seed_value["seeds"], "protocol seeds"),
        }
    )
    compute_budget = ProtocolComputeBudget(
        **dict(
            exact(
                ProtocolComputeBudget,
                payload["compute_budget"],
                "protocol compute budget",
            )
        )
    )
    interpretation_rules = InterpretationRules(
        **dict(
            exact(
                InterpretationRules,
                payload["interpretation_rules"],
                "protocol interpretation rules",
            )
        )
    )
    protocol = ResearchProtocol(
        study_id=payload["study_id"],
        study_version=payload["study_version"],
        primary_hypothesis=payload["primary_hypothesis"],
        primary_estimand=payload["primary_estimand"],
        primary_metric=payload["primary_metric"],
        secondary_metrics=_sequence(payload["secondary_metrics"], "secondary metrics"),
        unit_of_analysis=payload["unit_of_analysis"],
        resampling_unit=payload["resampling_unit"],
        data_exclusions=_sequence(payload["data_exclusions"], "data exclusions"),
        data_roles=data_roles,
        candidate_conditions=candidate_conditions,
        baseline_set=baselines,
        ablation_set=_sequence(payload["ablation_set"], "protocol ablations"),
        negative_controls=_sequence(
            payload["negative_controls"], "protocol negative controls"
        ),
        domain_nulls=domain_nulls,
        statistical_tests=statistical_tests,
        confidence_intervals=intervals,
        multiple_comparison_correction=payload["multiple_comparison_correction"],
        seed_policy=seed_policy,
        compute_budget=compute_budget,
        stopping_rules=_sequence(payload["stopping_rules"], "protocol stopping rules"),
        decision_ladder=_sequence(payload["decision_ladder"], "protocol decision ladder"),
        claim_scope_contract=payload["claim_scope_contract"],
        interpretation_rules=interpretation_rules,
        validity_reserve_fraction=payload["validity_reserve_fraction"],
        reserve_basis=payload["reserve_basis"],
        parent_protocol_hash=payload["parent_protocol_hash"],
        revision_reason=payload["revision_reason"],
    )
    if safe_json_loads(canonical_json_bytes(protocol.canonical_dict)) != value:
        raise ValidationError("frozen protocol does not round-trip through its typed model")
    validate_protocol(protocol)
    return protocol


def _holdout_seal_from_json(value: Any) -> HoldoutSeal:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(HoldoutSeal)},
        "holdout seal",
    )
    return HoldoutSeal(
        **{
            **dict(payload),
            "custody_independence": CustodyIndependence(
                payload["custody_independence"]
            ),
        }
    )


def _holdout_release_from_json(value: Any) -> HoldoutRelease:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(HoldoutRelease)},
        "holdout release",
    )
    return HoldoutRelease(**dict(payload))


def _holdout_access_from_json(value: Any) -> HoldoutAccessRecord:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(HoldoutAccessRecord)},
        "holdout access record",
    )
    return HoldoutAccessRecord(
        **{**dict(payload), "outcome": AccessOutcome(payload["outcome"])}
    )


def _single_evidence_source(
    registry: ArtifactRegistry,
    bindings: tuple[EvidenceSourceBinding, ...],
    kind: EvidenceKind,
    logical_type: str,
) -> str:
    matches = tuple(
        source_hash
        for source_hash in _source_hashes_for_kind(bindings, kind)
        if _require_frozen_artifact(registry, source_hash).logical_type == logical_type
    )
    if len(matches) != 1:
        raise ValidationError(
            f"confirmatory claim requires one exact {logical_type} evidence source"
        )
    return matches[0]


def _resolve_confirmatory_claim_authority(
    registry: ArtifactRegistry,
    claim_id: str,
    evidence_sources: tuple[EvidenceSourceBinding, ...],
    authoritative_evidence: set[str],
    *,
    ledger: EventLedger | None,
    run_id: str | None,
    confirmatory_timeline_receipt_hashes: tuple[str, ...],
) -> ConfirmatoryClaimAuthority:
    """Re-derive protected validity from the existing trusted-kernel artifacts."""

    protocol_hash = _single_evidence_source(
        registry,
        evidence_sources,
        EvidenceKind.PROTOCOL_VERSION,
        "frozen_protocol",
    )
    custody_hash = _single_evidence_source(
        registry,
        evidence_sources,
        EvidenceKind.DATASET_OR_FIXTURE,
        "custody_record",
    )
    result_hash = _single_evidence_source(
        registry,
        evidence_sources,
        EvidenceKind.RESULT,
        "machine_results",
    )
    if ledger is None or run_id is None:
        raise ValidationError(
            "confirmatory claims require exact live-ledger timeline authority"
        )
    custody_metadata = _require_frozen_artifact(
        registry,
        custody_hash,
        logical_type="custody_record",
        creator_role=Role.HOLDOUT_CUSTODIAN,
    )
    protocol_record, protocol_wrapper = _read_registry_json(
        registry,
        protocol_hash,
        logical_type="frozen_protocol",
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    if protocol_record.schema_version != "1.0" or protocol_record.parent_artifacts:
        raise ValidationError("frozen protocol registry metadata is not canonical version one")
    _require_exact_keys(
        protocol_wrapper,
        {
            "kind",
            "frozen",
            "protocol",
            "protocol_sha256",
            "baseline_equivalence",
            "blind_patterns",
            "reproduction_tolerance",
        },
        "frozen protocol wrapper",
    )
    protocol = _protocol_from_json(protocol_wrapper["protocol"])
    expected_equivalence = safe_json_loads(
        canonical_json_bytes([asdict(item) for item in validate_protocol(protocol)])
    )
    if (
        protocol_wrapper["kind"] != "FROZEN_SYNTHETIC_PROTOCOL"
        or protocol_wrapper["frozen"] is not True
        or protocol_wrapper["protocol_sha256"] != protocol.sha256
        or protocol_wrapper["baseline_equivalence"] != expected_equivalence
        or not isinstance(protocol_wrapper["blind_patterns"], list)
        or not protocol_wrapper["blind_patterns"]
        or isinstance(protocol_wrapper["reproduction_tolerance"], bool)
        or not isinstance(protocol_wrapper["reproduction_tolerance"], (int, float))
        or not math.isfinite(float(protocol_wrapper["reproduction_tolerance"]))
        or protocol_wrapper["reproduction_tolerance"] < 0
    ):
        raise ValidationError("frozen protocol wrapper semantics are invalid")

    # Resolve the pre-reveal receipt through the trusted ledger receipt.  The
    # post-reveal custody projection deliberately has more parents than the
    # sealed receipt, so parent-tuple equality would reject every honest run.
    # Conversely, merely accepting any custody ancestor would permit authority
    # substitution.  Enumerating the bounded authoritative set and replaying
    # the public timeline resolver gives one exact live-ledger binding without
    # parsing or reproducing timeline semantics locally.
    fresh_candidates = tuple(
        digest
        for digest in authoritative_evidence
        if (
            (candidate := _require_frozen_artifact(registry, digest)).logical_type
            == "fresh_custody_receipt"
            and candidate.creator_role is Role.HOLDOUT_CUSTODIAN
            and candidate.parent_artifacts[:1] == (protocol_hash,)
            and digest in custody_metadata.parent_artifacts
            and set(candidate.parent_artifacts[1:]).issubset(
                custody_metadata.parent_artifacts
            )
        )
    )
    timeline_matches: list[tuple[str, str, Any]] = []
    for fresh_candidate in fresh_candidates:
        for receipt_hash in confirmatory_timeline_receipt_hashes:
            if receipt_hash not in authoritative_evidence:
                raise ValidationError(
                    "confirmatory timeline receipt is absent from paper evidence"
                )
            try:
                timeline_receipt = require_confirmatory_timeline_receipt(
                    registry,
                    ledger,
                    receipt_artifact_sha256=receipt_hash,
                    run_id=run_id,
                    study_id=protocol.study_id,
                    study_version=protocol.study_version,
                    protocol_artifact_sha256=protocol_hash,
                    fresh_custody_receipt_sha256=fresh_candidate,
                    custody_record_sha256=custody_hash,
                    result_artifact_sha256=result_hash,
                )
            except (ScientificDesignError, ValidationError):
                continue
            timeline_matches.append(
                (fresh_candidate, receipt_hash, timeline_receipt)
            )
    if len(timeline_matches) != 1:
        raise ValidationError(
            "confirmatory claim requires one exact ledger-derived timeline receipt"
        )
    fresh_hash, timeline_receipt_hash, timeline_receipt = timeline_matches[0]
    if not {protocol_hash, custody_hash, result_hash, fresh_hash}.issubset(
        authoritative_evidence
    ):
        raise ValidationError("confirmatory authority is absent from the paper evidence set")

    fresh_record, fresh = _read_registry_json(
        registry,
        fresh_hash,
        logical_type="fresh_custody_receipt",
        creator_role=Role.HOLDOUT_CUSTODIAN,
    )
    if fresh_record.schema_version != "1.0":
        raise ValidationError("pre-reveal custody receipt has an unsupported schema")
    _require_exact_keys(
        fresh,
        {
            "schema_version",
            "study_id",
            "study_version",
            "seal",
            "status",
            "journal_head_hash",
            "journal_identity_sha256",
        },
        "pre-reveal custody receipt",
    )
    if fresh["schema_version"] != "1.0":
        raise ValidationError("pre-reveal custody payload has an unsupported schema")
    seal = _holdout_seal_from_json(fresh["seal"])
    fresh_status = _require_exact_keys(
        fresh["status"],
        {
            "custody_independence",
            "sealed",
            "revealed",
            "invalidated",
            "confirmatory_claims_valid",
            "authorized_access_count",
            "violation_reasons",
            "release_event",
            "durable_journal",
            "journal_head_hash",
        },
        "pre-reveal custody status",
    )
    validate_sha256(fresh["journal_head_hash"], "pre-reveal journal head")
    validate_sha256(fresh["journal_identity_sha256"], "custody journal identity")
    if (
        fresh["study_id"] != protocol.study_id
        or fresh["study_version"] != protocol.study_version
        or seal.protocol_hash != protocol.sha256
        or fresh_record.parent_artifacts[:2]
        != (protocol_hash, seal.pre_unblinding_interpretation_hash)
        or len(fresh_record.parent_artifacts) != 6
        or fresh_status["custody_independence"] != seal.custody_independence.value
        or fresh_status["sealed"] is not True
        or fresh_status["revealed"] is not False
        or fresh_status["invalidated"] is not False
        or fresh_status["confirmatory_claims_valid"] is not False
        or fresh_status["authorized_access_count"] != 0
        or fresh_status["violation_reasons"] != []
        or fresh_status["release_event"] is not None
        or fresh_status["durable_journal"] is not True
        or fresh_status["journal_head_hash"] != fresh["journal_head_hash"]
    ):
        raise ValidationError("pre-reveal custody receipt is not a valid sealed holdout")

    custody_record, custody = _read_registry_json(
        registry,
        custody_hash,
        logical_type="custody_record",
        creator_role=Role.HOLDOUT_CUSTODIAN,
    )
    if custody_record.schema_version != "1.0":
        raise ValidationError("post-reveal custody record has an unsupported schema")
    _require_exact_keys(
        custody,
        {
            "kind",
            "study_id",
            "study_version",
            "custody_independence",
            "holdout_identity_hash",
            "split_manifest_hash",
            "sealing_time",
            "authorized_access_count",
            "access_requester",
            "access_reason",
            "protocol_hash",
            "code_hash",
            "configuration_hash",
            "source_inventory_sha256",
            "configuration_inventory_sha256",
            "split_manifest_artifact_sha256",
            "midrun_review_sha256",
            "resource_charge_artifact_sha256",
            "resource_charge_ledger_event_id",
            "fresh_custody_receipt_sha256",
            "fresh_custody_receipt_event_id",
            "confirmatory_started_event_id",
            "confirmatory_validity_units",
            "pre_unblinding_interpretation_hash",
            "seal_hash",
            "release_event",
            "access_records",
            "confirmatory_claims_valid",
            "durable_journal",
            "journal_path",
            "journal_head_hash",
            "journal_sha256",
            "journal_size",
            "journal_identity_sha256",
            "genuine_independence_claimed",
        },
        "post-reveal custody record",
    )
    release = _holdout_release_from_json(custody["release_event"])
    access_values = _sequence(custody["access_records"], "holdout access records")
    accesses = tuple(_holdout_access_from_json(item) for item in access_values)
    for digest in (
        custody["holdout_identity_hash"],
        custody["split_manifest_hash"],
        custody["protocol_hash"],
        custody["code_hash"],
        custody["configuration_hash"],
        custody["source_inventory_sha256"],
        custody["configuration_inventory_sha256"],
        custody["split_manifest_artifact_sha256"],
        custody["midrun_review_sha256"],
        custody["resource_charge_artifact_sha256"],
        custody["fresh_custody_receipt_sha256"],
        custody["pre_unblinding_interpretation_hash"],
        custody["seal_hash"],
        custody["journal_head_hash"],
        custody["journal_sha256"],
        custody["journal_identity_sha256"],
    ):
        validate_sha256(digest, "post-reveal custody digest")
    if (
        custody["kind"] != "SIMULATED_HOLDOUT_CUSTODY"
        or seal.custody_independence is not CustodyIndependence.NON_INDEPENDENT
        or custody["custody_independence"] != "SIMULATED_NON_INDEPENDENT"
        or custody["genuine_independence_claimed"] is not False
        or custody_record.parent_artifacts
        != (
            protocol_hash,
            custody["source_inventory_sha256"],
            custody["configuration_inventory_sha256"],
            custody["split_manifest_artifact_sha256"],
            custody["pre_unblinding_interpretation_hash"],
            custody["midrun_review_sha256"],
            custody["resource_charge_artifact_sha256"],
            fresh_hash,
        )
        or custody["study_id"] != protocol.study_id
        or custody["study_version"] != protocol.study_version
        or custody["holdout_identity_hash"] != seal.holdout_identity_hash
        or custody["split_manifest_hash"] != seal.split_manifest_hash
        or custody["sealing_time"] != seal.sealed_at
        or custody["protocol_hash"] != protocol.sha256
        or custody["code_hash"] != seal.code_hash
        or custody["configuration_hash"] != seal.configuration_hash
        or custody["source_inventory_sha256"] != fresh_record.parent_artifacts[2]
        or custody["configuration_inventory_sha256"] != fresh_record.parent_artifacts[3]
        or custody["split_manifest_artifact_sha256"]
        != fresh_record.parent_artifacts[4]
        or custody["midrun_review_sha256"] != fresh_record.parent_artifacts[5]
        or custody["fresh_custody_receipt_sha256"] != fresh_hash
        or not isinstance(custody["resource_charge_ledger_event_id"], str)
        or not custody["resource_charge_ledger_event_id"].strip()
        or custody["fresh_custody_receipt_event_id"]
        != timeline_receipt.freeze_event_id
        or custody["confirmatory_started_event_id"]
        != timeline_receipt.confirmatory_started_event_id
        or not isinstance(custody["confirmatory_started_event_id"], str)
        or not custody["confirmatory_started_event_id"].strip()
        or isinstance(custody["confirmatory_validity_units"], bool)
        or not isinstance(custody["confirmatory_validity_units"], int)
        or custody["confirmatory_validity_units"] <= 0
        or custody["pre_unblinding_interpretation_hash"]
        != seal.pre_unblinding_interpretation_hash
        or custody["seal_hash"] != seal.seal_hash
        or custody["authorized_access_count"] != 1
        or custody["confirmatory_claims_valid"] is not True
        or custody["durable_journal"] is not True
        or not isinstance(custody["journal_path"], str)
        or not custody["journal_path"].strip()
        or isinstance(custody["journal_size"], bool)
        or not isinstance(custody["journal_size"], int)
        or custody["journal_size"] <= 0
        or custody["journal_identity_sha256"] != fresh["journal_identity_sha256"]
        or release.seal_hash != seal.seal_hash
        or release.holdout_identity_hash != seal.holdout_identity_hash
        or release.authorized_access_count != 1
        or release.requester != custody["access_requester"]
        or release.reason != custody["access_reason"]
        or len(accesses) != 1
        or accesses[0].authorized is not True
        or accesses[0].outcome is not AccessOutcome.RELEASED
        or accesses[0].authorized_access_count != 1
        or accesses[0].requester != release.requester
        or accesses[0].reason != release.reason
        or accesses[0].requested_at != release.released_at
        or accesses[0].detail != "single authorized confirmatory reveal"
    ):
        raise ValidationError("post-reveal custody semantics do not bind the sealed holdout")
    expected_custody_sources = (
        (
            seal.pre_unblinding_interpretation_hash,
            "blind_interpretation",
            Role.STATISTICIAN,
        ),
        (
            custody["source_inventory_sha256"],
            "frozen_source_inventory",
            Role.ORCHESTRATOR,
        ),
        (
            custody["configuration_inventory_sha256"],
            "frozen_configuration_inventory",
            Role.ORCHESTRATOR,
        ),
        (
            custody["split_manifest_artifact_sha256"],
            "frozen_confirmatory_split",
            Role.PROTOCOL_DESIGNER,
        ),
        (
            custody["midrun_review_sha256"],
            "midrun_review",
            Role.SCIENTIFIC_REVIEWER,
        ),
        (
            custody["resource_charge_artifact_sha256"],
            "resource_runtime_confirmatory_charge",
            Role.ORCHESTRATOR,
        ),
    )
    custody_source_records: dict[str, Any] = {}
    for source_hash, logical_type, creator_role in expected_custody_sources:
        custody_source_records[logical_type] = _require_frozen_artifact(
            registry,
            source_hash,
            logical_type=logical_type,
            creator_role=creator_role,
        )
    ledger_result = ledger.assert_valid()
    run_events = tuple(
        event for event in ledger_result.events if event.run_id == run_id
    )
    charge_matches = tuple(
        (index, event)
        for index, event in enumerate(run_events)
        if event.event_id == custody["resource_charge_ledger_event_id"]
    )
    started_matches = tuple(
        (index, event)
        for index, event in enumerate(run_events)
        if event.event_id == custody["confirmatory_started_event_id"]
    )
    if len(charge_matches) != 1 or len(started_matches) != 1:
        raise ValidationError("confirmatory custody event selectors are not unique")
    charge_index, charge_event = charge_matches[0]
    started_index, started_event = started_matches[0]
    charge_record = custody_source_records["resource_runtime_confirmatory_charge"]
    exact_started_records = (
        protocol_record,
        custody_source_records["frozen_source_inventory"],
        custody_source_records["frozen_configuration_inventory"],
        custody_source_records["frozen_confirmatory_split"],
        custody_source_records["blind_interpretation"],
        custody_source_records["midrun_review"],
        charge_record,
        fresh_record,
    )
    charge_metadata = charge_event.metadata
    started_metadata = started_event.metadata
    charge_checkpoint = charge_metadata.get("resource_authority_checkpoint")
    if (
        not timeline_receipt.freeze_event_index
        < charge_index
        < timeline_receipt.confirmatory_started_event_index
        or started_index != timeline_receipt.confirmatory_started_event_index
        or charge_event.event_type != "CHECKPOINT"
        or charge_event.actor_role is not Role.ORCHESTRATOR
        or charge_event.artifact_hashes != (charge_record.sha256,)
        or tuple(charge_metadata.get("artifact_types", ()))
        != ("resource_runtime_confirmatory_charge",)
        or tuple(charge_metadata.get("artifact_record_hashes", ()))
        != (str(charge_record.record_hash),)
        or not isinstance(charge_checkpoint, Mapping)
        or charge_checkpoint.get("logical_type")
        != "resource_runtime_confirmatory_charge"
        or charge_checkpoint.get("state_sha256") != charge_record.sha256
        or isinstance(charge_checkpoint.get("sequence"), bool)
        or not isinstance(charge_checkpoint.get("sequence"), int)
        or charge_checkpoint["sequence"] < 0
        or not isinstance(charge_checkpoint.get("authority_sha256"), str)
        or started_event.event_type != "CONFIRMATORY_STARTED"
        or started_event.actor_role is not Role.ORCHESTRATOR
        or started_event.requested_state_after.value != "CONFIRM"
        or started_event.artifact_hashes
        != tuple(item.sha256 for item in exact_started_records)
        or tuple(started_metadata.get("artifact_types", ()))
        != tuple(item.logical_type for item in exact_started_records)
        or tuple(started_metadata.get("artifact_record_hashes", ()))
        != tuple(str(item.record_hash) for item in exact_started_records)
        or started_metadata.get("resource_authority_checkpoint")
        != charge_checkpoint
        or charge_event.code_version != seal.code_hash
        or started_event.code_version != seal.code_hash
        or charge_event.configuration_hash != seal.configuration_hash
        or started_event.configuration_hash != seal.configuration_hash
    ):
        raise ValidationError(
            "confirmatory custody events do not bind the exact reveal authority"
        )
    validate_sha256(
        str(charge_checkpoint["authority_sha256"]),
        "confirmatory resource authority",
    )
    access_body = {
        "index": 0,
        "requested_at": accesses[0].requested_at,
        "requester": accesses[0].requester,
        "reason": accesses[0].reason,
        "authorized": True,
        "outcome": AccessOutcome.RELEASED.value,
        "authorized_access_count": 1,
        "detail": "single authorized confirmatory reveal",
    }
    release_body = {
        "seal_hash": seal.seal_hash,
        "released_at": release.released_at,
        "requester": release.requester,
        "reason": release.reason,
        "authorized_access_count": 1,
    }
    if (
        accesses[0].event_id
        != hashlib.sha256(canonical_json_bytes(access_body)).hexdigest()
        or release.release_id
        != hashlib.sha256(canonical_json_bytes(release_body)).hexdigest()
    ):
        raise ValidationError("holdout access or release identity is not canonical")

    result_record, machine = _read_registry_json(
        registry,
        result_hash,
        logical_type="machine_results",
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    if result_record.schema_version != "1.0":
        raise ValidationError("confirmatory machine result has an unsupported schema")
    _require_exact_keys(
        machine,
        {
            "kind",
            "evidence_class",
            "outcome_pattern",
            "dataset_fixture_ids",
            "random_seeds",
            "code_fingerprint",
            "configuration_sha256",
            "input_hashes",
            "scientific_protocol_sha256",
            "frozen_fixture",
            "primary_estimate",
            "control_mean",
            "treatment_mean",
            "n_control",
            "n_treatment",
            "output_hashes",
            "confirmatory_access_count",
            "tuned_after_reveal",
        },
        "confirmatory machine result",
    )
    input_hashes = _require_exact_keys(
        machine["input_hashes"],
        {
            "frozen_protocol",
            "blind_interpretation",
            "custody_record",
            "frozen_source_inventory",
            "frozen_configuration_inventory",
        },
        "confirmatory result inputs",
    )
    fixture = _require_exact_keys(
        machine["frozen_fixture"], {"control", "treatment"}, "confirmatory fixture"
    )
    control = _sequence(fixture["control"], "confirmatory control values")
    treatment = _sequence(fixture["treatment"], "confirmatory treatment values")
    if not control or not treatment or any(
        isinstance(item, bool)
        or not isinstance(item, (int, float))
        or not math.isfinite(float(item))
        for item in (*control, *treatment)
    ):
        raise ValidationError("confirmatory fixture observations are invalid")
    control_mean = math.fsum(float(item) for item in control) / len(control)
    treatment_mean = math.fsum(float(item) for item in treatment) / len(treatment)
    estimate = treatment_mean - control_mean
    result_core = {
        "primary_estimate": machine["primary_estimate"],
        "control_mean": machine["control_mean"],
        "treatment_mean": machine["treatment_mean"],
        "n_control": machine["n_control"],
        "n_treatment": machine["n_treatment"],
    }
    output_hashes = _require_exact_keys(
        machine["output_hashes"], {"result_core"}, "confirmatory output hashes"
    )
    expected_parents = (
        protocol_hash,
        seal.pre_unblinding_interpretation_hash,
        custody_hash,
        fresh_record.parent_artifacts[2],
        fresh_record.parent_artifacts[3],
    )
    if (
        machine["kind"] != "MACHINE_READABLE_RESULTS"
        or machine["evidence_class"] != "SYNTHETIC_CONFIRMATORY_FIXTURE"
        or not isinstance(machine["outcome_pattern"], str)
        or not machine["outcome_pattern"].strip()
        or tuple(_sequence(machine["dataset_fixture_ids"], "confirmatory dataset IDs"))
        != protocol.data_roles.holdout
        or tuple(_sequence(machine["random_seeds"], "confirmatory random seeds"))
        != protocol.seed_policy.seeds
        or machine["code_fingerprint"] != seal.code_hash
        or machine["configuration_sha256"] != seal.configuration_hash
        or input_hashes
        != {
            "frozen_protocol": protocol_hash,
            "blind_interpretation": seal.pre_unblinding_interpretation_hash,
            "custody_record": custody_hash,
            "frozen_source_inventory": fresh_record.parent_artifacts[2],
            "frozen_configuration_inventory": fresh_record.parent_artifacts[3],
        }
        or machine["scientific_protocol_sha256"] != protocol.sha256
        or hashlib.sha256(canonical_json_bytes(fixture)).hexdigest()
        != seal.holdout_identity_hash
        or machine["confirmatory_access_count"] != 1
        or machine["tuned_after_reveal"] is not False
        or result_record.parent_artifacts != expected_parents
        or machine["n_control"] != len(control)
        or machine["n_treatment"] != len(treatment)
        or not math.isclose(float(machine["control_mean"]), control_mean, abs_tol=1e-12)
        or not math.isclose(
            float(machine["treatment_mean"]), treatment_mean, abs_tol=1e-12
        )
        or not math.isclose(float(machine["primary_estimate"]), estimate, abs_tol=1e-12)
        or output_hashes["result_core"]
        != hashlib.sha256(canonical_json_bytes(result_core)).hexdigest()
    ):
        raise ValidationError("confirmatory result is not bound to the exact custody run")

    return ConfirmatoryClaimAuthority(
        claim_id=claim_id,
        run_id=run_id,
        timeline_receipt_hash=timeline_receipt_hash,
        protocol_artifact_hash=protocol_hash,
        fresh_custody_receipt_hash=fresh_hash,
        custody_record_hash=custody_hash,
        result_artifact_hash=result_hash,
        protocol_hash=protocol.sha256,
        study_id=protocol.study_id,
        study_version=protocol.study_version,
        holdout_identity_hash=seal.holdout_identity_hash,
        seal_hash=seal.seal_hash,
        release_id=release.release_id,
        scope=ConfirmatoryAuthorityScope.NON_EVIDENTIARY_FIXTURE,
        scientific_gate_passed=False,
    )


_CONFIRMATORY_CLAIM_AUTHORITY_SCHEMA = "confirmatory-claim-authority/v1"
_CONFIRMATORY_CLAIM_AUTHORITY_COMMAND = (
    "scientist-one",
    "record-confirmatory-claim-authority",
)


def _resolve_confirmatory_graph_claim(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    claim_id: str,
    claim_graph_artifact_hash: str,
    timeline_receipt_artifact_hash: str,
) -> tuple[
    ConfirmatoryClaimAuthority,
    tuple[EvidenceSourceBinding, ...],
    tuple[str, ...],
]:
    graph_record, wrapper = _read_registry_json(
        registry,
        claim_graph_artifact_hash,
        logical_type="claim_evidence_graph",
        creator_role=Role.CLAIM_VERIFIER,
    )
    graph_value = wrapper.get("graph")
    if not isinstance(graph_value, Mapping):
        raise ValidationError("confirmatory authority graph omits its typed graph")
    serialized = _serialized_decisions(graph_value)
    serialized_decision = serialized.get(claim_id)
    if serialized_decision is None:
        raise ValidationError("confirmatory authority graph omits the expected claim")
    receipt_hashes = serialized_decision.get("evidence_receipt_hashes")
    if not isinstance(receipt_hashes, list) or not receipt_hashes:
        raise ValidationError("confirmatory claim decision omits verification receipts")
    resolver_ids: set[str] = set()
    support_hashes: list[str] = []
    for receipt_hash in receipt_hashes:
        receipt_record = _require_frozen_artifact(
            registry,
            receipt_hash,
            creator_role=Role.CLAIM_VERIFIER,
        )
        if not receipt_record.logical_type.startswith(
            "claim_evidence_verification_receipt."
        ):
            raise ValidationError("confirmatory decision names the wrong receipt type")
        receipt = EvidenceVerificationReceipt.from_dict(
            safe_json_loads(registry.get_bytes(receipt_hash))
        )
        if (
            receipt.sha256 != receipt_hash
            or receipt_record.parent_artifacts
            != (receipt.artifact_hash, receipt.support_receipt_hash)
        ):
            raise ValidationError("confirmatory verification receipt is not canonical")
        support = _require_frozen_artifact(
            registry,
            receipt.support_receipt_hash,
            creator_role=Role.CLAIM_VERIFIER,
        )
        if not support.logical_type.startswith("claim_support_receipt."):
            raise ValidationError("confirmatory support receipt has the wrong type")
        resolver_ids.add(receipt.resolver_id)
        support_hashes.append(receipt.support_receipt_hash)
    if len(resolver_ids) != 1:
        raise ValidationError("confirmatory claim lacks one evidence resolver identity")
    resolver = artifact_registry_resolver(
        registry,
        resolver_id=resolver_ids.pop(),
    )
    graph = ClaimEvidenceGraph.from_dict(graph_value, evidence_resolver=resolver)
    claims = tuple(item for item in graph.claims if item.claim_id == claim_id)
    if (
        len(claims) != 1
        or claims[0].confirmatory is not True
    ):
        raise ValidationError(
            "confirmatory authority requires one exact confirmatory graph claim"
        )
    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    evidence_sources = _derive_evidence_source_bindings(
        registry,
        claims[0],
        evidence_by_id,
    )
    closure = tuple(
        dict.fromkeys(
            (
                *(
                    digest
                    for binding in evidence_sources
                    for digest in (
                        binding.evidence_artifact_hash,
                        *binding.source_artifact_hashes,
                    )
                ),
                *tuple(receipt_hashes),
                *support_hashes,
            )
        )
    )
    if not set(closure).issubset(set(graph_record.parent_artifacts) | {
        digest
        for binding in evidence_sources
        for digest in binding.source_artifact_hashes
    }):
        raise ValidationError("confirmatory graph provenance omits claim authority")
    fresh_candidates = tuple(
        record.sha256
        for record in registry.list_records()
        if record.logical_type == "fresh_custody_receipt"
    )
    authority = _resolve_confirmatory_claim_authority(
        registry,
        claim_id,
        evidence_sources,
        {
            claim_graph_artifact_hash,
            timeline_receipt_artifact_hash,
            *closure,
            *fresh_candidates,
        },
        ledger=ledger,
        run_id=run_id,
        confirmatory_timeline_receipt_hashes=(
            timeline_receipt_artifact_hash,
        ),
    )
    verifier_id = serialized_decision.get("verifier_id")
    if not isinstance(verifier_id, str):
        raise ValidationError("confirmatory claim decision omits its verifier")
    decision = graph.verify_claim(
        claim_id,
        verifier_id=verifier_id,
        verifier_role=Role.CLAIM_VERIFIER,
        confirmatory_evidence_valid=authority.scientific_gate_passed,
        evidence_resolver=resolver,
    )
    if not _decision_matches(serialized_decision, decision):
        raise ValidationError(
            "confirmatory claim decision differs from fresh custody authority"
        )
    return authority, evidence_sources, closure


def register_confirmatory_claim_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_id: str,
    run_id: str,
    claim_id: str,
    claim_graph_artifact_hash: str,
    timeline_receipt_artifact_hash: str,
) -> ArtifactRecord:
    """Persist a claim-scoped wrapper around the trusted timeline/custody replay."""

    validate_identifier(authority_id, "confirmatory claim authority ID")
    validate_identifier(run_id, "confirmatory claim authority run ID")
    validate_identifier(claim_id, "confirmatory claim authority claim ID")
    validate_sha256(claim_graph_artifact_hash, "confirmatory claim graph")
    validate_sha256(timeline_receipt_artifact_hash, "confirmatory timeline receipt")
    authority, evidence_sources, closure = _resolve_confirmatory_graph_claim(
        registry,
        ledger,
        run_id=run_id,
        claim_id=claim_id,
        claim_graph_artifact_hash=claim_graph_artifact_hash,
        timeline_receipt_artifact_hash=timeline_receipt_artifact_hash,
    )
    primary = (
        claim_graph_artifact_hash,
        timeline_receipt_artifact_hash,
        authority.protocol_artifact_hash,
        authority.fresh_custody_receipt_hash,
        authority.custody_record_hash,
        authority.result_artifact_hash,
    )
    parents = tuple(dict.fromkeys((*primary, *closure)))
    record = registry.put_json(
        {
            "schema_version": _CONFIRMATORY_CLAIM_AUTHORITY_SCHEMA,
            "authority_id": authority_id,
            "run_id": run_id,
            "claim_id": claim_id,
            "claim_graph_artifact_hash": claim_graph_artifact_hash,
            "timeline_receipt_artifact_hash": timeline_receipt_artifact_hash,
            "evidence_sources": _plain_json(evidence_sources),
            "claim_evidence_closure_hashes": list(closure),
            "authority": _plain_json(authority),
        },
        logical_type="confirmatory_claim_authority",
        origin="claim-scoped live replay of confirmatory timeline and custody authority",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=_CONFIRMATORY_CLAIM_AUTHORITY_COMMAND,
        parent_artifacts=parents,
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    require_confirmatory_claim_authority(
        registry,
        ledger,
        authority_artifact_hash=record.sha256,
        expected_run_id=run_id,
        expected_claim_id=claim_id,
        expected_claim_graph_artifact_hash=claim_graph_artifact_hash,
    )
    return record


def require_confirmatory_claim_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_artifact_hash: str,
    expected_run_id: str,
    expected_claim_id: str,
    expected_claim_graph_artifact_hash: str,
) -> ConfirmatoryClaimAuthority:
    """Freshly replay an exact claim-scoped confirmatory authority artifact."""

    validate_identifier(expected_run_id, "expected confirmatory authority run ID")
    validate_identifier(expected_claim_id, "expected confirmatory authority claim ID")
    validate_sha256(
        expected_claim_graph_artifact_hash,
        "expected confirmatory claim graph",
    )
    record, value = _read_registry_json(
        registry,
        authority_artifact_hash,
        logical_type="confirmatory_claim_authority",
        creator_role=Role.CLAIM_VERIFIER,
    )
    payload = _require_exact_keys(
        value,
        {
            "schema_version",
            "authority_id",
            "run_id",
            "claim_id",
            "claim_graph_artifact_hash",
            "timeline_receipt_artifact_hash",
            "evidence_sources",
            "claim_evidence_closure_hashes",
            "authority",
        },
        "confirmatory claim authority",
    )
    validate_identifier(payload["authority_id"], "confirmatory claim authority ID")
    if (
        record.schema_version != "1.0"
        or record.origin
        != "claim-scoped live replay of confirmatory timeline and custody authority"
        or record.creation_command != _CONFIRMATORY_CLAIM_AUTHORITY_COMMAND
        or payload["schema_version"] != _CONFIRMATORY_CLAIM_AUTHORITY_SCHEMA
        or payload["run_id"] != expected_run_id
        or payload["claim_id"] != expected_claim_id
        or payload["claim_graph_artifact_hash"]
        != expected_claim_graph_artifact_hash
    ):
        raise ValidationError("confirmatory claim authority identity was substituted")
    fresh, evidence_sources, closure = _resolve_confirmatory_graph_claim(
        registry,
        ledger,
        run_id=expected_run_id,
        claim_id=expected_claim_id,
        claim_graph_artifact_hash=expected_claim_graph_artifact_hash,
        timeline_receipt_artifact_hash=payload[
            "timeline_receipt_artifact_hash"
        ],
    )
    primary = (
        expected_claim_graph_artifact_hash,
        payload["timeline_receipt_artifact_hash"],
        fresh.protocol_artifact_hash,
        fresh.fresh_custody_receipt_hash,
        fresh.custody_record_hash,
        fresh.result_artifact_hash,
    )
    if (
        payload["evidence_sources"] != _plain_json(evidence_sources)
        or payload["claim_evidence_closure_hashes"] != list(closure)
        or payload["authority"] != _plain_json(fresh)
        or record.parent_artifacts
        != tuple(dict.fromkeys((*primary, *closure)))
    ):
        raise ValidationError(
            "confirmatory claim authority differs from fresh graph/custody replay"
        )
    return fresh


def _resolve_authoritative_claims(
    registry: ArtifactRegistry,
    graph_hash: str,
    state_authority: ResearchStateAuthoritySnapshot,
    authoritative_evidence: set[str],
    metrics: tuple[AuthoritativeMetric, ...],
    *,
    ledger: EventLedger | None,
    run_id: str | None,
    confirmatory_timeline_receipt_hashes: tuple[str, ...],
) -> tuple[AuthoritativeClaim, ...]:
    graph_record, wrapper = _read_registry_json(
        registry,
        graph_hash,
        logical_type="claim_evidence_graph",
        creator_role=Role.CLAIM_VERIFIER,
    )
    graph_value = wrapper.get("graph")
    if not isinstance(graph_value, Mapping):
        raise ValidationError("claim graph wrapper omits its authoritative graph")
    serialized = _serialized_decisions(graph_value)
    resolver_ids: set[str] = set()
    for serialized_decision in serialized.values():
        receipt_hashes = serialized_decision.get("evidence_receipt_hashes")
        if not isinstance(receipt_hashes, list) or not receipt_hashes:
            raise ValidationError("claim decision omits registry verification receipts")
        for receipt_hash in receipt_hashes:
            receipt_record = _require_frozen_artifact(
                registry,
                receipt_hash,
                creator_role=Role.CLAIM_VERIFIER,
            )
            if not receipt_record.logical_type.startswith(
                "claim_evidence_verification_receipt."
            ):
                raise ValidationError("claim decision names the wrong receipt type")
            receipt = EvidenceVerificationReceipt.from_dict(
                safe_json_loads(registry.get_bytes(receipt_hash))
            )
            resolver_ids.add(receipt.resolver_id)
    if len(resolver_ids) != 1:
        raise ValidationError("claim graph decisions do not share one bound resolver identity")
    resolver = artifact_registry_resolver(registry, resolver_id=resolver_ids.pop())
    graph = ClaimEvidenceGraph.from_dict(graph_value, evidence_resolver=resolver)
    state_claims: dict[str, ResearchStateAuthorityBinding] = {}
    for item in state_authority.entries:
        if isinstance(item.research_object, StateClaim):
            if item.research_object.claim_id in state_claims:
                raise ValidationError("canonical state duplicates a claim identity")
            state_claims[item.research_object.claim_id] = item
    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    result: list[AuthoritativeClaim] = []
    for material_claim in graph.claims:
        state_entry = state_claims.get(material_claim.claim_id)
        if state_entry is None:
            raise ValidationError("graph claim is absent from canonical research state")
        state_hash = state_entry.artifact_sha256
        state_claim = state_entry.research_object
        assert isinstance(state_claim, StateClaim)
        if ledger is None or run_id is None:
            raise ValidationError(
                "canonical paper claims require live ClaimSemantics replay"
            )
        claim_semantics, semantics_source = _resolved_claim_semantics(
            registry,
            ledger,
            run_id,
            state_entry,
        )
        if semantics_source.artifact_hash not in authoritative_evidence:
            raise ValidationError(
                "paper authority omits the resolved claim-semantics receipt"
            )
        if (
            claim_semantics.claim_graph_artifact_hash != graph_hash
            or claim_semantics.claim_id != material_claim.claim_id
            or claim_semantics.claim_text != material_claim.text
            or claim_semantics.claim_producer_role is not material_claim.producer_role
            or claim_semantics.claim_evidence_use is not material_claim.evidence_use
        ):
            raise ValidationError(
                "claim semantics differ from the exact checked claim graph"
            )
        evidence_sources = _derive_evidence_source_bindings(
            registry,
            material_claim,
            evidence_by_id,
        )
        confirmatory_authority = None
        if material_claim.confirmatory:
            confirmatory_authority = _resolve_confirmatory_claim_authority(
                registry,
                material_claim.claim_id,
                evidence_sources,
                authoritative_evidence,
                ledger=ledger,
                run_id=run_id,
                confirmatory_timeline_receipt_hashes=(
                    confirmatory_timeline_receipt_hashes
                ),
            )
        serialized_decision = serialized.get(material_claim.claim_id)
        verifier_id = serialized_decision.get("verifier_id") if serialized_decision else None
        if not isinstance(verifier_id, str):
            raise ValidationError("claim lacks a bound verifier identity")
        decision = graph.verify_claim(
            material_claim.claim_id,
            verifier_id=verifier_id,
            verifier_role=Role.CLAIM_VERIFIER,
            # This value is derived solely from a freshly resolved trusted-kernel
            # protocol/custody/reveal chain; no caller boolean reaches this gate.
            confirmatory_evidence_valid=(
                not material_claim.confirmatory
                or (
                    confirmatory_authority is not None
                    and confirmatory_authority.scientific_gate_passed
                )
            ),
            evidence_resolver=resolver,
        )
        if not _decision_matches(serialized_decision, decision):
            raise ValidationError("fresh claim verification conflicts with the frozen decision")
        if decision.decision is not ClaimDecision.ELIGIBLE:
            raise ValidationError("canonical paper claim did not survive fresh graph verification")
        graph_parents = set(graph_record.parent_artifacts)
        checked = set(decision.checked_evidence_hashes)
        receipts = set(decision.evidence_receipt_hashes)
        support_receipts: set[str] = set()
        for receipt_hash in decision.evidence_receipt_hashes:
            receipt_record = _require_frozen_artifact(
                registry,
                receipt_hash,
                creator_role=Role.CLAIM_VERIFIER,
            )
            if not receipt_record.logical_type.startswith(
                "claim_evidence_verification_receipt."
            ):
                raise ValidationError("claim decision names the wrong receipt type")
            raw = registry.get_bytes(receipt_hash)
            receipt_value = safe_json_loads(raw)
            receipt = EvidenceVerificationReceipt.from_dict(receipt_value)
            if raw != receipt.canonical_bytes or receipt.sha256 != receipt_hash:
                raise ValidationError("claim verification receipt is not canonical")
            if receipt.artifact_hash not in checked:
                raise ValidationError("claim verification receipt names unchecked evidence")
            if receipt_record.parent_artifacts != (
                receipt.artifact_hash,
                receipt.support_receipt_hash,
            ):
                raise ValidationError("claim verification receipt lineage is not content-bound")
            support = _require_frozen_artifact(
                registry,
                receipt.support_receipt_hash,
                creator_role=Role.CLAIM_VERIFIER,
            )
            if not support.logical_type.startswith("claim_support_receipt."):
                raise ValidationError("claim support receipt has the wrong logical type")
            support_receipts.add(receipt.support_receipt_hash)
        if not (checked | receipts | support_receipts).issubset(graph_parents):
            raise ValidationError("claim graph provenance omits checked evidence or receipts")
        if not (checked | receipts | support_receipts).issubset(authoritative_evidence):
            raise ValidationError("paper authority omits claim evidence or verification receipts")
        if (
            state_claim.claim_text != material_claim.text
            or state_claim.confirmatory is not material_claim.confirmatory
            or state_claim.evidence_use is not material_claim.evidence_use
            or state_claim.verification_status is not VerificationStatus.VERIFIED
            or graph_hash not in state_claim.source_artifact_ids
            or not state_claim.review_history
            or state_claim.review_history[-1].reviewer is not Role.CLAIM_VERIFIER
            or state_claim.review_history[-1].verification_status is not VerificationStatus.VERIFIED
            or not ({graph_hash} | receipts).issubset(
                set(state_claim.review_history[-1].source_artifact_ids)
            )
        ):
            raise ValidationError("canonical claim state is not bound to the fresh graph decision")
        expected_writer_eligibility = bool(
            claim_semantics.scientific_writer_eligible
            and material_claim.evidence_use is ClaimEvidenceUse.SCIENTIFIC
            and (
                not material_claim.confirmatory
                or (
                    confirmatory_authority is not None
                    and confirmatory_authority.scientific_gate_passed
                )
            )
        )
        if state_entry.scientific_evidence_eligible is not expected_writer_eligibility:
            raise ValidationError(
                "canonical claim eligibility differs from live graph/timeline authority"
            )
        if state_entry.scientific_evidence_eligible:
            _require_scientific_claim_dependency_closure(
                registry,
                ledger,
                run_id,
                state_authority,
                claim_semantics,
            )
        requirements = _derive_claim_paper_requirements(
            registry,
            claim_semantics,
            evidence_sources,
            metrics,
            state_authority,
            ledger,
            run_id,
        )
        if (
            state_entry.scientific_evidence_eligible
            and requirements.required_reference_artifact_hashes
        ):
            if ledger is None or run_id is None:
                raise ValidationError(
                    "scientific references require live run ledger authority"
                )
            if claim_semantics.semantic_proposal_artifact_hash is None:
                raise ValidationError(
                    "scientific references require the exact claim-semantics proposal"
                )
            if (
                claim_semantics.reference_support_semantic_judgment_artifact_hash
                is None
                or claim_semantics.semantic_authority_artifact_hash is None
            ):
                raise ValidationError(
                    "scientific references require exact Jref and K authority"
                )
            citation_sources = tuple(
                item
                for item in requirements.evidence_sources
                if item.kind is EvidenceKind.SOURCE_CITATION
            )
            reference_authorities: list[ReferenceAuthorityBinding] = []
            for reference_hash in requirements.required_reference_artifact_hashes:
                matches = tuple(
                    item
                    for item in citation_sources
                    if item.source_artifact_hashes
                    and item.source_artifact_hashes[0] == reference_hash
                )
                if (
                    len(matches) != 1
                    or len(matches[0].source_artifact_hashes) != 3
                ):
                    raise ValidationError(
                        "scientific reference lacks one exact three-source projection"
                    )
                reference_authority = _require_scientific_reference_source_authority(
                    registry,
                    ledger,
                    run_id=run_id,
                    claim_id=material_claim.claim_id,
                    claim_text=claim_semantics.claim_text,
                    claim_scope=claim_semantics.scope,
                    claim_graph_artifact_hash=graph_hash,
                    claim_semantics_proposal_artifact_hash=(
                        claim_semantics.semantic_proposal_artifact_hash
                    ),
                    reference_support_semantic_judgment_artifact_hash=(
                        claim_semantics.reference_support_semantic_judgment_artifact_hash
                    ),
                    source_citation_evidence_artifact_hash=(
                        matches[0].evidence_artifact_hash
                    ),
                    reference_artifact_hash=reference_hash,
                )
                if (
                    _CLAIM_STRENGTH_RANK[reference_authority.permitted_strength]
                    < _CLAIM_STRENGTH_RANK[claim_semantics.expressed_strength]
                    or _CLAIM_STRENGTH_RANK[
                        reference_authority.permitted_strength
                    ]
                    > _CLAIM_STRENGTH_RANK[claim_semantics.permitted_strength]
                ):
                    raise ValidationError(
                        "scientific reference authority conflicts with canonical claim strength"
                    )
                reference_authorities.append(reference_authority)
            if len(reference_authorities) != len(citation_sources):
                raise ValidationError(
                    "scientific reference authority contains an unused source projection"
                )
            requirements = replace(
                requirements,
                required_reference_authorities=tuple(
                    sorted(
                        reference_authorities,
                        key=lambda item: (
                            item.citation_id,
                            item.source_citation_evidence_artifact_hash,
                        ),
                    )
                ),
            )
        result.append(
            AuthoritativeClaim(
                claim_id=material_claim.claim_id,
                text=claim_semantics.claim_text,
                expressed_strength=claim_semantics.expressed_strength,
                permitted_strength=claim_semantics.permitted_strength,
                evidence_hashes=tuple(sorted(checked)),
                claim_state_artifact_hash=state_hash,
                graph_decision_hash=decision.sha256,
                claim_semantics_artifact_hash=semantics_source.artifact_hash,
                producer_role=claim_semantics.claim_producer_role,
                claim_semantics_evidence_scope=claim_semantics.evidence_scope,
                confidence=claim_semantics.confidence,
                verification_method=claim_semantics.verification_method,
                scientific_writer_eligible=(
                    state_entry.scientific_evidence_eligible
                ),
                evidence_use=claim_semantics.claim_evidence_use,
                claim_type=claim_semantics.claim_type,
                scope=claim_semantics.scope,
                dependency_claim_ids=claim_semantics.dependency_claim_ids,
                source_artifact_ids=state_claim.source_artifact_ids,
                requirements=requirements,
                confirmatory=material_claim.confirmatory,
                confirmatory_authority=confirmatory_authority,
            )
        )
    if not result:
        raise ValidationError("claim graph contains no canonical claims")
    return tuple(sorted(result, key=lambda item: item.claim_id))


def _verify_authoritative_metric(
    registry: ArtifactRegistry,
    metric: AuthoritativeMetric,
    state_authority: ResearchStateAuthoritySnapshot,
    authoritative_evidence: set[str],
) -> AuthoritativeMetric:
    result_binding = state_authority.binding_for_artifact(
        metric.result_state_artifact_hash
    )
    result = result_binding.research_object
    if not isinstance(result, StateResult):
        raise ValidationError("metric does not resolve to canonical Result state")
    metric_definition = state_authority.metric(result.metric_id)
    metric_binding = state_authority.object("Metric", result.metric_id)
    result_authority_sources = _state_authority_source_bindings(result_binding)
    metric_authority_sources = _state_authority_source_bindings(metric_binding)
    if (
        metric.metric_state_artifact_hash is not None
        and metric.metric_state_artifact_hash != metric_binding.artifact_sha256
    ):
        raise ValidationError("metric names a substituted canonical Metric state")
    if (
        metric.result_authority_sources
        and metric.result_authority_sources != result_authority_sources
    ) or (
        metric.metric_authority_sources
        and metric.metric_authority_sources != metric_authority_sources
    ):
        raise ValidationError("metric state-authority projection was substituted")
    raw_record = _require_frozen_artifact(registry, metric.result_artifact_hash)
    raw_bindings = tuple(
        (record_hash, logical_type, creator_role)
        for authority_hash, record_hash, logical_type, creator_role in zip(
            result_binding.authority_artifact_hashes,
            result_binding.authority_artifact_record_hashes,
            result_binding.authority_logical_types,
            result_binding.authority_creator_roles,
        )
        if authority_hash == metric.result_artifact_hash
    )
    if len(raw_bindings) != 1:
        raise ValidationError(
            "metric raw result is absent or ambiguous in resolved Result authority"
        )
    raw_record_hash, raw_logical_type, raw_creator_role = raw_bindings[0]
    raw_authority_valid = (
        raw_logical_type == "aggregate_experiment_result"
        and raw_creator_role is Role.STATISTICIAN
    ) or (
        raw_logical_type.startswith("experiment_output.")
        and raw_creator_role is Role.EXPERIMENT_RUNNER
    )
    expected_metric_id = (
        result.metric_id
        if metric.result_value_key is None
        else f"{metric.result_value_key}-{result.metric_id}"
    )
    if (
        metric.metric_id != expected_metric_id
        or float(metric.tolerance) != 0.0
        or result.metric_id != metric.canonical_metric_id
        or result.unit != metric.unit
        or result.direction.value != metric.direction.value
        or metric_definition.unit != metric.unit
        or metric_definition.direction.value != metric.direction.value
        or metric.result_artifact_hash not in result.source_artifact_hashes
        or metric.result_artifact_hash not in authoritative_evidence
        or not {
            item.artifact_hash
            for item in (*result_authority_sources, *metric_authority_sources)
        }.issubset(authoritative_evidence)
        or raw_record_hash != str(raw_record.record_hash)
        or raw_record.logical_type != raw_logical_type
        or raw_record.creator_role is not raw_creator_role
        or not raw_authority_valid
    ):
        raise ValidationError("metric identity, units, direction, or raw source conflicts")
    raw_value: Any = result.value
    if metric.result_value_key is not None:
        if not isinstance(raw_value, Mapping) or metric.result_value_key not in raw_value:
            raise ValidationError("canonical result does not contain the selected metric value")
        raw_value = raw_value[metric.result_value_key]
    if (
        isinstance(raw_value, bool)
        or not isinstance(raw_value, (int, float))
        or not math.isfinite(float(raw_value))
        or not _exact_numeric_equal(raw_value, metric.value)
    ):
        raise ValidationError("authoritative metric value conflicts with canonical Result state")
    return AuthoritativeMetric(
        metric_id=metric.metric_id,
        value=metric.value,
        unit=metric.unit,
        direction=metric.direction,
        result_artifact_hash=metric.result_artifact_hash,
        result_state_artifact_hash=metric.result_state_artifact_hash,
        canonical_metric_id=metric.canonical_metric_id,
        result_value_key=metric.result_value_key,
        tolerance=0.0,
        metric_state_artifact_hash=metric_binding.artifact_sha256,
        scientific_evidence_status=(
            MetricEvidenceStatus.SCIENTIFIC_ELIGIBLE
            if result_binding.scientific_evidence_eligible
            else MetricEvidenceStatus.NON_EVIDENTIARY
        ),
        result_authority_sources=result_authority_sources,
        metric_authority_sources=metric_authority_sources,
    )


def _verify_method_code_binding(
    registry: ArtifactRegistry,
    binding: MethodCodeBinding,
    state_authority: ResearchStateAuthoritySnapshot,
) -> None:
    method_binding = state_authority.binding_for_artifact(
        binding.method_state_artifact_hash
    )
    implementation_binding = state_authority.binding_for_artifact(
        binding.implementation_state_artifact_hash
    )
    method = method_binding.research_object
    implementation = implementation_binding.research_object
    if not isinstance(method, StateMethod) or not isinstance(
        implementation, StateImplementation
    ):
        raise ValidationError("method/code binding lacks canonical Method or Implementation state")
    expected_authority_sources = tuple(
        dict.fromkeys(
            (
                *_state_authority_source_bindings(method_binding),
                *_state_authority_source_bindings(implementation_binding),
            )
        )
    )
    parent_match = any(
        parent.object_type == method.object_type
        and parent.object_id == method.object_id
        and parent.content_hash == method.content_hash
        for parent in implementation.parents
    )
    method_record = _require_frozen_artifact(registry, binding.method_artifact_hash)
    code_record = _require_frozen_artifact(registry, binding.code_artifact_hash)
    method_authority_matches = tuple(
        (record_hash, logical_type, creator_role)
        for authority_hash, record_hash, logical_type, creator_role in zip(
            method_binding.authority_artifact_hashes,
            method_binding.authority_artifact_record_hashes,
            method_binding.authority_logical_types,
            method_binding.authority_creator_roles,
        )
        if authority_hash == binding.method_artifact_hash
    )
    code_authority_matches = tuple(
        (record_hash, logical_type, creator_role)
        for authority_hash, record_hash, logical_type, creator_role in zip(
            implementation_binding.authority_artifact_hashes,
            implementation_binding.authority_artifact_record_hashes,
            implementation_binding.authority_logical_types,
            implementation_binding.authority_creator_roles,
        )
        if authority_hash == binding.code_artifact_hash
    )
    allowed_method_authority = {
        ("method_definition", Role.HYPOTHESIS_DESIGNER),
        ("baseline_method_definition", Role.PROTOCOL_DESIGNER),
        (
            "autonomous_implementation.admitted_descriptor",
            Role.IMPLEMENTER,
        ),
    }
    allowed_code_authority = {
        ("experiment_code", Role.IMPLEMENTER),
        (
            "autonomous_implementation.reviewed_worker_code",
            Role.IMPLEMENTER,
        ),
    }
    if (
        len(method_authority_matches) != 1
        or len(code_authority_matches) != 1
        or binding.authority_sources != expected_authority_sources
        or implementation.method_id != method.object_id
        or binding.code_artifact_hash not in implementation.code_artifact_hashes
        or not parent_match
        or (
            method_authority_matches[0][1],
            method_authority_matches[0][2],
        )
        not in allowed_method_authority
        or (
            code_authority_matches[0][1],
            code_authority_matches[0][2],
        )
        not in allowed_code_authority
        or method_authority_matches[0][0] != str(method_record.record_hash)
        or code_authority_matches[0][0] != str(code_record.record_hash)
        or method_record.logical_type != method_authority_matches[0][1]
        or method_record.creator_role is not method_authority_matches[0][2]
        or code_record.logical_type != code_authority_matches[0][1]
        or code_record.creator_role is not code_authority_matches[0][2]
    ):
        raise ValidationError("canonical method/implementation binding conflicts")


def _resolve_soundness(
    registry: ArtifactRegistry,
    assessment_hash: str,
    *,
    claim_graph_hash: str,
    central_claim_ids: tuple[str, ...],
    ledger: EventLedger | None,
    run_id: str | None,
    confirmatory_claim_authority_hashes: tuple[str, ...],
    _round_replay: _PaperRoundReplay | None = None,
) -> SoundnessAssessment:
    if _round_replay is None:
        assessment = require_scientific_soundness_assessment(
            registry,
            assessment_artifact_hash=assessment_hash,
            ledger=ledger,
            expected_run_id=run_id,
        )
    else:
        if ledger is None or run_id is None:
            raise ValidationError("same-round paper Soundness requires its exact run and ledger")
        _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
        if assessment_hash != _round_replay.soundness.record.sha256:
            raise ValidationError("paper Soundness differs from the completed round source")
        assessment = _round_replay.soundness.assessment
    if (
        assessment.claim_graph_artifact_hash != claim_graph_hash
        or assessment.central_claim_ids != tuple(sorted(central_claim_ids))
        or assessment.confirmatory_claim_authority_hashes
        != confirmatory_claim_authority_hashes
    ):
        raise ValidationError(
            "soundness assessment is bound to another graph, claim set, or confirmatory authority"
        )
    return assessment


def _check_positive_policy_authority(
    soundness: SoundnessAssessment,
    flags: Mapping[str, bool],
) -> None:
    statuses = dict(soundness.dimensions)
    required_passes = {
        "required_baselines_complete": SoundnessDimension.BASELINE_COMPLETENESS,
        "evaluator_exploitation_resolved": SoundnessDimension.EVALUATOR_VALIDITY,
        "statistics_valid": SoundnessDimension.STATISTICS,
        "novelty_supported": SoundnessDimension.NOVELTY,
        "clean_reproduction_passed": SoundnessDimension.REPRODUCIBILITY,
        "external_validation_complete": SoundnessDimension.GENERALIZATION,
    }
    for flag, dimension in required_passes.items():
        if flags[flag] and statuses.get(dimension) is not DimensionStatus.PASS:
            raise ValidationError(f"positive {flag} conflicts with soundness evidence")
    reviews = {item.category: item for item in soundness.challenger_reviews}
    required_challenges = {
        "required_baselines_complete": (ChallengeCategory.BASELINES,),
        "leakage_resolved": (ChallengeCategory.LEAKAGE,),
        "evaluator_exploitation_resolved": (ChallengeCategory.EVALUATOR_GAMING,),
        "statistics_valid": (ChallengeCategory.STATISTICS,),
        "novelty_supported": (ChallengeCategory.PRIOR_ART,),
        "selection_integrity_valid": (
            ChallengeCategory.EXPERIMENTAL_DESIGN,
            ChallengeCategory.SEED_DEPENDENCE,
        ),
        "clean_reproduction_passed": (ChallengeCategory.REPRODUCTION,),
        "external_validation_complete": (ChallengeCategory.EXTERNAL_VALIDITY,),
    }
    unresolved_categories = {
        item.category
        for item in soundness.findings
        if item.status is ChallengeStatus.UNRESOLVED
    }
    for flag, categories in required_challenges.items():
        if not flags[flag]:
            continue
        if any(
            reviews.get(category) is None
            or reviews[category].execution_status
            is not ChallengerExecutionStatus.EXECUTED
            or category in unresolved_categories
            for category in categories
        ):
            raise ValidationError(
                f"positive {flag} conflicts with Challenger execution authority"
            )


def _derive_required_limitations(
    registry: ArtifactRegistry,
    soundness: SoundnessAssessment,
) -> tuple[str, ...]:
    """Derive disclosure text from frozen reviewer receipts, never caller prose."""

    limitations: list[str] = []
    if soundness.verdict is not SoundnessVerdict.PASS:
        limitations.append(soundness.reason)
    status_by_dimension = dict(soundness.dimensions)
    for receipt_hash in soundness.dimension_receipt_hashes:
        _, value = _read_registry_json(
            registry,
            receipt_hash,
            logical_type="soundness_dimension_evidence_receipt",
            creator_role=Role.SCIENTIFIC_REVIEWER,
        )
        receipt = SoundnessDimensionEvidenceReceipt.from_dict(value)
        if status_by_dimension.get(receipt.dimension) is not receipt.status:
            raise ValidationError("soundness limitation receipt conflicts with assessment")
        if receipt.status in {DimensionStatus.FAIL, DimensionStatus.UNTESTED}:
            limitations.append(receipt.rationale)
    for review in soundness.challenger_reviews:
        if review.execution_status is ChallengerExecutionStatus.UNTESTED:
            limitations.append(review.conclusion)
    for finding in soundness.findings:
        if finding.status is ChallengeStatus.UNRESOLVED:
            limitations.append(finding.attack)
    return tuple(dict.fromkeys(limitations))


def _verification_depth(value: Any) -> ReferenceDepth:
    if isinstance(value, bool):
        raise ValidationError("reference verification depth is malformed")
    if isinstance(value, int):
        return ReferenceDepth(f"LEVEL_{value}")
    if isinstance(value, str):
        return ReferenceDepth(value)
    raise ValidationError("reference verification depth is malformed")


def _verify_reference_use(
    registry: ArtifactRegistry,
    reference: ReferenceUse,
    authoritative_claims: Mapping[str, AuthoritativeClaim],
    authoritative_evidence: set[str],
    *,
    ledger: EventLedger | None,
    run_id: str,
    claim_graph_artifact_hash: str,
) -> None:
    if reference.reference_artifact_hash not in authoritative_evidence:
        raise ValidationError("reference is absent from the authoritative evidence bundle")
    record, wrapper = _read_registry_json(
        registry,
        reference.reference_artifact_hash,
        logical_type="reference_verification",
        creator_role=Role.CLAIM_VERIFIER,
    )
    claim_text = wrapper.get("claim_text")
    verification = wrapper.get("verification")
    if not isinstance(claim_text, str) or not isinstance(verification, Mapping):
        raise ValidationError("reference receipt omits claim text or verification")
    actual_depth = _verification_depth(verification.get("level"))
    parent_hashes = verification.get("parent_artifact_hashes")
    if (
        actual_depth is not reference.verification_depth
        or actual_depth.ordinal < 4
        or verification.get("metadata_mismatches") != []
        or verification.get("failure_reasons") != []
        or not isinstance(verification.get("locator"), Mapping)
        or not isinstance(parent_hashes, list)
        or tuple(parent_hashes) != record.parent_artifacts
        or reference.contradictory_context
    ):
        raise ValidationError("reference verification receipt is insufficient or contradictory")
    if reference.supported_claim_ids and actual_depth.ordinal < 5:
        raise ValidationError("claim-supporting reference lacks surrounding-context verification")
    scientific_claims: list[AuthoritativeClaim] = []
    for claim_id in reference.supported_claim_ids:
        authority = authoritative_claims.get(claim_id)
        if authority is None or authority.text != claim_text:
            raise ValidationError("reference receipt is not bound to the exact supported claim")
        if authority.scientific_writer_eligible:
            scientific_claims.append(authority)
    semantic_found = False
    context_found = actual_depth.ordinal < 5
    for parent_hash in record.parent_artifacts:
        parent_record = _require_frozen_artifact(registry, parent_hash)
        if parent_record.logical_type not in {
            "semantic_reference_assessment",
            "context_reference_assessment",
        }:
            continue
        if parent_record.creator_role is not Role.CLAIM_VERIFIER:
            raise ValidationError("reference assessment has the wrong authority")
        _, assessment = _read_registry_json(registry, parent_hash)
        if assessment.get("claim_text") != claim_text:
            raise ValidationError("reference assessment is bound to different claim text")
        if parent_record.logical_type == "semantic_reference_assessment":
            semantic_found = assessment.get("decision") == "SUPPORTS"
        else:
            context_found = assessment.get("decision") == "NOT_CONTRADICTED"
    if not semantic_found or not context_found:
        raise ValidationError("reference verification lacks content-bound semantic/context receipts")
    if not scientific_claims:
        if reference.source_citation_evidence_artifact_hash is not None:
            raise ValidationError(
                "non-scientific reference cannot present a scientific authority projection"
            )
        return
    if (
        len(scientific_claims) != 1
        or len(reference.supported_claim_ids) != 1
        or ledger is None
    ):
        raise ValidationError(
            "scientific reference use requires one exact claim and live ledger authority"
        )
    claim = scientific_claims[0]
    requirements = claim.requirements
    if requirements is None:
        raise ValidationError("scientific reference claim omits derived requirements")
    matches = tuple(
        item
        for item in requirements.required_reference_authorities
        if item.reference_artifact_hash == reference.reference_artifact_hash
        and item.citation_id == reference.citation_id
        and item.claim_id == claim.claim_id
    )
    if len(matches) != 1:
        raise ValidationError(
            "scientific reference lacks one exact claim-bound authority"
        )
    expected = matches[0]
    claim_semantics = require_claim_semantics_receipt(
        registry,
        ledger,
        receipt_artifact_hash=claim.claim_semantics_artifact_hash,
        expected_run_id=run_id,
        expected_claim_graph_artifact_hash=claim_graph_artifact_hash,
        expected_claim_id=claim.claim_id,
    )
    if (
        claim_semantics.scientific_writer_eligible is not True
        or claim_semantics.semantic_proposal_artifact_hash
        != expected.claim_semantics_proposal_artifact_hash
        or claim_semantics.reference_support_semantic_judgment_artifact_hash
        != expected.semantic_judgment_artifact_hash
        or claim_semantics.semantic_authority_artifact_hash is None
        or reference.source_citation_evidence_artifact_hash
        != expected.source_citation_evidence_artifact_hash
        or reference.citation_node_id != expected.citation_node_id
        or reference.passage_sha256 != expected.passage_sha256
        or reference.passage_locator_sha256 != expected.passage_locator_sha256
        or reference.context_sha256 != expected.context_sha256
        or reference.semantic_judgment_artifact_hash
        != expected.semantic_judgment_artifact_hash
        or not (
            set(expected.evidence_artifact_hashes)
            - {claim_graph_artifact_hash}
        ).issubset(authoritative_evidence)
        or _CLAIM_STRENGTH_RANK[expected.permitted_strength]
        < _CLAIM_STRENGTH_RANK[claim.expressed_strength]
        or _CLAIM_STRENGTH_RANK[expected.permitted_strength]
        > _CLAIM_STRENGTH_RANK[claim.permitted_strength]
    ):
        raise ValidationError(
            "scientific ReferenceUse omits or substitutes its exact signed projection"
        )
    fresh = _require_scientific_reference_source_authority(
        registry,
        ledger,
        run_id=run_id,
        claim_id=claim.claim_id,
        claim_text=claim.text,
        claim_scope=claim.scope,
        claim_graph_artifact_hash=claim_graph_artifact_hash,
        claim_semantics_proposal_artifact_hash=(
            expected.claim_semantics_proposal_artifact_hash
        ),
        reference_support_semantic_judgment_artifact_hash=(
            expected.semantic_judgment_artifact_hash
        ),
        source_citation_evidence_artifact_hash=(
            expected.source_citation_evidence_artifact_hash
        ),
        reference_artifact_hash=reference.reference_artifact_hash,
    )
    if fresh != expected:
        raise ValidationError(
            "scientific ReferenceUse differs from fresh claim-bound replay"
        )


def _verify_generated_asset(
    registry: ArtifactRegistry,
    asset: GeneratedAsset,
    authoritative_evidence: set[str],
    authoritative_roots: set[str],
) -> None:
    if asset.artifact_hash not in authoritative_evidence:
        raise ValidationError("paper asset is absent from authoritative evidence")
    record = _require_frozen_artifact(registry, asset.artifact_hash)
    if record.parent_artifacts != asset.authoritative_parent_hashes:
        raise ValidationError("paper asset declares different parents than registry metadata")
    if not set(record.parent_artifacts).issubset(authoritative_evidence):
        raise ValidationError("paper asset has a non-authoritative registry parent")
    if any(
        not _artifact_descends_from(registry, parent, authoritative_roots)
        for parent in record.parent_artifacts
    ):
        raise ValidationError("paper asset parent is not derived from claim/result authority")
    if asset.kind == "TABLE" and not (
        "table" in record.logical_type and record.mime_type in {"text/csv", "application/json"}
    ):
        raise ValidationError("paper table artifact has the wrong materialized type")
    if asset.kind == "FIGURE" and not (
        "figure" in record.logical_type and record.mime_type.startswith("image/")
    ):
        raise ValidationError("paper figure artifact has the wrong materialized type")


def _artifact_descends_from(
    registry: ArtifactRegistry,
    artifact_hash: str,
    roots: set[str],
) -> bool:
    pending = [artifact_hash]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in roots:
            return True
        if current in visited or len(visited) >= MAX_ITEMS:
            continue
        visited.add(current)
        record = _require_frozen_artifact(registry, current)
        pending.extend(record.parent_artifacts)
    return False


def _artifact_ancestor_closure(
    registry: ArtifactRegistry,
    roots: tuple[str, ...],
) -> frozenset[str]:
    """Return the exact bounded frozen-parent closure of trusted paper roots."""

    _hashes(roots, "paper authority roots", allow_empty=False)
    pending = list(roots)
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        if len(visited) >= 50_000:
            raise ValidationError("paper authority parent closure exceeds its bound")
        record = _require_frozen_artifact(registry, current)
        visited.add(current)
        pending.extend(record.parent_artifacts)
    return frozenset(visited)


def _required_paper_evidence_hashes(
    registry: ArtifactRegistry,
    *,
    claim_graph_hash: str,
    claims: tuple[AuthoritativeClaim, ...],
    metrics: tuple[AuthoritativeMetric, ...],
    method_code_bindings: tuple[MethodCodeBinding, ...],
) -> frozenset[str]:
    """Derive the exact bundle evidence inventory from freshly resolved inputs."""

    graph_record, graph_wrapper = _read_registry_json(
        registry,
        claim_graph_hash,
        logical_type="claim_evidence_graph",
        creator_role=Role.CLAIM_VERIFIER,
    )
    graph_value = graph_wrapper.get("graph")
    if not isinstance(graph_value, Mapping):
        raise ValidationError("claim graph omits its exact evidence inventory")
    serialized_decisions = _serialized_decisions(graph_value)
    expected_graph_parents: set[str] = set()
    for claim in claims:
        decision = serialized_decisions.get(claim.claim_id)
        receipt_hashes = (
            decision.get("evidence_receipt_hashes")
            if decision is not None
            else None
        )
        if not isinstance(receipt_hashes, list) or not receipt_hashes:
            raise ValidationError("claim graph decision omits verification receipts")
        expected_graph_parents.update(claim.evidence_hashes)
        for receipt_hash in receipt_hashes:
            receipt_record = _require_frozen_artifact(
                registry,
                receipt_hash,
                creator_role=Role.CLAIM_VERIFIER,
            )
            if (
                not receipt_record.logical_type.startswith(
                    "claim_evidence_verification_receipt."
                )
                or len(receipt_record.parent_artifacts) != 2
            ):
                raise ValidationError("claim graph receipt closure is malformed")
            expected_graph_parents.add(receipt_hash)
            expected_graph_parents.update(receipt_record.parent_artifacts)
    if set(graph_record.parent_artifacts) != expected_graph_parents:
        raise ValidationError("claim graph contains unused or omitted authority parents")
    required = set(expected_graph_parents)
    for claim in claims:
        required.add(claim.claim_semantics_artifact_hash)
        required.update(claim.evidence_hashes)
        if claim.requirements is None:
            raise ValidationError("authoritative claim omits derived paper requirements")
        for binding in claim.requirements.evidence_sources:
            required.add(binding.evidence_artifact_hash)
            required.update(binding.source_artifact_hashes)
        for binding in claim.requirements.required_reference_authorities:
            required.update(
                set(binding.evidence_artifact_hashes) - {claim_graph_hash}
            )
        for asset in claim.requirements.required_generated_assets:
            required.add(asset.artifact_hash)
            required.update(asset.authoritative_parent_hashes)
        if claim.confirmatory_authority is not None:
            confirmatory_roots = (
                claim.confirmatory_authority.timeline_receipt_hash,
                claim.confirmatory_authority.protocol_artifact_hash,
                claim.confirmatory_authority.fresh_custody_receipt_hash,
                claim.confirmatory_authority.custody_record_hash,
                claim.confirmatory_authority.result_artifact_hash,
            )
            required.update(confirmatory_roots)
            for digest in confirmatory_roots:
                required.update(
                    _require_frozen_artifact(registry, digest).parent_artifacts
                )
    for metric in metrics:
        required.add(metric.result_artifact_hash)
        required.update(
            source.artifact_hash
            for source in (
                *metric.result_authority_sources,
                *metric.metric_authority_sources,
            )
        )
    for binding in method_code_bindings:
        required.update((binding.method_artifact_hash, binding.code_artifact_hash))
        required.update(source.artifact_hash for source in binding.authority_sources)
    for digest in required:
        _require_frozen_artifact(registry, digest)
    return frozenset(required)


def _plain_json(value: Any) -> Any:
    return safe_json_loads(canonical_json_bytes(value))


def _state_authority_source_from_json(value: Any) -> StateAuthoritySourceBinding:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(StateAuthoritySourceBinding)},
        "state authority source binding",
    )
    return StateAuthoritySourceBinding(
        artifact_hash=payload["artifact_hash"],
        artifact_record_hash=payload["artifact_record_hash"],
        logical_type=payload["logical_type"],
        creator_role=Role(payload["creator_role"]),
    )


def _method_binding_from_json(value: Any) -> MethodCodeBinding:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(MethodCodeBinding)},
        "method/code binding",
    )
    return MethodCodeBinding(
        method_artifact_hash=payload["method_artifact_hash"],
        code_artifact_hash=payload["code_artifact_hash"],
        method_state_artifact_hash=payload["method_state_artifact_hash"],
        implementation_state_artifact_hash=payload[
            "implementation_state_artifact_hash"
        ],
        authority_sources=tuple(
            _state_authority_source_from_json(item)
            for item in _sequence(
                payload["authority_sources"], "method/code authority sources"
            )
        ),
    )


def _evidence_source_binding_from_json(value: Any) -> EvidenceSourceBinding:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(EvidenceSourceBinding)},
        "claim evidence-source binding",
    )
    return EvidenceSourceBinding(
        kind=EvidenceKind(payload["kind"]),
        evidence_artifact_hash=payload["evidence_artifact_hash"],
        source_artifact_hashes=_sequence(
            payload["source_artifact_hashes"],
            "claim evidence source artifacts",
        ),
    )


def _reference_authority_binding_from_json(value: Any) -> ReferenceAuthorityBinding:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(ReferenceAuthorityBinding)},
        "claim-bound reference authority",
    )
    return ReferenceAuthorityBinding(
        run_id=payload["run_id"],
        claim_id=payload["claim_id"],
        claim_text=payload["claim_text"],
        claim_scope=payload["claim_scope"],
        claim_graph_artifact_hash=payload["claim_graph_artifact_hash"],
        claim_semantics_proposal_artifact_hash=payload[
            "claim_semantics_proposal_artifact_hash"
        ],
        source_citation_evidence_id=payload["source_citation_evidence_id"],
        source_citation_evidence_artifact_hash=payload[
            "source_citation_evidence_artifact_hash"
        ],
        source_citation_evidence_record_hash=payload[
            "source_citation_evidence_record_hash"
        ],
        citation_graph_artifact_hash=payload["citation_graph_artifact_hash"],
        citation_graph_record_hash=payload["citation_graph_record_hash"],
        citation_node_id=payload["citation_node_id"],
        citation_node_record_sha256=payload["citation_node_record_sha256"],
        citation_id=payload["citation_id"],
        reference_artifact_hash=payload["reference_artifact_hash"],
        reference_record_hash=payload["reference_record_hash"],
        passage_sha256=payload["passage_sha256"],
        passage_locator_sha256=payload["passage_locator_sha256"],
        context_sha256=payload["context_sha256"],
        transport_execution_authority_artifact_hash=payload[
            "transport_execution_authority_artifact_hash"
        ],
        semantic_judgment_artifact_hash=payload[
            "semantic_judgment_artifact_hash"
        ],
        semantic_judgment_record_hash=payload["semantic_judgment_record_hash"],
        semantic_judgment_evidence_artifact_hashes=_sequence(
            payload["semantic_judgment_evidence_artifact_hashes"],
            "reference-support judgment evidence artifacts",
        ),
        semantic_judgment_context_artifact_hashes=_sequence(
            payload["semantic_judgment_context_artifact_hashes"],
            "reference-support judgment context artifacts",
        ),
        semantic_judgment_custody_artifact_hashes=_sequence(
            payload["semantic_judgment_custody_artifact_hashes"],
            "reference-support judgment custody artifacts",
        ),
        semantic_projection_sha256=payload["semantic_projection_sha256"],
        permitted_strength=ClaimStrength(payload["permitted_strength"]),
        evidence_artifact_hashes=_sequence(
            payload["evidence_artifact_hashes"],
            "claim-bound reference evidence artifacts",
        ),
        evidence_record_hashes=_sequence(
            payload["evidence_record_hashes"],
            "claim-bound reference evidence record hashes",
        ),
    )


def _claim_requirements_from_json(value: Any) -> ClaimPaperRequirements:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(ClaimPaperRequirements)},
        "claim paper requirements",
    )
    return ClaimPaperRequirements(
        claim_id=payload["claim_id"],
        claim_type=ClaimType(payload["claim_type"]),
        evidence_sources=tuple(
            _evidence_source_binding_from_json(item)
            for item in _sequence(
                payload["evidence_sources"], "claim evidence-source bindings"
            )
        ),
        required_metric_ids=_sequence(
            payload["required_metric_ids"], "required metric IDs"
        ),
        required_reference_artifact_hashes=_sequence(
            payload["required_reference_artifact_hashes"],
            "required reference artifacts",
        ),
        required_method_code_bindings=tuple(
            _method_binding_from_json(item)
            for item in _sequence(
                payload["required_method_code_bindings"],
                "required method/code bindings",
            )
        ),
        required_generated_assets=tuple(
            GeneratedAssetRequirement(
                kind=_require_exact_keys(
                    item,
                    {field.name for field in fields(GeneratedAssetRequirement)},
                    "required generated asset",
                )["kind"],
                artifact_hash=item["artifact_hash"],
                authoritative_parent_hashes=_sequence(
                    item["authoritative_parent_hashes"],
                    "required generated-asset parents",
                ),
            )
            for item in _sequence(
                payload["required_generated_assets"],
                "required generated assets",
            )
        ),
        required_reference_authorities=tuple(
            _reference_authority_binding_from_json(item)
            for item in _sequence(
                payload["required_reference_authorities"],
                "required claim-bound reference authorities",
            )
        ),
    )


def _authoritative_claim_from_json(value: Any) -> AuthoritativeClaim:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(AuthoritativeClaim)},
        "authoritative paper claim",
    )
    requirements = payload["requirements"]
    confirmatory = payload["confirmatory_authority"]
    return AuthoritativeClaim(
        claim_id=payload["claim_id"],
        text=payload["text"],
        expressed_strength=ClaimStrength(payload["expressed_strength"]),
        permitted_strength=ClaimStrength(payload["permitted_strength"]),
        evidence_hashes=_sequence(
            payload["evidence_hashes"], "authoritative claim evidence"
        ),
        claim_state_artifact_hash=payload["claim_state_artifact_hash"],
        graph_decision_hash=payload["graph_decision_hash"],
        claim_semantics_artifact_hash=payload[
            "claim_semantics_artifact_hash"
        ],
        producer_role=Role(payload["producer_role"]),
        claim_semantics_evidence_scope=ClaimSemanticsEvidenceScope(
            payload["claim_semantics_evidence_scope"]
        ),
        confidence=payload["confidence"],
        verification_method=payload["verification_method"],
        scientific_writer_eligible=payload["scientific_writer_eligible"],
        evidence_use=ClaimEvidenceUse(payload["evidence_use"]),
        claim_type=ClaimType(payload["claim_type"]),
        scope=payload["scope"],
        dependency_claim_ids=_sequence(
            payload["dependency_claim_ids"], "authoritative claim dependencies"
        ),
        source_artifact_ids=_sequence(
            payload["source_artifact_ids"], "authoritative claim source artifacts"
        ),
        requirements=(
            None if requirements is None else _claim_requirements_from_json(requirements)
        ),
        confirmatory=payload["confirmatory"],
        confirmatory_authority=(
            None
            if confirmatory is None
            else ConfirmatoryClaimAuthority(
                **{
                    **dict(
                        _require_exact_keys(
                            confirmatory,
                            {
                                item.name
                                for item in fields(ConfirmatoryClaimAuthority)
                            },
                            "confirmatory claim authority",
                        )
                    ),
                    "scope": ConfirmatoryAuthorityScope(confirmatory["scope"]),
                }
            )
        ),
    )


def _authoritative_bundle_from_json(value: Any) -> AuthoritativeResearchBundle:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(AuthoritativeResearchBundle)},
        "authoritative research bundle",
    )
    return AuthoritativeResearchBundle(
        research_state_hash=payload["research_state_hash"],
        claim_graph_hash=payload["claim_graph_hash"],
        claims=tuple(
            _authoritative_claim_from_json(item)
            for item in _sequence(payload["claims"], "authoritative claims")
        ),
        central_claim_ids=_sequence(
            payload["central_claim_ids"], "central claim IDs"
        ),
        authoritative_evidence_hashes=_sequence(
            payload["authoritative_evidence_hashes"], "authoritative evidence"
        ),
        metrics=tuple(
            AuthoritativeMetric(
                **{
                    **dict(
                        _require_exact_keys(
                            item,
                            {field.name for field in fields(AuthoritativeMetric)},
                            "authoritative metric",
                        )
                    ),
                    "direction": MetricDirection(item["direction"]),
                    "scientific_evidence_status": MetricEvidenceStatus(
                        item["scientific_evidence_status"]
                    ),
                    "result_authority_sources": tuple(
                        _state_authority_source_from_json(source)
                        for source in _sequence(
                            item["result_authority_sources"],
                            "result authority sources",
                        )
                    ),
                    "metric_authority_sources": tuple(
                        _state_authority_source_from_json(source)
                        for source in _sequence(
                            item["metric_authority_sources"],
                            "metric authority sources",
                        )
                    ),
                }
            )
            for item in _sequence(payload["metrics"], "authoritative metrics")
        ),
        method_code_bindings=tuple(
            _method_binding_from_json(item)
            for item in _sequence(
                payload["method_code_bindings"], "authoritative method/code bindings"
            )
        ),
        required_limitations=_sequence(
            payload["required_limitations"], "required limitations"
        ),
        required_baselines_complete=payload["required_baselines_complete"],
        leakage_resolved=payload["leakage_resolved"],
        evaluator_exploitation_resolved=payload[
            "evaluator_exploitation_resolved"
        ],
        statistics_valid=payload["statistics_valid"],
        novelty_supported=payload["novelty_supported"],
        selection_integrity_valid=payload["selection_integrity_valid"],
        clean_reproduction_passed=payload["clean_reproduction_passed"],
        soundness_verdict=SoundnessVerdict(payload["soundness_verdict"]),
        soundness_assessment_hash=payload["soundness_assessment_hash"],
        external_validation_complete=payload["external_validation_complete"],
        confirmatory_claim_authority_hashes=_sequence(
            payload["confirmatory_claim_authority_hashes"],
            "confirmatory claim authority artifacts",
        ),
        run_id=payload["run_id"],
        research_state_artifact_hashes=_sequence(
            payload["research_state_artifact_hashes"],
            "authoritative research-state artifacts",
        ),
        research_state_ledger_head_hash=payload[
            "research_state_ledger_head_hash"
        ],
        research_state_ledger_event_count=payload[
            "research_state_ledger_event_count"
        ],
        research_state_code_version=payload["research_state_code_version"],
        research_state_configuration_hash=payload[
            "research_state_configuration_hash"
        ],
    )


def _authoritative_bundle_parent_artifacts(
    bundle: AuthoritativeResearchBundle,
) -> tuple[str, ...]:
    parents = (
        bundle.research_state_hash,
        bundle.claim_graph_hash,
        bundle.soundness_assessment_hash,
        *bundle.confirmatory_claim_authority_hashes,
        *bundle.authoritative_evidence_hashes,
    )
    if len(parents) > MAX_ARTIFACT_PARENTS:
        raise ValidationError(
            "authoritative paper bundle exceeds the artifact parent bound"
        )
    if len(set(parents)) != len(parents):
        raise ValidationError(
            "authoritative paper bundle parents must be unique"
        )
    return parents


def _read_authoritative_bundle_artifact(
    registry: ArtifactRegistry,
    bundle_artifact_hash: str,
) -> tuple[ArtifactRecord, Mapping[str, Any], AuthoritativeResearchBundle]:
    """Parse the exact v2 artifact envelope without granting ledger authority."""

    if type(registry) is not ArtifactRegistry:
        raise ValidationError(
            "authoritative bundle readback requires the concrete registry"
        )
    record = _require_frozen_artifact(
        registry,
        bundle_artifact_hash,
        logical_type="authoritative_research_bundle",
        creator_role=Role.ORCHESTRATOR,
    )
    if (
        record.schema_version
        != AUTHORITATIVE_BUNDLE_ARTIFACT_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin
        != "issued exact authoritative research bundle"
        or record.creation_command
        != AUTHORITATIVE_BUNDLE_CREATION_COMMAND
    ):
        raise ValidationError(
            "artifact is not an issued authoritative research bundle"
        )
    raw = registry.get_bytes(bundle_artifact_hash)
    if len(raw) > MAX_AUTHORITATIVE_BUNDLE_BYTES:
        raise ValidationError(
            "authoritative research bundle exceeds its byte bound"
        )
    value = safe_json_loads(
        raw,
        max_bytes=MAX_AUTHORITATIVE_BUNDLE_BYTES,
    )
    required_keys = {
        "bundle",
        "bundle_id",
        "bundle_schema_version",
        "issued_at",
        "ledger_event_count_before_bundle",
        "ledger_head_hash_before_bundle",
        "research_state_snapshot_artifact_hash",
        "research_state_snapshot_ledger_event_count",
        "research_state_snapshot_ledger_head_hash",
        "run_id",
    }
    optional_keys = {
        "deterministic_control_derivations",
        "fixture_notice",
    }
    if (
        not isinstance(value, Mapping)
        or raw != canonical_json_bytes(value) + b"\n"
        or not required_keys.issubset(value)
        or not set(value).issubset(required_keys | optional_keys)
    ):
        raise ValidationError(
            "authoritative research-bundle envelope is malformed"
        )
    bundle_value = value["bundle"]
    try:
        bundle = _authoritative_bundle_from_json(bundle_value)
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError(
            "authoritative research-bundle payload is malformed"
        ) from exc
    if bundle_value != _plain_json(bundle):
        raise ValidationError(
            "authoritative research-bundle payload is noncanonical"
        )
    bundle_id = value["bundle_id"]
    run_id = value["run_id"]
    if not isinstance(bundle_id, str) or not isinstance(run_id, str):
        raise ValidationError(
            "authoritative research-bundle identity is malformed"
        )
    validate_identifier(bundle_id, "authoritative research-bundle ID")
    validate_identifier(run_id, "authoritative research-bundle run ID")
    count_before = value["ledger_event_count_before_bundle"]
    snapshot_count = value[
        "research_state_snapshot_ledger_event_count"
    ]
    if (
        isinstance(count_before, bool)
        or not isinstance(count_before, int)
        or count_before <= 0
        or count_before > MAX_LEDGER_EVENTS
        or isinstance(snapshot_count, bool)
        or not isinstance(snapshot_count, int)
        or snapshot_count <= 0
        or snapshot_count > count_before
    ):
        raise ValidationError(
            "authoritative research-bundle ledger bounds are malformed"
        )
    for label, digest in (
        ("pre-bundle ledger head", value["ledger_head_hash_before_bundle"]),
        (
            "research-state snapshot artifact",
            value["research_state_snapshot_artifact_hash"],
        ),
        (
            "research-state snapshot ledger head",
            value["research_state_snapshot_ledger_head_hash"],
        ),
    ):
        validate_sha256(digest, label)
    if (
        value["bundle_schema_version"]
        != AUTHORITATIVE_BUNDLE_PAYLOAD_SCHEMA
        or value["issued_at"] != record.created_at
        or run_id != bundle.run_id
        or value["research_state_snapshot_artifact_hash"]
        != bundle.research_state_hash
        or value["research_state_snapshot_ledger_head_hash"]
        != bundle.research_state_ledger_head_hash
        or snapshot_count != bundle.research_state_ledger_event_count
        or record.parent_artifacts
        != _authoritative_bundle_parent_artifacts(bundle)
    ):
        raise ValidationError(
            "authoritative research-bundle envelope was substituted"
        )
    if "fixture_notice" in value:
        _text(
            value["fixture_notice"],
            "authoritative research-bundle fixture notice",
            maximum=4096,
        )
    if (
        "deterministic_control_derivations" in value
        and not isinstance(value["deterministic_control_derivations"], Mapping)
    ):
        raise ValidationError(
            "authoritative research-bundle diagnostics must be an object"
        )
    return record, value, bundle


def _authoritative_bundle_event_metadata(
    record: ArtifactRecord,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "artifact_record_hashes": [str(record.record_hash)],
        "artifact_types": [record.logical_type],
        "authoritative_bundle_artifact_hash": record.sha256,
        "authoritative_bundle_artifact_record_hash": str(
            record.record_hash
        ),
        "authoritative_bundle_id": value["bundle_id"],
        "authoritative_bundle_schema_version": (
            AUTHORITATIVE_BUNDLE_PAYLOAD_SCHEMA
        ),
        "ledger_event_count_before_bundle": value[
            "ledger_event_count_before_bundle"
        ],
        "ledger_head_hash_before_bundle": value[
            "ledger_head_hash_before_bundle"
        ],
        "paper_operation": "AUTHORITATIVE_BUNDLE_ISSUED",
        "research_state_snapshot_artifact_hash": value[
            "research_state_snapshot_artifact_hash"
        ],
        "research_state_snapshot_ledger_event_count": value[
            "research_state_snapshot_ledger_event_count"
        ],
        "research_state_snapshot_ledger_head_hash": value[
            "research_state_snapshot_ledger_head_hash"
        ],
    }


def _require_authoritative_bundle_issuance(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    bundle_artifact_hash: str,
    expected_bundle: AuthoritativeResearchBundle | None = None,
    _round_replay: _PaperRoundReplay | None = None,
) -> LedgerEvent:
    """Require the one event that froze a paper bundle at its snapshot era."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ValidationError(
            "authoritative bundle issuance requires concrete registry and ledger"
        )
    if registry.policy.root != ledger.policy.root:
        raise ValidationError(
            "authoritative bundle registry and ledger roots differ"
        )
    record, value, bundle = _read_authoritative_bundle_artifact(
        registry,
        bundle_artifact_hash,
    )
    if expected_bundle is not None and (
        type(expected_bundle) is not AuthoritativeResearchBundle
        or bundle != expected_bundle
    ):
        raise ValidationError(
            "issued authoritative bundle differs from the typed bundle"
        )
    if (
        bundle.run_id is None
        or bundle.research_state_ledger_head_hash is None
        or bundle.research_state_ledger_event_count is None
        or bundle.research_state_code_version is None
        or bundle.research_state_configuration_hash is None
    ):
        raise ValidationError(
            "issued authoritative bundle lacks its research-state binding"
        )
    _resolve_paper_bound_state(
        registry, ledger, bundle, replay=_round_replay,
    )
    ledger_result = ledger.validate(raise_on_error=True)
    event_id = f"arb-{record.sha256[:48]}"
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) != 1:
        raise ValidationError(
            "authoritative research bundle lacks one exact issuance event"
        )
    event_index, event = matches[0]
    count_before = value["ledger_event_count_before_bundle"]
    head_before = value["ledger_head_hash_before_bundle"]
    snapshot_count = value[
        "research_state_snapshot_ledger_event_count"
    ]
    if (
        event_index != count_before
        or count_before <= 0
        or count_before >= len(ledger_result.events)
        or ledger_result.events[count_before - 1].event_hash != head_before
        or snapshot_count > count_before
        or ledger_result.events[snapshot_count - 1].event_hash
        != value["research_state_snapshot_ledger_head_hash"]
    ):
        raise ValidationError(
            "authoritative research-bundle issuance prefix is absent or changed"
        )
    if any(
        candidate.metadata.get("research_state_operation")
        in {"MATERIALIZED", "SUPERSEDED"}
        for candidate in ledger_result.events[snapshot_count:event_index]
    ):
        raise ValidationError(
            "canonical research state changed before bundle issuance"
        )
    issued_at = datetime.fromisoformat(
        record.created_at.replace("Z", "+00:00")
    )
    prefix_latest = max(
        datetime.fromisoformat(
            candidate.timestamp.replace("Z", "+00:00")
        )
        for candidate in ledger_result.events[:count_before]
    )
    if issued_at < prefix_latest:
        raise ValidationError(
            "authoritative research bundle predates its ledger prefix"
        )
    snapshot_event = ledger_result.events[snapshot_count - 1]
    expected = LedgerEvent.create(
        run_id=bundle.run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=snapshot_event.requested_state_after,
        requested_state_after=snapshot_event.requested_state_after,
        artifact_hashes=(record.sha256,),
        code_version=bundle.research_state_code_version,
        configuration_hash=bundle.research_state_configuration_hash,
        reason="issued authoritative research bundle at exact snapshot era",
        prior_event_hash=head_before,
        event_id=event_id,
        timestamp=record.created_at,
        event_type="CHECKPOINT",
        metadata=_authoritative_bundle_event_metadata(record, value),
    )
    if event != expected:
        raise ValidationError(
            "authoritative research-bundle issuance event was substituted"
        )
    if any(
        candidate.event_type == "CORRECTION"
        and candidate.supersedes_event_id == event_id
        for candidate in ledger_result.events[event_index + 1 :]
    ):
        raise ValidationError(
            "authoritative research-bundle issuance was later corrected"
        )
    if any(
        record.sha256 in candidate.artifact_hashes
        and candidate.event_id != event_id
        for candidate in ledger_result.events
    ):
        raise ValidationError(
            "authoritative research bundle has ambiguous ledger admissions"
        )
    return event


def _find_issued_authoritative_bundle(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    bundle: AuthoritativeResearchBundle,
    *,
    _round_replay: _PaperRoundReplay | None = None,
) -> ArtifactRecord:
    registry.verify_all(raise_on_error=True)
    matches: list[ArtifactRecord] = []
    for candidate in registry.list_records():
        if (
            candidate.logical_type != "authoritative_research_bundle"
            or candidate.schema_version
            != AUTHORITATIVE_BUNDLE_ARTIFACT_SCHEMA_VERSION
        ):
            continue
        record, _value, parsed = _read_authoritative_bundle_artifact(
            registry,
            candidate.sha256,
        )
        if parsed == bundle:
            matches.append(record)
    if len(matches) != 1:
        raise ValidationError(
            "typed paper bundle lacks one unique issued artifact"
        )
    _require_authoritative_bundle_issuance(
        registry,
        ledger,
        bundle_artifact_hash=matches[0].sha256,
        expected_bundle=bundle,
        _round_replay=_round_replay,
    )
    return matches[0]


def register_authoritative_research_bundle(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    bundle: AuthoritativeResearchBundle,
    *,
    bundle_id: str,
    created_at: str | None = None,
    deterministic_control_derivations: Mapping[str, Any] | None = None,
    fixture_notice: str | None = None,
) -> ArtifactRecord:
    """Atomically publish a bundle and its snapshot-era issuance event."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ValidationError(
            "authoritative bundle issuance requires concrete registry and ledger"
        )
    if type(bundle) is not AuthoritativeResearchBundle:
        raise ValidationError(
            "authoritative bundle issuance requires the exact typed bundle"
        )
    if registry.policy.root != ledger.policy.root:
        raise ValidationError(
            "authoritative bundle registry and ledger roots differ"
        )
    validate_identifier(bundle_id, "authoritative research-bundle ID")
    if fixture_notice is not None:
        _text(
            fixture_notice,
            "authoritative research-bundle fixture notice",
            maximum=4096,
        )
    controls = (
        None
        if deterministic_control_derivations is None
        else _plain_json(dict(deterministic_control_derivations))
    )
    if controls is not None and not isinstance(controls, Mapping):
        raise ValidationError(
            "authoritative research-bundle diagnostics must be an object"
        )
    if (
        bundle.run_id is None
        or bundle.research_state_ledger_head_hash is None
        or bundle.research_state_ledger_event_count is None
        or bundle.research_state_code_version is None
        or bundle.research_state_configuration_hash is None
    ):
        raise ValidationError(
            "authoritative bundle issuance requires complete state authority"
        )
    source_registry_result = registry.verify_all(raise_on_error=True)
    source_ledger_result = ledger.validate(raise_on_error=True)
    state_authority = resolve_bound_research_state_authority(
        registry,
        ledger,
        run_id=bundle.run_id,
        snapshot_artifact_hash=bundle.research_state_hash,
        state_artifact_hashes=bundle.research_state_artifact_hashes,
        ledger_head_hash=bundle.research_state_ledger_head_hash,
        ledger_event_count=bundle.research_state_ledger_event_count,
        expected_code_version=bundle.research_state_code_version,
        expected_configuration_hash=(
            bundle.research_state_configuration_hash
        ),
    )
    canonical_bundle = _build_authoritative_research_bundle(
        registry,
        state_authority=state_authority,
        ledger=ledger,
        run_id=bundle.run_id,
        confirmatory_timeline_receipt_hashes=tuple(
            item.confirmatory_authority.timeline_receipt_hash
            for item in bundle.claims
            if item.confirmatory_authority is not None
        ),
        confirmatory_claim_authority_hashes=(
            bundle.confirmatory_claim_authority_hashes
        ),
        research_state_hash=bundle.research_state_hash,
        claim_graph_hash=bundle.claim_graph_hash,
        central_claim_ids=bundle.central_claim_ids,
        authoritative_evidence_hashes=bundle.authoritative_evidence_hashes,
        metrics=bundle.metrics,
        method_code_bindings=bundle.method_code_bindings,
        required_baselines_complete=bundle.required_baselines_complete,
        leakage_resolved=bundle.leakage_resolved,
        evaluator_exploitation_resolved=(
            bundle.evaluator_exploitation_resolved
        ),
        statistics_valid=bundle.statistics_valid,
        novelty_supported=bundle.novelty_supported,
        selection_integrity_valid=bundle.selection_integrity_valid,
        clean_reproduction_passed=bundle.clean_reproduction_passed,
        soundness_assessment_hash=bundle.soundness_assessment_hash,
        external_validation_complete=bundle.external_validation_complete,
    )
    if canonical_bundle != bundle:
        raise ValidationError(
            "authoritative research bundle differs from fresh source replay"
        )
    registry_result = registry.verify_all(raise_on_error=True)
    ledger_result = ledger.validate(raise_on_error=True)
    if (
        registry_result != source_registry_result
        or ledger_result != source_ledger_result
    ):
        raise ValidationError(
            "authoritative research-bundle source changed during fresh replay"
        )
    if not ledger_result.events or ledger_result.head_hash is None:
        raise ValidationError(
            "authoritative bundle issuance requires a non-empty ledger"
        )
    snapshot_count = bundle.research_state_ledger_event_count
    if (
        snapshot_count > ledger_result.event_count
        or ledger_result.events[snapshot_count - 1].event_hash
        != bundle.research_state_ledger_head_hash
    ):
        raise ValidationError(
            "authoritative bundle snapshot prefix is absent"
        )
    identity_candidates: list[
        tuple[ArtifactRecord, Mapping[str, Any], AuthoritativeResearchBundle]
    ] = []
    exact_bundle_candidates: list[ArtifactRecord] = []
    for candidate in registry.list_records():
        if (
            candidate.logical_type != "authoritative_research_bundle"
            or candidate.schema_version
            != AUTHORITATIVE_BUNDLE_ARTIFACT_SCHEMA_VERSION
        ):
            continue
        record, value, parsed = _read_authoritative_bundle_artifact(
            registry,
            candidate.sha256,
        )
        if parsed == bundle:
            exact_bundle_candidates.append(record)
        if (
            value["run_id"] == bundle.run_id
            and value["bundle_id"] == bundle_id
        ):
            identity_candidates.append((record, value, parsed))
    if len(identity_candidates) > 1:
        raise ValidationError(
            "authoritative research-bundle identity is ambiguous"
        )
    if identity_candidates:
        completed_record, completed_value, completed_bundle = (
            identity_candidates[0]
        )
        if (
            completed_bundle != bundle
            or (
                created_at is not None
                and completed_record.created_at != created_at
            )
            or completed_value.get("fixture_notice") != fixture_notice
            or completed_value.get("deterministic_control_derivations")
            != controls
        ):
            raise ValidationError(
                "authoritative research-bundle identity collides"
            )
        completed_event_id = f"arb-{completed_record.sha256[:48]}"
        if any(
            event.event_id == completed_event_id
            for event in ledger_result.events
        ):
            _require_authoritative_bundle_issuance(
                registry,
                ledger,
                bundle_artifact_hash=completed_record.sha256,
                expected_bundle=bundle,
            )
            return completed_record
    if any(
        candidate.metadata.get("research_state_operation")
        in {"MATERIALIZED", "SUPERSEDED"}
        for candidate in ledger_result.events[snapshot_count:]
    ):
        raise ValidationError(
            "canonical research state changed before bundle issuance"
        )

    existing: ArtifactRecord | None = None
    if identity_candidates:
        existing, existing_value, existing_bundle = identity_candidates[0]
        if (
            existing_bundle != bundle
            or (created_at is not None and existing.created_at != created_at)
            or existing_value.get("fixture_notice") != fixture_notice
            or existing_value.get("deterministic_control_derivations")
            != controls
        ):
            raise ValidationError(
                "authoritative research-bundle identity collides"
            )
        if (
            existing_value["ledger_event_count_before_bundle"]
            != ledger_result.event_count
            or existing_value["ledger_head_hash_before_bundle"]
            != ledger_result.head_hash
            or any(
                existing.sha256 in event.artifact_hashes
                for event in ledger_result.events
            )
        ):
            raise ValidationError(
                "authoritative research-bundle orphan cannot resume after ledger change"
            )
        value = dict(existing_value)
        bundle_bytes = registry.get_bytes(existing.sha256)
        expected_record = existing
    else:
        if exact_bundle_candidates:
            raise ValidationError(
                "authoritative research bundle already has another issuance identity"
            )
        issued_at = utc_now() if created_at is None else created_at
        value = {
            "bundle": _plain_json(bundle),
            "bundle_id": bundle_id,
            "bundle_schema_version": AUTHORITATIVE_BUNDLE_PAYLOAD_SCHEMA,
            "issued_at": issued_at,
            "ledger_event_count_before_bundle": ledger_result.event_count,
            "ledger_head_hash_before_bundle": ledger_result.head_hash,
            "research_state_snapshot_artifact_hash": (
                bundle.research_state_hash
            ),
            "research_state_snapshot_ledger_event_count": snapshot_count,
            "research_state_snapshot_ledger_head_hash": (
                bundle.research_state_ledger_head_hash
            ),
            "run_id": bundle.run_id,
        }
        if controls is not None:
            value["deterministic_control_derivations"] = controls
        if fixture_notice is not None:
            value["fixture_notice"] = fixture_notice
        bundle_bytes = canonical_json_bytes(value) + b"\n"
        if len(bundle_bytes) > MAX_AUTHORITATIVE_BUNDLE_BYTES:
            raise ValidationError(
                "authoritative research bundle exceeds its byte bound"
            )
        digest = sha256_bytes(bundle_bytes)
        object_path = registry.objects_path / digest[:2] / digest
        metadata_path = registry.metadata_path / digest[:2] / f"{digest}.json"
        expected_record = ArtifactRecord(
            sha256=digest,
            path=object_path.as_posix(),
            relative_path=object_path.as_posix(),
            metadata_path=metadata_path.as_posix(),
            logical_type="authoritative_research_bundle",
            schema_version=AUTHORITATIVE_BUNDLE_ARTIFACT_SCHEMA_VERSION,
            mime_type="application/json",
            size=len(bundle_bytes),
            origin="issued exact authoritative research bundle",
            creator_role=Role.ORCHESTRATOR,
            creation_command=AUTHORITATIVE_BUNDLE_CREATION_COMMAND,
            parent_artifacts=_authoritative_bundle_parent_artifacts(bundle),
            validation_result="PASS",
            frozen=True,
            created_at=issued_at,
        )
        if any(
            candidate.sha256 == expected_record.sha256
            for candidate in registry.list_records()
        ):
            raise ValidationError(
                "authoritative research-bundle artifact collides"
            )
    if datetime.fromisoformat(
        expected_record.created_at.replace("Z", "+00:00")
    ) < max(
        datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        for event in ledger_result.events
    ):
        raise ValidationError(
            "authoritative research bundle cannot predate its ledger prefix"
        )
    if registry_result.count + int(existing is None) > MAX_REGISTRY_RECORDS:
        raise ValidationError(
            "authoritative research bundle exceeds registry capacity"
        )

    event_id = f"arb-{expected_record.sha256[:48]}"
    if any(
        event.event_id == event_id
        or expected_record.sha256 in event.artifact_hashes
        for event in ledger_result.events
    ):
        raise ValidationError(
            "authoritative research-bundle issuance event collides"
        )
    snapshot_event = ledger_result.events[snapshot_count - 1]
    event_to_append = LedgerEvent.create(
        run_id=bundle.run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=snapshot_event.requested_state_after,
        requested_state_after=snapshot_event.requested_state_after,
        artifact_hashes=(expected_record.sha256,),
        code_version=bundle.research_state_code_version,
        configuration_hash=bundle.research_state_configuration_hash,
        reason="issued authoritative research bundle at exact snapshot era",
        prior_event_hash=ledger_result.head_hash,
        event_id=event_id,
        timestamp=expected_record.created_at,
        event_type="CHECKPOINT",
        metadata=_authoritative_bundle_event_metadata(
            expected_record,
            value,
        ),
    )
    event_bytes = canonical_json_bytes(event_to_append.to_dict()) + b"\n"
    if ledger_result.event_count + 1 > MAX_LEDGER_EVENTS:
        raise ValidationError(
            "authoritative research bundle exceeds ledger capacity"
        )
    if ledger_result.valid_prefix_bytes + len(event_bytes) > MAX_LEDGER_BYTES:
        raise ValidationError(
            "authoritative research bundle exceeds ledger byte capacity"
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
                or locked_registry != registry_result
                or locked_ledger != ledger_result
            ):
                raise ValidationError(
                    "authoritative research-bundle source changed before issuance"
                )
            if existing is None:
                record = registry._put_bytes_locked(
                    registry_guard,
                    bundle_bytes,
                    logical_type=expected_record.logical_type,
                    origin=expected_record.origin,
                    creator_role=expected_record.creator_role,
                    creation_command=expected_record.creation_command,
                    parent_artifacts=expected_record.parent_artifacts,
                    schema_version=expected_record.schema_version,
                    mime_type=expected_record.mime_type,
                    validation_result=expected_record.validation_result,
                    frozen=expected_record.frozen,
                    created_at=expected_record.created_at,
                )
            else:
                record = registry._get_metadata_locked(
                    registry_guard,
                    existing.sha256,
                )
            if record != expected_record:
                raise ValidationError(
                    "authoritative research bundle changed during issuance"
                )

            def build_event(current: LedgerValidationResult) -> LedgerEvent:
                if current != locked_ledger:
                    raise ValidationError(
                        "authoritative research-bundle ledger changed during issuance"
                    )
                return event_to_append

            appended = ledger._append_locked(ledger_guard, build_event)
            if appended != event_to_append:
                raise ValidationError(
                    "authoritative research-bundle issuance event changed"
                )
            registry._verify_mutation_namespace(registry_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return record


def _paper_candidate_from_json(value: Any) -> PaperCandidate:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(PaperCandidate)},
        "paper candidate",
    )
    return PaperCandidate(
        candidate_id=payload["candidate_id"],
        title=payload["title"],
        claims=tuple(
            PaperClaim(
                claim_id=_require_exact_keys(
                    item,
                    {field.name for field in fields(PaperClaim)},
                    "paper claim",
                )["claim_id"],
                text=item["text"],
                strength=ClaimStrength(item["strength"]),
                evidence_hashes=_sequence(
                    item["evidence_hashes"], "paper claim evidence"
                ),
                citation_ids=_sequence(item["citation_ids"], "paper claim citations"),
                central=item["central"],
                claim_type=ClaimType(item["claim_type"]),
                scope=item["scope"],
                confidence=item["confidence"],
                verification_method=item["verification_method"],
                permitted_strength=ClaimStrength(item["permitted_strength"]),
                dependency_claim_ids=_sequence(
                    item["dependency_claim_ids"],
                    "paper claim dependencies",
                ),
                evidence_sources=tuple(
                    _evidence_source_binding_from_json(binding)
                    for binding in _sequence(
                        item["evidence_sources"],
                        "paper claim evidence-source bindings",
                    )
                ),
            )
            for item in _sequence(payload["claims"], "paper claims")
        ),
        numeric_assertions=tuple(
            PaperNumericAssertion(
                assertion_id=_require_exact_keys(
                    item,
                    {field.name for field in fields(PaperNumericAssertion)},
                    "paper numeric assertion",
                )["assertion_id"],
                claim_id=item["claim_id"],
                metric_id=item["metric_id"],
                value=item["value"],
                unit=item["unit"],
                direction=MetricDirection(item["direction"]),
                source_artifact_hash=item["source_artifact_hash"],
            )
            for item in _sequence(
                payload["numeric_assertions"], "paper numeric assertions"
            )
        ),
        references=tuple(
            ReferenceUse(
                citation_id=_require_exact_keys(
                    item,
                    {field.name for field in fields(ReferenceUse)},
                    "paper reference use",
                )["citation_id"],
                reference_artifact_hash=item["reference_artifact_hash"],
                verification_depth=ReferenceDepth(item["verification_depth"]),
                supported_claim_ids=_sequence(
                    item["supported_claim_ids"], "reference supported claims"
                ),
                contradictory_context=item["contradictory_context"],
                source_citation_evidence_artifact_hash=item[
                    "source_citation_evidence_artifact_hash"
                ],
                citation_node_id=item["citation_node_id"],
                passage_sha256=item["passage_sha256"],
                passage_locator_sha256=item["passage_locator_sha256"],
                context_sha256=item["context_sha256"],
                semantic_judgment_artifact_hash=item[
                    "semantic_judgment_artifact_hash"
                ],
            )
            for item in _sequence(payload["references"], "paper references")
        ),
        assets=tuple(
            GeneratedAsset(
                asset_id=_require_exact_keys(
                    item,
                    {field.name for field in fields(GeneratedAsset)},
                    "paper generated asset",
                )["asset_id"],
                kind=item["kind"],
                artifact_hash=item["artifact_hash"],
                authoritative_parent_hashes=_sequence(
                    item["authoritative_parent_hashes"], "generated asset parents"
                ),
            )
            for item in _sequence(payload["assets"], "paper generated assets")
        ),
        method_code_bindings=tuple(
            _method_binding_from_json(item)
            for item in _sequence(
                payload["method_code_bindings"], "paper method/code bindings"
            )
        ),
        limitations=_sequence(payload["limitations"], "paper limitations"),
        source_bundle_hashes=_sequence(
            payload["source_bundle_hashes"], "paper source bundle"
        ),
    )


def _paper_verification_from_json(value: Any) -> PaperVerification:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(PaperVerification)},
        "paper verification",
    )
    return PaperVerification(
        passed=payload["passed"],
        blockers=tuple(
            HardBlocker(item)
            for item in _sequence(payload["blockers"], "paper blockers")
        ),
        discrepancies=_sequence(
            payload["discrepancies"], "paper discrepancies"
        ),
        verified_claim_ids=_sequence(
            payload["verified_claim_ids"], "verified paper claim IDs"
        ),
    )


def _resolve_candidate_bundle_artifacts(
    registry: ArtifactRegistry,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
) -> None:
    candidate_record, candidate_wrapper = _read_registry_json(
        registry,
        candidate_artifact_hash,
        logical_type="paper_candidate",
        creator_role=Role.PAPER_WRITER,
    )
    bundle_record, bundle_wrapper, registered_bundle = (
        _read_authoritative_bundle_artifact(
            registry,
            bundle_artifact_hash,
        )
    )
    if candidate_wrapper.get("candidate") != _plain_json(candidate):
        raise ValidationError("registered paper candidate differs from the typed candidate")
    if (
        registered_bundle != bundle
        or bundle_wrapper.get("bundle") != _plain_json(bundle)
    ):
        raise ValidationError("registered paper bundle differs from the typed bundle")
    expected_candidate_parents = (
        bundle_artifact_hash,
        *(asset.artifact_hash for asset in candidate.assets),
    )
    if candidate_record.parent_artifacts != expected_candidate_parents:
        raise ValidationError(
            "registered paper candidate has substituted authority parents"
        )
    expected_bundle_parents = (
        bundle.research_state_hash,
        bundle.claim_graph_hash,
        bundle.soundness_assessment_hash,
        *bundle.confirmatory_claim_authority_hashes,
        *bundle.authoritative_evidence_hashes,
    )
    if bundle_record.parent_artifacts != expected_bundle_parents:
        raise ValidationError(
            "registered paper bundle has substituted authority parents"
        )
    core_sources = (
        bundle.research_state_hash,
        bundle.claim_graph_hash,
        bundle.soundness_assessment_hash,
        *bundle.confirmatory_claim_authority_hashes,
    )
    if candidate.source_bundle_hashes not in (
        core_sources,
        (*core_sources, bundle_artifact_hash),
    ):
        raise ValidationError("paper candidate source-bundle inventory was substituted")


def _candidate_source_bundle_resolves(
    registry: ArtifactRegistry,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    *,
    issued_bundle_artifact_hash: str,
) -> bool:
    core_sources = (
        bundle.research_state_hash,
        bundle.claim_graph_hash,
        bundle.soundness_assessment_hash,
        *bundle.confirmatory_claim_authority_hashes,
    )
    if candidate.source_bundle_hashes == core_sources:
        return True
    if (
        len(candidate.source_bundle_hashes) != len(core_sources) + 1
        or candidate.source_bundle_hashes[:-1] != core_sources
    ):
        return False
    bundle_artifact_hash = candidate.source_bundle_hashes[-1]
    if bundle_artifact_hash != issued_bundle_artifact_hash:
        return False
    try:
        bundle_record, wrapper, registered_bundle = (
            _read_authoritative_bundle_artifact(
                registry,
                bundle_artifact_hash,
            )
        )
    except Exception:
        return False
    return (
        registered_bundle == bundle
        and wrapper.get("bundle") == _plain_json(bundle)
        and bundle_record.parent_artifacts
        == (
            bundle.research_state_hash,
            bundle.claim_graph_hash,
            bundle.soundness_assessment_hash,
            *bundle.confirmatory_claim_authority_hashes,
            *bundle.authoritative_evidence_hashes,
        )
    )


def _paper_source_authority(
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    *,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
) -> set[str]:
    result = {
        candidate_artifact_hash,
        bundle_artifact_hash,
        bundle.research_state_hash,
        *bundle.research_state_artifact_hashes,
        bundle.claim_graph_hash,
        bundle.soundness_assessment_hash,
        *bundle.confirmatory_claim_authority_hashes,
        *bundle.authoritative_evidence_hashes,
    }
    for metric in bundle.metrics:
        result.update(
            {metric.result_artifact_hash, metric.result_state_artifact_hash}
        )
    for binding in bundle.method_code_bindings:
        result.update(
            {
                binding.method_artifact_hash,
                binding.code_artifact_hash,
                binding.method_state_artifact_hash,
                binding.implementation_state_artifact_hash,
                *binding.authority_sources,
            }
        )
    for claim in bundle.claims:
        result.add(claim.claim_state_artifact_hash)
        result.add(claim.claim_semantics_artifact_hash)
        result.update(claim.evidence_hashes)
        result.update(claim.source_artifact_ids)
        if claim.confirmatory_authority is not None:
            result.update(
                {
                    claim.confirmatory_authority.timeline_receipt_hash,
                    claim.confirmatory_authority.protocol_artifact_hash,
                    claim.confirmatory_authority.fresh_custody_receipt_hash,
                    claim.confirmatory_authority.custody_record_hash,
                    claim.confirmatory_authority.result_artifact_hash,
                }
            )
        if claim.requirements is not None:
            for source in claim.requirements.evidence_sources:
                result.add(source.evidence_artifact_hash)
                result.update(source.source_artifact_hashes)
            for authority in claim.requirements.required_reference_authorities:
                result.update(authority.evidence_artifact_hashes)
    for asset in candidate.assets:
        result.add(asset.artifact_hash)
        result.update(asset.authoritative_parent_hashes)
    return result


def _validate_manuscript_coverage(
    registry: ArtifactRegistry,
    profile: VenueProfile,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    sections: tuple[ManuscriptSection, ...],
    bindings: tuple[ArtifactReadinessBinding, ...],
    allowed_sources: set[str],
) -> None:
    by_section = {item.section_id: item for item in sections}
    by_requirement = {item.requirement: item for item in bindings}
    section_set_mismatch = set(profile.required_sections) != set(by_section)
    requirement_set_mismatch = set(profile.artifact_requirements) != set(by_requirement)
    if section_set_mismatch or requirement_set_mismatch:
        raise ValidationError(
            "venue manuscript does not exactly cover required sections or artifacts"
        )
    all_sources = {
        digest
        for collection in (
            *(item.source_artifact_hashes for item in sections),
            *(item.artifact_hashes for item in bindings),
        )
        for digest in collection
    }
    if not all_sources.issubset(allowed_sources):
        raise ValidationError("venue manuscript cites a non-authoritative source")
    for digest in all_sources:
        _require_frozen_artifact(registry, digest)

    required_code_hashes = tuple(
        sorted(binding.code_artifact_hash for binding in bundle.method_code_bindings)
    )
    code_binding = by_requirement.get("code")
    if "code" in profile.artifact_requirements and (
        code_binding is None
        or code_binding.artifact_hashes != required_code_hashes
        or not required_code_hashes
    ):
        raise ValidationError("venue code inventory differs from canonical method bindings")

    methods_section = by_section.get("methods")
    required_method_sources = tuple(
        sorted(
            {
                *required_code_hashes,
                *(binding.method_artifact_hash for binding in bundle.method_code_bindings),
            }
        )
    )
    if "methods" in profile.required_sections and (
        methods_section is None
        or methods_section.source_artifact_hashes != required_method_sources
    ):
        raise ValidationError("venue methods section omits canonical method/code sources")

    required_result_sources = tuple(
        sorted(
            {
                *(metric.result_artifact_hash for metric in bundle.metrics),
                *(asset.artifact_hash for asset in candidate.assets),
            }
        )
    )
    results_section = by_section.get("results")
    if "results" in profile.required_sections and (
        results_section is None
        or results_section.source_artifact_hashes != required_result_sources
    ):
        raise ValidationError("venue results section omits canonical result assets")

    # Non-code requirements are an inventory only at this stage.  Their actual
    # semantics are established later by a typed venue-requirement receipt with
    # full semantic-judgment custody.  Logical-type substrings never grant
    # readiness authority.


def register_paper_manuscript(
    registry: ArtifactRegistry,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    sections: tuple[ManuscriptSection, ...],
    artifact_bindings: tuple[ArtifactReadinessBinding, ...],
) -> ArtifactRecord:
    """Register a deterministic section/source inventory, not manuscript prose."""

    if not isinstance(registry, ArtifactRegistry):
        raise ValidationError("paper manuscript registration requires ArtifactRegistry")
    if not isinstance(candidate, PaperCandidate) or not isinstance(
        bundle, AuthoritativeResearchBundle
    ):
        raise ValidationError("paper manuscript registration requires typed paper state")
    if not isinstance(profile, VenueProfile):
        raise ValidationError("paper manuscript registration requires a venue profile")
    approved_profile = require_approved_venue_profile(
        registry,
        profile_artifact_hash,
        expected_profile_id=profile.profile_id,
    )
    if approved_profile != profile:
        raise ValidationError("paper manuscript profile differs from approved policy")
    validate_identifier(run_id, "paper manuscript run ID")
    if bundle.run_id != run_id:
        raise ValidationError("paper manuscript run differs from bundle authority")
    _typed_unique(
        sections,
        ManuscriptSection,
        "manuscript sections",
        lambda item: item.section_id,
    )
    _typed_unique(
        artifact_bindings,
        ArtifactReadinessBinding,
        "manuscript artifact bindings",
        lambda item: item.requirement,
    )
    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    allowed = _paper_source_authority(
        candidate,
        bundle,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
    )
    _validate_manuscript_coverage(
        registry,
        profile,
        candidate,
        bundle,
        sections,
        artifact_bindings,
        allowed,
    )
    sources = tuple(
        dict.fromkeys(
            digest
            for collection in (
                *(item.source_artifact_hashes for item in sections),
                *(item.artifact_hashes for item in artifact_bindings),
            )
            for digest in collection
        )
    )
    return registry.put_json(
        {
            "schema_version": "paper-manuscript/v1",
            "run_id": run_id,
            "candidate_id": candidate.candidate_id,
            "candidate_artifact_hash": candidate_artifact_hash,
            "bundle_artifact_hash": bundle_artifact_hash,
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
            "profile_artifact_hash": profile_artifact_hash,
            "sections": _plain_json(sections),
            "artifact_bindings": _plain_json(artifact_bindings),
        },
        logical_type="paper_manuscript",
        origin="deterministic paper section and authoritative-source inventory",
        creator_role=Role.PAPER_WRITER,
        creation_command=("scientist-one", "register-paper-manuscript"),
        parent_artifacts=(
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            *sources,
        ),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def register_paper_manuscript_revision(*args: Any, **kwargs: Any) -> Any:
    """Issue actual deterministic prose through the vNext composition layer.

    This lazy bridge keeps the established paper-pipeline import surface while
    avoiding a module cycle: :mod:`paper_composition` consumes the typed bundle
    and verification replay implemented here.
    """

    from .paper_composition import register_paper_manuscript_revision as register

    return register(*args, **kwargs)


def require_paper_manuscript_revision(*args: Any, **kwargs: Any) -> Any:
    """Freshly replay an issued deterministic manuscript revision."""

    from .paper_composition import require_paper_manuscript_revision as require

    return require(*args, **kwargs)


def _require_venue_manuscript_revision(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    revision_artifact_hash: str,
    _round_replay: _PaperRoundReplay | None = None,
) -> Any:
    """Keep current manuscript ownership complete in either readback context."""

    if _round_replay is None:
        return require_paper_manuscript_revision(
            registry, ledger, revision_artifact_hash=revision_artifact_hash,
        )
    from .paper_composition import _require_paper_manuscript_revision

    revision = _require_paper_manuscript_revision(
        registry, ledger, revision_artifact_hash=revision_artifact_hash,
        _round_replay=_round_replay,
    )
    _require_venue_prior_event(_round_replay, revision.issuance_event)
    return revision


def _require_venue_prior_event(replay: _PaperRoundReplay, event: LedgerEvent) -> None:
    """Join an already owned admission to this exact earlier ledger prefix."""

    events = replay.reviews.ledger_snapshot.events
    matches = tuple(index for index, item in enumerate(events) if item.event_id == event.event_id)
    if (
        len(matches) != 1
        or events[matches[0]] != event
        or not matches[0] < replay.reviews.before_event_index < len(events)
    ):
        raise ValidationError("Venue source admission does not precede its canonical projection")


def _read_paper_manuscript(
    registry: ArtifactRegistry,
    manuscript_artifact_hash: str,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
) -> tuple[tuple[ManuscriptSection, ...], tuple[ArtifactReadinessBinding, ...], tuple[str, ...]]:
    if bundle.run_id != run_id:
        raise ValidationError("paper manuscript run differs from bundle authority")
    if not isinstance(profile, VenueProfile):
        raise ValidationError("paper manuscript requires a venue profile")
    approved_profile = require_approved_venue_profile(
        registry,
        profile_artifact_hash,
        expected_profile_id=profile.profile_id,
    )
    if approved_profile != profile:
        raise ValidationError("paper manuscript profile differs from approved policy")
    record, value = _read_registry_json(
        registry,
        manuscript_artifact_hash,
        logical_type="paper_manuscript",
        creator_role=Role.PAPER_WRITER,
    )
    _require_exact_keys(
        value,
        {
            "schema_version",
            "run_id",
            "candidate_id",
            "candidate_artifact_hash",
            "bundle_artifact_hash",
            "profile_id",
            "profile_sha256",
            "profile_artifact_hash",
            "sections",
            "artifact_bindings",
        },
        "paper manuscript inventory",
    )
    if (
        record.schema_version != "1.0"
        or record.origin
        != "deterministic paper section and authoritative-source inventory"
        or record.creation_command
        != ("scientist-one", "register-paper-manuscript")
        or value["schema_version"] != "paper-manuscript/v1"
        or value["run_id"] != run_id
        or value["candidate_id"] != candidate.candidate_id
        or value["candidate_artifact_hash"] != candidate_artifact_hash
        or value["bundle_artifact_hash"] != bundle_artifact_hash
        or value["profile_id"] != profile.profile_id
        or value["profile_sha256"] != profile.sha256
        or value["profile_artifact_hash"] != profile_artifact_hash
    ):
        raise ValidationError("paper manuscript inventory is bound to different authority")
    sections = tuple(
        ManuscriptSection(
            section_id=_require_exact_keys(
                item,
                {"section_id", "source_artifact_hashes"},
                "manuscript section",
            )["section_id"],
            source_artifact_hashes=_sequence(
                item["source_artifact_hashes"], "manuscript section sources"
            ),
        )
        for item in _sequence(value["sections"], "manuscript sections")
    )
    bindings = tuple(
        ArtifactReadinessBinding(
            requirement=_require_exact_keys(
                item,
                {"requirement", "artifact_hashes"},
                "manuscript artifact binding",
            )["requirement"],
            artifact_hashes=_sequence(
                item["artifact_hashes"], "manuscript artifact sources"
            ),
        )
        for item in _sequence(value["artifact_bindings"], "manuscript artifact bindings")
    )
    _typed_unique(
        sections,
        ManuscriptSection,
        "manuscript sections",
        lambda item: item.section_id,
    )
    _typed_unique(
        bindings,
        ArtifactReadinessBinding,
        "manuscript artifact bindings",
        lambda item: item.requirement,
    )
    sources = tuple(
        dict.fromkeys(
            digest
            for collection in (
                *(item.source_artifact_hashes for item in sections),
                *(item.artifact_hashes for item in bindings),
            )
            for digest in collection
        )
    )
    if record.parent_artifacts != (
        candidate_artifact_hash,
        bundle_artifact_hash,
        profile_artifact_hash,
        *sources,
    ):
        raise ValidationError("paper manuscript registry parents are incomplete or reordered")
    allowed = _paper_source_authority(
        candidate,
        bundle,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
    )
    _validate_manuscript_coverage(
        registry,
        profile,
        candidate,
        bundle,
        sections,
        bindings,
        allowed,
    )
    return sections, bindings, sources


def _revision_sections_for_profile(
    revision: Any,
    profile: VenueProfile,
) -> tuple[ManuscriptSection, ...]:
    """Derive real section coverage from replayed composition blocks.

    ``paper-manuscript/v1`` is only a structural plan.  A venue section exists
    here only when the deterministic renderer emitted a substantive body block
    with byte-exact source-map coverage.  Headings never establish coverage,
    and domain-specific sections remain absent until their own source authority
    is composed.
    """

    block_prefixes = {
        "abstract": ("abstract-claim-",),
        "introduction": ("introduction-scope-",),
        "methods": ("method-",),
        "results": ("result-claim-", "result-numeric-", "result-asset-"),
        "limitations": ("limitations-body",),
        "reproducibility": ("reproducibility-body",),
    }
    derived: list[ManuscriptSection] = []
    for section_id in profile.required_sections:
        prefixes = block_prefixes.get(section_id, ())
        matching = tuple(
            entry
            for entry in revision.source_map
            if prefixes and entry.block_id.startswith(prefixes)
        )
        if not matching:
            continue
        sources = tuple(
            dict.fromkeys(
                digest
                for entry in matching
                for digest in entry.source_artifact_hashes
            )
        )
        if sources:
            derived.append(ManuscriptSection(section_id, sources))
    return tuple(derived)


def _validate_revision_section_coverage(
    registry: ArtifactRegistry,
    revision: Any,
    profile: VenueProfile,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    *,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
) -> tuple[ManuscriptSection, ...]:
    sections = _revision_sections_for_profile(revision, profile)
    if {item.section_id for item in sections} != set(profile.required_sections):
        raise ValidationError("issued manuscript content lacks required venue sections")
    allowed = _paper_source_authority(
        candidate,
        bundle,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
    )
    actual_sources = {
        digest for section in sections for digest in section.source_artifact_hashes
    }
    if not actual_sources.issubset(allowed):
        raise ValidationError(
            "issued manuscript section source map exceeds paper authority"
        )
    for digest in actual_sources:
        _require_frozen_artifact(registry, digest)
    return sections


def register_venue_readiness_manifest(
    registry: ArtifactRegistry,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    manuscript_artifact_hash: str,
    ledger: EventLedger | None = None,
    manuscript_revision_artifact_hash: str | None = None,
) -> ArtifactRecord:
    """Freeze reviewer-readable coverage derived from a registered manuscript."""

    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    sections, bindings, sources = _read_paper_manuscript(
        registry,
        manuscript_artifact_hash,
        candidate,
        bundle,
        profile,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
    )
    manuscript_content_artifact_hash: str | None = None
    composition_verification_artifact_hash: str | None = None
    if manuscript_revision_artifact_hash is not None:
        if ledger is None:
            raise ValidationError("venue manuscript revision requires EventLedger replay")
        revision = require_paper_manuscript_revision(
            registry,
            ledger,
            revision_artifact_hash=manuscript_revision_artifact_hash,
        )
        if (
            revision.revision.run_id != run_id
            or revision.revision.candidate_artifact_hash != candidate_artifact_hash
            or revision.revision.bundle_artifact_hash != bundle_artifact_hash
        ):
            raise ValidationError("venue manuscript revision names different paper authority")
        sections = _validate_revision_section_coverage(
            registry,
            revision,
            profile,
            candidate,
            bundle,
            candidate_artifact_hash=candidate_artifact_hash,
            bundle_artifact_hash=bundle_artifact_hash,
        )
        manuscript_content_artifact_hash = revision.content_record.sha256
        composition_verification_artifact_hash = (
            revision.composition_verification_record.sha256
        )
        sources = tuple(
            dict.fromkeys(
                (
                    *(digest for item in sections for digest in item.source_artifact_hashes),
                    *(digest for item in bindings for digest in item.artifact_hashes),
                    manuscript_content_artifact_hash,
                )
            )
        )
    manifest = VenueReadinessManifest(
        run_id=run_id,
        candidate_id=candidate.candidate_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        manuscript_artifact_hash=manuscript_artifact_hash,
        profile_id=profile.profile_id,
        profile_sha256=profile.sha256,
        profile_artifact_hash=profile_artifact_hash,
        sections=sections,
        artifact_bindings=bindings,
        source_artifact_hashes=sources,
        manuscript_revision_artifact_hash=manuscript_revision_artifact_hash,
        manuscript_content_artifact_hash=manuscript_content_artifact_hash,
        composition_verification_artifact_hash=(
            composition_verification_artifact_hash
        ),
        schema_version=(
            "venue-readiness/v2"
            if manuscript_revision_artifact_hash is not None
            else "venue-readiness/v1"
        ),
    )
    manifest_payload = manifest.to_dict()
    if manifest.schema_version == "venue-readiness/v1":
        for name in (
            "manuscript_revision_artifact_hash",
            "manuscript_content_artifact_hash",
            "composition_verification_artifact_hash",
        ):
            manifest_payload.pop(name)
    return registry.put_json(
        manifest_payload,
        logical_type="venue_readiness_manifest",
        origin=(
            _VENUE_READINESS_V2_ORIGIN
            if manifest.schema_version == "venue-readiness/v2"
            else _VENUE_READINESS_V1_ORIGIN
        ),
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_VENUE_READINESS_COMMAND,
        parent_artifacts=tuple(dict.fromkeys((
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            manuscript_artifact_hash,
            *((manuscript_revision_artifact_hash,) if manuscript_revision_artifact_hash else ()),
            *((composition_verification_artifact_hash,) if composition_verification_artifact_hash else ()),
            *sources,
        ))),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _resolve_venue_readiness_manifest(
    registry: ArtifactRegistry,
    manifest_hash: str,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    ledger: EventLedger | None = None,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    _round_replay: _PaperRoundReplay | None = None,
) -> VenueReadinessManifest:
    approved_profile = require_approved_venue_profile(
        registry,
        profile_artifact_hash,
        expected_profile_id=profile.profile_id,
    )
    if approved_profile != profile:
        raise ValidationError("venue-readiness profile differs from approved policy")
    record, value = _read_registry_json(
        registry,
        manifest_hash,
        logical_type="venue_readiness_manifest",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    schema = value.get("schema_version")
    expected_keys = {item.name for item in fields(VenueReadinessManifest)}
    if schema == "venue-readiness/v1":
        expected_keys -= {
            "manuscript_revision_artifact_hash",
            "manuscript_content_artifact_hash",
            "composition_verification_artifact_hash",
        }
    _require_exact_keys(value, expected_keys, "venue-readiness manifest")
    sections = tuple(
        ManuscriptSection(
            item["section_id"],
            _sequence(item["source_artifact_hashes"], "venue section sources"),
        )
        for item in _sequence(value["sections"], "venue sections")
        if isinstance(item, Mapping)
        and set(item) == {"section_id", "source_artifact_hashes"}
    )
    bindings = tuple(
        ArtifactReadinessBinding(
            item["requirement"],
            _sequence(item["artifact_hashes"], "venue artifact sources"),
        )
        for item in _sequence(value["artifact_bindings"], "venue artifact bindings")
        if isinstance(item, Mapping)
        and set(item) == {"requirement", "artifact_hashes"}
    )
    if len(sections) != len(value["sections"]) or len(bindings) != len(
        value["artifact_bindings"]
    ):
        raise ValidationError("venue-readiness nested schema is malformed")
    manifest = VenueReadinessManifest(
        run_id=value["run_id"],
        candidate_id=value["candidate_id"],
        candidate_artifact_hash=value["candidate_artifact_hash"],
        bundle_artifact_hash=value["bundle_artifact_hash"],
        manuscript_artifact_hash=value["manuscript_artifact_hash"],
        profile_id=value["profile_id"],
        profile_sha256=value["profile_sha256"],
        profile_artifact_hash=value["profile_artifact_hash"],
        sections=sections,
        artifact_bindings=bindings,
        source_artifact_hashes=_sequence(
            value["source_artifact_hashes"], "venue-readiness sources"
        ),
        manuscript_revision_artifact_hash=value.get(
            "manuscript_revision_artifact_hash"
        ),
        manuscript_content_artifact_hash=value.get(
            "manuscript_content_artifact_hash"
        ),
        composition_verification_artifact_hash=value.get(
            "composition_verification_artifact_hash"
        ),
        schema_version=value["schema_version"],
    )
    if (
        record.schema_version != "1.0"
        or record.origin
        != (
            _VENUE_READINESS_V2_ORIGIN
            if manifest.schema_version == "venue-readiness/v2"
            else _VENUE_READINESS_V1_ORIGIN
        )
        or record.creation_command != _VENUE_READINESS_COMMAND
        or manifest.run_id != run_id
        or manifest.candidate_id != candidate.candidate_id
        or manifest.candidate_artifact_hash != candidate_artifact_hash
        or manifest.bundle_artifact_hash != bundle_artifact_hash
        or manifest.profile_id != profile.profile_id
        or manifest.profile_sha256 != profile.sha256
        or manifest.profile_artifact_hash != profile_artifact_hash
        or record.parent_artifacts
        != tuple(dict.fromkeys((
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            manifest.manuscript_artifact_hash,
            *((manifest.manuscript_revision_artifact_hash,) if manifest.manuscript_revision_artifact_hash else ()),
            *((manifest.composition_verification_artifact_hash,) if manifest.composition_verification_artifact_hash else ()),
            *manifest.source_artifact_hashes,
        )))
    ):
        raise ValidationError("venue-readiness manifest authority binding is stale or substituted")
    planned_sections, bindings_fresh, planned_sources = _read_paper_manuscript(
        registry,
        manifest.manuscript_artifact_hash,
        candidate,
        bundle,
        profile,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
    )
    if manifest.schema_version == "venue-readiness/v1":
        if (
            manifest.sections != planned_sections
            or manifest.artifact_bindings != bindings_fresh
            or manifest.source_artifact_hashes != planned_sources
        ):
            raise ValidationError(
                "legacy venue-readiness differs from structural manuscript plan"
            )
    else:
        assert manifest.manuscript_revision_artifact_hash is not None
        if ledger is None:
            raise ValidationError("venue manuscript revision requires fresh ledger replay")
        revision = _require_venue_manuscript_revision(
            registry,
            ledger,
            revision_artifact_hash=manifest.manuscript_revision_artifact_hash,
            _round_replay=_round_replay,
        )
        if (
            revision.revision.run_id != run_id
            or revision.revision.candidate_artifact_hash != candidate_artifact_hash
            or revision.revision.bundle_artifact_hash != bundle_artifact_hash
            or revision.content_record.sha256
            != manifest.manuscript_content_artifact_hash
            or revision.composition_verification_record.sha256
            != manifest.composition_verification_artifact_hash
        ):
            raise ValidationError("venue manuscript revision binding is stale or substituted")
        actual_sections = _validate_revision_section_coverage(
            registry,
            revision,
            profile,
            candidate,
            bundle,
            candidate_artifact_hash=candidate_artifact_hash,
            bundle_artifact_hash=bundle_artifact_hash,
        )
        actual_sources = tuple(
            dict.fromkeys(
                (
                    *(digest for item in actual_sections for digest in item.source_artifact_hashes),
                    *(digest for item in bindings_fresh for digest in item.artifact_hashes),
                    revision.content_record.sha256,
                )
            )
        )
        if (
            {item.section_id for item in actual_sections}
            != set(profile.required_sections)
            or manifest.sections != actual_sections
            or manifest.artifact_bindings != bindings_fresh
            or manifest.source_artifact_hashes != actual_sources
        ):
            raise ValidationError(
                "venue-readiness differs from replayed manuscript content"
            )
    return manifest


def _venue_score_outcome(score: float) -> str:
    _validate_score(score)
    return f"SCORE:{canonical_json_bytes(float(score)).decode('ascii')}"


def _require_live_venue_semantic_judgment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    receipt_artifact_hash: str,
    subject_kind: JudgmentSubjectKind,
    subject_id: str,
    outcome: str,
    evidence_hashes: tuple[str, ...],
    context_hashes: tuple[str, ...],
    _before_event_index: int | None = None,
) -> None:
    """Require one outcome-independent live semantic slot.

    The selected digest is not enough: every other scientifically valid
    judgment for the same run/subject/evidence/context slot is replayed too.
    Any second outcome is ambiguous and therefore cannot be cherry-picked by
    a venue caller.
    """

    selected = require_scientific_semantic_judgment_receipt(
        registry,
        ledger,
        run_id=run_id,
        receipt_artifact_hash=receipt_artifact_hash,
        subject_kind=subject_kind,
        subject_id=subject_id,
        outcome=outcome,
        evidence_hashes=evidence_hashes,
        context_hashes=context_hashes,
    )
    for candidate_record in registry.list_records():
        if (
            candidate_record.sha256 == receipt_artifact_hash
            or candidate_record.logical_type
            != SEMANTIC_JUDGMENT_RECEIPT_LOGICAL_TYPE
            or candidate_record.schema_version
            != SEMANTIC_JUDGMENT_RECEIPT_SCHEMA_VERSION
            or candidate_record.mime_type != "application/json"
            or candidate_record.creator_role is not Role.SCIENTIFIC_REVIEWER
            or candidate_record.origin
            != (
                "content-bound scientific review of a captured advisory "
                "model judgment"
            )
            or candidate_record.creation_command
            != ("scientist-one", "record-semantic-judgment")
            or candidate_record.validation_result != "PASS"
            or candidate_record.frozen is not True
        ):
            continue
        try:
            raw = registry.get_bytes(candidate_record.sha256)
            value = safe_json_loads(raw)
            if (
                not isinstance(value, Mapping)
                or raw != canonical_json_bytes(value) + b"\n"
            ):
                continue
            candidate = SemanticJudgmentReceipt.from_dict(value)
            if candidate_record.parent_artifacts != (
                *candidate.evidence_hashes,
                *candidate.context_hashes,
                *candidate.custody_artifact_hashes,
            ):
                continue
        except Exception:
            continue
        if (
            candidate.subject_kind is not subject_kind
            or candidate.subject_id != subject_id
            or candidate.evidence_hashes != evidence_hashes
            or candidate.context_hashes != context_hashes
        ):
            continue
        try:
            require_scientific_semantic_judgment_receipt(
                registry,
                ledger,
                run_id=run_id,
                receipt_artifact_hash=candidate_record.sha256,
                subject_kind=subject_kind,
                subject_id=subject_id,
                outcome=candidate.outcome,
                evidence_hashes=evidence_hashes,
                context_hashes=context_hashes,
            )
        except Exception:
            continue
        raise ValidationError(
            "venue semantic judgment slot has conflicting live outcomes"
        )
    if _before_event_index is not None:
        # Reuse the full gateway owner, not a declared timestamp or transport
        # marker. Later corrections/conflicts remain visible to these owners.
        transport = _require_audited_live_semantic_transport(
            registry, ledger, run_id=run_id, receipt=selected,
        )
        events = ledger.validate(raise_on_error=True).events
        index = transport.ledger_prefix_event_count
        if (
            type(_before_event_index) is not int
            or not 0 <= index < _before_event_index < len(events)
            or events[index].event_id != transport.ledger_event_id
            or events[index].event_hash != transport.ledger_event_hash
        ):
            raise ValidationError("Venue semantic admission does not precede its canonical projection")


def _manifest_requirement_binding(
    manifest: VenueReadinessManifest,
    requirement: str,
) -> ArtifactReadinessBinding:
    matches = tuple(
        item for item in manifest.artifact_bindings if item.requirement == requirement
    )
    if len(matches) != 1:
        raise ValidationError("venue manifest lacks one exact requirement binding")
    return matches[0]


def _manifest_requirement_sources(
    manifest: VenueReadinessManifest,
    binding: ArtifactReadinessBinding,
) -> tuple[str, ...]:
    if manifest.schema_version != "venue-readiness/v2":
        return binding.artifact_hashes
    if manifest.manuscript_content_artifact_hash is None:
        raise ValidationError("venue requirement lacks issued manuscript content")
    return tuple(
        dict.fromkeys(
            (*binding.artifact_hashes, manifest.manuscript_content_artifact_hash)
        )
    )


def register_venue_requirement_receipt(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    receipt_id: str,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    requirement: str,
    semantic_judgment_hash: str | None,
) -> ArtifactRecord:
    """Register exact requirement authority; names and substrings carry no weight."""

    validate_identifier(receipt_id, "venue requirement receipt ID")
    validate_identifier(run_id, "venue requirement run ID")
    validate_identifier(requirement, "venue requirement")
    if requirement not in profile.artifact_requirements:
        raise ValidationError("venue receipt names a requirement outside the profile")
    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    manifest = _resolve_venue_readiness_manifest(
        registry,
        readiness_manifest_hash,
        candidate,
        bundle,
        profile,
        ledger=ledger,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
    )
    if manifest.schema_version != "venue-readiness/v2":
        raise ValidationError(
            "structural venue inventory cannot authorize requirement satisfaction"
        )
    binding = _manifest_requirement_binding(manifest, requirement)
    requirement_sources = _manifest_requirement_sources(manifest, binding)
    if requirement == "code":
        canonical_code = tuple(
            sorted(item.code_artifact_hash for item in bundle.method_code_bindings)
        )
        if not canonical_code or binding.artifact_hashes != canonical_code:
            raise ValidationError("venue code requirement differs from canonical methods")
        if semantic_judgment_hash is not None:
            raise ValidationError("deterministic code readiness cannot substitute a judgment")
    else:
        if semantic_judgment_hash is None:
            raise ValidationError("venue requirement lacks semantic-review authority")
        _require_live_venue_semantic_judgment(
            registry,
            ledger,
            run_id=run_id,
            receipt_artifact_hash=semantic_judgment_hash,
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id=requirement,
            outcome="SATISFIED",
            evidence_hashes=requirement_sources,
            context_hashes=(
                candidate_artifact_hash,
                bundle_artifact_hash,
                profile_artifact_hash,
                readiness_manifest_hash,
            ),
        )
    receipt = VenueRequirementReceipt(
        receipt_id=receipt_id,
        run_id=run_id,
        requirement=requirement,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_id=profile.profile_id,
        profile_sha256=profile.sha256,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
        source_artifact_hashes=requirement_sources,
        semantic_judgment_hash=semantic_judgment_hash,
    )
    return registry.put_json(
        receipt.to_dict(),
        logical_type="venue_requirement_receipt",
        origin="registry-resolved venue requirement over exact paper authority",
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=("scientist-one", "record-venue-requirement"),
        parent_artifacts=(
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *((semantic_judgment_hash,) if semantic_judgment_hash is not None else ()),
            *requirement_sources,
        ),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _resolve_venue_requirement_receipt(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    receipt_hash: str,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    manifest: VenueReadinessManifest,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    _before_event_index: int | None = None,
) -> VenueRequirementReceipt:
    if manifest.schema_version != "venue-readiness/v2":
        raise ValidationError(
            "structural venue inventory cannot authorize requirement receipts"
        )
    record, value = _read_registry_json(
        registry,
        receipt_hash,
        logical_type="venue_requirement_receipt",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    _require_exact_keys(
        value,
        {item.name for item in fields(VenueRequirementReceipt)},
        "venue requirement receipt",
    )
    receipt = VenueRequirementReceipt(
        receipt_id=value["receipt_id"],
        run_id=value["run_id"],
        requirement=value["requirement"],
        candidate_artifact_hash=value["candidate_artifact_hash"],
        bundle_artifact_hash=value["bundle_artifact_hash"],
        profile_id=value["profile_id"],
        profile_sha256=value["profile_sha256"],
        profile_artifact_hash=value["profile_artifact_hash"],
        readiness_manifest_hash=value["readiness_manifest_hash"],
        source_artifact_hashes=_sequence(
            value["source_artifact_hashes"], "venue requirement sources"
        ),
        semantic_judgment_hash=value["semantic_judgment_hash"],
        schema_version=value["schema_version"],
    )
    binding = _manifest_requirement_binding(manifest, receipt.requirement)
    requirement_sources = _manifest_requirement_sources(manifest, binding)
    if (
        record.schema_version != "1.0"
        or receipt.run_id != run_id
        or receipt.candidate_artifact_hash != candidate_artifact_hash
        or receipt.bundle_artifact_hash != bundle_artifact_hash
        or receipt.profile_id != profile.profile_id
        or receipt.profile_sha256 != profile.sha256
        or receipt.profile_artifact_hash != profile_artifact_hash
        or receipt.readiness_manifest_hash != readiness_manifest_hash
        or receipt.source_artifact_hashes != requirement_sources
        or record.parent_artifacts
        != (
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *(
                (receipt.semantic_judgment_hash,)
                if receipt.semantic_judgment_hash is not None
                else ()
            ),
            *receipt.source_artifact_hashes,
        )
    ):
        raise ValidationError("venue requirement receipt is stale or substituted")
    if receipt.requirement == "code":
        canonical_code = tuple(
            sorted(item.code_artifact_hash for item in bundle.method_code_bindings)
        )
        if (
            not canonical_code
            or binding.artifact_hashes != canonical_code
            or receipt.semantic_judgment_hash is not None
        ):
            raise ValidationError("venue code receipt is not deterministically derived")
    else:
        if receipt.semantic_judgment_hash is None:
            raise ValidationError("venue requirement receipt has no semantic authority")
        _require_live_venue_semantic_judgment(
            registry,
            ledger,
            run_id=run_id,
            receipt_artifact_hash=receipt.semantic_judgment_hash,
            subject_kind=JudgmentSubjectKind.VENUE_REQUIREMENT,
            subject_id=receipt.requirement,
            outcome="SATISFIED",
            evidence_hashes=receipt.source_artifact_hashes,
            context_hashes=(
                candidate_artifact_hash,
                bundle_artifact_hash,
                profile_artifact_hash,
                readiness_manifest_hash,
            ),
            **({"_before_event_index": _before_event_index} if _before_event_index is not None else {}),
        )
    return receipt


def _resolve_venue_requirements(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    receipt_hashes: tuple[str, ...],
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    manifest: VenueReadinessManifest,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    _before_event_index: int | None = None,
) -> tuple[tuple[str, ...], tuple[VenueRequirementReceipt, ...]]:
    _hashes(
        receipt_hashes,
        "venue requirement receipt artifacts",
        allow_empty=False,
    )
    resolved = tuple(
        (
            digest,
            _resolve_venue_requirement_receipt(
                registry,
                ledger,
                digest,
                candidate,
                bundle,
                profile,
                manifest,
                run_id=run_id,
                candidate_artifact_hash=candidate_artifact_hash,
                bundle_artifact_hash=bundle_artifact_hash,
                profile_artifact_hash=profile_artifact_hash,
                readiness_manifest_hash=readiness_manifest_hash,
                **({"_before_event_index": _before_event_index} if _before_event_index is not None else {}),
            ),
        )
        for digest in receipt_hashes
    )
    by_requirement = {receipt.requirement: (digest, receipt) for digest, receipt in resolved}
    if (
        len(by_requirement) != len(resolved)
        or set(by_requirement) != set(profile.artifact_requirements)
    ):
        raise ValidationError("venue requirement receipts are incomplete or duplicated")
    ordered_hashes = tuple(by_requirement[item][0] for item in profile.artifact_requirements)
    ordered_receipts = tuple(
        by_requirement[item][1] for item in profile.artifact_requirements
    )
    return ordered_hashes, ordered_receipts


def register_venue_dimension_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    assessment_id: str,
    run_id: str,
    dimension: str,
    score: float,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    requirement_receipt_hashes: tuple[str, ...],
    semantic_judgment_hash: str,
) -> ArtifactRecord:
    """Register one score only after replaying its full semantic-review custody."""

    validate_identifier(assessment_id, "venue dimension assessment ID")
    validate_identifier(run_id, "venue dimension run ID")
    if dimension not in READINESS_DIMENSIONS:
        raise ValidationError("venue assessment names an unknown dimension")
    _validate_score(score)
    manifest = _resolve_venue_readiness_manifest(
        registry,
        readiness_manifest_hash,
        candidate,
        bundle,
        profile,
        ledger=ledger,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
    )
    if manifest.schema_version != "venue-readiness/v2":
        raise ValidationError(
            "structural venue inventory cannot authorize dimension scores"
        )
    ordered_requirements, _ = _resolve_venue_requirements(
        registry,
        ledger,
        requirement_receipt_hashes,
        candidate,
        bundle,
        profile,
        manifest,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
    )
    if requirement_receipt_hashes != ordered_requirements:
        raise ValidationError("venue dimension requirements are reordered or substituted")
    _require_live_venue_semantic_judgment(
        registry,
        ledger,
        run_id=run_id,
        receipt_artifact_hash=semantic_judgment_hash,
        subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
        subject_id=dimension,
        outcome=_venue_score_outcome(score),
        evidence_hashes=manifest.source_artifact_hashes,
        context_hashes=(
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *ordered_requirements,
        ),
    )
    receipt = VenueDimensionAssessmentReceipt(
        assessment_id=assessment_id,
        run_id=run_id,
        dimension=dimension,
        score=float(score),
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_id=profile.profile_id,
        profile_sha256=profile.sha256,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
        requirement_receipt_hashes=ordered_requirements,
        semantic_judgment_hash=semantic_judgment_hash,
    )
    return registry.put_json(
        receipt.to_dict(),
        logical_type="venue_dimension_assessment",
        origin="registry-resolved venue dimension over exact paper authority",
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=("scientist-one", "record-venue-dimension"),
        parent_artifacts=(
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *ordered_requirements,
            semantic_judgment_hash,
            *manifest.source_artifact_hashes,
        ),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _resolve_venue_dimension_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    receipt_hash: str,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    manifest: VenueReadinessManifest,
    ordered_requirement_hashes: tuple[str, ...],
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    _before_event_index: int | None = None,
) -> VenueDimensionAssessmentReceipt:
    if manifest.schema_version != "venue-readiness/v2":
        raise ValidationError(
            "structural venue inventory cannot authorize dimension receipts"
        )
    record, value = _read_registry_json(
        registry,
        receipt_hash,
        logical_type="venue_dimension_assessment",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    _require_exact_keys(
        value,
        {item.name for item in fields(VenueDimensionAssessmentReceipt)},
        "venue dimension assessment",
    )
    receipt = VenueDimensionAssessmentReceipt(
        assessment_id=value["assessment_id"],
        run_id=value["run_id"],
        dimension=value["dimension"],
        score=value["score"],
        candidate_artifact_hash=value["candidate_artifact_hash"],
        bundle_artifact_hash=value["bundle_artifact_hash"],
        profile_id=value["profile_id"],
        profile_sha256=value["profile_sha256"],
        profile_artifact_hash=value["profile_artifact_hash"],
        readiness_manifest_hash=value["readiness_manifest_hash"],
        requirement_receipt_hashes=_sequence(
            value["requirement_receipt_hashes"],
            "venue dimension requirement receipts",
        ),
        semantic_judgment_hash=value["semantic_judgment_hash"],
        schema_version=value["schema_version"],
    )
    if (
        record.schema_version != "1.0"
        or receipt.run_id != run_id
        or receipt.candidate_artifact_hash != candidate_artifact_hash
        or receipt.bundle_artifact_hash != bundle_artifact_hash
        or receipt.profile_id != profile.profile_id
        or receipt.profile_sha256 != profile.sha256
        or receipt.profile_artifact_hash != profile_artifact_hash
        or receipt.readiness_manifest_hash != readiness_manifest_hash
        or receipt.requirement_receipt_hashes != ordered_requirement_hashes
        or record.parent_artifacts
        != (
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *ordered_requirement_hashes,
            receipt.semantic_judgment_hash,
            *manifest.source_artifact_hashes,
        )
    ):
        raise ValidationError("venue dimension assessment is stale or substituted")
    _require_live_venue_semantic_judgment(
        registry,
        ledger,
        run_id=run_id,
        receipt_artifact_hash=receipt.semantic_judgment_hash,
        subject_kind=JudgmentSubjectKind.VENUE_DIMENSION,
        subject_id=receipt.dimension,
        outcome=_venue_score_outcome(receipt.score),
        evidence_hashes=manifest.source_artifact_hashes,
        context_hashes=(
            candidate_artifact_hash,
            bundle_artifact_hash,
            profile_artifact_hash,
            readiness_manifest_hash,
            *ordered_requirement_hashes,
        ),
        **({"_before_event_index": _before_event_index} if _before_event_index is not None else {}),
    )
    return receipt


def assess_venue(
    profile: VenueProfile,
    verification: PaperVerification,
    dimension_scores: Mapping[str, float],
    *,
    external_validation_complete: bool,
    rationale: str,
    registry: ArtifactRegistry | None = None,
    ledger: EventLedger | None = None,
    candidate: PaperCandidate | None = None,
    bundle: AuthoritativeResearchBundle | None = None,
    run_id: str | None = None,
    candidate_artifact_hash: str | None = None,
    bundle_artifact_hash: str | None = None,
    profile_artifact_hash: str | None = None,
    readiness_manifest_hash: str | None = None,
    requirement_receipt_hashes: tuple[str, ...] = (),
    dimension_assessment_hashes: tuple[str, ...] = (),
) -> VenueAssessment:
    return _assess_venue(
        profile, verification, dimension_scores,
        external_validation_complete=external_validation_complete,
        rationale=rationale, registry=registry, ledger=ledger,
        candidate=candidate, bundle=bundle, run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
        requirement_receipt_hashes=requirement_receipt_hashes,
        dimension_assessment_hashes=dimension_assessment_hashes,
    )


def _assess_venue(
    profile: VenueProfile,
    verification: PaperVerification,
    dimension_scores: Mapping[str, float],
    *,
    external_validation_complete: bool,
    rationale: str,
    registry: ArtifactRegistry | None = None,
    ledger: EventLedger | None = None,
    candidate: PaperCandidate | None = None,
    bundle: AuthoritativeResearchBundle | None = None,
    run_id: str | None = None,
    candidate_artifact_hash: str | None = None,
    bundle_artifact_hash: str | None = None,
    profile_artifact_hash: str | None = None,
    readiness_manifest_hash: str | None = None,
    requirement_receipt_hashes: tuple[str, ...] = (),
    dimension_assessment_hashes: tuple[str, ...] = (),
    _round_replay: _PaperRoundReplay | None = None,
) -> VenueAssessment:
    if not isinstance(profile, VenueProfile) or not isinstance(verification, PaperVerification):
        raise ValidationError("venue assessment requires typed profile and verification")
    if set(dimension_scores) != set(READINESS_DIMENSIONS):
        raise ValidationError("readiness scores must cover every dimension exactly")
    supplied_scores = tuple(
        (name, float(dimension_scores[name])) for name in READINESS_DIMENSIONS
    )
    _validate_dimension_scores(supplied_scores)
    _text(rationale, "caller venue rationale")
    if not isinstance(external_validation_complete, bool):
        raise ValidationError("external validation flag must be boolean")
    authority_ready = False
    derived_external_validation = False
    authority_inputs = (
        registry,
        ledger,
        candidate,
        bundle,
        run_id,
        candidate_artifact_hash,
        bundle_artifact_hash,
        profile_artifact_hash,
        readiness_manifest_hash,
    )
    # Caller scores are accepted only as a compatibility summary input.  They
    # are not retained or classified unless every exact dimension authority
    # resolves below.
    ordered = tuple((name, 0.0) for name in READINESS_DIMENSIONS)
    resolved_requirement_hashes: tuple[str, ...] = ()
    resolved_dimension_hashes: tuple[str, ...] = ()
    if (
        all(item is not None for item in authority_inputs)
        and requirement_receipt_hashes
        and dimension_assessment_hashes
    ):
        try:
            assert isinstance(registry, ArtifactRegistry)
            assert isinstance(ledger, EventLedger)
            assert isinstance(candidate, PaperCandidate)
            assert isinstance(bundle, AuthoritativeResearchBundle)
            assert isinstance(run_id, str)
            assert isinstance(candidate_artifact_hash, str)
            assert isinstance(bundle_artifact_hash, str)
            assert isinstance(profile_artifact_hash, str)
            assert isinstance(readiness_manifest_hash, str)
            approved_profile = require_approved_venue_profile(
                registry,
                profile_artifact_hash,
                expected_profile_id=profile.profile_id,
            )
            if approved_profile != profile:
                raise ValidationError(
                    "venue assessment profile differs from approved policy"
                )
            _resolve_candidate_bundle_artifacts(
                registry,
                candidate,
                bundle,
                candidate_artifact_hash,
                bundle_artifact_hash,
            )
            if bundle.run_id != run_id:
                raise ValidationError("venue assessment run differs from bundle authority")
            if _round_replay is None:
                fresh_verification = verify_paper(candidate, bundle, registry, ledger)
            else:
                source = _require_paper_verification_bundle_source(
                    registry, ledger, bundle, _round_replay=_round_replay,
                )
                _require_paper_state_binding_join(
                    _round_replay.audited_state, source.state_authority,
                )
                fresh_verification = _verify_paper_from_replayed_bundle(
                    candidate, source, registry, ledger,
                )
            if fresh_verification != verification:
                raise ValidationError("venue assessment received stale paper verification")
            manifest = _resolve_venue_readiness_manifest(
                registry,
                readiness_manifest_hash,
                candidate,
                bundle,
                profile,
                ledger=ledger,
                run_id=run_id,
                candidate_artifact_hash=candidate_artifact_hash,
                bundle_artifact_hash=bundle_artifact_hash,
                profile_artifact_hash=profile_artifact_hash,
                **({"_round_replay": _round_replay} if _round_replay is not None else {}),
            )
            if manifest.manuscript_revision_artifact_hash is None:
                raise ValidationError(
                    "inventory-only manuscript cannot authorize venue readiness"
                )
            resolved_requirement_hashes, _ = _resolve_venue_requirements(
                registry,
                ledger,
                requirement_receipt_hashes,
                candidate,
                bundle,
                profile,
                manifest,
                run_id=run_id,
                candidate_artifact_hash=candidate_artifact_hash,
                bundle_artifact_hash=bundle_artifact_hash,
                profile_artifact_hash=profile_artifact_hash,
                readiness_manifest_hash=readiness_manifest_hash,
                **({"_before_event_index": _round_replay.reviews.before_event_index} if _round_replay is not None else {}),
            )
            dimension_pairs = tuple(
                (
                    digest,
                    _resolve_venue_dimension_assessment(
                        registry,
                        ledger,
                        digest,
                        candidate,
                        bundle,
                        profile,
                        manifest,
                        resolved_requirement_hashes,
                        run_id=run_id,
                        candidate_artifact_hash=candidate_artifact_hash,
                        bundle_artifact_hash=bundle_artifact_hash,
                        profile_artifact_hash=profile_artifact_hash,
                        readiness_manifest_hash=readiness_manifest_hash,
                        **({"_before_event_index": _round_replay.reviews.before_event_index} if _round_replay is not None else {}),
                    ),
                )
                for digest in dimension_assessment_hashes
            )
            by_dimension = {
                receipt.dimension: (digest, receipt)
                for digest, receipt in dimension_pairs
            }
            if (
                len(by_dimension) != len(dimension_pairs)
                or set(by_dimension) != set(READINESS_DIMENSIONS)
            ):
                raise ValidationError(
                    "venue dimension assessments are incomplete or duplicated"
                )
            resolved_dimension_hashes = tuple(
                by_dimension[name][0] for name in READINESS_DIMENSIONS
            )
            ordered = tuple(
                (name, by_dimension[name][1].score) for name in READINESS_DIMENSIONS
            )
            if supplied_scores != ordered:
                raise ValidationError(
                    "caller score summary differs from authoritative assessments"
                )
            derived_external_validation = bundle.external_validation_complete
            authority_ready = True
        except Exception:
            authority_ready = False
            ordered = tuple((name, 0.0) for name in READINESS_DIMENSIONS)
            resolved_requirement_hashes = ()
            resolved_dimension_hashes = ()
    minimum = min(score for _, score in ordered)
    mean = sum(score for _, score in ordered) / len(ordered)
    policy = _venue_classification_policy()
    strong_floor = policy["strong_conference_candidate"]
    solid_floor = policy["solid_conference_fit"]
    assert isinstance(strong_floor, Mapping) and isinstance(solid_floor, Mapping)
    hard_blockers = list(verification.blockers)
    if not authority_ready:
        hard_blockers.append(HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED)
    hard_blockers = list(dict.fromkeys(hard_blockers))
    if hard_blockers or verification.discrepancies:
        classification = VenueFit.NOT_READY
    elif not derived_external_validation:
        classification = VenueFit.UNCERTAIN
    elif minimum < profile.minimum_dimension_score:
        classification = VenueFit.WORKSHOP_FIT
    elif (
        mean >= strong_floor["minimum_mean_score"]
        and minimum >= strong_floor["minimum_dimension_score"]
    ):
        classification = VenueFit.STRONG_CONFERENCE_CANDIDATE
    elif (
        mean >= solid_floor["minimum_mean_score"]
        and minimum >= solid_floor["minimum_dimension_score"]
    ):
        classification = VenueFit.SOLID_CONFERENCE_FIT
    else:
        classification = VenueFit.SPECIALIZED_CONFERENCE_FIT
    policy_basis = (
        f"Source-owned venue policy {profile.profile_id}"
        if authority_ready
        else f"Unresolved venue policy request {profile.profile_id}"
    )
    derived_rationale = (
        f"{policy_basis} classified this candidate as "
        f"{classification.value}; authoritative_minimum={minimum:.6f}; "
        f"authoritative_mean={mean:.6f}; "
        f"external_validation={'complete' if derived_external_validation else 'incomplete'}; "
        f"hard_blockers={len(hard_blockers)}. This is not acceptance authority."
    )
    return VenueAssessment(
        profile_id=profile.profile_id,
        classification=classification,
        dimension_scores=ordered,
        hard_blockers=tuple(hard_blockers),
        rationale=derived_rationale,
        run_id=run_id if authority_ready else None,
        candidate_artifact_hash=(candidate_artifact_hash if authority_ready else None),
        bundle_artifact_hash=(bundle_artifact_hash if authority_ready else None),
        readiness_manifest_hash=(readiness_manifest_hash if authority_ready else None),
        profile_artifact_hash=(profile_artifact_hash if authority_ready else None),
        requirement_receipt_hashes=(
            resolved_requirement_hashes if authority_ready else ()
        ),
        dimension_assessment_hashes=(
            resolved_dimension_hashes if authority_ready else ()
        ),
    )


_VENUE_ASSESSMENT_SCHEMA = "venue-readiness-assessment/v1"
_VENUE_ASSESSMENT_ORIGIN = (
    "fresh deterministic venue assessment over exact paper authority"
)
_VENUE_ASSESSMENT_COMMAND = (
    "scientist-one",
    "register-venue-assessment",
)


def _venue_assessment_from_json(value: Any) -> VenueAssessment:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(VenueAssessment)},
        "venue assessment",
    )
    try:
        return VenueAssessment(
            profile_id=payload["profile_id"],
            classification=VenueFit(payload["classification"]),
            dimension_scores=tuple(
                (item[0], item[1])
                for item in _sequence(
                    payload["dimension_scores"],
                    "venue assessment dimension scores",
                )
                if isinstance(item, (list, tuple)) and len(item) == 2
            ),
            hard_blockers=tuple(
                HardBlocker(item)
                for item in _sequence(
                    payload["hard_blockers"],
                    "venue assessment hard blockers",
                )
            ),
            rationale=payload["rationale"],
            run_id=payload["run_id"],
            candidate_artifact_hash=payload["candidate_artifact_hash"],
            bundle_artifact_hash=payload["bundle_artifact_hash"],
            readiness_manifest_hash=payload["readiness_manifest_hash"],
            profile_artifact_hash=payload["profile_artifact_hash"],
            requirement_receipt_hashes=_sequence(
                payload["requirement_receipt_hashes"],
                "venue assessment requirement receipts",
            ),
            dimension_assessment_hashes=_sequence(
                payload["dimension_assessment_hashes"],
                "venue assessment dimension receipts",
            ),
        )
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("venue assessment payload is malformed") from exc


def _venue_assessment_authority_from_json(
    value: Any,
) -> VenueAssessmentAuthority:
    payload = _require_exact_keys(
        value,
        {item.name for item in fields(VenueAssessmentAuthority)},
        "final venue assessment authority",
    )
    try:
        return VenueAssessmentAuthority(
            assessment_id=payload["assessment_id"],
            run_id=payload["run_id"],
            candidate_id=payload["candidate_id"],
            venue_family=VenueFamily(payload["venue_family"]),
            evidence_ids=_sequence(
                payload["evidence_ids"],
                "venue assessment evidence IDs",
            ),
            assessed_at=payload["assessed_at"],
            paper_verification_artifact_hash=payload[
                "paper_verification_artifact_hash"
            ],
            assessment=_venue_assessment_from_json(payload["assessment"]),
            schema_version=payload["schema_version"],
        )
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError(
            "final venue assessment authority is malformed"
        ) from exc


def _venue_assessment_identity(
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
) -> str:
    slot = {
        "schema_version": "venue-assessment-slot/v1",
        "run_id": run_id,
        "candidate_artifact_hash": candidate_artifact_hash,
        "bundle_artifact_hash": bundle_artifact_hash,
        "profile_artifact_hash": profile_artifact_hash,
        "readiness_manifest_hash": readiness_manifest_hash,
    }
    return (
        "venue-assessment-"
        f"{hashlib.sha256(canonical_json_bytes(slot)).hexdigest()[:32]}"
    )


def _resolve_final_venue_inputs(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    paper_verification_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    requirement_receipt_hashes: tuple[str, ...],
    dimension_assessment_hashes: tuple[str, ...],
    _round_replay: _PaperRoundReplay | None = None,
) -> tuple[
    VenueAssessment,
    tuple[str, ...],
    tuple[str, ...],
]:
    """Freshly replay every input before deriving a final venue decision."""

    if not isinstance(registry, ArtifactRegistry) or not isinstance(
        ledger, EventLedger
    ):
        raise ValidationError("final venue assessment requires registry and ledger")
    if not isinstance(candidate, PaperCandidate) or not isinstance(
        bundle, AuthoritativeResearchBundle
    ):
        raise ValidationError("final venue assessment requires typed paper authority")
    if not isinstance(profile, VenueProfile):
        raise ValidationError("final venue assessment requires a typed profile")
    validate_identifier(run_id, "final venue assessment run ID")
    if bundle.run_id != run_id:
        raise ValidationError("final venue assessment run differs from its bundle")
    _resolve_candidate_bundle_artifacts(
        registry,
        candidate,
        bundle,
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    approved = require_approved_venue_profile(
        registry,
        profile_artifact_hash,
        expected_profile_id=profile.profile_id,
    )
    if approved != profile:
        raise ValidationError("final venue assessment profile was substituted")
    verification_record = _require_frozen_artifact(
        registry,
        paper_verification_artifact_hash,
        logical_type="paper_verification",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    if verification_record.parent_artifacts != (
        candidate_artifact_hash,
        bundle_artifact_hash,
    ):
        raise ValidationError(
            "final venue assessment paper verification has wrong parents"
        )
    if _round_replay is None:
        verification = require_paper_verification(
            registry,
            ledger,
            run_id=run_id,
            verification_artifact_hash=paper_verification_artifact_hash,
            expected_candidate_id=candidate.candidate_id,
        )
    else:
        verification, _paper_source = _require_paper_verification_with_round_sources(
            registry, ledger, expected_run_id=run_id,
            verification_artifact_hash=paper_verification_artifact_hash,
            expected_candidate_id=candidate.candidate_id,
            audited_state=_round_replay.audited_state,
            soundness=_round_replay.soundness,
            review_replay=_round_replay.reviews,
        )
    manifest = _resolve_venue_readiness_manifest(
        registry,
        readiness_manifest_hash,
        candidate,
        bundle,
        profile,
        ledger=ledger,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    if manifest.manuscript_revision_artifact_hash is None:
        raise ValidationError(
            "final venue assessment requires issued manuscript prose"
        )
    replayed_revision = _require_venue_manuscript_revision(
        registry,
        ledger,
        revision_artifact_hash=manifest.manuscript_revision_artifact_hash,
        _round_replay=_round_replay,
    )
    if (
        replayed_revision.revision.paper_verification_artifact_hash
        != paper_verification_artifact_hash
    ):
        raise ValidationError(
            "venue manuscript revision uses another paper verification"
        )
    ordered_requirements, _ = _resolve_venue_requirements(
        registry,
        ledger,
        requirement_receipt_hashes,
        candidate,
        bundle,
        profile,
        manifest,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
        **({"_before_event_index": _round_replay.reviews.before_event_index} if _round_replay is not None else {}),
    )
    resolved_dimensions = tuple(
        (
            digest,
            _resolve_venue_dimension_assessment(
                registry,
                ledger,
                digest,
                candidate,
                bundle,
                profile,
                manifest,
                ordered_requirements,
                run_id=run_id,
                candidate_artifact_hash=candidate_artifact_hash,
                bundle_artifact_hash=bundle_artifact_hash,
                profile_artifact_hash=profile_artifact_hash,
                readiness_manifest_hash=readiness_manifest_hash,
                **({"_before_event_index": _round_replay.reviews.before_event_index} if _round_replay is not None else {}),
            ),
        )
        for digest in dimension_assessment_hashes
    )
    by_dimension = {
        receipt.dimension: (digest, receipt)
        for digest, receipt in resolved_dimensions
    }
    if (
        len(by_dimension) != len(resolved_dimensions)
        or set(by_dimension) != set(READINESS_DIMENSIONS)
    ):
        raise ValidationError(
            "final venue dimension assessments are incomplete or duplicated"
        )
    ordered_dimensions = tuple(
        by_dimension[name][0] for name in READINESS_DIMENSIONS
    )
    scores = {
        name: by_dimension[name][1].score for name in READINESS_DIMENSIONS
    }
    venue_assessor = assess_venue if _round_replay is None else _assess_venue
    assessment = venue_assessor(
        profile,
        verification,
        scores,
        external_validation_complete=bundle.external_validation_complete,
        rationale="Source-owned venue policy replay.",
        registry=registry,
        ledger=ledger,
        candidate=candidate,
        bundle=bundle,
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
        requirement_receipt_hashes=ordered_requirements,
        dimension_assessment_hashes=ordered_dimensions,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    if (
        assessment.run_id != run_id
        or assessment.candidate_artifact_hash != candidate_artifact_hash
        or assessment.bundle_artifact_hash != bundle_artifact_hash
        or assessment.profile_artifact_hash != profile_artifact_hash
        or assessment.readiness_manifest_hash != readiness_manifest_hash
        or assessment.requirement_receipt_hashes != ordered_requirements
        or assessment.dimension_assessment_hashes != ordered_dimensions
        or assessment.dimension_scores
        != tuple((name, scores[name]) for name in READINESS_DIMENSIONS)
    ):
        raise ValidationError(
            "final venue assessment did not retain complete resolved authority"
        )
    return assessment, ordered_requirements, ordered_dimensions


def _final_venue_records(
    registry: ArtifactRegistry,
    *,
    assessment_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
) -> tuple[tuple[ArtifactRecord, VenueAssessmentAuthority], ...]:
    matches: list[tuple[ArtifactRecord, VenueAssessmentAuthority]] = []
    branch_prefix = (
        candidate_artifact_hash,
        bundle_artifact_hash,
    )
    for record in registry.list_records():
        if (
            record.logical_type != "venue_readiness_assessment"
            or record.creator_role is not Role.SCIENTIFIC_REVIEWER
            or record.origin != _VENUE_ASSESSMENT_ORIGIN
            or record.creation_command != _VENUE_ASSESSMENT_COMMAND
        ):
            continue
        try:
            _, value = _read_registry_json(
                registry,
                record.sha256,
                logical_type="venue_readiness_assessment",
                creator_role=Role.SCIENTIFIC_REVIEWER,
            )
            authority = _venue_assessment_authority_from_json(value)
        except Exception:
            if record.parent_artifacts[:2] == branch_prefix:
                raise ValidationError(
                    "final venue assessment branch contains malformed authority"
                )
            continue
        assessment = authority.assessment
        if (
            authority.assessment_id == assessment_id
            or (
                assessment.candidate_artifact_hash == candidate_artifact_hash
                and assessment.bundle_artifact_hash == bundle_artifact_hash
                and assessment.profile_artifact_hash == profile_artifact_hash
                and assessment.readiness_manifest_hash
                == readiness_manifest_hash
            )
        ):
            matches.append((record, authority))
    return tuple(matches)


def _preflight_venue_publication(
    registry: ArtifactRegistry,
    snapshot: RegistryValidationResult,
    authority: VenueAssessmentAuthority,
    parents: tuple[str, ...],
) -> tuple[bytes, ArtifactRecord | None, ArtifactRecord]:
    """Plan exact bytes/metadata only; this does not grant Venue authority."""

    raw = canonical_json_bytes(authority.to_dict()) + b"\n"
    safe_json_loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    indexed = {item.sha256: item for item in snapshot.records}
    existing = indexed.get(digest)
    if (
        len(parents) > MAX_ARTIFACT_PARENTS
        or len(set(parents)) != len(parents)
        or any(sha not in indexed for sha in parents)
        or snapshot.count + int(existing is None) > MAX_REGISTRY_RECORDS
    ):
        raise ValidationError("Venue publication lacks source or registry capacity")
    # assessed_at is the last canonical dimension's timestamp, not a maximum
    # or a publication clock. Preserve its existing wire meaning exactly.
    planned = ArtifactRecord(
        sha256=digest, path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(), size=len(raw),
        logical_type="venue_readiness_assessment", schema_version="1.0",
        mime_type="application/json", origin=_VENUE_ASSESSMENT_ORIGIN,
        creator_role=Role.SCIENTIFIC_REVIEWER, creation_command=_VENUE_ASSESSMENT_COMMAND,
        parent_artifacts=parents, validation_result="PASS", frozen=True,
        created_at=authority.assessed_at,
    )
    if existing is not None and (existing != planned or registry.get_bytes(digest) != raw):
        raise ValidationError("Venue publication content slot has different bytes or metadata")
    return raw, existing, planned


def register_venue_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    profile: VenueProfile,
    *,
    run_id: str,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    paper_verification_artifact_hash: str,
    profile_artifact_hash: str,
    readiness_manifest_hash: str,
    requirement_receipt_hashes: tuple[str, ...],
    dimension_assessment_hashes: tuple[str, ...],
) -> ArtifactRecord:
    """Register the only final assessment for one outcome-independent branch."""

    before = _locked_research_state_source_snapshot(registry, ledger, run_id=run_id)
    assessment, ordered_requirements, ordered_dimensions = (
        _resolve_final_venue_inputs(
            registry,
            ledger,
            candidate,
            bundle,
            profile,
            run_id=run_id,
            candidate_artifact_hash=candidate_artifact_hash,
            bundle_artifact_hash=bundle_artifact_hash,
            paper_verification_artifact_hash=(
                paper_verification_artifact_hash
            ),
            profile_artifact_hash=profile_artifact_hash,
            readiness_manifest_hash=readiness_manifest_hash,
            requirement_receipt_hashes=requirement_receipt_hashes,
            dimension_assessment_hashes=dimension_assessment_hashes,
        )
    )
    assessment_id = _venue_assessment_identity(
        run_id=run_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
    )
    assessed_at = registry.get_metadata(ordered_dimensions[-1]).created_at
    authority = VenueAssessmentAuthority(
        assessment_id=assessment_id,
        run_id=run_id,
        candidate_id=candidate.candidate_id,
        venue_family=profile.family,
        evidence_ids=tuple(item.claim_id for item in candidate.claims),
        assessed_at=assessed_at,
        paper_verification_artifact_hash=paper_verification_artifact_hash,
        assessment=assessment,
    )
    parents = (
        candidate_artifact_hash,
        bundle_artifact_hash,
        paper_verification_artifact_hash,
        profile_artifact_hash,
        readiness_manifest_hash,
        *ordered_requirements,
        *ordered_dimensions,
    )
    raw, existing_record, planned = _preflight_venue_publication(
        registry, before[0], authority, parents,
    )
    existing = _final_venue_records(
        registry,
        assessment_id=assessment_id,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        profile_artifact_hash=profile_artifact_hash,
        readiness_manifest_hash=readiness_manifest_hash,
    )
    if existing:
        if (
            len(existing) != 1
            or existing[0][1] != authority
            or existing[0][0] != planned
            or existing[0][0] != existing_record
        ):
            raise ValidationError(
                "venue assessment branch already has conflicting final authority"
            )
    elif existing_record is not None:
        raise ValidationError("Venue publication source slot is outside its exact branch")

    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            locked_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if (locked_registry, locked_ledger) != before or not locked_ledger.valid:
                raise ValidationError("Venue sources changed before publication")
            record = existing_record
            if record is None:
                record = registry._put_bytes_locked(
                    registry_guard, raw, logical_type=planned.logical_type,
                    schema_version=planned.schema_version, mime_type=planned.mime_type,
                    origin=planned.origin, creator_role=planned.creator_role,
                    creation_command=planned.creation_command,
                    parent_artifacts=planned.parent_artifacts,
                    validation_result=planned.validation_result, frozen=planned.frozen,
                    created_at=planned.created_at,
                )
            after_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            after_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            expected = {item.sha256: item for item in before[0].records}
            expected[record.sha256] = record
            if (
                record != planned
                or after_registry.count != before[0].count + int(existing_record is None)
                or {item.sha256: item for item in after_registry.records} != expected
                or after_ledger != before[1]
            ):
                raise ValidationError("Venue publication produced an unexpected source delta")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    if require_venue_assessment(
        registry, ledger, run_id=run_id, assessment_artifact_hash=record.sha256,
        expected_candidate_id=candidate.candidate_id,
    ) != authority:
        raise ValidationError("Venue publication differs from complete source readback")
    if _locked_research_state_source_snapshot(registry, ledger, run_id=run_id) != (after_registry, after_ledger):
        raise ValidationError("Venue sources changed after publication")
    return record


def require_venue_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    assessment_artifact_hash: str,
    expected_candidate_id: str | None = None,
) -> VenueAssessmentAuthority:
    """Rehydrate and freshly replay one final venue-assessment artifact."""

    return _require_venue_assessment(
        registry, ledger, run_id=run_id,
        assessment_artifact_hash=assessment_artifact_hash,
        expected_candidate_id=expected_candidate_id,
    )


def _require_venue_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    assessment_artifact_hash: str,
    expected_candidate_id: str | None = None,
    _round_replay: _PaperRoundReplay | None = None,
) -> VenueAssessmentAuthority:
    """Full shared Venue owner; private context changes no source obligation."""

    if not isinstance(registry, ArtifactRegistry) or not isinstance(
        ledger, EventLedger
    ):
        raise ValidationError("venue assessment readback requires registry and ledger")
    validate_identifier(run_id, "venue assessment readback run ID")
    if expected_candidate_id is not None:
        validate_identifier(expected_candidate_id, "expected venue candidate ID")
    if _round_replay is not None:
        _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
    record, value = _read_registry_json(
        registry,
        assessment_artifact_hash,
        logical_type="venue_readiness_assessment",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    authority = _venue_assessment_authority_from_json(value)
    assessment = authority.assessment
    if (
        record.schema_version != "1.0"
        or record.origin != _VENUE_ASSESSMENT_ORIGIN
        or record.creation_command != _VENUE_ASSESSMENT_COMMAND
        or authority.schema_version != _VENUE_ASSESSMENT_SCHEMA
        or authority.run_id != run_id
        or record.created_at != authority.assessed_at
        or (
            expected_candidate_id is not None
            and authority.candidate_id != expected_candidate_id
        )
    ):
        raise ValidationError("final venue assessment metadata was substituted")
    assert assessment.candidate_artifact_hash is not None
    assert assessment.bundle_artifact_hash is not None
    assert assessment.profile_artifact_hash is not None
    assert assessment.readiness_manifest_hash is not None
    candidate_hash = assessment.candidate_artifact_hash
    bundle_hash = assessment.bundle_artifact_hash
    profile_hash = assessment.profile_artifact_hash
    manifest_hash = assessment.readiness_manifest_hash
    _, candidate_wrapper = _read_registry_json(
        registry,
        candidate_hash,
        logical_type="paper_candidate",
        creator_role=Role.PAPER_WRITER,
    )
    _, bundle_wrapper = _read_registry_json(
        registry,
        bundle_hash,
        logical_type="authoritative_research_bundle",
        creator_role=Role.ORCHESTRATOR,
    )
    candidate_value = candidate_wrapper.get("candidate")
    bundle_value = bundle_wrapper.get("bundle")
    if candidate_value is None or bundle_value is None:
        raise ValidationError("venue assessment parents omit typed paper authority")
    try:
        candidate = _paper_candidate_from_json(candidate_value)
        bundle = _authoritative_bundle_from_json(bundle_value)
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("venue assessment paper parents are malformed") from exc
    profile = require_approved_venue_profile(
        registry,
        profile_hash,
        expected_profile_id=assessment.profile_id,
    )
    fresh, ordered_requirements, ordered_dimensions = (
        _resolve_final_venue_inputs(
            registry,
            ledger,
            candidate,
            bundle,
            profile,
            run_id=run_id,
            candidate_artifact_hash=candidate_hash,
            bundle_artifact_hash=bundle_hash,
            paper_verification_artifact_hash=(
                authority.paper_verification_artifact_hash
            ),
            profile_artifact_hash=profile_hash,
            readiness_manifest_hash=manifest_hash,
            requirement_receipt_hashes=(
                assessment.requirement_receipt_hashes
            ),
            dimension_assessment_hashes=(
                assessment.dimension_assessment_hashes
            ),
            **({"_round_replay": _round_replay} if _round_replay is not None else {}),
        )
    )
    expected_id = _venue_assessment_identity(
        run_id=run_id,
        candidate_artifact_hash=candidate_hash,
        bundle_artifact_hash=bundle_hash,
        profile_artifact_hash=profile_hash,
        readiness_manifest_hash=manifest_hash,
    )
    expected_parents = (
        candidate_hash,
        bundle_hash,
        authority.paper_verification_artifact_hash,
        profile_hash,
        manifest_hash,
        *ordered_requirements,
        *ordered_dimensions,
    )
    if (
        authority.assessment_id != expected_id
        or authority.candidate_id != candidate.candidate_id
        or authority.venue_family is not profile.family
        or authority.evidence_ids
        != tuple(item.claim_id for item in candidate.claims)
        or authority.assessed_at
        != registry.get_metadata(ordered_dimensions[-1]).created_at
        or authority.assessment != fresh
        or authority.to_dict() != value
        or record.parent_artifacts != expected_parents
    ):
        raise ValidationError(
            "final venue assessment differs from fresh source authority"
        )
    matches = _final_venue_records(
        registry,
        assessment_id=expected_id,
        candidate_artifact_hash=candidate_hash,
        bundle_artifact_hash=bundle_hash,
        profile_artifact_hash=profile_hash,
        readiness_manifest_hash=manifest_hash,
    )
    if len(matches) != 1 or matches[0][0].sha256 != record.sha256:
        raise ValidationError(
            "venue assessment branch has ambiguous final authority"
        )
    if _round_replay is not None:
        _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
    return authority


def _require_venue_assessment_with_round_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    assessment_artifact_hash: str,
    audited_state: ResearchStateAuthoritySnapshot,
    soundness: _SemanticChallengerAuditRoundSoundness,
    review_replay: _SameRoundReviewReplay,
) -> VenueAssessmentAuthority:
    """Full final-Venue owner inside one completed chronological source round."""

    replay = _PaperRoundReplay(audited_state, soundness, review_replay)
    _require_paper_round_sources(registry, ledger, replay, run_id=run_id)
    authority = _require_venue_assessment(
        registry, ledger, run_id=run_id,
        assessment_artifact_hash=assessment_artifact_hash, _round_replay=replay,
    )
    _require_paper_round_sources(registry, ledger, replay, run_id=run_id)
    return authority


def default_venue_profiles() -> tuple[VenueProfile, ...]:
    common = ("abstract", "introduction", "methods", "results", "limitations", "reproducibility")
    return (
        VenueProfile("ml-ai", VenueFamily.ML_AI, common, ("code", "data_identity", "seed_results")),
        VenueProfile(
            "medical-imaging",
            VenueFamily.MEDICAL_IMAGING,
            common + ("ethics_and_data_governance",),
            ("subject_split", "site_stratification", "uncertainty"),
        ),
        VenueProfile(
            "operations-research",
            VenueFamily.OPERATIONS_RESEARCH,
            common + ("formulation",),
            ("feasibility", "bounds", "solver_environment"),
        ),
        VenueProfile(
            "systems",
            VenueFamily.SYSTEMS,
            common + ("system_context",),
            ("hardware_identity", "workload", "repeated_measurements", "end_to_end"),
        ),
    )


def _validate_dimension_scores(values: tuple[tuple[str, float], ...]) -> None:
    if (
        not isinstance(values, tuple)
        or {name for name, _ in values} != set(READINESS_DIMENSIONS)
        or len(values) != len(READINESS_DIMENSIONS)
    ):
        raise ValidationError("dimension scores are incomplete or duplicated")
    for _, score in values:
        _validate_score(score)


def _validate_score(score: float) -> None:
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or not 0 <= float(score) <= 1
    ):
        raise ValidationError("dimension score must be finite within [0,1]")


def _exact_numeric_equal(left: int | float, right: int | float) -> bool:
    """Compare retained numeric tokens without IEEE-754 integer aliasing."""

    if isinstance(left, bool) or isinstance(right, bool):
        return False
    try:
        return Decimal(str(left)) == Decimal(str(right))
    except (InvalidOperation, ValueError):
        return False


def _text(value: str, label: str, *, maximum: int = MAX_TEXT_BYTES) -> None:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{label} must be non-empty bounded UTF-8 text")


def _texts(values: tuple[str, ...], label: str, *, allow_empty: bool) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > MAX_ITEMS
        or len(set(values)) != len(values)
    ):
        raise ValidationError(f"{label} must be a bounded unique tuple")
    for item in values:
        _text(item, label)


def _hashes(values: tuple[str, ...], label: str, *, allow_empty: bool) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > MAX_ITEMS
        or len(set(values)) != len(values)
    ):
        raise ValidationError(f"{label} must be a bounded unique tuple")
    for item in values:
        validate_sha256(item, label)


def _identifiers(values: tuple[str, ...], label: str, *, allow_empty: bool) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > MAX_ITEMS
        or len(set(values)) != len(values)
    ):
        raise ValidationError(f"{label} must be a bounded unique tuple")
    for item in values:
        validate_identifier(item, label)


def _typed_unique(values: tuple, item_type: type, label: str, identity, *, allow_empty: bool = False) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > MAX_ITEMS
        or any(not isinstance(item, item_type) for item in values)
        or len({identity(item) for item in values}) != len(values)
    ):
        raise ValidationError(f"{label} must be a bounded unique typed tuple")


__all__ = [
    "ArtifactReadinessBinding",
    "AuthoritativeClaim",
    "AuthoritativeMetric",
    "AuthoritativeResearchBundle",
    "ClaimPaperRequirements",
    "ConfirmatoryAuthorityScope",
    "ConfirmatoryClaimAuthority",
    "EvidenceSourceBinding",
    "GeneratedAsset",
    "GeneratedAssetRequirement",
    "HardBlocker",
    "ManuscriptSection",
    "MetricDirection",
    "MetricEvidenceStatus",
    "MethodCodeBinding",
    "PaperCandidate",
    "PaperClaim",
    "PaperNumericAssertion",
    "PaperVerification",
    "READINESS_DIMENSIONS",
    "ReferenceAuthorityBinding",
    "ReferenceDepth",
    "ReferenceUse",
    "StateAuthoritySourceBinding",
    "VenueAssessment",
    "VenueAssessmentAuthority",
    "VenueDimensionAssessmentReceipt",
    "VenueFamily",
    "VenueFit",
    "VenueProfile",
    "VenueReadinessManifest",
    "VenueRequirementReceipt",
    "assess_venue",
    "build_authoritative_research_bundle",
    "default_venue_profiles",
    "register_authoritative_research_bundle",
    "register_paper_verification",
    "register_approved_venue_profile",
    "register_confirmatory_claim_authority",
    "register_paper_manuscript",
    "register_paper_manuscript_revision",
    "register_venue_dimension_assessment",
    "register_venue_assessment",
    "register_venue_readiness_manifest",
    "register_venue_requirement_receipt",
    "require_paper_verification",
    "require_paper_manuscript_revision",
    "require_approved_venue_profile",
    "require_confirmatory_claim_authority",
    "require_venue_assessment",
    "verify_paper",
]
