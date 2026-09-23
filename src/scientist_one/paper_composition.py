"""Deterministic, evidence-only paper composition and revision replay.

This module deliberately has no model/provider interface.  It renders a fixed
Markdown view of an already verified :class:`PaperCandidate`, stores the bytes
separately from their source map, and admits a manuscript revision only through
one inert ledger checkpoint.  The structured research state remains the source
of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .claims import ClaimEvidenceUse
from .errors import ValidationError
from .gates import ChallengeStatus, SoundnessVerdict
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .models import utc_now, validate_identifier, validate_sha256
from .paper_pipeline import (
    AuthoritativeResearchBundle,
    ConfirmatoryAuthorityScope,
    MetricEvidenceStatus,
    PaperCandidate,
    PaperVerification,
    _PaperRoundReplay,
    _paper_candidate_from_json,
    _plain_json,
    _read_authoritative_bundle_artifact,
    _read_registry_json,
    _require_authoritative_bundle_issuance,
    _require_frozen_artifact,
    _require_paper_round_sources,
    _require_paper_verification_with_round_sources,
    _resolve_candidate_bundle_artifacts,
    _resolve_soundness,
    require_paper_verification,
)
from .research_state import ClaimSemanticsEvidenceScope
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes


COMPOSITION_INPUT_SCHEMA = "paper-composition-input/v1"
COMPOSITION_VERIFICATION_SCHEMA = "paper-composition-verification/v1"
MANUSCRIPT_REVISION_SCHEMA = "paper-manuscript-revision/v1"
LEGACY_RENDERER_VERSION = "deterministic-markdown/v1"
RENDERER_VERSION = "deterministic-markdown/v2"
SUPPORTED_RENDERER_VERSIONS = frozenset(
    {LEGACY_RENDERER_VERSION, RENDERER_VERSION}
)
MAX_COMPOSITION_BYTES = 8 * 1024 * 1024
MAX_REVISIONS = 512
MAX_REVISION_LINEAGE_DEPTH = MAX_REVISIONS


def _tuple(value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be a list")
    return tuple(value)


def _canonical_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{label} must be an object")
    try:
        parsed = safe_json_loads(canonical_json_bytes(value))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} must be finite canonical JSON") from exc
    if not isinstance(parsed, Mapping):
        raise ValidationError(f"{label} must be an object")
    return parsed


@dataclass(frozen=True, slots=True)
class PaperCompositionInput:
    run_id: str
    manuscript_id: str
    revision: int
    predecessor_revision_artifact_hash: str | None
    candidate_id: str
    candidate_artifact_hash: str
    bundle_artifact_hash: str
    verification_artifact_hash: str
    bundle_issuance_event_id: str
    bundle_issuance_event_hash: str
    bundle_issuance_event_index: int
    historical_ledger_head_hash: str
    historical_ledger_event_count: int
    research_state_binding: Mapping[str, Any]
    authority_scope: str
    claims: tuple[Mapping[str, Any], ...]
    numeric_assertions: tuple[Mapping[str, Any], ...]
    references: tuple[Mapping[str, Any], ...]
    assets: tuple[Mapping[str, Any], ...]
    method_code_bindings: tuple[Mapping[str, Any], ...]
    required_limitations: tuple[str, ...]
    soundness: Mapping[str, Any]
    findings: tuple[Mapping[str, Any], ...]
    challenger_reviews: tuple[Mapping[str, Any], ...]
    schema_version: str = COMPOSITION_INPUT_SCHEMA

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "composition run ID")
        validate_identifier(self.manuscript_id, "manuscript ID")
        validate_identifier(self.candidate_id, "composition candidate ID")
        validate_identifier(self.bundle_issuance_event_id, "bundle issuance event ID")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or not 1 <= self.revision <= MAX_REVISIONS:
            raise ValidationError("manuscript revision must be a bounded positive integer")
        if (self.revision == 1) != (self.predecessor_revision_artifact_hash is None):
            raise ValidationError("revision one has no predecessor and later revisions require one")
        for digest in (
            self.candidate_artifact_hash,
            self.bundle_artifact_hash,
            self.verification_artifact_hash,
            self.bundle_issuance_event_hash,
            self.historical_ledger_head_hash,
        ):
            validate_sha256(digest, "composition authority SHA-256")
        if self.predecessor_revision_artifact_hash is not None:
            validate_sha256(self.predecessor_revision_artifact_hash, "predecessor revision SHA-256")
        if (
            isinstance(self.bundle_issuance_event_index, bool)
            or not isinstance(self.bundle_issuance_event_index, int)
            or self.bundle_issuance_event_index < 0
            or isinstance(self.historical_ledger_event_count, bool)
            or not isinstance(self.historical_ledger_event_count, int)
            or self.historical_ledger_event_count <= self.bundle_issuance_event_index
        ):
            raise ValidationError("composition historical ledger binding is invalid")
        if self.authority_scope not in {"SCIENTIFIC_EVIDENCE", "SYSTEM_FIXTURE"}:
            raise ValidationError("composition authority scope is unsupported")
        for values, label in (
            (self.claims, "claims"),
            (self.numeric_assertions, "numeric assertions"),
            (self.references, "references"),
            (self.assets, "assets"),
            (self.method_code_bindings, "method/code bindings"),
            (self.findings, "findings"),
            (self.challenger_reviews, "Challenger reviews"),
        ):
            if not isinstance(values, tuple) or len(values) > 2048:
                raise ValidationError(f"composition {label} must be a bounded tuple")
            for item in values:
                _canonical_object(item, f"composition {label} item")
        nested_schemas = (
            (self.claims, {"claim_id", "text", "scope", "claim_type", "expressed_strength", "permitted_strength", "claim_state_artifact_hash", "claim_semantics_artifact_hash", "evidence_hashes", "dependency_claim_ids", "source_artifact_ids", "central"}, "claim"),
            (self.numeric_assertions, {"assertion_id", "claim_id", "metric_id", "value", "unit", "direction", "source_artifact_hash"}, "numeric assertion"),
            (self.references, {"citation_id", "reference_artifact_hash", "verification_depth", "supported_claim_ids", "contradictory_context", "source_citation_evidence_artifact_hash", "citation_node_id", "passage_sha256", "passage_locator_sha256", "context_sha256", "semantic_judgment_artifact_hash"}, "reference"),
            (self.assets, {"asset_id", "kind", "artifact_hash", "authoritative_parent_hashes"}, "asset"),
            (self.method_code_bindings, {"method_artifact_hash", "code_artifact_hash", "method_state_artifact_hash", "implementation_state_artifact_hash", "authority_sources"}, "method/code binding"),
            (self.findings, {"finding_artifact_hash", "challenge_id", "category", "severity", "status", "target_claim_ids", "attack", "resolution", "resolution_receipt_hash"}, "finding"),
            (self.challenger_reviews, {"review_artifact_hash", "review_id", "category", "execution_status", "finding_artifact_hashes", "attack", "conclusion"}, "Challenger review"),
        )
        for values, expected, label in nested_schemas:
            if any(set(item) != expected for item in values):
                raise ValidationError(
                    f"composition {label} has unknown or missing fields"
                )
        if set(self.research_state_binding) != {
            "snapshot_artifact_hash", "state_artifact_hashes", "ledger_head_hash",
            "ledger_event_count", "code_version", "configuration_hash",
        }:
            raise ValidationError("research-state binding has unknown or missing fields")
        if set(self.soundness) != {
            "assessment_artifact_hash", "assessment_id", "verdict", "reason",
            "dimension_statuses",
        }:
            raise ValidationError("composition soundness has unknown or missing fields")
        if not self.claims:
            raise ValidationError("composition requires at least one eligible claim")
        if (
            not isinstance(self.required_limitations, tuple)
            or len(self.required_limitations) > 2048
            or len(set(self.required_limitations)) != len(self.required_limitations)
            or any(not isinstance(item, str) or not item for item in self.required_limitations)
        ):
            raise ValidationError("composition limitations must be unique bounded text")
        _canonical_object(self.research_state_binding, "research-state binding")
        _canonical_object(self.soundness, "composition soundness")
        if self.schema_version != COMPOSITION_INPUT_SCHEMA:
            raise ValidationError("unsupported paper composition-input schema")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PaperCompositionInput":
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise ValidationError("paper composition input has unknown or missing fields")
        return cls(
            run_id=value["run_id"], manuscript_id=value["manuscript_id"], revision=value["revision"],
            predecessor_revision_artifact_hash=value["predecessor_revision_artifact_hash"],
            candidate_id=value["candidate_id"], candidate_artifact_hash=value["candidate_artifact_hash"],
            bundle_artifact_hash=value["bundle_artifact_hash"], verification_artifact_hash=value["verification_artifact_hash"],
            bundle_issuance_event_id=value["bundle_issuance_event_id"], bundle_issuance_event_hash=value["bundle_issuance_event_hash"],
            bundle_issuance_event_index=value["bundle_issuance_event_index"], historical_ledger_head_hash=value["historical_ledger_head_hash"],
            historical_ledger_event_count=value["historical_ledger_event_count"], research_state_binding=value["research_state_binding"],
            authority_scope=value["authority_scope"],
            claims=tuple(_canonical_object(item, "claim") for item in _tuple(value["claims"], "claims")),
            numeric_assertions=tuple(_canonical_object(item, "numeric assertion") for item in _tuple(value["numeric_assertions"], "numeric assertions")),
            references=tuple(_canonical_object(item, "reference") for item in _tuple(value["references"], "references")),
            assets=tuple(_canonical_object(item, "asset") for item in _tuple(value["assets"], "assets")),
            method_code_bindings=tuple(_canonical_object(item, "method binding") for item in _tuple(value["method_code_bindings"], "method bindings")),
            required_limitations=tuple(_tuple(value["required_limitations"], "limitations")), soundness=value["soundness"],
            findings=tuple(_canonical_object(item, "finding") for item in _tuple(value["findings"], "findings")),
            challenger_reviews=tuple(_canonical_object(item, "Challenger review") for item in _tuple(value["challenger_reviews"], "Challenger reviews")),
            schema_version=value["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class CompositionSourceMapEntry:
    block_id: str
    start_byte: int
    end_byte: int
    block_sha256: str
    source_artifact_hashes: tuple[str, ...]
    source_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.block_id, "composition block ID")
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (self.start_byte, self.end_byte)) or self.start_byte < 0 or self.end_byte <= self.start_byte:
            raise ValidationError("composition source-map byte range is invalid")
        validate_sha256(self.block_sha256, "composition block SHA-256")
        if not self.source_artifact_hashes or len(set(self.source_artifact_hashes)) != len(self.source_artifact_hashes):
            raise ValidationError("composition block requires unique source artifacts")
        for digest in self.source_artifact_hashes:
            validate_sha256(digest, "composition block source")
        if not self.source_fields or len(set(self.source_fields)) != len(self.source_fields) or any(not isinstance(item, str) or not item for item in self.source_fields):
            raise ValidationError("composition block requires canonical source fields")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))


@dataclass(frozen=True, slots=True)
class PaperCompositionRender:
    content_bytes: bytes
    source_map: tuple[CompositionSourceMapEntry, ...]


@dataclass(frozen=True, slots=True)
class PaperManuscriptRevision:
    run_id: str
    manuscript_id: str
    revision: int
    predecessor_revision_artifact_hash: str | None
    composition_input_artifact_hash: str
    content_artifact_hash: str
    composition_verification_artifact_hash: str
    candidate_artifact_hash: str
    bundle_artifact_hash: str
    paper_verification_artifact_hash: str
    resolved_finding_artifact_hashes: tuple[str, ...]
    unresolved_finding_artifact_hashes: tuple[str, ...]
    manuscript_status: str = "MANUSCRIPT_CANDIDATE"
    release_status: str = "NOT_RELEASED"
    submission_status: str = "NOT_SUBMITTED"
    schema_version: str = MANUSCRIPT_REVISION_SCHEMA

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "revision run ID")
        validate_identifier(self.manuscript_id, "revision manuscript ID")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or not 1 <= self.revision <= MAX_REVISIONS:
            raise ValidationError("revision number is invalid")
        if (self.revision == 1) != (self.predecessor_revision_artifact_hash is None):
            raise ValidationError("revision predecessor is inconsistent")
        for digest in (
            self.composition_input_artifact_hash, self.content_artifact_hash,
            self.composition_verification_artifact_hash, self.candidate_artifact_hash,
            self.bundle_artifact_hash, self.paper_verification_artifact_hash,
            *self.resolved_finding_artifact_hashes,
            *self.unresolved_finding_artifact_hashes,
        ):
            validate_sha256(digest, "revision authority SHA-256")
        if self.predecessor_revision_artifact_hash is not None:
            validate_sha256(self.predecessor_revision_artifact_hash, "revision predecessor")
        for values in (self.resolved_finding_artifact_hashes, self.unresolved_finding_artifact_hashes):
            if len(set(values)) != len(values):
                raise ValidationError("revision hash partitions must be unique")
        if set(self.resolved_finding_artifact_hashes) & set(self.unresolved_finding_artifact_hashes):
            raise ValidationError("finding partitions overlap")
        if (self.manuscript_status, self.release_status, self.submission_status) != ("MANUSCRIPT_CANDIDATE", "NOT_RELEASED", "NOT_SUBMITTED"):
            raise ValidationError("composition cannot grant release or submission authority")
        if self.schema_version != MANUSCRIPT_REVISION_SCHEMA:
            raise ValidationError("unsupported manuscript-revision schema")

    def to_dict(self) -> dict[str, Any]:
        return safe_json_loads(canonical_json_bytes(self))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PaperManuscriptRevision":
        if set(value) != set(cls.__dataclass_fields__):
            raise ValidationError("manuscript revision has unknown or missing fields")
        kwargs = dict(value)
        for name in ("resolved_finding_artifact_hashes", "unresolved_finding_artifact_hashes"):
            kwargs[name] = tuple(_tuple(kwargs[name], name))
        return cls(**kwargs)


@dataclass(frozen=True, slots=True)
class RegisteredPaperManuscriptRevision:
    revision_record: ArtifactRecord
    revision: PaperManuscriptRevision
    composition_input_record: ArtifactRecord
    content_record: ArtifactRecord
    composition_verification_record: ArtifactRecord
    content_bytes: bytes
    source_map: tuple[CompositionSourceMapEntry, ...]
    issuance_event: LedgerEvent


@dataclass(frozen=True, slots=True)
class _ImmutableRevisionReplay:
    """Exact historical revision replay without current scientific authority."""

    revision_record: ArtifactRecord
    revision: PaperManuscriptRevision
    composition_input_record: ArtifactRecord
    composition: PaperCompositionInput
    content_record: ArtifactRecord
    composition_verification_record: ArtifactRecord
    content_bytes: bytes
    source_map: tuple[CompositionSourceMapEntry, ...]
    issuance_event: LedgerEvent
    issuance_event_index: int


@dataclass(frozen=True, slots=True)
class _FreshCompositionReplay:
    composition: PaperCompositionInput
    registry_snapshot: RegistryValidationResult
    ledger_snapshot: LedgerValidationResult


def _json_line(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _literal(value: Any) -> str:
    """Render inert one-line canonical JSON in a non-breakable code span."""

    payload = _json_line(value)
    # split() does not directly expose runs; count them explicitly and choose a
    # fence strictly longer than every run in the payload.
    run = maximum = 0
    for character in payload:
        if character == "`":
            run += 1
            maximum = max(maximum, run)
        else:
            run = 0
    fence = "`" * max(1, maximum + 1)
    return f"{fence} {payload} {fence}"


def render_paper_composition(
    composition: PaperCompositionInput,
    *,
    renderer_version: str = RENDERER_VERSION,
) -> PaperCompositionRender:
    """Render one supported immutable Markdown version and its exact source map."""

    if not isinstance(composition, PaperCompositionInput):
        raise ValidationError("paper renderer requires typed composition input")
    if renderer_version not in SUPPORTED_RENDERER_VERSIONS:
        raise ValidationError("paper renderer version is unsupported")
    blocks: list[bytes] = []
    maps: list[CompositionSourceMapEntry] = []

    def add(block_id: str, text: str, sources: tuple[str, ...], fields: tuple[str, ...]) -> None:
        raw = text.encode("utf-8")
        start = sum(len(item) for item in blocks)
        blocks.append(raw)
        maps.append(CompositionSourceMapEntry(block_id, start, start + len(raw), sha256_bytes(raw), tuple(dict.fromkeys(sources)), fields))

    core = (composition.candidate_artifact_hash, composition.bundle_artifact_hash, composition.verification_artifact_hash)
    status = (
        "SYSTEM_FIXTURE / NOT_SCIENTIFIC_MANUSCRIPT / NOT_RELEASED / "
        "NOT_SUBMITTED"
        if composition.authority_scope == "SYSTEM_FIXTURE"
        else "MANUSCRIPT_CANDIDATE / NOT_RELEASED / NOT_SUBMITTED"
    )
    add(
        "front-matter",
        f"# Evidence dossier\n\nStatus: {status}\n\n",
        core,
        ("authority_scope",),
    )

    def claim_sources(claim: Mapping[str, Any]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                (
                    str(claim["claim_state_artifact_hash"]),
                    str(claim["claim_semantics_artifact_hash"]),
                    *(str(item) for item in claim["evidence_hashes"]),
                    *(str(item) for item in claim["source_artifact_ids"]),
                )
            )
        )

    def method_sources(binding: Mapping[str, Any]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                (
                    *(str(binding[name]) for name in (
                        "method_artifact_hash", "code_artifact_hash",
                        "method_state_artifact_hash",
                        "implementation_state_artifact_hash",
                    )),
                    *(str(item) for item in binding["authority_sources"]),
                )
            )
        )

    if renderer_version == LEGACY_RENDERER_VERSION:
        add("claims-heading", "## Verified claims\n\n", core, ("claims",))
        for index, claim in enumerate(composition.claims):
            claim_id = str(claim["claim_id"])
            sources = tuple(dict.fromkeys((str(claim["claim_state_artifact_hash"]), str(claim["claim_semantics_artifact_hash"]), *tuple(claim["evidence_hashes"]))))
            add(f"claim-{index + 1}", f"### Claim\n\nID: {_literal(claim_id)}\n\nText: {_literal(claim['text'])}\n\nScope: {_literal(claim['scope'])}\n\n", sources, (f"claims[{index}].claim_id", f"claims[{index}].text", f"claims[{index}].scope"))
        add("numbers-heading", "## Verified numeric assertions\n\n", core, ("numeric_assertions",))
        for index, assertion in enumerate(composition.numeric_assertions):
            add(f"numeric-{index + 1}", f"- {_literal(assertion)}\n", (str(assertion["source_artifact_hash"]),), (f"numeric_assertions[{index}]",))
        add("numbers-tail", "\n", core, ("numeric_assertions",))
        add("references-heading", "## Registered references\n\n", core, ("references",))
        for index, reference in enumerate(composition.references):
            sources = tuple(dict.fromkeys(
                (str(reference["reference_artifact_hash"]),)
                + ((str(reference["source_citation_evidence_artifact_hash"]),) if reference.get("source_citation_evidence_artifact_hash") else ())
                + ((str(reference["semantic_judgment_artifact_hash"]),) if reference.get("semantic_judgment_artifact_hash") else ())
            ))
            add(f"reference-{index + 1}", f"- {_literal(reference)}\n", sources, (f"references[{index}]",))
        add("references-tail", "\n", core, ("references",))
        add("assets-heading", "## Registered tables and figures\n\n", core, ("assets",))
        for index, asset in enumerate(composition.assets):
            add(f"asset-{index + 1}", f"- {_literal(asset)}\n", (str(asset["artifact_hash"]), *tuple(asset["authoritative_parent_hashes"])), (f"assets[{index}]",))
        add("assets-tail", "\n", core, ("assets",))
        add("methods-heading", "## Registered method/code bindings\n\n", core, ("method_code_bindings",))
        for index, binding in enumerate(composition.method_code_bindings):
            add(f"method-{index + 1}", f"- {_literal(binding)}\n", method_sources(binding), (f"method_code_bindings[{index}]",))
        add("methods-tail", "\n", core, ("method_code_bindings",))
        add("limitations-heading", "## Required limitations\n\n", (composition.bundle_artifact_hash, str(composition.soundness["assessment_artifact_hash"])), ("required_limitations",))
        for index, limitation in enumerate(composition.required_limitations):
            add(f"limitation-{index + 1}", f"- {_literal(limitation)}\n", (composition.bundle_artifact_hash, str(composition.soundness["assessment_artifact_hash"])), (f"required_limitations[{index}]",))
        add("limitations-tail", "\n", core, ("required_limitations",))
    else:
        add("abstract-heading", "## Abstract\n\n", core, ("claims",))
        for index, claim in enumerate(composition.claims):
            abstract_claim = {
                "claim_id": claim["claim_id"],
                "text": claim["text"],
                "scope": claim["scope"],
                "expressed_strength": claim["expressed_strength"],
                "permitted_strength": claim["permitted_strength"],
            }
            add(
                f"abstract-claim-{index + 1}",
                f"- {_literal(abstract_claim)}\n",
                claim_sources(claim),
                (
                    f"claims[{index}].claim_id", f"claims[{index}].text",
                    f"claims[{index}].scope",
                    f"claims[{index}].expressed_strength",
                    f"claims[{index}].permitted_strength",
                ),
            )
        add("abstract-tail", "\n", core, ("claims",))

        add("introduction-heading", "## Introduction\n\n", core, ("claims",))
        for index, claim in enumerate(composition.claims):
            scope = {
                "claim_id": claim["claim_id"],
                "scope": claim["scope"],
                "dependency_claim_ids": claim["dependency_claim_ids"],
                "central": claim["central"],
            }
            add(
                f"introduction-scope-{index + 1}",
                f"- Registered claim scope: {_literal(scope)}\n",
                claim_sources(claim),
                (
                    f"claims[{index}].claim_id", f"claims[{index}].scope",
                    f"claims[{index}].dependency_claim_ids",
                    f"claims[{index}].central",
                ),
            )
        add("introduction-tail", "\n", core, ("claims",))

        add("methods-heading", "## Methods\n\n", core, ("method_code_bindings",))
        for index, binding in enumerate(composition.method_code_bindings):
            add(
                f"method-{index + 1}",
                f"- {_literal(binding)}\n",
                method_sources(binding),
                (f"method_code_bindings[{index}]",),
            )
        add("methods-tail", "\n", core, ("method_code_bindings",))

        add("results-heading", "## Results\n\n", core, ("claims", "numeric_assertions", "assets"))
        for index, claim in enumerate(composition.claims):
            add(
                f"result-claim-{index + 1}",
                f"- Verified claim: {_literal(claim)}\n",
                claim_sources(claim),
                (f"claims[{index}]",),
            )
        for index, assertion in enumerate(composition.numeric_assertions):
            add(f"result-numeric-{index + 1}", f"- Numeric assertion: {_literal(assertion)}\n", (str(assertion["source_artifact_hash"]),), (f"numeric_assertions[{index}]",))
        for index, asset in enumerate(composition.assets):
            add(f"result-asset-{index + 1}", f"- Table or figure: {_literal(asset)}\n", (str(asset["artifact_hash"]), *tuple(asset["authoritative_parent_hashes"])), (f"assets[{index}]",))
        add("results-tail", "\n", core, ("claims", "numeric_assertions", "assets"))

        add("references-heading", "## Registered references\n\n", core, ("references",))
        for index, reference in enumerate(composition.references):
            sources = tuple(dict.fromkeys(
                (str(reference["reference_artifact_hash"]),)
                + ((str(reference["source_citation_evidence_artifact_hash"]),) if reference.get("source_citation_evidence_artifact_hash") else ())
                + ((str(reference["semantic_judgment_artifact_hash"]),) if reference.get("semantic_judgment_artifact_hash") else ())
            ))
            add(f"reference-{index + 1}", f"- {_literal(reference)}\n", sources, (f"references[{index}]",))
        add("references-tail", "\n", core, ("references",))

        limitation_sources = (
            composition.bundle_artifact_hash,
            str(composition.soundness["assessment_artifact_hash"]),
        )
        add("limitations-heading", "## Limitations\n\n", limitation_sources, ("required_limitations",))
        add(
            "limitations-body",
            f"Required limitation inventory: {_literal(composition.required_limitations)}\n\n",
            limitation_sources,
            ("required_limitations",),
        )

        reproduction_sources = tuple(
            dict.fromkeys(
                (
                    composition.bundle_artifact_hash,
                    str(composition.research_state_binding["snapshot_artifact_hash"]),
                    *(
                        str(digest)
                        for digest in composition.research_state_binding[
                            "state_artifact_hashes"
                        ]
                    ),
                    *(
                        digest
                        for binding in composition.method_code_bindings
                        for digest in method_sources(binding)
                    ),
                )
            )
        )
        replay_binding = {
            "research_state_binding": composition.research_state_binding,
            "bundle_issuance": {
                "event_id": composition.bundle_issuance_event_id,
                "event_hash": composition.bundle_issuance_event_hash,
                "event_index": composition.bundle_issuance_event_index,
            },
            "method_code_bindings": composition.method_code_bindings,
        }
        add("reproducibility-heading", "## Reproducibility\n\n", reproduction_sources, ("research_state_binding", "bundle_issuance_event_id", "bundle_issuance_event_hash", "bundle_issuance_event_index", "method_code_bindings"))
        add(
            "reproducibility-body",
            f"Replay authority: {_literal(replay_binding)}\n\n"
            "This exact provenance inventory does not itself establish independent "
            "reproduction or external validation.\n\n",
            reproduction_sources,
            ("research_state_binding", "bundle_issuance_event_id", "bundle_issuance_event_hash", "bundle_issuance_event_index", "method_code_bindings"),
        )

    add("review-heading", "## Soundness and Challenger record\n\n", (str(composition.soundness["assessment_artifact_hash"]),), ("soundness", "findings", "challenger_reviews"))
    dimension_sources = tuple(
        str(item["receipt_artifact_hash"])
        for item in composition.soundness.get("dimension_statuses", ())
    )
    add("soundness", f"- Soundness: {_literal(composition.soundness)}\n", (str(composition.soundness["assessment_artifact_hash"]), *dimension_sources), ("soundness",))
    for index, finding in enumerate(composition.findings):
        add(f"finding-{index + 1}", f"- Finding: {_literal(finding)}\n", (str(finding["finding_artifact_hash"]),), (f"findings[{index}]",))
    for index, review in enumerate(composition.challenger_reviews):
        add(f"challenger-{index + 1}", f"- Challenger review: {_literal(review)}\n", (str(review["review_artifact_hash"]),), (f"challenger_reviews[{index}]",))
    content = b"".join(blocks)
    if len(content) > MAX_COMPOSITION_BYTES:
        raise ValidationError("rendered paper exceeds the composition byte bound")
    _validate_source_map(content, tuple(maps))
    return PaperCompositionRender(content, tuple(maps))


def _validate_source_map(content: bytes, source_map: tuple[CompositionSourceMapEntry, ...]) -> None:
    cursor = 0
    seen: set[str] = set()
    for entry in source_map:
        if entry.block_id in seen or entry.start_byte != cursor or entry.end_byte > len(content):
            raise ValidationError("composition source map is incomplete, overlapping, or ambiguous")
        block = content[entry.start_byte:entry.end_byte]
        if sha256_bytes(block) != entry.block_sha256:
            raise ValidationError("composition source-map block hash differs from content")
        cursor = entry.end_byte
        seen.add(entry.block_id)
    if not source_map or cursor != len(content):
        raise ValidationError("composition source map does not cover every content byte")


def _derive_composition_input(
    registry: ArtifactRegistry, ledger: EventLedger, candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle, *, run_id: str, manuscript_id: str,
    revision: int, predecessor_revision_artifact_hash: str | None,
    candidate_artifact_hash: str, bundle_artifact_hash: str,
    verification_artifact_hash: str,
    _round_replay: _PaperRoundReplay | None = None,
) -> PaperCompositionInput:
    # Authorization intentionally precedes rendering/content construction.
    verification_record = _require_frozen_artifact(
        registry,
        verification_artifact_hash,
        logical_type="paper_verification",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    if verification_record.parent_artifacts != (
        candidate_artifact_hash,
        bundle_artifact_hash,
    ):
        raise ValidationError(
            "paper verification is not bound to the supplied candidate and bundle"
        )
    if (
        verification_record.schema_version != "1.0"
        or verification_record.mime_type != "application/json"
        or verification_record.origin
        != "fresh registry-and-ledger replay of exact paper authority"
        or verification_record.creation_command
        != ("scientist-one", "verify-paper-authority")
    ):
        raise ValidationError("paper verification envelope is stale or substituted")
    try:
        if _round_replay is None:
            verification = require_paper_verification(registry, ledger, run_id=run_id, verification_artifact_hash=verification_artifact_hash, expected_candidate_id=candidate.candidate_id)
        else:
            verification, _paper_source = _require_paper_verification_with_round_sources(
                registry, ledger,
                verification_artifact_hash=verification_artifact_hash,
                expected_run_id=run_id,
                expected_candidate_id=candidate.candidate_id,
                audited_state=_round_replay.audited_state,
                soundness=_round_replay.soundness,
                review_replay=_round_replay.reviews,
            )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(
            "paper composition requires a present, fresh verification"
        ) from exc
    _validate_composition_authority(bundle, verification)
    _resolve_candidate_bundle_artifacts(registry, candidate, bundle, candidate_artifact_hash, bundle_artifact_hash)
    issuance = _require_authoritative_bundle_issuance(
        registry, ledger, bundle_artifact_hash=bundle_artifact_hash, expected_bundle=bundle,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    eligible_ids = tuple(item.claim_id for item in bundle.claims if item.scientific_writer_eligible)
    if not eligible_ids or not set(eligible_ids).issubset(verification.verified_claim_ids):
        raise ValidationError("fresh verification does not cover every eligible claim")
    candidate_claims = {item.claim_id: item for item in candidate.claims}
    if not set(eligible_ids).issubset(candidate_claims):
        raise ValidationError("paper candidate omits an eligible claim")
    soundness = _resolve_soundness(
        registry, bundle.soundness_assessment_hash, claim_graph_hash=bundle.claim_graph_hash,
        central_claim_ids=bundle.central_claim_ids, ledger=ledger, run_id=run_id,
        confirmatory_claim_authority_hashes=bundle.confirmatory_claim_authority_hashes,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    ledger_result = ledger.validate(raise_on_error=True)
    issuance_matches = [(index, event) for index, event in enumerate(ledger_result.events) if event.event_id == issuance.event_id]
    if len(issuance_matches) != 1 or ledger_result.head_hash is None:
        raise ValidationError("bundle issuance is not uniquely present in current history")
    claims = tuple(
        {
            "claim_id": item.claim_id, "text": item.text, "scope": item.scope,
            "claim_type": item.claim_type.value, "expressed_strength": item.expressed_strength.value,
            "permitted_strength": item.permitted_strength.value, "claim_state_artifact_hash": item.claim_state_artifact_hash,
            "claim_semantics_artifact_hash": item.claim_semantics_artifact_hash,
            "evidence_hashes": list(item.evidence_hashes), "dependency_claim_ids": list(item.dependency_claim_ids),
            "source_artifact_ids": list(item.source_artifact_ids), "central": item.claim_id in bundle.central_claim_ids,
        }
        for item in bundle.claims if item.scientific_writer_eligible
    )
    findings = tuple(
        {
            "finding_artifact_hash": digest, "challenge_id": finding.challenge_id,
            "category": finding.category.value, "severity": finding.severity.value,
            "status": finding.status.value, "target_claim_ids": list(finding.target_claim_ids),
            "attack": finding.attack, "resolution": finding.resolution,
            "resolution_receipt_hash": finding.resolution_receipt_hash,
        }
        for finding, digest in zip(soundness.findings, soundness.finding_artifact_hashes, strict=True)
    )
    reviews = tuple(
        {
            "review_artifact_hash": digest, "review_id": review.review_id,
            "category": review.category.value, "execution_status": review.execution_status.value,
            "finding_artifact_hashes": list(review.finding_artifact_hashes),
            "attack": review.attack, "conclusion": review.conclusion,
        }
        for review, digest in zip(soundness.challenger_reviews, soundness.challenger_review_hashes, strict=True)
    )
    return PaperCompositionInput(
        run_id=run_id, manuscript_id=manuscript_id, revision=revision,
        predecessor_revision_artifact_hash=predecessor_revision_artifact_hash,
        candidate_id=candidate.candidate_id, candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash, verification_artifact_hash=verification_artifact_hash,
        bundle_issuance_event_id=issuance.event_id, bundle_issuance_event_hash=str(issuance.event_hash),
        bundle_issuance_event_index=issuance_matches[0][0], historical_ledger_head_hash=ledger_result.head_hash,
        historical_ledger_event_count=ledger_result.event_count,
        research_state_binding={
            "snapshot_artifact_hash": bundle.research_state_hash,
            "state_artifact_hashes": list(bundle.research_state_artifact_hashes),
            "ledger_head_hash": bundle.research_state_ledger_head_hash,
            "ledger_event_count": bundle.research_state_ledger_event_count,
            "code_version": bundle.research_state_code_version,
            "configuration_hash": bundle.research_state_configuration_hash,
        },
        authority_scope="SCIENTIFIC_EVIDENCE", claims=claims,
        numeric_assertions=tuple(_plain_json(item) for item in candidate.numeric_assertions),
        references=tuple(_plain_json(item) for item in candidate.references), assets=tuple(_plain_json(item) for item in candidate.assets),
        method_code_bindings=tuple(_plain_json(item) for item in candidate.method_code_bindings),
        required_limitations=bundle.required_limitations,
        soundness={"assessment_artifact_hash": bundle.soundness_assessment_hash, "assessment_id": soundness.assessment_id, "verdict": soundness.verdict.value, "reason": soundness.reason, "dimension_statuses": [{"dimension": dimension.value, "status": status.value, "receipt_artifact_hash": digest} for (dimension, status), digest in zip(soundness.dimensions, soundness.dimension_receipt_hashes, strict=True)]},
        findings=findings, challenger_reviews=reviews,
    )


def _locked_paper_authority_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
) -> tuple[RegistryValidationResult, LedgerValidationResult]:
    """Take one co-locked registry/ledger snapshot in publication lock order."""

    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            registry_result = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            ledger_result = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if not ledger_result.valid:
                raise ValidationError("paper authority ledger did not validate")
            return registry_result, ledger_result
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)


def _derive_composition_input_stably(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle,
    *,
    run_id: str,
    manuscript_id: str,
    revision: int,
    predecessor_revision_artifact_hash: str | None,
    candidate_artifact_hash: str,
    bundle_artifact_hash: str,
    verification_artifact_hash: str,
    _round_replay: _PaperRoundReplay | None = None,
) -> _FreshCompositionReplay:
    """Require the complete fresh replay to observe one stable authority era."""

    if _round_replay is not None:
        _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
    before_registry, before_ledger = _locked_paper_authority_snapshot(
        registry,
        ledger,
    )
    if _round_replay is not None and (
        before_registry != _round_replay.reviews.registry_snapshot
        or before_ledger != _round_replay.reviews.ledger_snapshot
    ):
        raise ValidationError("manuscript round sources changed before fresh composition replay")
    composition = _derive_composition_input(
        registry,
        ledger,
        candidate,
        bundle,
        run_id=run_id,
        manuscript_id=manuscript_id,
        revision=revision,
        predecessor_revision_artifact_hash=predecessor_revision_artifact_hash,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        verification_artifact_hash=verification_artifact_hash,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    if _round_replay is not None:
        _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
    after_registry, after_ledger = _locked_paper_authority_snapshot(
        registry,
        ledger,
    )
    if after_registry != before_registry or after_ledger != before_ledger:
        raise ValidationError(
            "paper authority changed during fresh composition replay; retry"
        )
    if _round_replay is not None and (
        after_registry != _round_replay.reviews.registry_snapshot
        or after_ledger != _round_replay.reviews.ledger_snapshot
    ):
        raise ValidationError("manuscript round sources changed after fresh composition replay")
    if (
        composition.historical_ledger_head_hash != after_ledger.head_hash
        or composition.historical_ledger_event_count != after_ledger.event_count
    ):
        raise ValidationError(
            "fresh composition does not bind its stable authority snapshot"
        )
    return _FreshCompositionReplay(composition, after_registry, after_ledger)


def _validate_composition_authority(
    bundle: AuthoritativeResearchBundle,
    verification: PaperVerification,
) -> None:
    """Fail-closed scientific authorization, called before any rendering."""

    if not isinstance(bundle, AuthoritativeResearchBundle) or not isinstance(
        verification, PaperVerification
    ):
        raise ValidationError("composition authorization requires typed paper authority")
    if not verification.passed:
        raise ValidationError("paper composition requires a freshly passed verification")
    if bundle.soundness_verdict not in {
        SoundnessVerdict.PASS,
        SoundnessVerdict.CONDITIONAL_PASS,
    }:
        raise ValidationError(
            "paper composition requires PASS or CONDITIONAL_PASS soundness"
        )
    central = {
        item.claim_id: item
        for item in bundle.claims
        if item.claim_id in bundle.central_claim_ids
    }
    if set(central) != set(bundle.central_claim_ids) or any(
        not item.scientific_writer_eligible for item in central.values()
    ):
        raise ValidationError(
            "every central claim must have scientific writer authority"
        )
    if any(
        item.evidence_use is not ClaimEvidenceUse.SCIENTIFIC
        or item.claim_semantics_evidence_scope
        is not ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE
        for item in bundle.claims
    ):
        raise ValidationError(
            "SYSTEM_FIXTURE/NON_EVIDENTIARY claim scope cannot be composed"
        )
    if any(
        item.scientific_evidence_status
        is not MetricEvidenceStatus.SCIENTIFIC_ELIGIBLE
        for item in bundle.metrics
    ):
        raise ValidationError("NON_EVIDENTIARY metric scope cannot be composed")
    if any(
        item.confirmatory_authority is not None
        and item.confirmatory_authority.scope
        is not ConfirmatoryAuthorityScope.SCIENTIFIC_EVIDENCE
        for item in bundle.claims
    ):
        raise ValidationError(
            "NON_EVIDENTIARY confirmatory scope cannot be composed"
        )


def _record_for_bytes(registry: ArtifactRegistry, data: bytes, *, logical_type: str, schema_version: str, mime_type: str, origin: str, creator_role: Role, creation_command: tuple[str, ...], parents: tuple[str, ...], created_at: str) -> ArtifactRecord:
    digest = sha256_bytes(data)
    matches = [item for item in registry.list_records() if item.sha256 == digest]
    if matches:
        record = matches[0]
        if not registry._semantic_match(record, logical_type=logical_type, schema_version=schema_version, mime_type=mime_type, origin=origin, creator_role=creator_role, creation_command=creation_command, parents=parents, validation_result="PASS", frozen=True):
            raise ValidationError("composition artifact content collides with different metadata")
        return record
    return ArtifactRecord(sha256=digest, path=(registry.objects_path / digest[:2] / digest).as_posix(), relative_path=(registry.objects_path / digest[:2] / digest).as_posix(), metadata_path=(registry.metadata_path / digest[:2] / f"{digest}.json").as_posix(), logical_type=logical_type, schema_version=schema_version, mime_type=mime_type, size=len(data), origin=origin, creator_role=creator_role, creation_command=creation_command, parent_artifacts=parents, validation_result="PASS", frozen=True, created_at=created_at)


def _revision_event_metadata(records: tuple[ArtifactRecord, ...], revision: PaperManuscriptRevision, composition: PaperCompositionInput) -> dict[str, Any]:
    return {
        "artifact_record_hashes": [str(item.record_hash) for item in records],
        "artifact_types": [item.logical_type for item in records],
        "paper_operation": "MANUSCRIPT_REVISION_ISSUED",
        "manuscript_id": revision.manuscript_id, "revision": revision.revision,
        "predecessor_revision_artifact_hash": revision.predecessor_revision_artifact_hash,
        "revision_artifact_hash": records[-1].sha256,
        "composition_input_artifact_hash": revision.composition_input_artifact_hash,
        "content_artifact_hash": revision.content_artifact_hash,
        "composition_verification_artifact_hash": revision.composition_verification_artifact_hash,
        "ledger_event_count_before_revision": composition.historical_ledger_event_count,
        "ledger_head_hash_before_revision": composition.historical_ledger_head_hash,
        "bundle_issuance_event_id": composition.bundle_issuance_event_id,
        "bundle_issuance_event_hash": composition.bundle_issuance_event_hash,
        "manuscript_status": "MANUSCRIPT_CANDIDATE", "release_status": "NOT_RELEASED", "submission_status": "NOT_SUBMITTED",
    }


def _validate_revision_timestamp(
    revision_record: ArtifactRecord,
    historical_events: tuple[LedgerEvent, ...],
) -> None:
    if not historical_events:
        raise ValidationError("manuscript revision requires a historical ledger prefix")
    revision_time = datetime.fromisoformat(
        revision_record.created_at.replace("Z", "+00:00")
    )
    latest_history = max(
        datetime.fromisoformat(item.timestamp.replace("Z", "+00:00"))
        for item in historical_events
    )
    if revision_time < latest_history:
        raise ValidationError("manuscript revision cannot predate its historical prefix")


def _parse_source_map(value: Any) -> tuple[CompositionSourceMapEntry, ...]:
    result = []
    for item in _tuple(value, "composition source map"):
        if not isinstance(item, Mapping) or set(item) != set(CompositionSourceMapEntry.__dataclass_fields__):
            raise ValidationError("composition source-map entry is malformed")
        result.append(CompositionSourceMapEntry(item["block_id"], item["start_byte"], item["end_byte"], item["block_sha256"], tuple(_tuple(item["source_artifact_hashes"], "source artifacts")), tuple(_tuple(item["source_fields"], "source fields"))))
    return tuple(result)


def _read_revision_record(registry: ArtifactRegistry, digest: str) -> tuple[ArtifactRecord, PaperManuscriptRevision]:
    record, value = _read_registry_json(registry, digest, logical_type="paper_manuscript_revision", creator_role=Role.PAPER_WRITER)
    revision = PaperManuscriptRevision.from_dict(value)
    if record.schema_version != "1.0" or record.origin != "issued deterministic evidence-only manuscript revision" or record.creation_command != ("scientist-one", "paper", "issue-manuscript-revision"):
        raise ValidationError("manuscript revision envelope is substituted")
    expected_parents = tuple(dict.fromkeys((revision.composition_input_artifact_hash, revision.content_artifact_hash, revision.composition_verification_artifact_hash, revision.candidate_artifact_hash, revision.bundle_artifact_hash, revision.paper_verification_artifact_hash, *((revision.predecessor_revision_artifact_hash,) if revision.predecessor_revision_artifact_hash else ()))))
    if record.parent_artifacts != expected_parents:
        raise ValidationError("manuscript revision parent closure is incomplete")
    return record, revision


def _revision_identity_hashes(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    manuscript_id: str,
    revision: int,
) -> frozenset[str]:
    matches: set[str] = set()
    for record in records:
        if record.logical_type != "paper_manuscript_revision":
            continue
        try:
            _, value = _read_revision_record(registry, record.sha256)
        except ValidationError:
            continue
        if value.manuscript_id == manuscript_id and value.revision == revision:
            matches.add(record.sha256)
    return frozenset(matches)


def _event_admitted_revision_identity_hashes(
    registry: ArtifactRegistry,
    ledger_events: tuple[LedgerEvent, ...],
    *,
    manuscript_id: str,
    revision: int,
) -> frozenset[str]:
    referenced = {
        digest for event in ledger_events for digest in event.artifact_hashes
    }
    records = tuple(
        record
        for record in registry.list_records()
        if record.logical_type == "paper_manuscript_revision"
        and record.sha256 in referenced
    )
    return _revision_identity_hashes(
        registry,
        records,
        manuscript_id=manuscript_id,
        revision=revision,
    )


def _require_revision_identity_namespace_unchanged(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    manuscript_id: str,
    revision: int,
    initial_identity_hashes: frozenset[str],
) -> None:
    current = _revision_identity_hashes(
        registry,
        records,
        manuscript_id=manuscript_id,
        revision=revision,
    )
    if current != initial_identity_hashes:
        raise ValidationError(
            "manuscript revision identity changed during derivation; retry"
        )


def _require_revision_event_from_history(
    registry: ArtifactRegistry,
    events: tuple[LedgerEvent, ...],
    record: ArtifactRecord,
    revision: PaperManuscriptRevision,
    composition: PaperCompositionInput,
    records: tuple[ArtifactRecord, ...],
) -> tuple[int, LedgerEvent]:
    """Replay one exact issuance against one already-validated ledger snapshot."""

    event_id = f"pmr-{record.sha256[:48]}"
    matches = [
        (index, event)
        for index, event in enumerate(events)
        if event.event_id == event_id
    ]
    if len(matches) != 1:
        raise ValidationError("manuscript revision lacks one exact issuance event")
    admitted_roots = _event_admitted_revision_identity_hashes(
        registry,
        events,
        manuscript_id=revision.manuscript_id,
        revision=revision.revision,
    )
    if admitted_roots != frozenset((record.sha256,)):
        raise ValidationError(
            "manuscript revision identity lacks one unique admitted root"
        )
    index, event = matches[0]
    count = composition.historical_ledger_event_count
    if (
        index != count
        or count <= 0
        or events[count - 1].event_hash
        != composition.historical_ledger_head_hash
    ):
        raise ValidationError("manuscript revision historical prefix is absent or changed")
    _validate_revision_timestamp(record, events[:index])
    prior = events[count - 1]
    expected = LedgerEvent.create(run_id=revision.run_id, actor_role=Role.PAPER_WRITER, state_before=prior.requested_state_after, requested_state_after=prior.requested_state_after, artifact_hashes=(record.sha256,), code_version=str(composition.research_state_binding["code_version"]), configuration_hash=str(composition.research_state_binding["configuration_hash"]), reason="issued deterministic evidence-only manuscript revision", prior_event_hash=composition.historical_ledger_head_hash, event_id=event_id, timestamp=record.created_at, event_type="CHECKPOINT", metadata=_revision_event_metadata(records, revision, composition))
    if event != expected:
        raise ValidationError("manuscript revision issuance event was substituted")
    if any(
        item.event_type == "CORRECTION"
        and item.supersedes_event_id == event_id
        for item in events[index + 1 :]
    ):
        raise ValidationError("manuscript revision issuance was corrected")
    if any(
        record.sha256 in item.artifact_hashes and item.event_id != event_id
        for item in events
    ):
        raise ValidationError("manuscript revision has ambiguous ledger admission")
    return index, event


def _require_revision_event(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    record: ArtifactRecord,
    revision: PaperManuscriptRevision,
    composition: PaperCompositionInput,
    records: tuple[ArtifactRecord, ...],
) -> LedgerEvent:
    events = ledger.validate(raise_on_error=True).events
    return _require_revision_event_from_history(
        registry,
        events,
        record,
        revision,
        composition,
        records,
    )[1]


def _require_historical_bundle_binding(
    events: tuple[LedgerEvent, ...],
    composition: PaperCompositionInput,
    *,
    revision_event_index: int,
) -> None:
    """Verify the exact old bundle event without treating it as current authority."""

    index = composition.bundle_issuance_event_index
    if index >= revision_event_index or index >= len(events):
        raise ValidationError(
            "historical manuscript bundle issuance is outside its ledger prefix"
        )
    event = events[index]
    if (
        event.event_id != composition.bundle_issuance_event_id
        or event.event_hash != composition.bundle_issuance_event_hash
        or event.artifact_hashes != (composition.bundle_artifact_hash,)
    ):
        raise ValidationError(
            "historical manuscript bundle issuance binding is substituted"
        )
    if any(
        candidate.event_type == "CORRECTION"
        and candidate.supersedes_event_id == event.event_id
        for candidate in events[index + 1 :]
    ):
        raise ValidationError(
            "historical manuscript bundle issuance was corrected"
        )
    if any(
        composition.bundle_artifact_hash in candidate.artifact_hashes
        and candidate.event_id != event.event_id
        for candidate in events
    ):
        raise ValidationError(
            "historical manuscript bundle has ambiguous ledger admission"
        )


def _replay_immutable_revision(
    registry: ArtifactRegistry,
    events: tuple[LedgerEvent, ...],
    *,
    revision_artifact_hash: str,
) -> _ImmutableRevisionReplay:
    """Verify immutable revision bytes and provenance without source currentness."""

    record, revision = _read_revision_record(registry, revision_artifact_hash)
    admitted_roots = _event_admitted_revision_identity_hashes(
        registry,
        events,
        manuscript_id=revision.manuscript_id,
        revision=revision.revision,
    )
    if admitted_roots != frozenset((record.sha256,)):
        raise ValidationError(
            "manuscript revision identity lacks one unique admitted root"
        )
    input_record, input_value = _read_registry_json(
        registry,
        revision.composition_input_artifact_hash,
        logical_type="paper_composition_input",
        creator_role=Role.PAPER_WRITER,
    )
    if (
        input_record.schema_version != "1.0"
        or input_record.origin != "canonical source-owned paper composition input"
        or input_record.creation_command
        != ("scientist-one", "paper", "derive-composition-input")
    ):
        raise ValidationError("paper composition-input envelope is substituted")
    composition = PaperCompositionInput.from_dict(input_value)
    if (
        composition.authority_scope != "SCIENTIFIC_EVIDENCE"
        or composition.run_id != revision.run_id
        or composition.manuscript_id != revision.manuscript_id
        or composition.revision != revision.revision
        or composition.predecessor_revision_artifact_hash
        != revision.predecessor_revision_artifact_hash
        or composition.candidate_artifact_hash
        != revision.candidate_artifact_hash
        or composition.bundle_artifact_hash != revision.bundle_artifact_hash
        or composition.verification_artifact_hash
        != revision.paper_verification_artifact_hash
    ):
        raise ValidationError("manuscript revision composition input is substituted")
    expected_input_parents = tuple(
        dict.fromkeys(
            (
                revision.candidate_artifact_hash,
                revision.bundle_artifact_hash,
                revision.paper_verification_artifact_hash,
                str(composition.soundness["assessment_artifact_hash"]),
                *(
                    (revision.predecessor_revision_artifact_hash,)
                    if revision.predecessor_revision_artifact_hash
                    else ()
                ),
            )
        )
    )
    if input_record.parent_artifacts != expected_input_parents:
        raise ValidationError("paper composition-input parent closure is incomplete")

    content_record = _require_frozen_artifact(
        registry,
        revision.content_artifact_hash,
        logical_type="paper_manuscript_content",
        creator_role=Role.PAPER_WRITER,
    )
    if (
        content_record.schema_version != "1.0"
        or content_record.mime_type != "text/markdown"
        or content_record.origin
        != "deterministic evidence-only manuscript content"
        or content_record.creation_command
        != ("scientist-one", "paper", "render-manuscript")
        or content_record.parent_artifacts
        != (revision.candidate_artifact_hash, revision.bundle_artifact_hash)
    ):
        raise ValidationError("manuscript content envelope is substituted")
    content = registry.get_bytes(content_record.sha256)
    if len(content) > MAX_COMPOSITION_BYTES:
        raise ValidationError("rendered paper exceeds the composition byte bound")

    verification_record, verification_value = _read_registry_json(
        registry,
        revision.composition_verification_artifact_hash,
        logical_type="paper_composition_verification",
        creator_role=Role.SCIENTIFIC_REVIEWER,
    )
    if (
        verification_record.schema_version != "1.0"
        or verification_record.origin
        != "byte-exact deterministic manuscript replay verification"
        or verification_record.creation_command
        != ("scientist-one", "paper", "verify-composition")
        or verification_record.parent_artifacts
        != (input_record.sha256, content_record.sha256)
    ):
        raise ValidationError("paper composition-verification envelope is substituted")
    expected_keys = {
        "schema_version",
        "renderer_version",
        "composition_input_artifact_hash",
        "content_artifact_hash",
        "content_sha256",
        "source_map",
        "passed",
    }
    if (
        set(verification_value) != expected_keys
        or verification_value["schema_version"]
        != COMPOSITION_VERIFICATION_SCHEMA
        or verification_value["renderer_version"]
        not in SUPPORTED_RENDERER_VERSIONS
        or verification_value["composition_input_artifact_hash"]
        != input_record.sha256
        or verification_value["content_artifact_hash"] != content_record.sha256
        or verification_value["content_sha256"] != sha256_bytes(content)
        or verification_value["passed"] is not True
    ):
        raise ValidationError("composition verification is stale or substituted")
    source_map = _parse_source_map(verification_value["source_map"])
    _validate_source_map(content, source_map)
    rendered = render_paper_composition(
        composition,
        renderer_version=verification_value["renderer_version"],
    )
    if rendered.content_bytes != content or rendered.source_map != source_map:
        raise ValidationError("manuscript content differs from deterministic replay")
    for entry in source_map:
        for digest in entry.source_artifact_hashes:
            _require_frozen_artifact(registry, digest)

    resolved = tuple(
        item["finding_artifact_hash"]
        for item in composition.findings
        if item["status"] == ChallengeStatus.RESOLVED.value
    )
    unresolved = tuple(
        item["finding_artifact_hash"]
        for item in composition.findings
        if item["status"] == ChallengeStatus.UNRESOLVED.value
    )
    if (
        revision.resolved_finding_artifact_hashes != resolved
        or revision.unresolved_finding_artifact_hashes != unresolved
    ):
        raise ValidationError(
            "revision finding partition differs from source-owned status"
        )
    records = (input_record, content_record, verification_record, record)
    event_index, event = _require_revision_event_from_history(
        registry,
        events,
        record,
        revision,
        composition,
        records,
    )
    _require_historical_bundle_binding(
        events,
        composition,
        revision_event_index=event_index,
    )
    return _ImmutableRevisionReplay(
        record,
        revision,
        input_record,
        composition,
        content_record,
        verification_record,
        content,
        source_map,
        event,
        event_index,
    )


def _require_historical_predecessor_lineage(
    registry: ArtifactRegistry,
    events: tuple[LedgerEvent, ...],
    *,
    predecessor_revision_artifact_hash: str,
    expected_run_id: str,
    expected_manuscript_id: str,
    expected_revision: int,
    expected_candidate_id: str,
    before_event_index: int,
) -> _ImmutableRevisionReplay:
    """Verify a bounded old chain while granting no current-use authority."""

    validate_sha256(
        predecessor_revision_artifact_hash,
        "historical predecessor revision",
    )
    validate_identifier(expected_run_id, "historical predecessor run ID")
    validate_identifier(
        expected_manuscript_id,
        "historical predecessor manuscript ID",
    )
    validate_identifier(expected_candidate_id, "historical predecessor candidate ID")
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 1
        or isinstance(before_event_index, bool)
        or not isinstance(before_event_index, int)
        or before_event_index <= 0
    ):
        raise ValidationError("historical predecessor expectation is invalid")

    current_hash = predecessor_revision_artifact_hash
    revision_number = expected_revision
    child_event_index = before_event_index
    immediate: _ImmutableRevisionReplay | None = None
    depth = 0
    while True:
        depth += 1
        if depth > MAX_REVISION_LINEAGE_DEPTH:
            raise ValidationError("manuscript predecessor lineage exceeds depth bound")
        replay = _replay_immutable_revision(
            registry,
            events,
            revision_artifact_hash=current_hash,
        )
        if (
            replay.revision.run_id != expected_run_id
            or replay.revision.manuscript_id != expected_manuscript_id
            or replay.revision.revision != revision_number
        ):
            raise ValidationError(
                "manuscript predecessor lineage is not exact revision n-1"
            )
        if replay.composition.candidate_id != expected_candidate_id:
            raise ValidationError("manuscript lineage cannot switch candidate identity")
        if replay.issuance_event_index >= child_event_index:
            raise ValidationError(
                "manuscript predecessor issuance is outside the child prefix"
            )
        if immediate is None:
            immediate = replay
        if revision_number == 1:
            if replay.revision.predecessor_revision_artifact_hash is not None:
                raise ValidationError(
                    "manuscript predecessor lineage does not terminate at revision one"
                )
            break
        predecessor_hash = replay.revision.predecessor_revision_artifact_hash
        if predecessor_hash is None:
            raise ValidationError("manuscript predecessor lineage has a revision gap")
        current_hash = predecessor_hash
        revision_number -= 1
        child_event_index = replay.issuance_event_index

    assert immediate is not None
    return immediate


def require_paper_manuscript_revision(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    revision_artifact_hash: str,
) -> RegisteredPaperManuscriptRevision:
    """Freshly replay one current revision and only historical predecessors."""

    return _require_paper_manuscript_revision(
        registry, ledger, revision_artifact_hash=revision_artifact_hash,
    )


def _require_paper_manuscript_revision(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    revision_artifact_hash: str,
    _round_replay: _PaperRoundReplay | None = None,
) -> RegisteredPaperManuscriptRevision:
    """Freshly replay one current revision and only historical predecessors."""

    if (
        type(registry) is not ArtifactRegistry
        or type(ledger) is not EventLedger
        or registry.policy.root != ledger.policy.root
    ):
        raise ValidationError(
            "manuscript replay requires one concrete registry/ledger root"
        )
    initial_events = ledger.validate(raise_on_error=True).events
    replay = _replay_immutable_revision(
        registry,
        initial_events,
        revision_artifact_hash=revision_artifact_hash,
    )
    revision = replay.revision
    composition = replay.composition

    candidate_record, candidate_value = _read_registry_json(
        registry,
        revision.candidate_artifact_hash,
        logical_type="paper_candidate",
        creator_role=Role.PAPER_WRITER,
    )
    _, _, bundle = _read_authoritative_bundle_artifact(
        registry,
        revision.bundle_artifact_hash,
    )
    candidate = _paper_candidate_from_json(candidate_value["candidate"])
    fresh_replay = _derive_composition_input_stably(
        registry,
        ledger,
        candidate,
        bundle,
        run_id=revision.run_id,
        manuscript_id=revision.manuscript_id,
        revision=revision.revision,
        predecessor_revision_artifact_hash=(
            revision.predecessor_revision_artifact_hash
        ),
        candidate_artifact_hash=candidate_record.sha256,
        bundle_artifact_hash=revision.bundle_artifact_hash,
        verification_artifact_hash=revision.paper_verification_artifact_hash,
        **({"_round_replay": _round_replay} if _round_replay is not None else {}),
    )
    fresh = fresh_replay.composition
    # Later unrelated appends are allowed; only the historical head/count fields
    # differ. Scientific-source supersession is rejected inside fresh derivation.
    fresh_value = fresh.to_dict()
    stored_value = composition.to_dict()
    fresh_value["historical_ledger_head_hash"] = stored_value[
        "historical_ledger_head_hash"
    ]
    fresh_value["historical_ledger_event_count"] = stored_value[
        "historical_ledger_event_count"
    ]
    if fresh_value != stored_value:
        raise ValidationError("composition input differs from fresh authority replay")

    # Replay the target and its complete predecessor chain against the exact
    # stable ledger snapshot captured with the fresh scientific authorities.
    # Old sources need not remain current, but every immutable byte and issuance
    # event must still replay inside that captured prefix.
    final_events = fresh_replay.ledger_snapshot.events
    replay = _replay_immutable_revision(
        registry,
        final_events,
        revision_artifact_hash=revision_artifact_hash,
    )
    if revision.predecessor_revision_artifact_hash is not None:
        _require_historical_predecessor_lineage(
            registry,
            final_events,
            predecessor_revision_artifact_hash=(
                revision.predecessor_revision_artifact_hash
            ),
            expected_run_id=revision.run_id,
            expected_manuscript_id=revision.manuscript_id,
            expected_revision=revision.revision - 1,
            expected_candidate_id=composition.candidate_id,
            before_event_index=replay.issuance_event_index,
        )

    # Make this co-locked equality check the last mutable-state read before
    # returning. A correction or registry admission during immutable replay
    # therefore invalidates the result instead of creating a mixed-era view.
    final_registry, final_ledger = _locked_paper_authority_snapshot(
        registry,
        ledger,
    )
    if (
        final_registry != fresh_replay.registry_snapshot
        or final_ledger != fresh_replay.ledger_snapshot
    ):
        raise ValidationError(
            "paper authority changed after fresh composition replay; retry"
        )
    return RegisteredPaperManuscriptRevision(
        replay.revision_record,
        replay.revision,
        replay.composition_input_record,
        replay.content_record,
        replay.composition_verification_record,
        replay.content_bytes,
        replay.source_map,
        replay.issuance_event,
    )


def register_paper_manuscript_revision(
    registry: ArtifactRegistry, ledger: EventLedger, candidate: PaperCandidate,
    bundle: AuthoritativeResearchBundle, *, run_id: str, manuscript_id: str,
    revision: int, candidate_artifact_hash: str, bundle_artifact_hash: str,
    verification_artifact_hash: str, predecessor_revision_artifact_hash: str | None = None,
) -> RegisteredPaperManuscriptRevision:
    """Atomically admit one deterministic manuscript revision checkpoint."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger or registry.policy.root != ledger.policy.root:
        raise ValidationError("manuscript registration requires one concrete registry/ledger root")
    if not isinstance(candidate, PaperCandidate) or not isinstance(
        bundle, AuthoritativeResearchBundle
    ):
        raise ValidationError("manuscript registration requires typed paper authority")
    validate_identifier(manuscript_id, "manuscript ID")
    try:
        _resolve_candidate_bundle_artifacts(
            registry,
            candidate,
            bundle,
            candidate_artifact_hash,
            bundle_artifact_hash,
        )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(
            "manuscript registration paper authority is absent or malformed"
        ) from exc
    # Completed identity is idempotent and still undergoes full fresh replay.
    orphan_identity_records: list[ArtifactRecord] = []
    completed_identity_records: list[RegisteredPaperManuscriptRevision] = []
    initial_identity_hashes: set[str] = set()
    ledger_snapshot = ledger.validate(raise_on_error=True)
    for candidate_record in registry.list_records():
        if candidate_record.logical_type != "paper_manuscript_revision":
            continue
        try:
            _, existing = _read_revision_record(registry, candidate_record.sha256)
        except Exception:
            continue
        if existing.manuscript_id == manuscript_id and existing.revision == revision:
            initial_identity_hashes.add(candidate_record.sha256)
            try:
                completed = require_paper_manuscript_revision(registry, ledger, revision_artifact_hash=candidate_record.sha256)
            except ValidationError:
                event_id = f"pmr-{candidate_record.sha256[:48]}"
                if any(
                    event.event_id == event_id
                    or candidate_record.sha256 in event.artifact_hashes
                    for event in ledger_snapshot.events
                ):
                    raise
                orphan_identity_records.append(candidate_record)
                continue
            requested = (run_id, predecessor_revision_artifact_hash, candidate_artifact_hash, bundle_artifact_hash, verification_artifact_hash)
            observed = (existing.run_id, existing.predecessor_revision_artifact_hash, existing.candidate_artifact_hash, existing.bundle_artifact_hash, existing.paper_verification_artifact_hash)
            if requested != observed:
                raise ValidationError("manuscript revision identity collides")
            completed_identity_records.append(completed)
    if len(completed_identity_records) > 1:
        raise ValidationError("manuscript revision identity has multiple admitted roots")
    if completed_identity_records:
        return completed_identity_records[0]
    if len(orphan_identity_records) > 1:
        raise ValidationError("manuscript revision identity has ambiguous inert orphans")
    if (revision == 1) != (predecessor_revision_artifact_hash is None):
        raise ValidationError("revision one has no predecessor and later revisions require one")
    if predecessor_revision_artifact_hash is not None:
        predecessor_events = ledger.validate(raise_on_error=True).events
        _require_historical_predecessor_lineage(
            registry,
            predecessor_events,
            predecessor_revision_artifact_hash=(
                predecessor_revision_artifact_hash
            ),
            expected_run_id=run_id,
            expected_manuscript_id=manuscript_id,
            expected_revision=revision - 1,
            expected_candidate_id=candidate.candidate_id,
            before_event_index=len(predecessor_events),
        )
    fresh_replay = _derive_composition_input_stably(
        registry,
        ledger,
        candidate,
        bundle,
        run_id=run_id,
        manuscript_id=manuscript_id,
        revision=revision,
        predecessor_revision_artifact_hash=predecessor_revision_artifact_hash,
        candidate_artifact_hash=candidate_artifact_hash,
        bundle_artifact_hash=bundle_artifact_hash,
        verification_artifact_hash=verification_artifact_hash,
    )
    composition = fresh_replay.composition
    rendered = render_paper_composition(composition)
    input_bytes = canonical_json_bytes(composition.to_dict()) + b"\n"
    created_at = utc_now()
    input_parents = tuple(dict.fromkeys((candidate_artifact_hash, bundle_artifact_hash, verification_artifact_hash, bundle.soundness_assessment_hash, *((predecessor_revision_artifact_hash,) if predecessor_revision_artifact_hash else ()))))
    input_record = _record_for_bytes(registry, input_bytes, logical_type="paper_composition_input", schema_version="1.0", mime_type="application/json", origin="canonical source-owned paper composition input", creator_role=Role.PAPER_WRITER, creation_command=("scientist-one", "paper", "derive-composition-input"), parents=input_parents, created_at=created_at)
    content_record = _record_for_bytes(registry, rendered.content_bytes, logical_type="paper_manuscript_content", schema_version="1.0", mime_type="text/markdown", origin="deterministic evidence-only manuscript content", creator_role=Role.PAPER_WRITER, creation_command=("scientist-one", "paper", "render-manuscript"), parents=(candidate_artifact_hash, bundle_artifact_hash), created_at=created_at)
    verification_value = {"schema_version": COMPOSITION_VERIFICATION_SCHEMA, "renderer_version": RENDERER_VERSION, "composition_input_artifact_hash": input_record.sha256, "content_artifact_hash": content_record.sha256, "content_sha256": sha256_bytes(rendered.content_bytes), "source_map": [item.to_dict() for item in rendered.source_map], "passed": True}
    verification_bytes = canonical_json_bytes(verification_value) + b"\n"
    composition_verification_record = _record_for_bytes(registry, verification_bytes, logical_type="paper_composition_verification", schema_version="1.0", mime_type="application/json", origin="byte-exact deterministic manuscript replay verification", creator_role=Role.SCIENTIFIC_REVIEWER, creation_command=("scientist-one", "paper", "verify-composition"), parents=(input_record.sha256, content_record.sha256), created_at=created_at)
    resolved = tuple(item["finding_artifact_hash"] for item in composition.findings if item["status"] == ChallengeStatus.RESOLVED.value)
    unresolved = tuple(item["finding_artifact_hash"] for item in composition.findings if item["status"] == ChallengeStatus.UNRESOLVED.value)
    revision_value = PaperManuscriptRevision(run_id, manuscript_id, revision, predecessor_revision_artifact_hash, input_record.sha256, content_record.sha256, composition_verification_record.sha256, candidate_artifact_hash, bundle_artifact_hash, verification_artifact_hash, resolved, unresolved)
    revision_bytes = canonical_json_bytes(revision_value.to_dict()) + b"\n"
    revision_parents = tuple(dict.fromkeys((input_record.sha256, content_record.sha256, composition_verification_record.sha256, candidate_artifact_hash, bundle_artifact_hash, verification_artifact_hash, *((predecessor_revision_artifact_hash,) if predecessor_revision_artifact_hash else ()))))
    if max(len(input_parents), len(revision_parents)) > MAX_ARTIFACT_PARENTS:
        raise ValidationError("manuscript revision exceeds artifact parent capacity")
    revision_record = _record_for_bytes(registry, revision_bytes, logical_type="paper_manuscript_revision", schema_version="1.0", mime_type="application/json", origin="issued deterministic evidence-only manuscript revision", creator_role=Role.PAPER_WRITER, creation_command=("scientist-one", "paper", "issue-manuscript-revision"), parents=revision_parents, created_at=created_at)
    if orphan_identity_records and orphan_identity_records[0].sha256 != revision_record.sha256:
        raise ValidationError("manuscript revision identity collides with a different inert orphan")
    records = (input_record, content_record, composition_verification_record, revision_record)
    registry_result = registry.verify_all(raise_on_error=True)
    _require_revision_identity_namespace_unchanged(
        registry,
        registry_result.records,
        manuscript_id=manuscript_id,
        revision=revision,
        initial_identity_hashes=frozenset(initial_identity_hashes),
    )
    ledger_result = ledger.validate(raise_on_error=True)
    if (
        registry_result != fresh_replay.registry_snapshot
        or ledger_result != fresh_replay.ledger_snapshot
    ):
        raise ValidationError(
            "paper authority changed after fresh composition replay; retry"
        )
    if ledger_result.head_hash != composition.historical_ledger_head_hash or ledger_result.event_count != composition.historical_ledger_event_count or not ledger_result.events:
        raise ValidationError("paper authority changed before manuscript preflight")
    if predecessor_revision_artifact_hash is not None:
        _require_historical_predecessor_lineage(
            registry,
            ledger_result.events,
            predecessor_revision_artifact_hash=(
                predecessor_revision_artifact_hash
            ),
            expected_run_id=run_id,
            expected_manuscript_id=manuscript_id,
            expected_revision=revision - 1,
            expected_candidate_id=candidate.candidate_id,
            before_event_index=ledger_result.event_count,
        )
    new_count = sum(not any(item.sha256 == record.sha256 for item in registry_result.records) for record in records)
    if registry_result.count + new_count > MAX_REGISTRY_RECORDS:
        raise ValidationError("manuscript revision exceeds registry capacity")
    prior = ledger_result.events[-1]
    event = LedgerEvent.create(run_id=run_id, actor_role=Role.PAPER_WRITER, state_before=prior.requested_state_after, requested_state_after=prior.requested_state_after, artifact_hashes=(revision_record.sha256,), code_version=str(composition.research_state_binding["code_version"]), configuration_hash=str(composition.research_state_binding["configuration_hash"]), reason="issued deterministic evidence-only manuscript revision", prior_event_hash=ledger_result.head_hash, event_id=f"pmr-{revision_record.sha256[:48]}", timestamp=revision_record.created_at, event_type="CHECKPOINT", metadata=_revision_event_metadata(records, revision_value, composition))
    line = canonical_json_bytes(event.to_dict()) + b"\n"
    if ledger_result.event_count + 1 > MAX_LEDGER_EVENTS or ledger_result.valid_prefix_bytes + len(line) > MAX_LEDGER_BYTES:
        raise ValidationError("manuscript revision exceeds ledger capacity")
    _validate_revision_timestamp(revision_record, ledger_result.events)
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            locked_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if locked_registry != registry_result or locked_ledger != ledger_result:
                raise ValidationError("paper authority changed before manuscript issuance")
            actual: list[ArtifactRecord] = []
            for expected, data in zip(records, (input_bytes, rendered.content_bytes, verification_bytes, revision_bytes), strict=True):
                actual_record = registry._put_bytes_locked(registry_guard, data, logical_type=expected.logical_type, origin=expected.origin, creator_role=expected.creator_role, creation_command=expected.creation_command, parent_artifacts=expected.parent_artifacts, schema_version=expected.schema_version, mime_type=expected.mime_type, validation_result="PASS", frozen=True, created_at=expected.created_at)
                if actual_record != expected:
                    raise ValidationError("composition artifact changed during issuance")
                actual.append(actual_record)
            appended = ledger._append_locked(ledger_guard, lambda current: event if current == locked_ledger else (_ for _ in ()).throw(ValidationError("ledger changed during manuscript issuance")))
            if appended != event:
                raise ValidationError("manuscript issuance event changed")
            registry._verify_mutation_namespace(registry_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return require_paper_manuscript_revision(registry, ledger, revision_artifact_hash=revision_record.sha256)


__all__ = [
    "CompositionSourceMapEntry", "PaperCompositionInput", "PaperCompositionRender",
    "PaperManuscriptRevision", "RegisteredPaperManuscriptRevision",
    "register_paper_manuscript_revision", "render_paper_composition",
    "require_paper_manuscript_revision",
]
