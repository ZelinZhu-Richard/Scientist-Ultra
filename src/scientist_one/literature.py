"""Provider-neutral scholarly normalization and reference verification.

This module deliberately owns no network primitive.  Scholarly adapters build
typed requests and consume responses captured by an injected gateway.  All
external strings remain untrusted evidence; adapters normalize data but never
interpret it as executable authority.

Reference verification is deliberately monotone and conservative:

``LEVEL_0`` reference text exists
``LEVEL_1`` the identifier resolves to a normalized scholarly record
``LEVEL_2`` the expected identifier and bibliography metadata match
``LEVEL_3`` an exact section/passage locator structurally resolves for a claim
            (this level does not imply semantic support)
``LEVEL_4`` a judgment bound to that exact claim and passage supports the claim
``LEVEL_5`` a second bound judgment finds no contradiction in surrounding text

Metadata resolution alone therefore never establishes semantic support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import hashlib
import json
import math
import re
import unicodedata
from types import MappingProxyType
from typing import Any, ClassVar, Mapping, Protocol, Sequence, final, runtime_checkable

from .artifacts import MAX_ARTIFACT_PARENTS


class LiteratureError(ValueError):
    """Base failure for malformed scholarly data or verification inputs."""


class IdentifierNormalizationError(LiteratureError):
    """A scholarly identifier cannot be normalized without guessing."""


class ScholarlySource(str, Enum):
    OPENALEX = "openalex"
    SEMANTIC_SCHOLAR = "semantic_scholar"
    CROSSREF = "crossref"
    ARXIV = "arxiv"
    PUBMED = "pubmed"
    PMC = "pmc"
    MERGED = "merged"


class ScholarlyRole(str, Enum):
    DISCOVERY = "discovery"
    CITATION_GRAPH = "citation_graph"
    METADATA = "metadata"
    DOI_VALIDATION = "doi_validation"
    PREPRINT = "preprint"
    BIOMEDICAL = "biomedical"
    FULL_TEXT = "full_text"


class IdentifierKind(str, Enum):
    DOI = "doi"
    OPENALEX = "openalex"
    SEMANTIC_SCHOLAR = "semantic_scholar"
    ARXIV = "arxiv"
    PMID = "pmid"
    PMCID = "pmcid"


class RetrievalStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    LICENSE_RESTRICTED = "LICENSE_RESTRICTED"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    MALFORMED = "MALFORMED"


class FullTextStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    METADATA_ONLY = "METADATA_ONLY"
    UNAVAILABLE = "UNAVAILABLE"
    LICENSE_RESTRICTED = "LICENSE_RESTRICTED"


class VerificationLevel(IntEnum):
    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5


class CitationTraversal(str, Enum):
    """Direction requested from a scholarly citation-graph adapter."""

    REFERENCES = "REFERENCES"
    CITED_BY = "CITED_BY"


class CitationExecutionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL_PERSISTENCE_BUDGET = "PARTIAL_PERSISTENCE_BUDGET"
    PARTIAL_PAGE_BUDGET = "PARTIAL_PAGE_BUDGET"
    PARTIAL_GRAPH_BUDGET = "PARTIAL_GRAPH_BUDGET"
    PARTIAL_TASK_LIMIT = "PARTIAL_TASK_LIMIT"
    PARTIAL_EVIDENCE_ANOMALY = "PARTIAL_EVIDENCE_ANOMALY"
    COMPLETED_WITH_FAILURES = "COMPLETED_WITH_FAILURES"


class CitationTruncationReason(str, Enum):
    GRAPH_BUDGET = "GRAPH_BUDGET"
    PERSISTENCE_PARENT_BUDGET = "PERSISTENCE_PARENT_BUDGET"
    PAGE_LIMIT = "PAGE_LIMIT"
    CURSOR_CYCLE = "CURSOR_CYCLE"
    GRAPH_CONFLICT = "GRAPH_CONFLICT"


class SourceFitnessTier(str, Enum):
    """Operational fitness of a captured source, not a truth/quality judgment."""

    FULL_TEXT_CAPTURED = "FULL_TEXT_CAPTURED"
    METADATA_CAPTURED = "METADATA_CAPTURED"
    CONFLICTED_METADATA = "CONFLICTED_METADATA"


class EvidenceSupportTier(str, Enum):
    """Claim-support depth kept distinct from source retrieval fitness."""

    CONTEXT_CHECKED_SUPPORT = "CONTEXT_CHECKED_SUPPORT"
    PASSAGE_SUPPORT = "PASSAGE_SUPPORT"
    PASSAGE_LOCATED = "PASSAGE_LOCATED"
    METADATA_MATCHED = "METADATA_MATCHED"
    RESOLVED_WORK = "RESOLVED_WORK"
    CAPTURED_RECORD_ONLY = "CAPTURED_RECORD_ONLY"


class GeneralWebPurpose(str, Enum):
    """Narrow purposes for which a policy may permit general-web evidence."""

    SOFTWARE_ARTIFACT = "SOFTWARE_ARTIFACT"
    DATASET_DOCUMENTATION = "DATASET_DOCUMENTATION"
    STANDARD_OR_POLICY = "STANDARD_OR_POLICY"
    GREY_LITERATURE = "GREY_LITERATURE"


class GeneralWebFallbackStatus(str, Enum):
    SCHOLARLY_EVIDENCE_SUFFICIENT = "SCHOLARLY_EVIDENCE_SUFFICIENT"
    MORE_SCHOLARLY_SEARCH_REQUIRED = "MORE_SCHOLARLY_SEARCH_REQUIRED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    ALLOWED_AFTER_SCHOLARLY_INSUFFICIENCY = (
        "ALLOWED_AFTER_SCHOLARLY_INSUFFICIENCY"
    )


class ScholarlySearchPurpose(str, Enum):
    """Scientific purpose of an explicit, target-bound scholarly search."""

    SEED = "SEED"
    DISCONFIRMING = "DISCONFIRMING"


class ScholarlySearchSelectionPolicy(str, Enum):
    """Deterministic rule used to turn captured hits into resolution work."""

    ALL_CAPTURED_HITS = "ALL_CAPTURED_HITS"


_DOI_RE = re.compile(r"^10\.\d{4,9}/\S+$", re.IGNORECASE)
_OPENALEX_RE = re.compile(r"^W\d+$", re.IGNORECASE)
_S2_RE = re.compile(r"^[A-Za-z0-9_-]{3,128}$")
_ARXIV_RE = re.compile(
    r"^(?:\d{4}\.\d{4,5}|[a-z][a-z0-9.-]+/\d{7})(?:v\d+)?$",
    re.IGNORECASE,
)
_PMID_RE = re.compile(r"^\d+$")
_PMCID_RE = re.compile(r"^PMC\d+$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 1_048_576
_MAX_JSON_DEPTH = 32
_MAX_JSON_ITEMS = 20_000


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _require_hash(value: str | None, field_name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise LiteratureError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _require_persistable_parent_count(
    parent_artifact_hashes: Sequence[str],
    label: str,
    *,
    reserved_parent_slots: int = 0,
) -> None:
    """Keep persisted-ready literature objects within registry fan-in bounds."""

    if (
        len(set(parent_artifact_hashes)) + reserved_parent_slots
        > MAX_ARTIFACT_PARENTS
    ):
        raise LiteratureError(
            f"{label} provenance exceeds the artifact-registry parent bound"
        )


def _valid_custody_hash(value: object) -> str | None:
    """Return a syntactically valid custody hash without trusting its container."""

    return value if isinstance(value, str) and _SHA256_RE.fullmatch(value) else None


def _captured_custody_hash(captured: object, field_name: str) -> str | None:
    """Salvage a valid gateway-owned hash even when the envelope is malformed."""

    try:
        value = getattr(captured, field_name)
    except Exception:
        return None
    return _valid_custody_hash(value)


def _clean_text(value: Any, field_name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise LiteratureError(f"{field_name} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized and not optional:
        raise LiteratureError(f"{field_name} cannot be empty")
    if len(normalized) > _MAX_TEXT:
        raise LiteratureError(f"{field_name} exceeds the text bound")
    return normalized or None


def _match_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _freeze_json(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > _MAX_JSON_ITEMS:
        raise LiteratureError("gateway payload exceeds the item bound")
    if depth > _MAX_JSON_DEPTH:
        raise LiteratureError("gateway payload exceeds the depth bound")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > _MAX_TEXT:
            raise LiteratureError("gateway payload string exceeds the text bound")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LiteratureError("gateway payload contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or not key for key in value):
            raise LiteratureError("gateway payload keys must be non-empty strings")
        return MappingProxyType(
            {
                key: _freeze_json(child, depth=depth + 1, budget=budget)
                for key, child in value.items()
            }
        )
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(child, depth=depth + 1, budget=budget) for child in value
        )
    raise LiteratureError("gateway payload is not JSON-safe")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def normalize_identifier(kind: IdentifierKind | str, value: str) -> str:
    """Normalize an identifier without resolving it or repairing ambiguity."""

    try:
        normalized_kind = kind if isinstance(kind, IdentifierKind) else IdentifierKind(kind)
    except (TypeError, ValueError) as exc:
        raise IdentifierNormalizationError("unknown scholarly identifier kind") from exc
    raw = _clean_text(value, "identifier")
    assert raw is not None

    if normalized_kind is IdentifierKind.DOI:
        candidate = re.sub(
            r"^(?:doi:\s*|https?://(?:dx\.)?doi\.org/)",
            "",
            raw,
            flags=re.IGNORECASE,
        ).strip()
        candidate = candidate.strip("<>").rstrip(".,;").casefold()
        if _DOI_RE.fullmatch(candidate) is None or any(char.isspace() for char in candidate):
            raise IdentifierNormalizationError("invalid DOI")
        return candidate
    if normalized_kind is IdentifierKind.OPENALEX:
        candidate = re.sub(
            r"^https?://(?:api\.)?openalex\.org/",
            "",
            raw,
            flags=re.IGNORECASE,
        ).upper()
        if _OPENALEX_RE.fullmatch(candidate) is None:
            raise IdentifierNormalizationError("invalid OpenAlex work identifier")
        return candidate
    if normalized_kind is IdentifierKind.SEMANTIC_SCHOLAR:
        candidate = re.sub(
            r"^https?://(?:www\.)?semanticscholar\.org/paper/",
            "",
            raw,
            flags=re.IGNORECASE,
        ).strip("/").casefold()
        if _S2_RE.fullmatch(candidate) is None:
            raise IdentifierNormalizationError("invalid Semantic Scholar paper identifier")
        return candidate
    if normalized_kind is IdentifierKind.ARXIV:
        candidate = re.sub(
            r"^(?:arxiv:\s*|https?://arxiv\.org/(?:abs|pdf)/)",
            "",
            raw,
            flags=re.IGNORECASE,
        )
        candidate = re.sub(r"\.pdf$", "", candidate, flags=re.IGNORECASE).strip("/").casefold()
        if _ARXIV_RE.fullmatch(candidate) is None:
            raise IdentifierNormalizationError("invalid arXiv identifier")
        return candidate
    if normalized_kind is IdentifierKind.PMID:
        candidate = re.sub(r"^(?:pmid:\s*|https?://pubmed\.ncbi\.nlm\.nih\.gov/)", "", raw, flags=re.IGNORECASE).strip("/")
        if _PMID_RE.fullmatch(candidate) is None:
            raise IdentifierNormalizationError("invalid PubMed identifier")
        return candidate
    candidate = re.sub(
        r"^(?:pmcid:\s*|https?://(?:www\.)?ncbi\.nlm\.nih\.gov/pmc/articles/)",
        "",
        raw,
        flags=re.IGNORECASE,
    ).strip("/").upper()
    if candidate.isdigit():
        candidate = "PMC" + candidate
    if _PMCID_RE.fullmatch(candidate) is None:
        raise IdentifierNormalizationError("invalid PMC identifier")
    return candidate


@dataclass(frozen=True, slots=True, order=True)
class ScholarlyIdentifier:
    kind: IdentifierKind
    value: str

    def __post_init__(self) -> None:
        try:
            kind = self.kind if isinstance(self.kind, IdentifierKind) else IdentifierKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise IdentifierNormalizationError("unknown scholarly identifier kind") from exc
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "value", normalize_identifier(kind, self.value))

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "value": self.value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlyIdentifier:
        _exact_keys(value, frozenset({"kind", "value"}), "scholarly identifier")
        return cls(value["kind"], value["value"])


@dataclass(frozen=True, slots=True)
class ScholarlyRequest:
    source: ScholarlySource
    operation: str
    identifier: ScholarlyIdentifier
    request_id: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("unknown scholarly source") from exc
        if source is ScholarlySource.MERGED:
            raise LiteratureError("merged records are not an external source")
        operation = _clean_text(self.operation, "operation")
        if not isinstance(self.identifier, ScholarlyIdentifier):
            raise LiteratureError("request identifier must be ScholarlyIdentifier")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(
            self,
            "request_id",
            _sha256(
                _canonical_json(
                    {
                        "source": source.value,
                        "operation": operation,
                        "identifier_kind": self.identifier.kind.value,
                        "identifier": self.identifier.value,
                    }
                )
            ),
        )


@dataclass(frozen=True, slots=True, order=True)
class ScholarlySearchFilter:
    """One exact provider-neutral search constraint."""

    name: str
    value: str

    def __post_init__(self) -> None:
        name = _clean_text(self.name, "scholarly search filter name")
        value = _clean_text(self.value, "scholarly search filter value")
        assert name is not None and value is not None
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "value", value)

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchFilter:
        _exact_keys(
            value,
            frozenset({"name", "value"}),
            "scholarly search filter",
        )
        return cls(name=value["name"], value=value["value"])


@dataclass(frozen=True, slots=True)
class ScholarlySearchPlan:
    """Immutable search intent bound to one goal and one scientific target."""

    purpose: ScholarlySearchPurpose
    goal_id: str
    goal_sha256: str
    target_sha256: str
    query: str
    synonyms: tuple[str, ...]
    filters: tuple[ScholarlySearchFilter, ...]
    allowed_sources: tuple[ScholarlySource, ...]
    max_results: int
    parent_artifact_hashes: tuple[str, ...]
    schema_version: str = "scholarly-search-plan/v1"

    def __post_init__(self) -> None:
        try:
            purpose = (
                self.purpose
                if isinstance(self.purpose, ScholarlySearchPurpose)
                else ScholarlySearchPurpose(self.purpose)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search purpose is invalid") from exc
        goal_id = _clean_text(self.goal_id, "scholarly search goal_id")
        query = _clean_text(self.query, "scholarly search query")
        assert goal_id is not None and query is not None
        _require_hash(self.goal_sha256, "scholarly search goal_sha256")
        _require_hash(self.target_sha256, "scholarly search target_sha256")
        if not isinstance(self.synonyms, tuple):
            raise LiteratureError("scholarly search synonyms must be a tuple")
        synonyms = tuple(
            _clean_text(value, "scholarly search synonym") for value in self.synonyms
        )
        if any(value is None for value in synonyms):
            raise LiteratureError("scholarly search synonym cannot be empty")
        normalized_synonyms = tuple(value for value in synonyms if value is not None)
        if len(set(normalized_synonyms)) != len(normalized_synonyms):
            raise LiteratureError("scholarly search synonyms must be unique")
        if not isinstance(self.filters, tuple) or not all(
            isinstance(value, ScholarlySearchFilter) for value in self.filters
        ):
            raise LiteratureError("scholarly search filters are malformed")
        filters = tuple(sorted(self.filters))
        if len(set(filters)) != len(filters):
            raise LiteratureError("scholarly search filters must be unique")
        if not isinstance(self.allowed_sources, tuple) or not self.allowed_sources:
            raise LiteratureError("scholarly search requires allowed sources")
        try:
            sources = tuple(
                value
                if isinstance(value, ScholarlySource)
                else ScholarlySource(value)
                for value in self.allowed_sources
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search source policy is invalid") from exc
        if ScholarlySource.MERGED in sources or len(set(sources)) != len(sources):
            raise LiteratureError("scholarly search sources must be unique external sources")
        sources = tuple(sorted(sources, key=lambda value: value.value))
        if (
            isinstance(self.max_results, bool)
            or not isinstance(self.max_results, int)
            or not 1 <= self.max_results <= 512
        ):
            raise LiteratureError("scholarly search max_results must be an integer in [1, 512]")
        if not isinstance(self.parent_artifact_hashes, tuple) or not self.parent_artifact_hashes:
            raise LiteratureError("scholarly search plan requires artifact provenance")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        if len(parents) != len(self.parent_artifact_hashes):
            raise LiteratureError("scholarly search plan parents must be unique")
        for value in parents:
            _require_hash(value, "scholarly search plan parent_artifact_hash")
        _require_persistable_parent_count(parents, "scholarly search plan")
        if self.schema_version != "scholarly-search-plan/v1":
            raise LiteratureError("unsupported scholarly search plan schema")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "goal_id", goal_id)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "synonyms", normalized_synonyms)
        object.__setattr__(self, "filters", filters)
        object.__setattr__(self, "allowed_sources", sources)
        object.__setattr__(self, "parent_artifact_hashes", parents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "purpose": self.purpose.value,
            "goal_id": self.goal_id,
            "goal_sha256": self.goal_sha256,
            "target_sha256": self.target_sha256,
            "query": self.query,
            "synonyms": list(self.synonyms),
            "filters": [value.to_dict() for value in self.filters],
            "allowed_sources": [value.value for value in self.allowed_sources],
            "max_results": self.max_results,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchPlan:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "purpose",
                    "goal_id",
                    "goal_sha256",
                    "target_sha256",
                    "query",
                    "synonyms",
                    "filters",
                    "allowed_sources",
                    "max_results",
                    "parent_artifact_hashes",
                }
            ),
            "scholarly search plan",
        )
        for name in ("synonyms", "filters", "allowed_sources", "parent_artifact_hashes"):
            if not isinstance(value[name], (list, tuple)):
                raise LiteratureError(f"scholarly search plan {name} must be a list")
        return cls(
            purpose=value["purpose"],
            goal_id=value["goal_id"],
            goal_sha256=value["goal_sha256"],
            target_sha256=value["target_sha256"],
            query=value["query"],
            synonyms=tuple(value["synonyms"]),
            filters=tuple(
                ScholarlySearchFilter.from_dict(item) for item in value["filters"]
            ),
            allowed_sources=tuple(value["allowed_sources"]),
            max_results=value["max_results"],
            parent_artifact_hashes=tuple(value["parent_artifact_hashes"]),
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class ScholarlySearchRequest:
    """One deterministic provider request derived from a search plan."""

    plan_sha256: str
    purpose: ScholarlySearchPurpose
    goal_sha256: str
    target_sha256: str
    source: ScholarlySource
    query: str
    synonyms: tuple[str, ...]
    filters: tuple[ScholarlySearchFilter, ...]
    max_results: int
    request_id: str = field(init=False)
    schema_version: str = "scholarly-search-request/v1"

    def __post_init__(self) -> None:
        _require_hash(self.plan_sha256, "scholarly search request plan_sha256")
        _require_hash(self.goal_sha256, "scholarly search request goal_sha256")
        _require_hash(self.target_sha256, "scholarly search request target_sha256")
        try:
            purpose = (
                self.purpose
                if isinstance(self.purpose, ScholarlySearchPurpose)
                else ScholarlySearchPurpose(self.purpose)
            )
            source = (
                self.source
                if isinstance(self.source, ScholarlySource)
                else ScholarlySource(self.source)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search request enum is invalid") from exc
        if source is ScholarlySource.MERGED:
            raise LiteratureError("merged records cannot be searched externally")
        query = _clean_text(self.query, "scholarly search request query")
        assert query is not None
        if not isinstance(self.synonyms, tuple):
            raise LiteratureError("scholarly search request synonyms must be a tuple")
        synonyms = tuple(
            _clean_text(value, "scholarly search request synonym")
            for value in self.synonyms
        )
        if any(value is None for value in synonyms) or len(set(synonyms)) != len(synonyms):
            raise LiteratureError("scholarly search request synonyms are malformed")
        if not isinstance(self.filters, tuple) or not all(
            isinstance(value, ScholarlySearchFilter) for value in self.filters
        ):
            raise LiteratureError("scholarly search request filters are malformed")
        filters = tuple(sorted(self.filters))
        if len(set(filters)) != len(filters):
            raise LiteratureError("scholarly search request filters must be unique")
        if (
            isinstance(self.max_results, bool)
            or not isinstance(self.max_results, int)
            or not 1 <= self.max_results <= 512
        ):
            raise LiteratureError("scholarly search request max_results is invalid")
        if self.schema_version != "scholarly-search-request/v1":
            raise LiteratureError("unsupported scholarly search request schema")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "query", query)
        object.__setattr__(self, "synonyms", tuple(value for value in synonyms if value is not None))
        object.__setattr__(self, "filters", filters)
        object.__setattr__(
            self,
            "request_id",
            _sha256(
                _canonical_json(
                    {
                        "schema_version": self.schema_version,
                        "plan_sha256": self.plan_sha256,
                        "purpose": purpose.value,
                        "goal_sha256": self.goal_sha256,
                        "target_sha256": self.target_sha256,
                        "source": source.value,
                        "query": query,
                        "synonyms": list(self.synonyms),
                        "filters": [value.to_dict() for value in filters],
                        "max_results": self.max_results,
                    }
                )
            ),
        )

    @classmethod
    def from_plan(
        cls,
        plan: ScholarlySearchPlan,
        source: ScholarlySource,
    ) -> ScholarlySearchRequest:
        if not isinstance(plan, ScholarlySearchPlan):
            raise LiteratureError("scholarly search request requires a typed plan")
        normalized_source = (
            source if isinstance(source, ScholarlySource) else ScholarlySource(source)
        )
        if normalized_source not in plan.allowed_sources:
            raise LiteratureError("scholarly search request violates its source policy")
        return cls(
            plan_sha256=plan.sha256,
            purpose=plan.purpose,
            goal_sha256=plan.goal_sha256,
            target_sha256=plan.target_sha256,
            source=normalized_source,
            query=plan.query,
            synonyms=plan.synonyms,
            filters=plan.filters,
            max_results=plan.max_results,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "plan_sha256": self.plan_sha256,
            "purpose": self.purpose.value,
            "goal_sha256": self.goal_sha256,
            "target_sha256": self.target_sha256,
            "source": self.source.value,
            "query": self.query,
            "synonyms": list(self.synonyms),
            "filters": [value.to_dict() for value in self.filters],
            "max_results": self.max_results,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchRequest:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "request_id",
                    "plan_sha256",
                    "purpose",
                    "goal_sha256",
                    "target_sha256",
                    "source",
                    "query",
                    "synonyms",
                    "filters",
                    "max_results",
                }
            ),
            "scholarly search request",
        )
        if not isinstance(value["synonyms"], (list, tuple)) or not isinstance(
            value["filters"], (list, tuple)
        ):
            raise LiteratureError("scholarly search request collections must be lists")
        request = cls(
            plan_sha256=value["plan_sha256"],
            purpose=value["purpose"],
            goal_sha256=value["goal_sha256"],
            target_sha256=value["target_sha256"],
            source=value["source"],
            query=value["query"],
            synonyms=tuple(value["synonyms"]),
            filters=tuple(
                ScholarlySearchFilter.from_dict(item) for item in value["filters"]
            ),
            max_results=value["max_results"],
            schema_version=value["schema_version"],
        )
        if request.request_id != value["request_id"]:
            raise LiteratureError("scholarly search request identity was tampered")
        return request


@dataclass(frozen=True, slots=True)
class ScholarlySearchHit:
    """Normalized identifier hit; still untrusted, non-scientific evidence."""

    source: ScholarlySource
    identifier: ScholarlyIdentifier
    title: str
    rank: int
    hit_id: str = field(init=False)
    schema_version: str = "scholarly-search-hit/v1"

    def __post_init__(self) -> None:
        try:
            source = (
                self.source
                if isinstance(self.source, ScholarlySource)
                else ScholarlySource(self.source)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search hit source is invalid") from exc
        if source is ScholarlySource.MERGED:
            raise LiteratureError("scholarly search hit cannot use merged source")
        if not isinstance(self.identifier, ScholarlyIdentifier):
            raise LiteratureError("scholarly search hit identifier is malformed")
        title = _clean_text(self.title, "scholarly search hit title")
        assert title is not None
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or self.rank <= 0:
            raise LiteratureError("scholarly search hit rank must be a positive integer")
        if self.schema_version != "scholarly-search-hit/v1":
            raise LiteratureError("unsupported scholarly search hit schema")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "title", title)
        object.__setattr__(
            self,
            "hit_id",
            _sha256(
                _canonical_json(
                    {
                        "schema_version": self.schema_version,
                        "source": source.value,
                        "identifier": self.identifier.to_dict(),
                        "title": title,
                        "rank": self.rank,
                    }
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "hit_id": self.hit_id,
            "source": self.source.value,
            "identifier": self.identifier.to_dict(),
            "title": self.title,
            "rank": self.rank,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchHit:
        _exact_keys(
            value,
            frozenset(
                {"schema_version", "hit_id", "source", "identifier", "title", "rank"}
            ),
            "scholarly search hit",
        )
        hit = cls(
            source=value["source"],
            identifier=ScholarlyIdentifier.from_dict(value["identifier"]),
            title=value["title"],
            rank=value["rank"],
            schema_version=value["schema_version"],
        )
        if hit.hit_id != value["hit_id"]:
            raise LiteratureError("scholarly search hit identity was tampered")
        return hit


@dataclass(frozen=True, slots=True)
class ScholarlySearchResult:
    """Bounded normalized result for one captured search request."""

    plan_sha256: str
    plan_artifact_hash: str
    request: ScholarlySearchRequest
    status: RetrievalStatus
    hits: tuple[ScholarlySearchHit, ...]
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None = None
    scientific_evidence: bool = False
    schema_version: str = "scholarly-search-result/v1"

    def __post_init__(self) -> None:
        _require_hash(self.plan_sha256, "scholarly search result plan_sha256")
        _require_hash(self.plan_artifact_hash, "scholarly search result plan_artifact_hash")
        if not isinstance(self.request, ScholarlySearchRequest):
            raise LiteratureError("scholarly search result requires a typed request")
        if self.request.plan_sha256 != self.plan_sha256:
            raise LiteratureError("scholarly search result is bound to another plan")
        try:
            status = (
                self.status
                if isinstance(self.status, RetrievalStatus)
                else RetrievalStatus(self.status)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search result status is invalid") from exc
        if not isinstance(self.hits, tuple) or not all(
            isinstance(value, ScholarlySearchHit) for value in self.hits
        ):
            raise LiteratureError("scholarly search result hits are malformed")
        hits = tuple(sorted(self.hits, key=lambda value: value.rank))
        hit_ids = tuple(value.hit_id for value in hits)
        if len(set(hit_ids)) != len(hit_ids):
            raise LiteratureError("scholarly search result contains duplicate hits")
        if tuple(value.rank for value in hits) != tuple(range(1, len(hits) + 1)):
            raise LiteratureError("scholarly search result ranks must be contiguous")
        if len(hits) > self.request.max_results:
            raise LiteratureError("scholarly search result exceeds its result bound")
        for hit in hits:
            if hit.source is not self.request.source:
                raise LiteratureError("scholarly search hit is bound to another source")
        _require_hash(self.raw_artifact_hash, "scholarly search raw_artifact_hash", optional=True)
        _require_hash(
            self.response_artifact_hash,
            "scholarly search response_artifact_hash",
            optional=True,
        )
        failure_reason = _clean_text(
            self.failure_reason,
            "scholarly search failure_reason",
            optional=True,
        )
        if status is RetrievalStatus.AVAILABLE:
            if self.raw_artifact_hash is None or self.response_artifact_hash is None:
                raise LiteratureError("available scholarly search requires captured provenance")
            if failure_reason is not None:
                raise LiteratureError("available scholarly search cannot have failure_reason")
        elif hits:
            raise LiteratureError("unavailable scholarly search cannot contain hits")
        if self.scientific_evidence is not False:
            raise LiteratureError("scholarly search results are not scientific evidence")
        if self.schema_version != "scholarly-search-result/v1":
            raise LiteratureError("unsupported scholarly search result schema")
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "scholarly search result",
        )
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "hits", hits)
        object.__setattr__(self, "failure_reason", failure_reason)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    self.plan_artifact_hash,
                    *(value for value in (
                        self.raw_artifact_hash,
                        self.response_artifact_hash,
                    ) if value is not None),
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_sha256": self.plan_sha256,
            "plan_artifact_hash": self.plan_artifact_hash,
            "request": self.request.to_dict(),
            "status": self.status.value,
            "hits": [value.to_dict() for value in self.hits],
            "raw_artifact_hash": self.raw_artifact_hash,
            "response_artifact_hash": self.response_artifact_hash,
            "failure_reason": self.failure_reason,
            "scientific_evidence": self.scientific_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchResult:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "plan_sha256",
                    "plan_artifact_hash",
                    "request",
                    "status",
                    "hits",
                    "raw_artifact_hash",
                    "response_artifact_hash",
                    "failure_reason",
                    "scientific_evidence",
                }
            ),
            "scholarly search result",
        )
        if not isinstance(value["hits"], (list, tuple)):
            raise LiteratureError("scholarly search result hits must be a list")
        return cls(
            plan_sha256=value["plan_sha256"],
            plan_artifact_hash=value["plan_artifact_hash"],
            request=ScholarlySearchRequest.from_dict(value["request"]),
            status=value["status"],
            hits=tuple(ScholarlySearchHit.from_dict(item) for item in value["hits"]),
            raw_artifact_hash=value["raw_artifact_hash"],
            response_artifact_hash=value["response_artifact_hash"],
            failure_reason=value["failure_reason"],
            scientific_evidence=value["scientific_evidence"],
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
@final
class ScholarlySearchPlanV2:
    """One immutable bounded query intent; no cursor or execution progress."""

    purpose: ScholarlySearchPurpose
    goal_id: str
    goal_sha256: str
    target_sha256: str
    query: str
    synonyms: tuple[str, ...]
    filters: tuple[ScholarlySearchFilter, ...]
    allowed_sources: tuple[ScholarlySource, ...]
    page_size: int
    max_page_requests: int
    parent_artifact_hashes: tuple[str, ...]
    schema_version: str = "scholarly-search-plan/v2"

    def __post_init__(self) -> None:
        for name, upper in (("page_size", 100), ("max_page_requests", 16)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= upper:
                raise LiteratureError(f"search v2 {name} is outside its bound")
        if self.page_size * self.max_page_requests > 512:
            raise LiteratureError("search v2 cumulative hit bound exceeds 512")
        if self.schema_version != "scholarly-search-plan/v2":
            raise LiteratureError("unsupported scholarly search v2 plan schema")
        # Reuse only the old intent-field validators, never its wire identity.
        intent = ScholarlySearchPlan(
            self.purpose, self.goal_id, self.goal_sha256, self.target_sha256,
            self.query, self.synonyms, self.filters, self.allowed_sources,
            self.page_size, self.parent_artifact_hashes,
        )
        for name in ("purpose", "goal_id", "query", "synonyms", "filters",
                     "allowed_sources", "parent_artifact_hashes"):
            object.__setattr__(self, name, getattr(intent, name))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "purpose": self.purpose.value,
            "goal_id": self.goal_id, "goal_sha256": self.goal_sha256,
            "target_sha256": self.target_sha256, "query": self.query,
            "synonyms": list(self.synonyms),
            "filters": [value.to_dict() for value in self.filters],
            "allowed_sources": [value.value for value in self.allowed_sources],
            "page_size": self.page_size, "max_page_requests": self.max_page_requests,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchPlanV2:
        _exact_keys(value, frozenset({
            "schema_version", "purpose", "goal_id", "goal_sha256", "target_sha256",
            "query", "synonyms", "filters", "allowed_sources", "page_size",
            "max_page_requests", "parent_artifact_hashes",
        }), "scholarly search v2 plan")
        for name in ("synonyms", "filters", "allowed_sources", "parent_artifact_hashes"):
            if not isinstance(value[name], (list, tuple)):
                raise LiteratureError(f"search v2 {name} must be a list")
        return cls(
            purpose=value["purpose"], goal_id=value["goal_id"],
            goal_sha256=value["goal_sha256"], target_sha256=value["target_sha256"],
            query=value["query"], synonyms=tuple(value["synonyms"]),
            filters=tuple(ScholarlySearchFilter.from_dict(item) for item in value["filters"]),
            allowed_sources=tuple(value["allowed_sources"]), page_size=value["page_size"],
            max_page_requests=value["max_page_requests"],
            parent_artifact_hashes=tuple(value["parent_artifact_hashes"]),
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def require_scholarly_search_cursor(value: object) -> str:
    """Preserve an opaque UTF-8 token exactly or reject it, never normalize it."""

    if type(value) is not str or not value:
        raise LiteratureError("search cursor must be a nonempty exact string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise LiteratureError("search cursor is not UTF-8") from exc
    if size > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise LiteratureError("search cursor exceeds its byte/control bound")
    return value


@dataclass(frozen=True, slots=True)
@final
class ScholarlySearchPageRequest:
    plan_sha256: str
    plan_artifact_hash: str
    purpose: ScholarlySearchPurpose
    goal_sha256: str
    target_sha256: str
    source: ScholarlySource
    query: str
    synonyms: tuple[str, ...]
    filters: tuple[ScholarlySearchFilter, ...]
    page_size: int
    page_number: int
    cursor: str
    previous_result_artifact_hash: str | None
    request_id: str = field(init=False)
    schema_version: str = "scholarly-search-page-request/v2"

    def __post_init__(self) -> None:
        _require_hash(self.plan_artifact_hash, "search page registered plan")
        _require_hash(self.previous_result_artifact_hash, "search page predecessor", optional=True)
        if type(self.page_size) is not int or not 1 <= self.page_size <= 100:
            raise LiteratureError("search page size is invalid")
        if type(self.page_number) is not int or not 1 <= self.page_number <= 16:
            raise LiteratureError("search page ordinal is invalid")
        require_scholarly_search_cursor(self.cursor)
        if (self.page_number == 1) != (self.previous_result_artifact_hash is None):
            raise LiteratureError("search page predecessor and ordinal disagree")
        if (self.page_number == 1) != (self.cursor == "*"):
            raise LiteratureError("search page initial cursor is inconsistent")
        if self.schema_version != "scholarly-search-page-request/v2":
            raise LiteratureError("unsupported scholarly search page schema")
        request = ScholarlySearchRequest(
            self.plan_sha256, self.purpose, self.goal_sha256, self.target_sha256,
            self.source, self.query, self.synonyms, self.filters, self.page_size,
        )
        for name in ("purpose", "source", "query", "synonyms", "filters"):
            object.__setattr__(self, name, getattr(request, name))
        object.__setattr__(self, "request_id", _sha256(_canonical_json(self._identity())))

    def _identity(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "plan_sha256": self.plan_sha256,
            "plan_artifact_hash": self.plan_artifact_hash, "purpose": self.purpose.value,
            "goal_sha256": self.goal_sha256, "target_sha256": self.target_sha256,
            "source": self.source.value, "query": self.query,
            "synonyms": list(self.synonyms), "filters": [item.to_dict() for item in self.filters],
            "page_size": self.page_size, "page_number": self.page_number,
            "cursor": self.cursor, "previous_result_artifact_hash": self.previous_result_artifact_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._identity(), "request_id": self.request_id}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchPageRequest:
        _exact_keys(value, frozenset({
            "schema_version", "plan_sha256", "plan_artifact_hash", "purpose",
            "goal_sha256", "target_sha256", "source", "query", "synonyms", "filters",
            "page_size", "page_number", "cursor", "previous_result_artifact_hash", "request_id",
        }), "scholarly search page request")
        if not isinstance(value["synonyms"], (list, tuple)) or not isinstance(value["filters"], (list, tuple)):
            raise LiteratureError("search page query collections are malformed")
        request = cls(**{key: item for key, item in value.items()
                        if key not in {"request_id", "synonyms", "filters"}},
                      synonyms=tuple(value["synonyms"]),
                      filters=tuple(ScholarlySearchFilter.from_dict(item) for item in value["filters"]))
        if request.request_id != value["request_id"]:
            raise LiteratureError("scholarly search page request identity changed")
        return request

    @classmethod
    def from_plan(cls, plan: ScholarlySearchPlanV2, *, plan_artifact_hash: str,
                  source: ScholarlySource, page_number: int, cursor: str,
                  previous_result_artifact_hash: str | None) -> ScholarlySearchPageRequest:
        if type(plan) is not ScholarlySearchPlanV2 or source not in plan.allowed_sources:
            raise LiteratureError("search page requires an exact plan and permitted source")
        if type(page_number) is not int or not 1 <= page_number <= plan.max_page_requests:
            raise LiteratureError("search page exceeds the frozen page budget")
        return cls(plan.sha256, plan_artifact_hash, plan.purpose, plan.goal_sha256,
                   plan.target_sha256, source, plan.query, plan.synonyms, plan.filters,
                   plan.page_size, page_number, cursor, previous_result_artifact_hash)


@dataclass(frozen=True, slots=True)
@final
class ScholarlySearchResultV2:
    """One immutable page checkpoint; continuation facts are derived on replay."""

    request: ScholarlySearchPageRequest
    status: RetrievalStatus
    hits: tuple[ScholarlySearchHit, ...]
    next_cursor: str | None
    reported_count: int | None
    reported_page_size: int | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None = None
    scientific_evidence: bool = False
    schema_version: str = "scholarly-search-result/v2"

    def __post_init__(self) -> None:
        if type(self.request) is not ScholarlySearchPageRequest:
            raise LiteratureError("search v2 result requires an exact page request")
        request = self.request
        checked = ScholarlySearchResult(
            request.plan_sha256, request.plan_artifact_hash,
            ScholarlySearchRequest(request.plan_sha256, request.purpose, request.goal_sha256,
                                   request.target_sha256, request.source, request.query,
                                   request.synonyms, request.filters, request.page_size),
            self.status, self.hits, self.raw_artifact_hash, self.response_artifact_hash,
            self.failure_reason, self.scientific_evidence,
        )
        if self.schema_version != "scholarly-search-result/v2":
            raise LiteratureError("unsupported scholarly search v2 result schema")
        if checked.status is RetrievalStatus.AVAILABLE:
            if type(self.reported_count) is not int or self.reported_count < 0:
                raise LiteratureError("successful search page requires a reported count")
            if type(self.reported_page_size) is not int or self.reported_page_size != request.page_size:
                raise LiteratureError("successful search page size differs from its request")
            if self.next_cursor is not None:
                require_scholarly_search_cursor(self.next_cursor)
        elif self.next_cursor is not None or self.reported_count is not None or self.reported_page_size is not None:
            raise LiteratureError("failed search pages cannot invent parsed metadata")
        keys = tuple((hit.source, hit.identifier.kind, hit.identifier.value) for hit in checked.hits)
        if len(set(keys)) != len(keys):
            raise LiteratureError("search page has duplicate canonical work identities")
        object.__setattr__(self, "status", checked.status)
        object.__setattr__(self, "hits", checked.hits)
        object.__setattr__(self, "failure_reason", checked.failure_reason)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(sorted({self.request.plan_artifact_hash, *(value for value in (
            self.raw_artifact_hash, self.response_artifact_hash,
            self.request.previous_result_artifact_hash,
        ) if value is not None)}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "request": self.request.to_dict(),
            "status": self.status.value, "hits": [value.to_dict() for value in self.hits],
            "next_cursor": self.next_cursor, "reported_count": self.reported_count,
            "reported_page_size": self.reported_page_size,
            "raw_artifact_hash": self.raw_artifact_hash,
            "response_artifact_hash": self.response_artifact_hash,
            "failure_reason": self.failure_reason, "scientific_evidence": self.scientific_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchResultV2:
        _exact_keys(value, frozenset({
            "schema_version", "request", "status", "hits", "next_cursor", "reported_count",
            "reported_page_size", "raw_artifact_hash", "response_artifact_hash", "failure_reason",
            "scientific_evidence",
        }), "scholarly search v2 result")
        if not isinstance(value["hits"], (list, tuple)):
            raise LiteratureError("search v2 hits must be a list")
        return cls(**{key: item for key, item in value.items() if key not in {"request", "hits"}},
                   request=ScholarlySearchPageRequest.from_dict(value["request"]),
                   hits=tuple(ScholarlySearchHit.from_dict(item) for item in value["hits"]))

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def normalize_scholarly_search_page(request: ScholarlySearchPageRequest,
                                    envelope: GatewayEnvelope) -> ScholarlySearchResultV2:
    if type(request) is not ScholarlySearchPageRequest or not isinstance(envelope, GatewayEnvelope):
        raise LiteratureError("search page normalization requires exact request and envelope")
    if envelope.source is not request.source or envelope.request_id != request.request_id:
        raise LiteratureError("search page response belongs to another request")
    if envelope.status is not RetrievalStatus.AVAILABLE:
        return ScholarlySearchResultV2(request, envelope.status, (), None, None, None,
                                       envelope.raw_artifact_hash, envelope.response_artifact_hash,
                                       envelope.failure_reason)
    payload = envelope.payload_dict
    if payload is None:
        raise LiteratureError("successful search page is missing payload")
    _exact_keys(payload, frozenset({"results", "next_cursor", "reported_count", "reported_page_size"}),
                "search page payload")
    if not isinstance(payload["results"], (list, tuple)) or len(payload["results"]) > request.page_size:
        raise LiteratureError("search page results exceed the page bound")
    hits = []
    for rank, item in enumerate(payload["results"], start=1):
        _exact_keys(item, frozenset({"identifier", "identifier_kind", "title"}), "search page hit")
        hits.append(ScholarlySearchHit(request.source,
                    ScholarlyIdentifier(item["identifier_kind"], item["identifier"]), item["title"], rank))
    return ScholarlySearchResultV2(request, envelope.status, tuple(hits), payload["next_cursor"],
                                   payload["reported_count"], payload["reported_page_size"],
                                   envelope.raw_artifact_hash, envelope.response_artifact_hash)


class ScholarlySearchStopReason(str, Enum):
    CONTINUATION_AVAILABLE = "CONTINUATION_AVAILABLE"
    PROVIDER_TERMINAL_OBSERVED = "PROVIDER_TERMINAL_OBSERVED"
    PAGE_BUDGET_TRUNCATED = "PAGE_BUDGET_TRUNCATED"
    CAPTURED_FAILURE = "CAPTURED_FAILURE"
    PAGINATION_ANOMALY = "PAGINATION_ANOMALY"


@dataclass(frozen=True, slots=True)
@final
class ScholarlySearchProgress:
    pages: tuple[ScholarlySearchResultV2, ...]
    result_artifact_hashes: tuple[str, ...]
    captured_hit_count: int
    unique_work_count: int
    reported_counts: tuple[int | None, ...]
    anomalies: tuple[str, ...]
    stop_reason: ScholarlySearchStopReason
    next_request: ScholarlySearchPageRequest | None


def derive_scholarly_search_progress(
    plan: ScholarlySearchPlanV2, *, plan_artifact_hash: str, source: ScholarlySource,
    checkpoints: tuple[tuple[str, ScholarlySearchResultV2], ...],
) -> ScholarlySearchProgress:
    """Re-derive one bounded selected chain, never a latest head or source census."""
    if type(plan) is not ScholarlySearchPlanV2 or not isinstance(checkpoints, tuple):
        raise LiteratureError("search progression requires exact plan and checkpoint tuple")
    if len(checkpoints) > plan.max_page_requests:
        raise LiteratureError("search checkpoint chain exceeds the frozen budget")
    expected = ScholarlySearchPageRequest.from_plan(plan, plan_artifact_hash=plan_artifact_hash,
        source=source, page_number=1, cursor="*", previous_result_artifact_hash=None)
    seen_artifacts: set[str] = set()
    requested_cursors: set[str] = set()
    identities: set[tuple[ScholarlySource, IdentifierKind, str]] = set()
    pages: list[ScholarlySearchResultV2] = []
    hashes: list[str] = []
    counts: list[int | None] = []
    anomalies: list[str] = []
    captured_count = 0
    stop = ScholarlySearchStopReason.CONTINUATION_AVAILABLE
    for index, checkpoint in enumerate(checkpoints, start=1):
        if not isinstance(checkpoint, tuple) or len(checkpoint) != 2:
            raise LiteratureError("search checkpoint binding is malformed")
        digest, result = checkpoint
        _require_hash(digest, "search checkpoint artifact")
        if digest in seen_artifacts or type(result) is not ScholarlySearchResultV2:
            raise LiteratureError("search checkpoint is repeated or malformed")
        if expected is None or result.request.to_dict() != expected.to_dict():
            raise LiteratureError("search checkpoint does not continue its exact predecessor")
        seen_artifacts.add(digest)
        requested_cursors.add(result.request.cursor)
        pages.append(result)
        hashes.append(digest)
        counts.append(result.reported_count)
        captured_count += len(result.hits)
        if result.status is not RetrievalStatus.AVAILABLE:
            stop = ScholarlySearchStopReason.CAPTURED_FAILURE
        else:
            keys = {(hit.source, hit.identifier.kind, hit.identifier.value) for hit in result.hits}
            if identities.intersection(keys):
                anomalies.append("CROSS_PAGE_WORK_OVERLAP")
            identities.update(keys)
            if len({count for count in counts if count is not None}) > 1:
                anomalies.append("REPORTED_COUNT_DRIFT")
            if result.next_cursor in requested_cursors:
                anomalies.append("CURSOR_CYCLE")
            if result.hits and result.next_cursor is None:
                anomalies.append("NONEMPTY_NULL_CURSOR")
            if anomalies:
                stop = ScholarlySearchStopReason.PAGINATION_ANOMALY
            elif result.next_cursor is None:
                stop = ScholarlySearchStopReason.PROVIDER_TERMINAL_OBSERVED
            elif index == plan.max_page_requests:
                stop = ScholarlySearchStopReason.PAGE_BUDGET_TRUNCATED
        expected = (ScholarlySearchPageRequest.from_plan(plan,
            plan_artifact_hash=plan_artifact_hash, source=source, page_number=index + 1,
            cursor=result.next_cursor, previous_result_artifact_hash=digest)
            if stop is ScholarlySearchStopReason.CONTINUATION_AVAILABLE else None)
    return ScholarlySearchProgress(tuple(pages), tuple(hashes), captured_count, len(identities),
                                    tuple(counts), tuple(anomalies), stop, expected)


@dataclass(frozen=True, slots=True)
class ScholarlySearchHitResolutionBinding:
    """Exact bridge from an untrusted hit to a normalized resolve-work artifact."""

    hit_id: str
    resolution_request_id: str
    scholarly_record_artifact_hash: str
    source_id: str

    def __post_init__(self) -> None:
        _require_hash(self.hit_id, "scholarly search binding hit_id")
        _require_hash(
            self.resolution_request_id,
            "scholarly search binding resolution_request_id",
        )
        _require_hash(
            self.scholarly_record_artifact_hash,
            "scholarly search binding scholarly_record_artifact_hash",
        )
        source_id = _clean_text(self.source_id, "scholarly search binding source_id")
        assert source_id is not None
        object.__setattr__(self, "source_id", source_id)

    def to_dict(self) -> dict[str, str]:
        return {
            "hit_id": self.hit_id,
            "resolution_request_id": self.resolution_request_id,
            "scholarly_record_artifact_hash": self.scholarly_record_artifact_hash,
            "source_id": self.source_id,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> ScholarlySearchHitResolutionBinding:
        _exact_keys(
            value,
            frozenset(
                {
                    "hit_id",
                    "resolution_request_id",
                    "scholarly_record_artifact_hash",
                    "source_id",
                }
            ),
            "scholarly search hit-resolution binding",
        )
        return cls(
            hit_id=value["hit_id"],
            resolution_request_id=value["resolution_request_id"],
            scholarly_record_artifact_hash=value["scholarly_record_artifact_hash"],
            source_id=value["source_id"],
        )


@dataclass(frozen=True, slots=True)
class ScholarlySearchSelection:
    """Persisted-ready deterministic accounting for every captured search hit."""

    plan_sha256: str
    plan_artifact_hash: str
    result: ScholarlySearchResult
    result_artifact_hash: str
    policy: ScholarlySearchSelectionPolicy
    bindings: tuple[ScholarlySearchHitResolutionBinding, ...]
    unselected_hit_ids: tuple[str, ...]
    scientific_evidence: bool = False
    schema_version: str = "scholarly-search-selection/v1"

    def __post_init__(self) -> None:
        _require_hash(self.plan_sha256, "scholarly search selection plan_sha256")
        _require_hash(
            self.plan_artifact_hash,
            "scholarly search selection plan_artifact_hash",
        )
        _require_hash(
            self.result_artifact_hash,
            "scholarly search selection result_artifact_hash",
        )
        if not isinstance(self.result, ScholarlySearchResult):
            raise LiteratureError("scholarly search selection requires typed result")
        if (
            self.result.plan_sha256 != self.plan_sha256
            or self.result.plan_artifact_hash != self.plan_artifact_hash
            or self.result.status is not RetrievalStatus.AVAILABLE
        ):
            raise LiteratureError("scholarly search selection rebinds its result or plan")
        try:
            policy = (
                self.policy
                if isinstance(self.policy, ScholarlySearchSelectionPolicy)
                else ScholarlySearchSelectionPolicy(self.policy)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly search selection policy is invalid") from exc
        if not isinstance(self.bindings, tuple) or not all(
            isinstance(value, ScholarlySearchHitResolutionBinding)
            for value in self.bindings
        ):
            raise LiteratureError("scholarly search selection bindings are malformed")
        hit_rank = {value.hit_id: value.rank for value in self.result.hits}
        bound_hit_ids = tuple(value.hit_id for value in self.bindings)
        if any(value not in hit_rank for value in bound_hit_ids):
            raise LiteratureError("scholarly search selection binds an unknown hit")
        if len(set(bound_hit_ids)) != len(bound_hit_ids):
            raise LiteratureError("scholarly search selection reuses a hit")
        if tuple(hit_rank[value] for value in bound_hit_ids) != tuple(
            sorted(hit_rank[value] for value in bound_hit_ids)
        ):
            raise LiteratureError("scholarly search bindings must preserve provider rank")
        if not isinstance(self.unselected_hit_ids, tuple):
            raise LiteratureError("scholarly search unselected hits must be a tuple")
        unselected = tuple(self.unselected_hit_ids)
        for value in unselected:
            _require_hash(value, "scholarly search unselected_hit_id")
        if len(set(unselected)) != len(unselected):
            raise LiteratureError("scholarly search unselected hits must be unique")
        expected_hit_ids = {value.hit_id for value in self.result.hits}
        if set(bound_hit_ids).intersection(unselected) or set(bound_hit_ids).union(
            unselected
        ) != expected_hit_ids:
            raise LiteratureError("scholarly search selection does not account for every hit")
        if policy is ScholarlySearchSelectionPolicy.ALL_CAPTURED_HITS and unselected:
            raise LiteratureError("all-captured-hits policy cannot omit a result")
        for name, values in (
            ("source IDs", tuple(value.source_id for value in self.bindings)),
            (
                "resolution requests",
                tuple(value.resolution_request_id for value in self.bindings),
            ),
            (
                "record artifacts",
                tuple(value.scholarly_record_artifact_hash for value in self.bindings),
            ),
        ):
            if len(set(values)) != len(values):
                raise LiteratureError(f"scholarly search selection reuses {name}")
        if self.scientific_evidence is not False:
            raise LiteratureError("scholarly search selection is not scientific evidence")
        if self.schema_version != "scholarly-search-selection/v1":
            raise LiteratureError("unsupported scholarly search selection schema")
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "scholarly search selection",
        )
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "unselected_hit_ids", unselected)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    self.plan_artifact_hash,
                    self.result_artifact_hash,
                    *(
                        value.scholarly_record_artifact_hash
                        for value in self.bindings
                    ),
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_sha256": self.plan_sha256,
            "plan_artifact_hash": self.plan_artifact_hash,
            "result": self.result.to_dict(),
            "result_sha256": self.result.sha256,
            "result_artifact_hash": self.result_artifact_hash,
            "policy": self.policy.value,
            "bindings": [value.to_dict() for value in self.bindings],
            "unselected_hit_ids": list(self.unselected_hit_ids),
            "scientific_evidence": self.scientific_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlySearchSelection:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "plan_sha256",
                    "plan_artifact_hash",
                    "result",
                    "result_sha256",
                    "result_artifact_hash",
                    "policy",
                    "bindings",
                    "unselected_hit_ids",
                    "scientific_evidence",
                }
            ),
            "scholarly search selection",
        )
        if not isinstance(value["bindings"], (list, tuple)) or not isinstance(
            value["unselected_hit_ids"], (list, tuple)
        ):
            raise LiteratureError("scholarly search selection collections must be lists")
        result = ScholarlySearchResult.from_dict(value["result"])
        if result.sha256 != value["result_sha256"]:
            raise LiteratureError("scholarly search selection result hash was tampered")
        return cls(
            plan_sha256=value["plan_sha256"],
            plan_artifact_hash=value["plan_artifact_hash"],
            result=result,
            result_artifact_hash=value["result_artifact_hash"],
            policy=value["policy"],
            bindings=tuple(
                ScholarlySearchHitResolutionBinding.from_dict(item)
                for item in value["bindings"]
            ),
            unselected_hit_ids=tuple(value["unselected_hit_ids"]),
            scientific_evidence=value["scientific_evidence"],
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class GatewayEnvelope:
    """Captured gateway response.  ``payload`` remains inert untrusted data."""

    source: ScholarlySource
    request_id: str
    status: RetrievalStatus
    payload: Mapping[str, Any] | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None = None
    license: str | None = None
    full_text_status: FullTextStatus | None = None

    def __post_init__(self) -> None:
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
            status = self.status if isinstance(self.status, RetrievalStatus) else RetrievalStatus(self.status)
            full_text_status = (
                self.full_text_status
                if isinstance(self.full_text_status, FullTextStatus)
                else FullTextStatus(self.full_text_status)
                if self.full_text_status is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("gateway envelope source or status is invalid") from exc
        _require_hash(self.request_id, "request_id")
        _require_hash(self.raw_artifact_hash, "raw_artifact_hash", optional=True)
        _require_hash(self.response_artifact_hash, "response_artifact_hash", optional=True)
        if status is RetrievalStatus.AVAILABLE:
            if not isinstance(self.payload, Mapping):
                raise LiteratureError("available gateway response requires an object payload")
            if self.raw_artifact_hash is None or self.response_artifact_hash is None:
                raise LiteratureError("available gateway response requires raw and response provenance")
        elif self.payload is not None and not isinstance(self.payload, Mapping):
            raise LiteratureError("gateway payload must be an object when present")
        reason = _clean_text(self.failure_reason, "failure_reason", optional=True)
        license_value = _clean_text(self.license, "license", optional=True)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "failure_reason", reason)
        object.__setattr__(self, "license", license_value)
        object.__setattr__(self, "full_text_status", full_text_status)
        if self.payload is not None:
            object.__setattr__(self, "payload", _freeze_json(self.payload))

    @property
    def payload_dict(self) -> dict[str, Any] | None:
        return None if self.payload is None else _thaw_json(self.payload)


@runtime_checkable
class LiteratureGateway(Protocol):
    """Structural gateway interface; implementations own all external access."""

    def fetch(
        self,
        request: ScholarlyRequest | ScholarlySearchRequest | CitationPageRequest,
        /,
    ) -> object:
        """Return an already captured response for a typed scholarly request."""


@runtime_checkable
class CapturedGatewayResponse(Protocol):
    """Structural response shape for gateways implemented in other modules."""

    source: ScholarlySource | str
    request_id: str
    status: RetrievalStatus | str
    payload: Mapping[str, Any] | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None
    license: str | None


@dataclass(frozen=True, slots=True)
class ProvenancedValue:
    source: ScholarlySource
    normalized_value: str
    raw_value: str
    response_artifact_hash: str

    def __post_init__(self) -> None:
        try:
            source = (
                self.source
                if isinstance(self.source, ScholarlySource)
                else ScholarlySource(self.source)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("conflict provenance source is invalid") from exc
        _clean_text(self.normalized_value, "normalized conflict value")
        _clean_text(self.raw_value, "raw conflict value")
        _require_hash(self.response_artifact_hash, "conflict response_artifact_hash")
        object.__setattr__(self, "source", source)

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source.value,
            "normalized_value": self.normalized_value,
            "raw_value": self.raw_value,
            "response_artifact_hash": self.response_artifact_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ProvenancedValue:
        _exact_keys(
            value,
            frozenset(
                {
                    "source",
                    "normalized_value",
                    "raw_value",
                    "response_artifact_hash",
                }
            ),
            "provenanced conflict value",
        )
        return cls(
            source=value["source"],
            normalized_value=value["normalized_value"],
            raw_value=value["raw_value"],
            response_artifact_hash=value["response_artifact_hash"],
        )


@dataclass(frozen=True, slots=True)
class MetadataConflict:
    field_name: str
    candidates: tuple[ProvenancedValue, ...]

    def __post_init__(self) -> None:
        _clean_text(self.field_name, "conflict field")
        if not isinstance(self.candidates, tuple) or len(self.candidates) < 2:
            raise LiteratureError("metadata conflict requires at least two candidates")
        if not all(isinstance(value, ProvenancedValue) for value in self.candidates):
            raise LiteratureError("metadata conflict candidates are malformed")
        if len({value.normalized_value for value in self.candidates}) < 2:
            raise LiteratureError("metadata conflict candidates do not disagree")

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_name": self.field_name,
            "candidates": [value.to_dict() for value in self.candidates],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> MetadataConflict:
        _exact_keys(
            value,
            frozenset({"field_name", "candidates"}),
            "metadata conflict",
        )
        candidates = value["candidates"]
        if not isinstance(candidates, (list, tuple)):
            raise LiteratureError("metadata conflict candidates must be a list")
        return cls(
            field_name=value["field_name"],
            candidates=tuple(
                ProvenancedValue.from_dict(item) for item in candidates
            ),
        )


@dataclass(frozen=True, slots=True)
class FullTextPassage:
    section_id: str
    passage_id: str
    text: str
    start_char: int
    end_char: int
    source_artifact_hash: str
    context_before: str = ""
    context_after: str = ""

    def __post_init__(self) -> None:
        for name in ("section_id", "passage_id"):
            normalized = _clean_text(getattr(self, name), name)
            object.__setattr__(self, name, normalized)
        if (
            not isinstance(self.text, str)
            or not self.text.strip()
            or len(self.text) > _MAX_TEXT
        ):
            raise LiteratureError("passage text must be bounded non-empty text")
        for name in ("context_before", "context_after"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) > _MAX_TEXT:
                raise LiteratureError(f"{name} must be bounded text")
        if (
            isinstance(self.start_char, bool)
            or isinstance(self.end_char, bool)
            or not isinstance(self.start_char, int)
            or not isinstance(self.end_char, int)
            or self.start_char < 0
            or self.end_char <= self.start_char
        ):
            raise LiteratureError("passage offsets must be increasing non-negative integers")
        if self.end_char - self.start_char != len(self.text):
            raise LiteratureError("passage offsets must exactly span passage text")
        _require_hash(self.source_artifact_hash, "passage source_artifact_hash")

    @property
    def passage_sha256(self) -> str:
        return _sha256(self.text)

    @property
    def locator_sha256(self) -> str:
        """Bind this occurrence, not merely text that may repeat elsewhere."""

        return _sha256(
            _canonical_json(
                {
                    "section_id": self.section_id,
                    "passage_id": self.passage_id,
                    "start_char": self.start_char,
                    "end_char": self.end_char,
                    "passage_sha256": self.passage_sha256,
                    "source_artifact_hash": self.source_artifact_hash,
                }
            )
        )

    @property
    def context_sha256(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "section_id": self.section_id,
                    "passage_id": self.passage_id,
                    "context_before": self.context_before,
                    "text": self.text,
                    "context_after": self.context_after,
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "passage_id": self.passage_id,
            "text": self.text,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "source_artifact_hash": self.source_artifact_hash,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "passage_sha256": self.passage_sha256,
            "locator_sha256": self.locator_sha256,
            "context_sha256": self.context_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FullTextPassage:
        _exact_keys(
            value,
            frozenset(
                {
                    "section_id",
                    "passage_id",
                    "text",
                    "start_char",
                    "end_char",
                    "source_artifact_hash",
                    "context_before",
                    "context_after",
                    "passage_sha256",
                    "locator_sha256",
                    "context_sha256",
                }
            ),
            "full-text passage",
        )
        passage = cls(
            section_id=value["section_id"],
            passage_id=value["passage_id"],
            text=value["text"],
            start_char=value["start_char"],
            end_char=value["end_char"],
            source_artifact_hash=value["source_artifact_hash"],
            context_before=value["context_before"],
            context_after=value["context_after"],
        )
        if (
            value["passage_sha256"] != passage.passage_sha256
            or value["locator_sha256"] != passage.locator_sha256
            or value["context_sha256"] != passage.context_sha256
        ):
            raise LiteratureError("full-text passage hashes were tampered")
        return passage


@dataclass(frozen=True, slots=True)
class ScholarlyRecord:
    source: ScholarlySource
    source_record_id: str
    identifiers: tuple[ScholarlyIdentifier, ...]
    title: str
    authors: tuple[str, ...]
    publication_year: int | None
    venue: str | None
    abstract: str | None
    roles: tuple[ScholarlyRole, ...]
    full_text_status: FullTextStatus
    passages: tuple[FullTextPassage, ...]
    request_id: str
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    parent_artifact_hashes: tuple[str, ...]
    license: str | None = None
    conflicts: tuple[MetadataConflict, ...] = ()
    untrusted_evidence: bool = True

    def __post_init__(self) -> None:
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
            full_text = self.full_text_status if isinstance(self.full_text_status, FullTextStatus) else FullTextStatus(self.full_text_status)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("record source or full-text status is invalid") from exc
        source_record_id = _clean_text(self.source_record_id, "source_record_id")
        title = _clean_text(self.title, "title")
        if not isinstance(self.identifiers, tuple) or not self.identifiers:
            raise LiteratureError("scholarly record requires normalized identifiers")
        if not all(isinstance(value, ScholarlyIdentifier) for value in self.identifiers):
            raise LiteratureError("scholarly record identifiers are malformed")
        identifiers = tuple(sorted(set(self.identifiers), key=lambda item: (item.kind.value, item.value)))
        if not isinstance(self.authors, tuple) or any(not isinstance(value, str) for value in self.authors):
            raise LiteratureError("authors must be a tuple of strings")
        authors = tuple(_clean_text(value, "author") for value in self.authors)
        if self.publication_year is not None and (
            isinstance(self.publication_year, bool)
            or not isinstance(self.publication_year, int)
            or not 1000 <= self.publication_year <= 3000
        ):
            raise LiteratureError("publication_year is invalid")
        venue = _clean_text(self.venue, "venue", optional=True)
        abstract = _clean_text(self.abstract, "abstract", optional=True)
        license_value = _clean_text(self.license, "license", optional=True)
        if not isinstance(self.roles, tuple) or not self.roles:
            raise LiteratureError("record requires adapter roles")
        try:
            roles = tuple(sorted({role if isinstance(role, ScholarlyRole) else ScholarlyRole(role) for role in self.roles}, key=lambda role: role.value))
        except (TypeError, ValueError) as exc:
            raise LiteratureError("record contains an invalid adapter role") from exc
        if not isinstance(self.passages, tuple) or not all(isinstance(value, FullTextPassage) for value in self.passages):
            raise LiteratureError("passages must contain FullTextPassage values")
        if self.passages and full_text is not FullTextStatus.AVAILABLE:
            raise LiteratureError("captured passages require AVAILABLE full text")
        if full_text is FullTextStatus.AVAILABLE and not self.passages:
            raise LiteratureError("AVAILABLE full text requires at least one exact passage")
        _require_hash(self.request_id, "request_id")
        _require_hash(self.raw_artifact_hash, "raw_artifact_hash", optional=True)
        _require_hash(self.response_artifact_hash, "response_artifact_hash", optional=True)
        if source is not ScholarlySource.MERGED and (
            self.raw_artifact_hash is None or self.response_artifact_hash is None
        ):
            raise LiteratureError("source record requires response/raw provenance")
        if not isinstance(self.parent_artifact_hashes, tuple):
            raise LiteratureError("parent_artifact_hashes must be a tuple")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        for value in parents:
            _require_hash(value, "parent_artifact_hash")
        required_parents = {
            value
            for value in (self.raw_artifact_hash, self.response_artifact_hash)
            if value is not None
        }
        required_parents.update(passage.source_artifact_hash for passage in self.passages)
        if not required_parents.issubset(parents):
            raise LiteratureError("record provenance omits raw, response, or full-text parent")
        _require_persistable_parent_count(parents, "scholarly record")
        if not isinstance(self.conflicts, tuple) or not all(isinstance(value, MetadataConflict) for value in self.conflicts):
            raise LiteratureError("record conflicts are malformed")
        if self.untrusted_evidence is not True:
            raise LiteratureError("external scholarly records must remain untrusted evidence")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "source_record_id", source_record_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "identifiers", identifiers)
        object.__setattr__(self, "authors", authors)
        object.__setattr__(self, "venue", venue)
        object.__setattr__(self, "abstract", abstract)
        object.__setattr__(self, "license", license_value)
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "full_text_status", full_text)
        object.__setattr__(self, "parent_artifact_hashes", parents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "scholarly-record/v1",
            "record_sha256": scholarly_record_sha256(self),
            "source": self.source.value,
            "source_record_id": self.source_record_id,
            "identifiers": [value.to_dict() for value in self.identifiers],
            "title": self.title,
            "authors": list(self.authors),
            "publication_year": self.publication_year,
            "venue": self.venue,
            "abstract": self.abstract,
            "roles": [value.value for value in self.roles],
            "full_text_status": self.full_text_status.value,
            "passages": [value.to_dict() for value in self.passages],
            "request_id": self.request_id,
            "raw_artifact_hash": self.raw_artifact_hash,
            "response_artifact_hash": self.response_artifact_hash,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
            "license": self.license,
            "conflicts": [value.to_dict() for value in self.conflicts],
            "untrusted_evidence": self.untrusted_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlyRecord:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "record_sha256",
                    "source",
                    "source_record_id",
                    "identifiers",
                    "title",
                    "authors",
                    "publication_year",
                    "venue",
                    "abstract",
                    "roles",
                    "full_text_status",
                    "passages",
                    "request_id",
                    "raw_artifact_hash",
                    "response_artifact_hash",
                    "parent_artifact_hashes",
                    "license",
                    "conflicts",
                    "untrusted_evidence",
                }
            ),
            "scholarly record",
        )
        if value["schema_version"] != "scholarly-record/v1":
            raise LiteratureError("unsupported scholarly record schema")
        for name in (
            "identifiers",
            "authors",
            "roles",
            "passages",
            "parent_artifact_hashes",
            "conflicts",
        ):
            if not isinstance(value[name], (list, tuple)):
                raise LiteratureError(f"scholarly record {name} must be a list")
        record = cls(
            source=value["source"],
            source_record_id=value["source_record_id"],
            identifiers=tuple(
                ScholarlyIdentifier.from_dict(item)
                for item in value["identifiers"]
            ),
            title=value["title"],
            authors=tuple(value["authors"]),
            publication_year=value["publication_year"],
            venue=value["venue"],
            abstract=value["abstract"],
            roles=tuple(value["roles"]),
            full_text_status=value["full_text_status"],
            passages=tuple(
                FullTextPassage.from_dict(item) for item in value["passages"]
            ),
            request_id=value["request_id"],
            raw_artifact_hash=value["raw_artifact_hash"],
            response_artifact_hash=value["response_artifact_hash"],
            parent_artifact_hashes=tuple(value["parent_artifact_hashes"]),
            license=value["license"],
            conflicts=tuple(
                MetadataConflict.from_dict(item) for item in value["conflicts"]
            ),
            untrusted_evidence=value["untrusted_evidence"],
        )
        if value["record_sha256"] != scholarly_record_sha256(record):
            raise LiteratureError("scholarly record content hash was tampered")
        return record

    @property
    def conflicted_fields(self) -> tuple[str, ...]:
        return tuple(sorted({conflict.field_name for conflict in self.conflicts}))

    def identifiers_of_kind(self, kind: IdentifierKind) -> tuple[str, ...]:
        return tuple(value.value for value in self.identifiers if value.kind is kind)


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    source: ScholarlySource
    status: RetrievalStatus
    request: ScholarlyRequest
    record: ScholarlyRecord | None
    failure_reason: str | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    license: str | None = None

    @property
    def available(self) -> bool:
        return self.status is RetrievalStatus.AVAILABLE and self.record is not None


@runtime_checkable
class ScholarlyAdapter(Protocol):
    source: ScholarlySource
    roles: tuple[ScholarlyRole, ...]

    def build_request(self, identifier: ScholarlyIdentifier) -> ScholarlyRequest:
        """Build a deterministic request for the controlled gateway."""

    def normalize(self, envelope: GatewayEnvelope) -> ScholarlyRecord:
        """Normalize one captured, available gateway response."""


def _sequence(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _first_text(value: Any) -> str | None:
    for candidate in _sequence(value):
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return None


def _year(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1000 <= value <= 3000 else None
    if isinstance(value, str):
        match = re.search(r"(?:^|\D)(\d{4})(?:\D|$)", value)
        return int(match.group(1)) if match else None
    return None


def _authors(value: Any) -> tuple[str, ...]:
    output: list[str] = []
    for item in _sequence(value):
        name: str | None = None
        if isinstance(item, str):
            name = item
        elif isinstance(item, Mapping):
            if isinstance(item.get("name"), str):
                name = item["name"]
            elif isinstance(item.get("display_name"), str):
                name = item["display_name"]
            elif isinstance(item.get("author"), Mapping):
                author = item["author"]
                name = author.get("display_name") or author.get("name")
            else:
                given = item.get("given")
                family = item.get("family")
                if isinstance(family, str):
                    name = f"{given} {family}" if isinstance(given, str) and given else family
        if isinstance(name, str) and name.strip():
            output.append(" ".join(unicodedata.normalize("NFKC", name).split()))
    return tuple(output)


def _identifier_candidates(
    source: ScholarlySource,
    payload: Mapping[str, Any],
) -> tuple[tuple[IdentifierKind, str], ...]:
    values: list[tuple[IdentifierKind, str]] = []

    def add(kind: IdentifierKind, value: Any) -> None:
        if isinstance(value, str) and value.strip():
            values.append((kind, value))

    if source is ScholarlySource.OPENALEX:
        add(IdentifierKind.OPENALEX, payload.get("id"))
        add(IdentifierKind.DOI, payload.get("doi"))
    elif source is ScholarlySource.SEMANTIC_SCHOLAR:
        add(IdentifierKind.SEMANTIC_SCHOLAR, payload.get("paperId"))
    elif source is ScholarlySource.CROSSREF:
        add(IdentifierKind.DOI, payload.get("DOI") or payload.get("doi"))
    elif source is ScholarlySource.ARXIV:
        add(IdentifierKind.ARXIV, payload.get("id") or payload.get("arxiv_id"))
        add(IdentifierKind.DOI, payload.get("doi"))
    elif source is ScholarlySource.PUBMED:
        add(IdentifierKind.PMID, payload.get("pmid") or payload.get("id"))
        add(IdentifierKind.DOI, payload.get("doi"))
        add(IdentifierKind.PMCID, payload.get("pmcid"))
    elif source is ScholarlySource.PMC:
        add(IdentifierKind.PMCID, payload.get("pmcid") or payload.get("id"))
        add(IdentifierKind.PMID, payload.get("pmid"))
        add(IdentifierKind.DOI, payload.get("doi"))

    identifiers = payload.get("ids") or payload.get("externalIds")
    if isinstance(identifiers, Mapping):
        aliases = {
            "doi": IdentifierKind.DOI,
            "openalex": IdentifierKind.OPENALEX,
            "paperid": IdentifierKind.SEMANTIC_SCHOLAR,
            "semanticscholar": IdentifierKind.SEMANTIC_SCHOLAR,
            "arxiv": IdentifierKind.ARXIV,
            "pubmed": IdentifierKind.PMID,
            "pmid": IdentifierKind.PMID,
            "pmc": IdentifierKind.PMCID,
            "pmcid": IdentifierKind.PMCID,
        }
        for key, value in identifiers.items():
            kind = aliases.get(str(key).replace("_", "").casefold())
            if kind is not None:
                add(kind, value)
    return tuple(values)


def _passages(payload: Mapping[str, Any], source_hash: str) -> tuple[FullTextPassage, ...]:
    passages: list[FullTextPassage] = []
    for index, item in enumerate(_sequence(payload.get("passages"))):
        if not isinstance(item, Mapping):
            raise LiteratureError("full-text passage must be an object")
        text = item.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > _MAX_TEXT:
            raise LiteratureError("passage.text must be bounded non-empty text")
        start = item.get("start_char")
        if start is None:
            raise LiteratureError("full-text passage requires start_char")
        end = item.get("end_char", start + len(text) if isinstance(start, int) else None)
        passages.append(
            FullTextPassage(
                section_id=item.get("section_id") or item.get("section") or "unknown-section",
                passage_id=item.get("passage_id") or f"passage-{index}",
                text=text,
                start_char=start,
                end_char=end,
                # Artifact identity is gateway-owned provenance.  A payload may
                # mention a hash, but that untrusted string must never become an
                # authoritative parent edge.
                source_artifact_hash=source_hash,
                context_before=item.get("context_before", ""),
                context_after=item.get("context_after", ""),
            )
        )
    return tuple(passages)


def _record_conflicts(
    source: ScholarlySource,
    raw_candidates: Sequence[tuple[IdentifierKind, str]],
    response_hash: str,
) -> tuple[MetadataConflict, ...]:
    grouped: dict[IdentifierKind, list[tuple[str, str]]] = {}
    for kind, raw in raw_candidates:
        normalized = normalize_identifier(kind, raw)
        grouped.setdefault(kind, []).append((raw, normalized))
    conflicts: list[MetadataConflict] = []
    for kind, candidates in grouped.items():
        distinct = {normalized for _, normalized in candidates}
        if len(distinct) > 1:
            values = tuple(
                ProvenancedValue(source, normalized, raw, response_hash)
                for raw, normalized in sorted(candidates, key=lambda item: (item[1], item[0]))
            )
            conflicts.append(MetadataConflict(f"identifier.{kind.value}", values))
    return tuple(conflicts)


class _BaseAdapter:
    source: ClassVar[ScholarlySource]
    roles: ClassVar[tuple[ScholarlyRole, ...]]
    title_fields: ClassVar[tuple[str, ...]] = ("title",)
    author_field: ClassVar[str] = "authors"
    year_fields: ClassVar[tuple[str, ...]] = ("year", "publication_year", "published")
    venue_fields: ClassVar[tuple[str, ...]] = ("venue", "journal")
    abstract_fields: ClassVar[tuple[str, ...]] = ("abstract", "summary")

    def build_request(self, identifier: ScholarlyIdentifier) -> ScholarlyRequest:
        if not isinstance(identifier, ScholarlyIdentifier):
            raise LiteratureError("adapter request requires ScholarlyIdentifier")
        return ScholarlyRequest(self.source, "resolve_work", identifier)

    def _payload(self, envelope: GatewayEnvelope) -> Mapping[str, Any]:
        if not isinstance(envelope, GatewayEnvelope):
            raise LiteratureError("adapter requires a captured GatewayEnvelope")
        if envelope.source is not self.source:
            raise LiteratureError("gateway response source does not match adapter")
        if envelope.status is not RetrievalStatus.AVAILABLE:
            raise LiteratureError("only available responses can be normalized")
        payload = envelope.payload_dict
        if payload is None:
            raise LiteratureError("available response has no payload")
        return payload

    def _unwrap(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return payload

    def _title(self, payload: Mapping[str, Any]) -> str | None:
        for field_name in self.title_fields:
            value = _first_text(payload.get(field_name))
            if value:
                return value
        return None

    def _year(self, payload: Mapping[str, Any]) -> int | None:
        for field_name in self.year_fields:
            value = _year(payload.get(field_name))
            if value is not None:
                return value
        return None

    def _venue(self, payload: Mapping[str, Any]) -> str | None:
        for field_name in self.venue_fields:
            value = _first_text(payload.get(field_name))
            if value:
                return value
        return None

    def _abstract(self, payload: Mapping[str, Any]) -> str | None:
        for field_name in self.abstract_fields:
            value = _first_text(payload.get(field_name))
            if value:
                return value
        return None

    def _authors(self, payload: Mapping[str, Any]) -> tuple[str, ...]:
        return _authors(payload.get(self.author_field))

    def normalize(self, envelope: GatewayEnvelope) -> ScholarlyRecord:
        payload = self._unwrap(self._payload(envelope))
        title = self._title(payload)
        if title is None:
            raise LiteratureError("scholarly record has no title")
        raw_identifiers = _identifier_candidates(self.source, payload)
        if not raw_identifiers:
            raise LiteratureError("scholarly record has no recognized identifier")
        identifiers = tuple(ScholarlyIdentifier(kind, raw) for kind, raw in raw_identifiers)
        has_passage_material = bool(_sequence(payload.get("passages")))
        if has_passage_material and ScholarlyRole.FULL_TEXT not in self.roles:
            raise LiteratureError("adapter role does not permit full-text passage normalization")
        passages = (
            _passages(payload, envelope.raw_artifact_hash or "")
            if ScholarlyRole.FULL_TEXT in self.roles
            else ()
        )
        if passages:
            if envelope.full_text_status is not FullTextStatus.AVAILABLE:
                raise LiteratureError("gateway did not attest that captured full text is available")
            if envelope.license is None:
                raise LiteratureError("available full text requires an explicit license/access decision")
            full_text_status = FullTextStatus.AVAILABLE
        else:
            if envelope.full_text_status is FullTextStatus.AVAILABLE:
                raise LiteratureError("AVAILABLE full text requires captured passages")
            full_text_status = envelope.full_text_status or FullTextStatus.METADATA_ONLY
        parents = {
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            *(passage.source_artifact_hash for passage in passages),
        }
        parents.discard(None)
        source_identifier_kinds = {
            ScholarlySource.OPENALEX: IdentifierKind.OPENALEX,
            ScholarlySource.SEMANTIC_SCHOLAR: IdentifierKind.SEMANTIC_SCHOLAR,
            ScholarlySource.CROSSREF: IdentifierKind.DOI,
            ScholarlySource.ARXIV: IdentifierKind.ARXIV,
            ScholarlySource.PUBMED: IdentifierKind.PMID,
            ScholarlySource.PMC: IdentifierKind.PMCID,
        }
        expected_source_kind = source_identifier_kinds[self.source]
        source_ids = sorted(
            {value.value for value in identifiers if value.kind is expected_source_kind}
        )
        if not source_ids:
            raise LiteratureError("scholarly response omits its source-native identifier")
        source_record_id = source_ids[0]
        return ScholarlyRecord(
            source=self.source,
            source_record_id=source_record_id,
            identifiers=identifiers,
            title=title,
            authors=self._authors(payload),
            publication_year=self._year(payload),
            venue=self._venue(payload),
            abstract=self._abstract(payload),
            roles=self.roles,
            full_text_status=full_text_status,
            passages=passages,
            request_id=envelope.request_id,
            raw_artifact_hash=envelope.raw_artifact_hash,
            response_artifact_hash=envelope.response_artifact_hash,
            parent_artifact_hashes=tuple(sorted(parents)),  # type: ignore[arg-type]
            license=envelope.license,
            conflicts=_record_conflicts(
                self.source,
                raw_identifiers,
                envelope.response_artifact_hash or "",
            ),
        )


class OpenAlexAdapter(_BaseAdapter):
    source = ScholarlySource.OPENALEX
    roles = (ScholarlyRole.DISCOVERY, ScholarlyRole.CITATION_GRAPH, ScholarlyRole.METADATA)
    author_field = "authorships"
    year_fields = ("publication_year", "year")

    def _title(self, payload: Mapping[str, Any]) -> str | None:
        return _first_text(payload.get("title") or payload.get("display_name"))

    def _venue(self, payload: Mapping[str, Any]) -> str | None:
        location = payload.get("primary_location")
        if isinstance(location, Mapping):
            source = location.get("source")
            if isinstance(source, Mapping):
                return _first_text(source.get("display_name"))
        return super()._venue(payload)


class SemanticScholarAdapter(_BaseAdapter):
    source = ScholarlySource.SEMANTIC_SCHOLAR
    roles = (ScholarlyRole.DISCOVERY, ScholarlyRole.CITATION_GRAPH, ScholarlyRole.METADATA)


class CrossrefAdapter(_BaseAdapter):
    source = ScholarlySource.CROSSREF
    roles = (ScholarlyRole.DOI_VALIDATION, ScholarlyRole.METADATA)
    author_field = "author"
    venue_fields = ("container-title", "publisher")

    def _unwrap(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        message = payload.get("message")
        return message if isinstance(message, Mapping) else payload

    def _year(self, payload: Mapping[str, Any]) -> int | None:
        for field_name in ("published-print", "published-online", "issued"):
            value = payload.get(field_name)
            if isinstance(value, Mapping):
                parts = value.get("date-parts")
                if isinstance(parts, (list, tuple)) and parts and isinstance(parts[0], (list, tuple)) and parts[0]:
                    parsed = _year(parts[0][0])
                    if parsed is not None:
                        return parsed
        return super()._year(payload)


class ArxivAdapter(_BaseAdapter):
    source = ScholarlySource.ARXIV
    roles = (ScholarlyRole.DISCOVERY, ScholarlyRole.PREPRINT, ScholarlyRole.METADATA, ScholarlyRole.FULL_TEXT)


class PubMedAdapter(_BaseAdapter):
    source = ScholarlySource.PUBMED
    roles = (ScholarlyRole.DISCOVERY, ScholarlyRole.BIOMEDICAL, ScholarlyRole.METADATA)


class PMCAdapter(_BaseAdapter):
    source = ScholarlySource.PMC
    roles = (ScholarlyRole.BIOMEDICAL, ScholarlyRole.METADATA, ScholarlyRole.FULL_TEXT)


def acquire_scholarly_record(
    adapter: ScholarlyAdapter,
    gateway: LiteratureGateway,
    identifier: ScholarlyIdentifier,
) -> AcquisitionResult:
    """Resolve and normalize through the injected gateway, failing as typed state."""

    if not isinstance(adapter, ScholarlyAdapter):
        raise LiteratureError("adapter does not satisfy ScholarlyAdapter")
    if not isinstance(gateway, LiteratureGateway):
        raise LiteratureError("gateway does not satisfy LiteratureGateway")
    request = adapter.build_request(identifier)
    try:
        captured = gateway.fetch(request)
    except Exception as exc:
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.FAILED,
            request,
            None,
            f"gateway failure: {type(exc).__name__}",
            None,
            None,
        )
    captured_raw_hash = _captured_custody_hash(captured, "raw_artifact_hash")
    captured_response_hash = _captured_custody_hash(
        captured, "response_artifact_hash"
    )
    try:
        if isinstance(captured, GatewayEnvelope):
            envelope = captured
        elif isinstance(captured, CapturedGatewayResponse):
            envelope = GatewayEnvelope(
                source=captured.source,
                request_id=captured.request_id,
                status=captured.status,
                payload=captured.payload,
                raw_artifact_hash=captured.raw_artifact_hash,
                response_artifact_hash=captured.response_artifact_hash,
                failure_reason=captured.failure_reason,
                license=captured.license,
                full_text_status=getattr(captured, "full_text_status", None),
            )
        else:
            raise LiteratureError("gateway response does not satisfy the captured-response protocol")
    except (LiteratureError, TypeError, ValueError):
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            "gateway returned an invalid envelope",
            captured_raw_hash,
            captured_response_hash,
        )
    if envelope.source is not adapter.source or envelope.request_id != request.request_id:
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            "gateway response is not bound to the request",
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    if envelope.status is not RetrievalStatus.AVAILABLE:
        return AcquisitionResult(
            adapter.source,
            envelope.status,
            request,
            None,
            envelope.failure_reason,
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    try:
        record = adapter.normalize(envelope)
    except (LiteratureError, TypeError, ValueError, KeyError) as exc:
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            f"normalization failed: {exc}",
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    if not isinstance(record, ScholarlyRecord):
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            "adapter returned an invalid normalized record",
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    binding_failures: list[str] = []
    if record.source is not adapter.source:
        binding_failures.append("source")
    if record.request_id != request.request_id:
        binding_failures.append("request")
    if record.raw_artifact_hash != envelope.raw_artifact_hash:
        binding_failures.append("raw artifact")
    if record.response_artifact_hash != envelope.response_artifact_hash:
        binding_failures.append("response artifact")
    if any(
        passage.source_artifact_hash != envelope.raw_artifact_hash
        for passage in record.passages
    ):
        binding_failures.append("passage source artifact")
    if binding_failures:
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            "normalized response changed authoritative envelope binding: "
            + ", ".join(binding_failures),
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    if request.identifier not in record.identifiers:
        return AcquisitionResult(
            adapter.source,
            RetrievalStatus.MALFORMED,
            request,
            None,
            "normalized response does not contain the requested identifier",
            envelope.raw_artifact_hash,
            envelope.response_artifact_hash,
            envelope.license,
        )
    return AcquisitionResult(
        adapter.source,
        RetrievalStatus.AVAILABLE,
        request,
        record,
        None,
        envelope.raw_artifact_hash,
        envelope.response_artifact_hash,
        envelope.license,
    )


def normalize_scholarly_search_result(
    request: ScholarlySearchRequest,
    envelope: GatewayEnvelope,
    *,
    plan_artifact_hash: str,
) -> ScholarlySearchResult:
    """Normalize one exact captured search response without trusting its prose."""

    if not isinstance(request, ScholarlySearchRequest):
        raise LiteratureError("search normalization requires ScholarlySearchRequest")
    if not isinstance(envelope, GatewayEnvelope):
        raise LiteratureError("search normalization requires GatewayEnvelope")
    _require_hash(plan_artifact_hash, "scholarly search plan_artifact_hash")
    if envelope.source is not request.source or envelope.request_id != request.request_id:
        raise LiteratureError("scholarly search response is not bound to its request")
    if envelope.status is not RetrievalStatus.AVAILABLE:
        return ScholarlySearchResult(
            plan_sha256=request.plan_sha256,
            plan_artifact_hash=plan_artifact_hash,
            request=request,
            status=envelope.status,
            hits=(),
            raw_artifact_hash=envelope.raw_artifact_hash,
            response_artifact_hash=envelope.response_artifact_hash,
            failure_reason=envelope.failure_reason,
        )
    payload = envelope.payload_dict
    if payload is None:
        raise LiteratureError("available scholarly search response omits payload")
    _exact_keys(
        payload,
        frozenset({"next_cursor", "results"}),
        "scholarly search response payload",
    )
    if payload["next_cursor"] is not None:
        raise LiteratureError("single-page scholarly search cannot claim an unconsumed cursor")
    values = payload["results"]
    if not isinstance(values, (list, tuple)):
        raise LiteratureError("scholarly search results must be a list")
    if len(values) > request.max_results:
        raise LiteratureError("scholarly search response exceeds the requested result bound")
    hits: list[ScholarlySearchHit] = []
    for rank, item in enumerate(values, start=1):
        _exact_keys(
            item,
            frozenset({"identifier", "identifier_kind", "title"}),
            "scholarly search result item",
        )
        hits.append(
            ScholarlySearchHit(
                source=request.source,
                identifier=ScholarlyIdentifier(
                    item["identifier_kind"],
                    item["identifier"],
                ),
                title=item["title"],
                rank=rank,
            )
        )
    return ScholarlySearchResult(
        plan_sha256=request.plan_sha256,
        plan_artifact_hash=plan_artifact_hash,
        request=request,
        status=RetrievalStatus.AVAILABLE,
        hits=tuple(hits),
        raw_artifact_hash=envelope.raw_artifact_hash,
        response_artifact_hash=envelope.response_artifact_hash,
    )


def execute_scholarly_search(
    plan: ScholarlySearchPlan,
    gateway: LiteratureGateway,
    *,
    source: ScholarlySource,
    plan_artifact_hash: str,
) -> ScholarlySearchResult:
    """Execute one bounded plan request through the injected audited gateway."""

    if not isinstance(plan, ScholarlySearchPlan):
        raise LiteratureError("scholarly search execution requires a typed plan")
    if not isinstance(gateway, LiteratureGateway):
        raise LiteratureError("scholarly search execution requires LiteratureGateway")
    request = ScholarlySearchRequest.from_plan(plan, source)
    try:
        captured = gateway.fetch(request)
    except Exception as exc:
        return ScholarlySearchResult(
            plan_sha256=plan.sha256,
            plan_artifact_hash=plan_artifact_hash,
            request=request,
            status=RetrievalStatus.FAILED,
            hits=(),
            raw_artifact_hash=None,
            response_artifact_hash=None,
            failure_reason=f"gateway failure: {type(exc).__name__}",
        )
    captured_raw_hash = _captured_custody_hash(captured, "raw_artifact_hash")
    captured_response_hash = _captured_custody_hash(
        captured,
        "response_artifact_hash",
    )
    try:
        if isinstance(captured, GatewayEnvelope):
            envelope = captured
        elif isinstance(captured, CapturedGatewayResponse):
            envelope = GatewayEnvelope(
                source=captured.source,
                request_id=captured.request_id,
                status=captured.status,
                payload=captured.payload,
                raw_artifact_hash=captured.raw_artifact_hash,
                response_artifact_hash=captured.response_artifact_hash,
                failure_reason=captured.failure_reason,
                license=captured.license,
                full_text_status=getattr(captured, "full_text_status", None),
            )
        else:
            raise LiteratureError("gateway response does not satisfy captured protocol")
        return normalize_scholarly_search_result(
            request,
            envelope,
            plan_artifact_hash=plan_artifact_hash,
        )
    except (LiteratureError, TypeError, ValueError, KeyError) as exc:
        return ScholarlySearchResult(
            plan_sha256=plan.sha256,
            plan_artifact_hash=plan_artifact_hash,
            request=request,
            status=RetrievalStatus.MALFORMED,
            hits=(),
            raw_artifact_hash=captured_raw_hash,
            response_artifact_hash=captured_response_hash,
            failure_reason=f"search normalization failed: {exc}",
        )


def _conflict_value(record: ScholarlyRecord, field_name: str, value: Any) -> ProvenancedValue:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True) if not isinstance(value, str) else value
    return ProvenancedValue(
        record.source,
        rendered.casefold() if isinstance(rendered, str) else str(rendered),
        rendered,
        record.response_artifact_hash or record.parent_artifact_hashes[0],
    )


def merge_scholarly_records(records: Sequence[ScholarlyRecord]) -> ScholarlyRecord:
    """Merge records deterministically while retaining every disagreement."""

    if not isinstance(records, Sequence) or not records:
        raise LiteratureError("at least one scholarly record is required")
    if not all(isinstance(record, ScholarlyRecord) for record in records):
        raise LiteratureError("merge input contains a malformed scholarly record")
    ordered = tuple(
        sorted(
            records,
            key=lambda record: (
                record.source.value,
                record.source_record_id,
                record.request_id,
                record.response_artifact_hash or "",
                record.raw_artifact_hash or "",
            ),
        )
    )
    # A merge is an identity assertion, not a metadata-similarity heuristic.
    # Require the graph formed by exact shared normalized identifiers to be
    # connected; this permits DOI->PMID->PMCID transitive joins without ever
    # merging unrelated works merely because their titles or authors resemble
    # one another.
    identity_sets = tuple(
        {
            identifier
            for identifier in record.identifiers
            if f"identifier.{identifier.kind.value}" not in record.conflicted_fields
        }
        for record in ordered
    )
    reached = {0}
    frontier = [0]
    while frontier:
        current = frontier.pop()
        for index, identifiers_for_record in enumerate(identity_sets):
            if index not in reached and identity_sets[current].intersection(identifiers_for_record):
                reached.add(index)
                frontier.append(index)
    if len(reached) != len(ordered):
        raise LiteratureError("scholarly records do not share a connected identifier identity")
    conflicts: list[MetadataConflict] = [conflict for record in ordered for conflict in record.conflicts]

    def choose(field_name: str, *, normalize: Any = lambda value: value) -> Any:
        present = [(record, getattr(record, field_name)) for record in ordered if getattr(record, field_name) not in (None, (), "")]
        if not present:
            return None
        groups: dict[Any, list[tuple[ScholarlyRecord, Any]]] = {}
        for record, value in present:
            groups.setdefault(normalize(value), []).append((record, value))
        if len(groups) > 1:
            candidates = tuple(
                _conflict_value(record, field_name, value)
                for record, value in present
            )
            # Candidates can repeat; the conflict constructor requires at least
            # two distinct normalized values, which the groups already prove.
            conflicts.append(MetadataConflict(field_name, candidates))
        return present[0][1]

    title = choose("title", normalize=_match_text)
    authors = choose("authors", normalize=lambda values: tuple(_match_text(value) for value in values)) or ()
    year = choose("publication_year")
    venue = choose("venue", normalize=_match_text)
    abstract = choose("abstract", normalize=_match_text)
    license_value = choose("license", normalize=_match_text)
    identifiers = tuple(
        sorted(
            {identifier for record in ordered for identifier in record.identifiers},
            key=lambda item: (item.kind.value, item.value),
        )
    )
    for kind in IdentifierKind:
        candidates = [
            (record, identifier)
            for record in ordered
            for identifier in record.identifiers
            if identifier.kind is kind
        ]
        if len({identifier.value for _, identifier in candidates}) > 1:
            conflicts.append(
                MetadataConflict(
                    f"identifier.{kind.value}",
                    tuple(
                        ProvenancedValue(
                            record.source,
                            identifier.value,
                            identifier.value,
                            record.response_artifact_hash or record.parent_artifact_hashes[0],
                        )
                        for record, identifier in candidates
                    ),
                )
            )
    passages = tuple(
        sorted(
            {passage for record in ordered for passage in record.passages},
            key=lambda passage: (
                passage.source_artifact_hash,
                passage.section_id,
                passage.passage_id,
                passage.start_char,
            ),
        )
    )
    parents = tuple(sorted({value for record in ordered for value in record.parent_artifact_hashes}))
    request_id = _sha256(_canonical_json([record.request_id for record in ordered]))
    source_record_id = "merged:" + _sha256(
        _canonical_json(
            [(identifier.kind.value, identifier.value) for identifier in identifiers]
        )
    )[:24]
    conflict_candidates: dict[str, dict[tuple[str, str, str, str], ProvenancedValue]] = {}
    for conflict in conflicts:
        field_candidates = conflict_candidates.setdefault(conflict.field_name, {})
        for candidate in conflict.candidates:
            key = (
                candidate.source.value,
                candidate.normalized_value,
                candidate.raw_value,
                candidate.response_artifact_hash,
            )
            field_candidates[key] = candidate
    merged_conflicts = tuple(
        MetadataConflict(
            field_name,
            tuple(candidates[key] for key in sorted(candidates)),
        )
        for field_name, candidates in sorted(conflict_candidates.items())
        if len({candidate.normalized_value for candidate in candidates.values()}) > 1
    )
    if passages:
        merged_full_text_status = FullTextStatus.AVAILABLE
    elif any(
        record.full_text_status is FullTextStatus.LICENSE_RESTRICTED for record in ordered
    ):
        merged_full_text_status = FullTextStatus.LICENSE_RESTRICTED
    elif any(record.full_text_status is FullTextStatus.UNAVAILABLE for record in ordered):
        merged_full_text_status = FullTextStatus.UNAVAILABLE
    else:
        merged_full_text_status = FullTextStatus.METADATA_ONLY
    return ScholarlyRecord(
        source=ScholarlySource.MERGED,
        source_record_id=source_record_id,
        identifiers=identifiers,
        title=title,
        authors=authors,
        publication_year=year,
        venue=venue,
        abstract=abstract,
        roles=tuple(role for record in ordered for role in record.roles),
        full_text_status=merged_full_text_status,
        passages=passages,
        request_id=request_id,
        raw_artifact_hash=None,
        response_artifact_hash=None,
        parent_artifact_hashes=parents,
        license=license_value,
        conflicts=merged_conflicts,
    )


_CITATION_NODE_RE = re.compile(r"^citation-node:[0-9a-f]{64}$")
_CITATION_WORK_RE = re.compile(r"^citation-work:[0-9a-f]{64}$")
_CITATION_IDENTITY_ORDER = (
    IdentifierKind.DOI,
    IdentifierKind.PMCID,
    IdentifierKind.PMID,
    IdentifierKind.ARXIV,
    IdentifierKind.OPENALEX,
    IdentifierKind.SEMANTIC_SCHOLAR,
)
_CITATION_GRAPH_SOURCES = frozenset(
    {ScholarlySource.OPENALEX, ScholarlySource.SEMANTIC_SCHOLAR}
)


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    if not isinstance(value, Mapping):
        raise LiteratureError(f"{name} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise LiteratureError(f"{name} fields are invalid: {'; '.join(detail)}")


def scholarly_record_sha256(record: ScholarlyRecord) -> str:
    """Hash all normalized record content without treating it as trusted control."""

    if not isinstance(record, ScholarlyRecord):
        raise LiteratureError("record must be ScholarlyRecord")
    payload = {
        "source": record.source.value,
        "source_record_id": record.source_record_id,
        "identifiers": [
            {"kind": identifier.kind.value, "value": identifier.value}
            for identifier in record.identifiers
        ],
        "title": record.title,
        "authors": list(record.authors),
        "publication_year": record.publication_year,
        "venue": record.venue,
        "abstract": record.abstract,
        "roles": [role.value for role in record.roles],
        "full_text_status": record.full_text_status.value,
        "passages": [
            {
                "section_id": passage.section_id,
                "passage_id": passage.passage_id,
                "start_char": passage.start_char,
                "end_char": passage.end_char,
                "passage_sha256": passage.passage_sha256,
                "locator_sha256": passage.locator_sha256,
                "context_sha256": passage.context_sha256,
                "source_artifact_hash": passage.source_artifact_hash,
            }
            for passage in record.passages
        ],
        "request_id": record.request_id,
        "raw_artifact_hash": record.raw_artifact_hash,
        "response_artifact_hash": record.response_artifact_hash,
        "parent_artifact_hashes": list(record.parent_artifact_hashes),
        "license": record.license,
        "conflicts": [
            {
                "field_name": conflict.field_name,
                "candidates": [
                    {
                        "source": candidate.source.value,
                        "normalized_value": candidate.normalized_value,
                        "raw_value": candidate.raw_value,
                        "response_artifact_hash": candidate.response_artifact_hash,
                    }
                    for candidate in conflict.candidates
                ],
            }
            for conflict in record.conflicts
        ],
        "untrusted_evidence": record.untrusted_evidence,
    }
    return _sha256(_canonical_json(payload))


def _citation_work_key(identifiers: tuple[ScholarlyIdentifier, ...]) -> str:
    for kind in _CITATION_IDENTITY_ORDER:
        values = sorted(
            identifier.value for identifier in identifiers if identifier.kind is kind
        )
        if values:
            return "citation-work:" + _sha256(
                _canonical_json({"kind": kind.value, "value": values[0]})
            )
    raise LiteratureError("citation graph node requires a stable scholarly identifier")


def _citation_node_id(source: ScholarlySource, source_record_id: str) -> str:
    """Stable occurrence identity; identifier enrichment cannot rewrite it."""

    return "citation-node:" + _sha256(
        _canonical_json(
            {"source": source.value, "source_record_id": source_record_id}
        )
    )


@dataclass(frozen=True, slots=True)
class CitationGraphNode:
    """Persistable, provenance-bound view of one normalized scholarly work."""

    node_id: str
    source: ScholarlySource
    source_record_id: str
    identifiers: tuple[ScholarlyIdentifier, ...]
    title: str
    publication_year: int | None
    full_text_status: FullTextStatus
    request_id: str
    record_sha256: str
    parent_artifact_hashes: tuple[str, ...]
    canonical_work_key: str = field(init=False)
    untrusted_evidence: bool = True
    schema_version: str = "citation-graph-node/v1"

    def __post_init__(self) -> None:
        try:
            source = (
                self.source
                if isinstance(self.source, ScholarlySource)
                else ScholarlySource(self.source)
            )
            full_text = (
                self.full_text_status
                if isinstance(self.full_text_status, FullTextStatus)
                else FullTextStatus(self.full_text_status)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation graph node source/status is invalid") from exc
        if not isinstance(self.identifiers, tuple) or not self.identifiers:
            raise LiteratureError("citation graph node requires identifiers")
        if not all(isinstance(value, ScholarlyIdentifier) for value in self.identifiers):
            raise LiteratureError("citation graph node identifiers are malformed")
        identifiers = tuple(
            sorted(set(self.identifiers), key=lambda item: (item.kind.value, item.value))
        )
        source_record_id = _clean_text(self.source_record_id, "citation source_record_id")
        assert source_record_id is not None
        expected_node_id = _citation_node_id(source, source_record_id)
        if self.node_id != expected_node_id or _CITATION_NODE_RE.fullmatch(self.node_id) is None:
            raise LiteratureError("citation graph node identity does not match its source occurrence")
        work_key = _citation_work_key(identifiers)
        title = _clean_text(self.title, "citation node title")
        if self.publication_year is not None and (
            isinstance(self.publication_year, bool)
            or not isinstance(self.publication_year, int)
            or not 1000 <= self.publication_year <= 3000
        ):
            raise LiteratureError("citation node publication_year is invalid")
        _require_hash(self.request_id, "citation node request_id")
        _require_hash(self.record_sha256, "citation node record_sha256")
        if not isinstance(self.parent_artifact_hashes, tuple) or not self.parent_artifact_hashes:
            raise LiteratureError("citation graph node requires provenance parents")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        if len(parents) != len(self.parent_artifact_hashes):
            raise LiteratureError("citation graph node provenance parents must be unique")
        for parent in parents:
            _require_hash(parent, "citation node parent_artifact_hash")
        if self.untrusted_evidence is not True:
            raise LiteratureError("citation graph nodes remain untrusted evidence")
        if self.schema_version != "citation-graph-node/v1":
            raise LiteratureError("unsupported citation graph node schema")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "source_record_id", source_record_id)
        object.__setattr__(self, "identifiers", identifiers)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "full_text_status", full_text)
        object.__setattr__(self, "parent_artifact_hashes", parents)
        object.__setattr__(self, "canonical_work_key", work_key)

    @classmethod
    def from_record(cls, record: ScholarlyRecord) -> CitationGraphNode:
        if not isinstance(record, ScholarlyRecord):
            raise LiteratureError("citation graph node requires ScholarlyRecord")
        return cls(
            node_id=_citation_node_id(record.source, record.source_record_id),
            source=record.source,
            source_record_id=record.source_record_id,
            identifiers=record.identifiers,
            title=record.title,
            publication_year=record.publication_year,
            full_text_status=record.full_text_status,
            request_id=record.request_id,
            record_sha256=scholarly_record_sha256(record),
            parent_artifact_hashes=record.parent_artifact_hashes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "node_id": self.node_id,
            "canonical_work_key": self.canonical_work_key,
            "source": self.source.value,
            "source_record_id": self.source_record_id,
            "identifiers": [
                {"kind": value.kind.value, "value": value.value}
                for value in self.identifiers
            ],
            "title": self.title,
            "publication_year": self.publication_year,
            "full_text_status": self.full_text_status.value,
            "request_id": self.request_id,
            "record_sha256": self.record_sha256,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
            "untrusted_evidence": self.untrusted_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationGraphNode:
        expected = frozenset(
            {
                "schema_version",
                "node_id",
                "canonical_work_key",
                "source",
                "source_record_id",
                "identifiers",
                "title",
                "publication_year",
                "full_text_status",
                "request_id",
                "record_sha256",
                "parent_artifact_hashes",
                "untrusted_evidence",
            }
        )
        _exact_keys(value, expected, "citation graph node")
        identifier_values = value["identifiers"]
        if not isinstance(identifier_values, (list, tuple)):
            raise LiteratureError("citation graph node identifiers must be a list")
        identifiers = []
        for item in identifier_values:
            _exact_keys(item, frozenset({"kind", "value"}), "citation identifier")
            identifiers.append(ScholarlyIdentifier(item["kind"], item["value"]))
        parents = value["parent_artifact_hashes"]
        if not isinstance(parents, (list, tuple)):
            raise LiteratureError("citation graph node parents must be a list")
        node = cls(
            node_id=value["node_id"],
            source=value["source"],
            source_record_id=value["source_record_id"],
            identifiers=tuple(identifiers),
            title=value["title"],
            publication_year=value["publication_year"],
            full_text_status=value["full_text_status"],
            request_id=value["request_id"],
            record_sha256=value["record_sha256"],
            parent_artifact_hashes=tuple(parents),
            untrusted_evidence=value["untrusted_evidence"],
            schema_version=value["schema_version"],
        )
        if value["canonical_work_key"] != node.canonical_work_key:
            raise LiteratureError("citation graph work identity was tampered")
        return node


@dataclass(frozen=True, slots=True, order=True)
class CitationEdgeObservation:
    """Atomic source/request/artifact binding for one observed citation."""

    source: ScholarlySource
    request_id: str
    evidence_artifact_hash: str

    def __post_init__(self) -> None:
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation edge observation source is invalid") from exc
        if source is ScholarlySource.MERGED:
            raise LiteratureError("merged state cannot assert an external citation edge")
        _require_hash(self.request_id, "citation edge observation request_id")
        _require_hash(
            self.evidence_artifact_hash,
            "citation edge observation evidence_artifact_hash",
        )
        object.__setattr__(self, "source", source)

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source.value,
            "request_id": self.request_id,
            "evidence_artifact_hash": self.evidence_artifact_hash,
        }


@dataclass(frozen=True, slots=True)
class CitationGraphEdge:
    """One citations relation with non-spliceable captured observations."""

    citing_node_id: str
    cited_node_id: str
    observations: tuple[CitationEdgeObservation, ...]
    edge_id: str = field(init=False)
    schema_version: str = "citation-graph-edge/v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.citing_node_id, str)
            or _CITATION_NODE_RE.fullmatch(self.citing_node_id) is None
            or not isinstance(self.cited_node_id, str)
            or _CITATION_NODE_RE.fullmatch(self.cited_node_id) is None
        ):
            raise LiteratureError("citation edge contains an invalid node identity")
        if not isinstance(self.observations, tuple) or not self.observations:
            raise LiteratureError("citation edge requires evidence provenance")
        if not all(isinstance(value, CitationEdgeObservation) for value in self.observations):
            raise LiteratureError("citation edge observations are malformed")
        observations = tuple(sorted(self.observations))
        if len(set(observations)) != len(observations):
            raise LiteratureError("citation edge observations must be unique")
        if self.schema_version != "citation-graph-edge/v1":
            raise LiteratureError("unsupported citation graph edge schema")
        edge_id = _sha256(
            _canonical_json(
                {
                    "schema_version": self.schema_version,
                    "citing_node_id": self.citing_node_id,
                    "cited_node_id": self.cited_node_id,
                }
            )
        )
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "edge_id", edge_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "edge_id": self.edge_id,
            "citing_node_id": self.citing_node_id,
            "cited_node_id": self.cited_node_id,
            "observations": [value.to_dict() for value in self.observations],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationGraphEdge:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "edge_id",
                    "citing_node_id",
                    "cited_node_id",
                    "observations",
                }
            ),
            "citation graph edge",
        )
        observations = value["observations"]
        if not isinstance(observations, (list, tuple)):
            raise LiteratureError("citation graph edge observations must be a list")
        parsed_observations = []
        for observation in observations:
            _exact_keys(
                observation,
                frozenset({"source", "request_id", "evidence_artifact_hash"}),
                "citation edge observation",
            )
            parsed_observations.append(
                CitationEdgeObservation(
                    source=observation["source"],
                    request_id=observation["request_id"],
                    evidence_artifact_hash=observation["evidence_artifact_hash"],
                )
            )
        edge = cls(
            citing_node_id=value["citing_node_id"],
            cited_node_id=value["cited_node_id"],
            observations=tuple(parsed_observations),
            schema_version=value["schema_version"],
        )
        if value["edge_id"] != edge.edge_id:
            raise LiteratureError("citation graph edge identity was tampered")
        return edge


@dataclass(frozen=True, slots=True)
class CitationGraph:
    """Immutable citation snapshot that preserves and reports observed cycles."""

    nodes: tuple[CitationGraphNode, ...]
    edges: tuple[CitationGraphEdge, ...]
    cycle_node_ids: tuple[str, ...] = field(init=False)
    schema_version: str = "citation-graph/v2"

    def __post_init__(self) -> None:
        if not isinstance(self.nodes, tuple) or not self.nodes:
            raise LiteratureError("citation graph requires at least one node")
        if len(self.nodes) > _MAX_JSON_ITEMS:
            raise LiteratureError("citation graph node count exceeds the bound")
        if not all(isinstance(value, CitationGraphNode) for value in self.nodes):
            raise LiteratureError("citation graph nodes are malformed")
        if not isinstance(self.edges, tuple) or not all(
            isinstance(value, CitationGraphEdge) for value in self.edges
        ):
            raise LiteratureError("citation graph edges are malformed")
        if len(self.edges) > _MAX_JSON_ITEMS:
            raise LiteratureError("citation graph edge count exceeds the bound")
        node_ids = tuple(value.node_id for value in self.nodes)
        if len(set(node_ids)) != len(node_ids):
            raise LiteratureError("citation graph contains duplicate nodes")
        node_id_set = set(node_ids)
        relationships = tuple(
            (value.citing_node_id, value.cited_node_id) for value in self.edges
        )
        if len(set(relationships)) != len(relationships):
            raise LiteratureError("citation graph contains duplicate relationships")
        unknown = {
            node_id
            for edge in self.edges
            for node_id in (edge.citing_node_id, edge.cited_node_id)
            if node_id not in node_id_set
        }
        if unknown:
            raise LiteratureError("citation graph edge references an unknown node")
        adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
        for edge in self.edges:
            adjacency[edge.citing_node_id].add(edge.cited_node_id)
        colors = {node_id: 0 for node_id in node_ids}
        cycle_nodes: set[str] = set()
        for start in sorted(node_ids):
            if colors[start] != 0:
                continue
            path: list[str] = [start]
            path_positions = {start: 0}
            colors[start] = 1
            stack: list[tuple[str, object]] = [
                (start, iter(sorted(adjacency[start])))
            ]
            while stack:
                current, children = stack[-1]
                try:
                    child = next(children)  # type: ignore[arg-type]
                except StopIteration:
                    stack.pop()
                    colors[current] = 2
                    path_positions.pop(current, None)
                    if path and path[-1] == current:
                        path.pop()
                    continue
                if colors[child] == 0:
                    colors[child] = 1
                    path_positions[child] = len(path)
                    path.append(child)
                    stack.append((child, iter(sorted(adjacency[child]))))
                elif colors[child] == 1:
                    cycle_nodes.update(path[path_positions[child] :])
        if self.schema_version != "citation-graph/v2":
            raise LiteratureError("unsupported citation graph schema")
        object.__setattr__(self, "nodes", tuple(sorted(self.nodes, key=lambda value: value.node_id)))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=lambda value: value.edge_id)))
        object.__setattr__(self, "cycle_node_ids", tuple(sorted(cycle_nodes)))
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "citation graph",
            reserved_parent_slots=1,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "nodes": [value.to_dict() for value in self.nodes],
            "edges": [value.to_dict() for value in self.edges],
            "cycle_node_ids": list(self.cycle_node_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationGraph:
        _exact_keys(
            value,
            frozenset({"schema_version", "nodes", "edges", "cycle_node_ids"}),
            "citation graph",
        )
        nodes = value["nodes"]
        edges = value["edges"]
        if not isinstance(nodes, (list, tuple)) or not isinstance(edges, (list, tuple)):
            raise LiteratureError("citation graph nodes and edges must be lists")
        cycle_node_ids = value["cycle_node_ids"]
        if not isinstance(cycle_node_ids, (list, tuple)):
            raise LiteratureError("citation graph cycle findings must be a list")
        graph = cls(
            nodes=tuple(CitationGraphNode.from_dict(item) for item in nodes),
            edges=tuple(CitationGraphEdge.from_dict(item) for item in edges),
            schema_version=value["schema_version"],
        )
        if tuple(cycle_node_ids) != graph.cycle_node_ids:
            raise LiteratureError("citation graph topology findings were tampered")
        return graph

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    artifact_hash
                    for node in self.nodes
                    for artifact_hash in node.parent_artifact_hashes
                }
                | {
                    observation.evidence_artifact_hash
                    for edge in self.edges
                    for observation in edge.observations
                }
            )
        )

    @property
    def has_cycles(self) -> bool:
        return bool(self.cycle_node_ids)


@dataclass(frozen=True, slots=True)
class CitationExpansionPolicy:
    """Scientific ceilings for planning citation traversal.

    Execution additionally enforces the artifact registry's content-addressed
    parent ceiling.  If provenance fan-in becomes the effective lower bound,
    it stops before gateway I/O with a typed persistence-budget truncation;
    these larger scientific node/edge limits are not a persistence promise.
    """

    allowed_sources: tuple[ScholarlySource, ...] = (
        ScholarlySource.OPENALEX,
        ScholarlySource.SEMANTIC_SCHOLAR,
    )
    traversals: tuple[CitationTraversal, ...] = (
        CitationTraversal.REFERENCES,
        CitationTraversal.CITED_BY,
    )
    max_requests: int = 64
    max_depth: int = 2
    max_pages_per_task: int = 2
    max_total_page_requests: int = 128
    max_nodes: int = 4096
    max_edges: int = 8192
    schema_version: str = "citation-expansion-policy/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_sources, tuple) or not self.allowed_sources:
            raise LiteratureError("citation expansion requires allowed sources")
        try:
            sources = tuple(
                value if isinstance(value, ScholarlySource) else ScholarlySource(value)
                for value in self.allowed_sources
            )
            traversals = tuple(
                value if isinstance(value, CitationTraversal) else CitationTraversal(value)
                for value in self.traversals
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation expansion policy contains an invalid enum") from exc
        if len(set(sources)) != len(sources) or not set(sources).issubset(_CITATION_GRAPH_SOURCES):
            raise LiteratureError("citation expansion source lacks an approved graph adapter")
        if not traversals or len(set(traversals)) != len(traversals):
            raise LiteratureError("citation expansion traversals must be unique and non-empty")
        for name in (
            "max_requests",
            "max_depth",
            "max_pages_per_task",
            "max_total_page_requests",
            "max_nodes",
            "max_edges",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise LiteratureError(f"{name} must be a positive integer")
        if self.schema_version != "citation-expansion-policy/v1":
            raise LiteratureError("unsupported citation expansion policy schema")
        object.__setattr__(self, "allowed_sources", tuple(sorted(sources, key=lambda value: value.value)))
        object.__setattr__(self, "traversals", tuple(sorted(traversals, key=lambda value: value.value)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allowed_sources": [value.value for value in self.allowed_sources],
            "traversals": [value.value for value in self.traversals],
            "max_requests": self.max_requests,
            "max_depth": self.max_depth,
            "max_pages_per_task": self.max_pages_per_task,
            "max_total_page_requests": self.max_total_page_requests,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationExpansionPolicy:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "allowed_sources",
                    "traversals",
                    "max_requests",
                    "max_depth",
                    "max_pages_per_task",
                    "max_total_page_requests",
                    "max_nodes",
                    "max_edges",
                }
            ),
            "citation expansion policy",
        )
        sources = value["allowed_sources"]
        traversals = value["traversals"]
        if not isinstance(sources, (list, tuple)) or not isinstance(traversals, (list, tuple)):
            raise LiteratureError("citation expansion policy collections must be lists")
        return cls(
            allowed_sources=tuple(sources),
            traversals=tuple(traversals),
            max_requests=value["max_requests"],
            max_depth=value["max_depth"],
            max_pages_per_task=value["max_pages_per_task"],
            max_total_page_requests=value["max_total_page_requests"],
            max_nodes=value["max_nodes"],
            max_edges=value["max_edges"],
            schema_version=value["schema_version"],
        )

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True, slots=True)
class CitationExpansionTask:
    origin_node_id: str
    traversal: CitationTraversal
    request: ScholarlyRequest
    depth: int
    acquisition_request_ids: tuple[str, ...]
    parent_artifact_hashes: tuple[str, ...]
    task_id: str = field(init=False)
    schema_version: str = "citation-expansion-task/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.origin_node_id, str) or _CITATION_NODE_RE.fullmatch(self.origin_node_id) is None:
            raise LiteratureError("citation expansion origin node is invalid")
        try:
            traversal = (
                self.traversal
                if isinstance(self.traversal, CitationTraversal)
                else CitationTraversal(self.traversal)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation expansion traversal is invalid") from exc
        if not isinstance(self.request, ScholarlyRequest):
            raise LiteratureError("citation expansion task requires ScholarlyRequest")
        expected_operation = {
            CitationTraversal.REFERENCES: "expand_references",
            CitationTraversal.CITED_BY: "expand_citations",
        }[traversal]
        if self.request.operation != expected_operation:
            raise LiteratureError("citation expansion request operation is inconsistent")
        if self.request.source not in _CITATION_GRAPH_SOURCES:
            raise LiteratureError("citation expansion request source is not approved")
        if isinstance(self.depth, bool) or not isinstance(self.depth, int) or self.depth <= 0:
            raise LiteratureError("citation expansion depth must be positive")
        if not isinstance(self.acquisition_request_ids, tuple) or not self.acquisition_request_ids:
            raise LiteratureError("citation expansion task requires acquisition provenance")
        acquisition_ids = tuple(sorted(set(self.acquisition_request_ids)))
        if len(acquisition_ids) != len(self.acquisition_request_ids):
            raise LiteratureError("citation expansion acquisition IDs must be unique")
        for value in acquisition_ids:
            _require_hash(value, "citation expansion acquisition_request_id")
        if not isinstance(self.parent_artifact_hashes, tuple) or not self.parent_artifact_hashes:
            raise LiteratureError("citation expansion task requires artifact provenance")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        if len(parents) != len(self.parent_artifact_hashes):
            raise LiteratureError("citation expansion parent hashes must be unique")
        for value in parents:
            _require_hash(value, "citation expansion parent_artifact_hash")
        if self.schema_version != "citation-expansion-task/v1":
            raise LiteratureError("unsupported citation expansion task schema")
        task_id = _sha256(
            _canonical_json(
                {
                    "schema_version": self.schema_version,
                    "origin_node_id": self.origin_node_id,
                    "traversal": traversal.value,
                    "request_id": self.request.request_id,
                    "depth": self.depth,
                }
            )
        )
        object.__setattr__(self, "traversal", traversal)
        object.__setattr__(self, "acquisition_request_ids", acquisition_ids)
        object.__setattr__(self, "parent_artifact_hashes", parents)
        object.__setattr__(self, "task_id", task_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "origin_node_id": self.origin_node_id,
            "traversal": self.traversal.value,
            "request": {
                "source": self.request.source.value,
                "operation": self.request.operation,
                "identifier": {
                    "kind": self.request.identifier.kind.value,
                    "value": self.request.identifier.value,
                },
                "request_id": self.request.request_id,
            },
            "depth": self.depth,
            "acquisition_request_ids": list(self.acquisition_request_ids),
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationExpansionTask:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "task_id",
                    "origin_node_id",
                    "traversal",
                    "request",
                    "depth",
                    "acquisition_request_ids",
                    "parent_artifact_hashes",
                }
            ),
            "citation expansion task",
        )
        request_value = value["request"]
        _exact_keys(
            request_value,
            frozenset({"source", "operation", "identifier", "request_id"}),
            "citation expansion request",
        )
        identifier_value = request_value["identifier"]
        _exact_keys(
            identifier_value,
            frozenset({"kind", "value"}),
            "citation expansion request identifier",
        )
        request = ScholarlyRequest(
            request_value["source"],
            request_value["operation"],
            ScholarlyIdentifier(identifier_value["kind"], identifier_value["value"]),
        )
        if request.request_id != request_value["request_id"]:
            raise LiteratureError("citation expansion request identity was tampered")
        acquisition_ids = value["acquisition_request_ids"]
        parents = value["parent_artifact_hashes"]
        if not isinstance(acquisition_ids, (list, tuple)) or not isinstance(parents, (list, tuple)):
            raise LiteratureError("citation expansion task provenance must be lists")
        task = cls(
            origin_node_id=value["origin_node_id"],
            traversal=value["traversal"],
            request=request,
            depth=value["depth"],
            acquisition_request_ids=tuple(acquisition_ids),
            parent_artifact_hashes=tuple(parents),
            schema_version=value["schema_version"],
        )
        if task.task_id != value["task_id"]:
            raise LiteratureError("citation expansion task identity was tampered")
        return task


@dataclass(frozen=True, slots=True)
class CitationExpansionPlan:
    policy: CitationExpansionPolicy
    acquired_request_ids: tuple[str, ...]
    tasks: tuple[CitationExpansionTask, ...]
    deferred_tasks: tuple[CitationExpansionTask, ...]
    schema_version: str = "citation-expansion-plan/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.policy, CitationExpansionPolicy):
            raise LiteratureError("citation expansion plan requires a policy")
        if not isinstance(self.acquired_request_ids, tuple):
            raise LiteratureError("citation expansion acquired IDs must be a tuple")
        acquired = tuple(sorted(set(self.acquired_request_ids)))
        if len(acquired) != len(self.acquired_request_ids):
            raise LiteratureError("citation expansion acquired IDs must be unique")
        for value in acquired:
            _require_hash(value, "citation expansion acquired_request_id")
        if not isinstance(self.tasks, tuple) or not all(
            isinstance(value, CitationExpansionTask) for value in self.tasks
        ):
            raise LiteratureError("citation expansion tasks are malformed")
        if len(self.tasks) > self.policy.max_requests:
            raise LiteratureError("citation expansion plan exceeds request budget")
        task_ids = tuple(task.task_id for task in self.tasks)
        if len(set(task_ids)) != len(task_ids):
            raise LiteratureError("citation expansion plan contains duplicate tasks")
        for task in self.tasks:
            if task.request.source not in self.policy.allowed_sources:
                raise LiteratureError("citation expansion task violates source policy")
            if task.traversal not in self.policy.traversals:
                raise LiteratureError("citation expansion task violates traversal policy")
            if task.depth > self.policy.max_depth:
                raise LiteratureError("citation expansion task exceeds depth policy")
            if not set(task.acquisition_request_ids).issubset(acquired):
                raise LiteratureError("citation expansion task has unknown acquisition parent")
        if not isinstance(self.deferred_tasks, tuple) or not all(
            isinstance(value, CitationExpansionTask) for value in self.deferred_tasks
        ):
            raise LiteratureError("deferred citation tasks are malformed")
        deferred = tuple(sorted(self.deferred_tasks, key=lambda value: value.task_id))
        deferred_ids = tuple(value.task_id for value in deferred)
        if len(set(deferred_ids)) != len(deferred_ids):
            raise LiteratureError("deferred citation task IDs must be unique")
        if set(task_ids).intersection(deferred_ids):
            raise LiteratureError("a citation task cannot be active and deferred")
        for task in deferred:
            if (
                task.request.source not in self.policy.allowed_sources
                or task.traversal not in self.policy.traversals
                or task.depth > self.policy.max_depth
            ):
                raise LiteratureError("deferred citation task violates policy")
            if not set(task.acquisition_request_ids).issubset(acquired):
                raise LiteratureError("deferred task has unknown acquisition parent")
        if self.schema_version != "citation-expansion-plan/v1":
            raise LiteratureError("unsupported citation expansion plan schema")
        object.__setattr__(self, "acquired_request_ids", acquired)
        object.__setattr__(self, "tasks", tuple(sorted(self.tasks, key=lambda value: value.task_id)))
        object.__setattr__(self, "deferred_tasks", deferred)
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "citation expansion plan",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy": self.policy.to_dict(),
            "policy_sha256": self.policy.sha256,
            "acquired_request_ids": list(self.acquired_request_ids),
            "tasks": [value.to_dict() for value in self.tasks],
            "deferred_tasks": [value.to_dict() for value in self.deferred_tasks],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationExpansionPlan:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "policy",
                    "policy_sha256",
                    "acquired_request_ids",
                    "tasks",
                    "deferred_tasks",
                }
            ),
            "citation expansion plan",
        )
        policy = CitationExpansionPolicy.from_dict(value["policy"])
        if policy.sha256 != value["policy_sha256"]:
            raise LiteratureError("citation expansion policy hash was tampered")
        acquired = value["acquired_request_ids"]
        tasks = value["tasks"]
        deferred = value["deferred_tasks"]
        if not all(isinstance(item, (list, tuple)) for item in (acquired, tasks, deferred)):
            raise LiteratureError("citation expansion plan collections must be lists")
        return cls(
            policy=policy,
            acquired_request_ids=tuple(acquired),
            tasks=tuple(CitationExpansionTask.from_dict(item) for item in tasks),
            deferred_tasks=tuple(
                CitationExpansionTask.from_dict(item) for item in deferred
            ),
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def deferred_task_ids(self) -> tuple[str, ...]:
        return tuple(value.task_id for value in self.deferred_tasks)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    artifact_hash
                    for task in self.tasks + self.deferred_tasks
                    for artifact_hash in task.parent_artifact_hashes
                }
            )
        )


def _expansion_identifier(
    record: ScholarlyRecord,
    source: ScholarlySource,
) -> ScholarlyIdentifier:
    native_kind = {
        ScholarlySource.OPENALEX: IdentifierKind.OPENALEX,
        ScholarlySource.SEMANTIC_SCHOLAR: IdentifierKind.SEMANTIC_SCHOLAR,
    }[source]
    order = (
        native_kind,
        IdentifierKind.DOI,
        IdentifierKind.ARXIV,
        IdentifierKind.PMID,
        IdentifierKind.PMCID,
        IdentifierKind.OPENALEX,
        IdentifierKind.SEMANTIC_SCHOLAR,
    )
    for kind in order:
        matches = sorted(
            (value for value in record.identifiers if value.kind is kind),
            key=lambda value: value.value,
        )
        if matches:
            return matches[0]
    raise LiteratureError("acquired record has no citation-expansion identifier")


def plan_citation_expansion(
    acquisitions: Sequence[AcquisitionResult],
    policy: CitationExpansionPolicy | None = None,
    *,
    depth: int = 1,
) -> CitationExpansionPlan:
    """Deterministically plan bounded gateway requests from captured acquisitions.

    The function performs no I/O.  It emits ordinary ``ScholarlyRequest``
    values for the same audited gateway used by all other adapters.
    """

    if not isinstance(acquisitions, Sequence) or isinstance(acquisitions, (str, bytes)):
        raise LiteratureError("citation expansion acquisitions must be a sequence")
    if len(acquisitions) > _MAX_JSON_ITEMS:
        raise LiteratureError("citation expansion acquisition input is too large")
    selected_policy = policy or CitationExpansionPolicy()
    if not isinstance(selected_policy, CitationExpansionPolicy):
        raise LiteratureError("citation expansion policy is invalid")
    if isinstance(depth, bool) or not isinstance(depth, int) or depth <= 0:
        raise LiteratureError("citation expansion depth must be positive")
    if depth > selected_policy.max_depth:
        raise LiteratureError("citation expansion depth exceeds policy")
    acquisition_ids: set[str] = set()
    task_parts: dict[
        tuple[str, CitationTraversal, str],
        tuple[ScholarlyRequest, set[str], set[str]],
    ] = {}
    for acquisition in acquisitions:
        if not isinstance(acquisition, AcquisitionResult):
            raise LiteratureError("citation expansion contains an invalid acquisition")
        acquisition_ids.add(acquisition.request.request_id)
        if acquisition.status is RetrievalStatus.AVAILABLE:
            if acquisition.record is None:
                raise LiteratureError("available acquisition omits its record")
            record = acquisition.record
            if (
                acquisition.source is not record.source
                or acquisition.request.request_id != record.request_id
                or acquisition.raw_artifact_hash != record.raw_artifact_hash
                or acquisition.response_artifact_hash != record.response_artifact_hash
                or not record.parent_artifact_hashes
            ):
                raise LiteratureError("available acquisition provenance is inconsistent")
            node = CitationGraphNode.from_record(record)
            for source in selected_policy.allowed_sources:
                identifier = _expansion_identifier(record, source)
                for traversal in selected_policy.traversals:
                    operation = {
                        CitationTraversal.REFERENCES: "expand_references",
                        CitationTraversal.CITED_BY: "expand_citations",
                    }[traversal]
                    request = ScholarlyRequest(source, operation, identifier)
                    key = (node.node_id, traversal, request.request_id)
                    if key not in task_parts:
                        task_parts[key] = (request, set(), set())
                    elif (
                        task_parts[key][1] != {acquisition.request.request_id}
                        or task_parts[key][2] != set(record.parent_artifact_hashes)
                    ):
                        raise LiteratureError(
                            "citation expansion origin has ambiguous acquisition provenance"
                        )
                    task_parts[key][1].add(acquisition.request.request_id)
                    task_parts[key][2].update(record.parent_artifact_hashes)
        elif acquisition.record is not None:
            raise LiteratureError("unavailable acquisition must not contain a record")
    candidates = tuple(
        sorted(
            (
                CitationExpansionTask(
                    origin_node_id=key[0],
                    traversal=key[1],
                    request=parts[0],
                    depth=depth,
                    acquisition_request_ids=tuple(sorted(parts[1])),
                    parent_artifact_hashes=tuple(sorted(parts[2])),
                )
                for key, parts in task_parts.items()
            ),
            key=lambda value: value.task_id,
        )
    )
    active = candidates[: selected_policy.max_requests]
    deferred = candidates[selected_policy.max_requests :]
    return CitationExpansionPlan(
        policy=selected_policy,
        acquired_request_ids=tuple(sorted(acquisition_ids)),
        tasks=active,
        deferred_tasks=deferred,
    )


@dataclass(frozen=True, slots=True)
class CitationPageRequest:
    """Versioned page request routed through the same audited gateway."""

    plan_sha256: str
    task_id: str
    source: ScholarlySource
    operation: str
    identifier: ScholarlyIdentifier
    traversal: CitationTraversal
    origin_node_id: str
    depth: int
    page_number: int
    cursor: str | None
    request_id: str = field(init=False)
    schema_version: str = "citation-page-request/v1"

    def __post_init__(self) -> None:
        _require_hash(self.plan_sha256, "citation page plan_sha256")
        _require_hash(self.task_id, "citation page task_id")
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
            traversal = self.traversal if isinstance(self.traversal, CitationTraversal) else CitationTraversal(self.traversal)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation page request enum is invalid") from exc
        if source not in _CITATION_GRAPH_SOURCES:
            raise LiteratureError("citation page request source is not approved")
        operation = _clean_text(self.operation, "citation page operation")
        expected_operation = {
            CitationTraversal.REFERENCES: "expand_references",
            CitationTraversal.CITED_BY: "expand_citations",
        }[traversal]
        if operation != expected_operation:
            raise LiteratureError("citation page request operation is inconsistent")
        if not isinstance(self.identifier, ScholarlyIdentifier):
            raise LiteratureError("citation page request identifier is malformed")
        if not isinstance(self.origin_node_id, str) or _CITATION_NODE_RE.fullmatch(self.origin_node_id) is None:
            raise LiteratureError("citation page origin node is invalid")
        for name in ("depth", "page_number"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise LiteratureError(f"citation page {name} must be positive")
        cursor = _clean_text(self.cursor, "citation page cursor", optional=True)
        if self.schema_version != "citation-page-request/v1":
            raise LiteratureError("unsupported citation page request schema")
        request_id = _sha256(
            _canonical_json(
                {
                    "schema_version": self.schema_version,
                    "plan_sha256": self.plan_sha256,
                    "task_id": self.task_id,
                    "source": source.value,
                    "operation": operation,
                    "identifier": {
                        "kind": self.identifier.kind.value,
                        "value": self.identifier.value,
                    },
                    "traversal": traversal.value,
                    "origin_node_id": self.origin_node_id,
                    "depth": self.depth,
                    "page_number": self.page_number,
                    "cursor": cursor,
                }
            )
        )
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "traversal", traversal)
        object.__setattr__(self, "cursor", cursor)
        object.__setattr__(self, "request_id", request_id)

    @classmethod
    def for_task(
        cls,
        plan: CitationExpansionPlan,
        task: CitationExpansionTask,
        *,
        page_number: int,
        cursor: str | None,
    ) -> CitationPageRequest:
        return cls(
            plan_sha256=plan.sha256,
            task_id=task.task_id,
            source=task.request.source,
            operation=task.request.operation,
            identifier=task.request.identifier,
            traversal=task.traversal,
            origin_node_id=task.origin_node_id,
            depth=task.depth,
            page_number=page_number,
            cursor=cursor,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "plan_sha256": self.plan_sha256,
            "task_id": self.task_id,
            "source": self.source.value,
            "operation": self.operation,
            "identifier": {
                "kind": self.identifier.kind.value,
                "value": self.identifier.value,
            },
            "traversal": self.traversal.value,
            "origin_node_id": self.origin_node_id,
            "depth": self.depth,
            "page_number": self.page_number,
            "cursor": self.cursor,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationPageRequest:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "request_id",
                    "plan_sha256",
                    "task_id",
                    "source",
                    "operation",
                    "identifier",
                    "traversal",
                    "origin_node_id",
                    "depth",
                    "page_number",
                    "cursor",
                }
            ),
            "citation page request",
        )
        identifier = value["identifier"]
        _exact_keys(identifier, frozenset({"kind", "value"}), "citation page identifier")
        request = cls(
            plan_sha256=value["plan_sha256"],
            task_id=value["task_id"],
            source=value["source"],
            operation=value["operation"],
            identifier=ScholarlyIdentifier(identifier["kind"], identifier["value"]),
            traversal=value["traversal"],
            origin_node_id=value["origin_node_id"],
            depth=value["depth"],
            page_number=value["page_number"],
            cursor=value["cursor"],
            schema_version=value["schema_version"],
        )
        if request.request_id != value["request_id"]:
            raise LiteratureError("citation page request identity was tampered")
        return request


@dataclass(frozen=True, slots=True)
class CitationPageCursor:
    task_id: str
    next_page_number: int
    cursor: str | None

    def __post_init__(self) -> None:
        _require_hash(self.task_id, "citation cursor task_id")
        if (
            isinstance(self.next_page_number, bool)
            or not isinstance(self.next_page_number, int)
            or self.next_page_number <= 0
        ):
            raise LiteratureError("citation cursor next_page_number must be positive")
        object.__setattr__(
            self,
            "cursor",
            _clean_text(self.cursor, "citation cursor", optional=True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "next_page_number": self.next_page_number,
            "cursor": self.cursor,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationPageCursor:
        _exact_keys(
            value,
            frozenset({"task_id", "next_page_number", "cursor"}),
            "citation page cursor",
        )
        return cls(value["task_id"], value["next_page_number"], value["cursor"])


@dataclass(frozen=True, slots=True)
class CitationExpansionPageReceipt:
    request: CitationPageRequest
    status: RetrievalStatus
    nodes: tuple[CitationGraphNode, ...]
    edges: tuple[CitationGraphEdge, ...]
    next_cursor: str | None
    raw_artifact_hash: str | None
    response_artifact_hash: str | None
    failure_reason: str | None
    schema_version: str = "citation-expansion-page-receipt/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.request, CitationPageRequest):
            raise LiteratureError("citation page receipt requires CitationPageRequest")
        try:
            status = self.status if isinstance(self.status, RetrievalStatus) else RetrievalStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation page receipt status is invalid") from exc
        if not isinstance(self.nodes, tuple) or not all(isinstance(value, CitationGraphNode) for value in self.nodes):
            raise LiteratureError("citation page receipt nodes are malformed")
        if not isinstance(self.edges, tuple) or not all(isinstance(value, CitationGraphEdge) for value in self.edges):
            raise LiteratureError("citation page receipt edges are malformed")
        if len({value.node_id for value in self.nodes}) != len(self.nodes):
            raise LiteratureError("citation page contains duplicate node occurrences")
        if len({(value.citing_node_id, value.cited_node_id) for value in self.edges}) != len(self.edges):
            raise LiteratureError("citation page contains duplicate relationships")
        next_cursor = _clean_text(self.next_cursor, "citation page next_cursor", optional=True)
        if next_cursor is not None and next_cursor == self.request.cursor:
            raise LiteratureError("citation page replayed its input cursor")
        raw_hash = _require_hash(self.raw_artifact_hash, "citation page raw_artifact_hash", optional=True)
        response_hash = _require_hash(
            self.response_artifact_hash,
            "citation page response_artifact_hash",
            optional=True,
        )
        reason = _clean_text(self.failure_reason, "citation page failure_reason", optional=True)
        if status is RetrievalStatus.AVAILABLE:
            if raw_hash is None or response_hash is None:
                raise LiteratureError("available citation page requires captured provenance")
            if reason is not None:
                raise LiteratureError("available citation page cannot have a failure reason")
            if any(
                node.source is not self.request.source
                or node.request_id != self.request.request_id
                or raw_hash not in node.parent_artifact_hashes
                or response_hash not in node.parent_artifact_hashes
                for node in self.nodes
            ):
                raise LiteratureError(
                    "citation page node is not bound to request/raw/response provenance"
                )
            node_ids = {node.node_id for node in self.nodes}
            expected_relationships = {
                (
                    (self.request.origin_node_id, node_id)
                    if self.request.traversal is CitationTraversal.REFERENCES
                    else (node_id, self.request.origin_node_id)
                )
                for node_id in node_ids
            }
            actual_relationships = {
                (edge.citing_node_id, edge.cited_node_id) for edge in self.edges
            }
            if actual_relationships != expected_relationships:
                raise LiteratureError(
                    "citation page edges do not match request traversal and returned nodes"
                )
            if any(
                len(edge.observations) != 1
                or edge.observations[0].source is not self.request.source
                or edge.observations[0].request_id != self.request.request_id
                or edge.observations[0].evidence_artifact_hash != response_hash
                for edge in self.edges
            ):
                raise LiteratureError(
                    "citation page edge observation is not bound to the response"
                )
        else:
            if self.nodes or self.edges or next_cursor is not None:
                raise LiteratureError("failed citation page cannot contain graph data")
            if reason is None:
                raise LiteratureError("failed citation page requires an explicit reason")
        if self.schema_version != "citation-expansion-page-receipt/v1":
            raise LiteratureError("unsupported citation page receipt schema")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "nodes", tuple(sorted(self.nodes, key=lambda value: value.node_id)))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=lambda value: value.edge_id)))
        object.__setattr__(self, "next_cursor", next_cursor)
        object.__setattr__(self, "raw_artifact_hash", raw_hash)
        object.__setattr__(self, "response_artifact_hash", response_hash)
        object.__setattr__(self, "failure_reason", reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request": self.request.to_dict(),
            "status": self.status.value,
            "nodes": [value.to_dict() for value in self.nodes],
            "edges": [value.to_dict() for value in self.edges],
            "next_cursor": self.next_cursor,
            "raw_artifact_hash": self.raw_artifact_hash,
            "response_artifact_hash": self.response_artifact_hash,
            "failure_reason": self.failure_reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationExpansionPageReceipt:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "request",
                    "status",
                    "nodes",
                    "edges",
                    "next_cursor",
                    "raw_artifact_hash",
                    "response_artifact_hash",
                    "failure_reason",
                }
            ),
            "citation expansion page receipt",
        )
        nodes = value["nodes"]
        edges = value["edges"]
        if not isinstance(nodes, (list, tuple)) or not isinstance(edges, (list, tuple)):
            raise LiteratureError("citation page receipt graph data must be lists")
        return cls(
            request=CitationPageRequest.from_dict(value["request"]),
            status=value["status"],
            nodes=tuple(CitationGraphNode.from_dict(item) for item in nodes),
            edges=tuple(CitationGraphEdge.from_dict(item) for item in edges),
            next_cursor=value["next_cursor"],
            raw_artifact_hash=value["raw_artifact_hash"],
            response_artifact_hash=value["response_artifact_hash"],
            failure_reason=value["failure_reason"],
            schema_version=value["schema_version"],
        )

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True, slots=True)
class CitationTaskTruncation:
    task_id: str
    reason: CitationTruncationReason
    terminal_page_request_id: str

    def __post_init__(self) -> None:
        _require_hash(self.task_id, "citation truncation task_id")
        _require_hash(
            self.terminal_page_request_id,
            "citation truncation terminal_page_request_id",
        )
        try:
            reason = self.reason if isinstance(self.reason, CitationTruncationReason) else CitationTruncationReason(self.reason)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation truncation reason is invalid") from exc
        object.__setattr__(self, "reason", reason)

    def to_dict(self) -> dict[str, str]:
        return {
            "task_id": self.task_id,
            "reason": self.reason.value,
            "terminal_page_request_id": self.terminal_page_request_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationTaskTruncation:
        _exact_keys(
            value,
            frozenset({"task_id", "reason", "terminal_page_request_id"}),
            "citation task truncation",
        )
        return cls(
            value["task_id"],
            value["reason"],
            value["terminal_page_request_id"],
        )


@dataclass(frozen=True, slots=True)
class CitationExpansionExecution:
    plan_sha256: str
    plan_artifact_hash: str
    base_graph_sha256: str
    base_graph_artifact_hash: str
    graph: CitationGraph
    pages: tuple[CitationExpansionPageReceipt, ...]
    applied_page_request_ids: tuple[str, ...]
    pending: tuple[CitationPageCursor, ...]
    active_task_ids: tuple[str, ...]
    deferred_task_ids: tuple[str, ...]
    completed_task_ids: tuple[str, ...]
    failed_task_ids: tuple[str, ...]
    truncations: tuple[CitationTaskTruncation, ...]
    status: CitationExecutionStatus
    previous_execution_sha256: str | None = None
    previous_execution_artifact_hash: str | None = None
    schema_version: str = "citation-expansion-execution/v2"

    def __post_init__(self) -> None:
        _require_hash(self.plan_sha256, "citation execution plan_sha256")
        _require_hash(self.plan_artifact_hash, "citation execution plan_artifact_hash")
        _require_hash(self.base_graph_sha256, "citation execution base_graph_sha256")
        _require_hash(
            self.base_graph_artifact_hash,
            "citation execution base_graph_artifact_hash",
        )
        if not isinstance(self.graph, CitationGraph):
            raise LiteratureError("citation execution graph is malformed")
        if not isinstance(self.pages, tuple) or not all(
            isinstance(value, CitationExpansionPageReceipt) for value in self.pages
        ):
            raise LiteratureError("citation execution pages are malformed")
        page_requests = tuple(value.request.request_id for value in self.pages)
        if len(set(page_requests)) != len(page_requests):
            raise LiteratureError("citation execution replays a page request")
        if any(value.request.plan_sha256 != self.plan_sha256 for value in self.pages):
            raise LiteratureError("citation execution page belongs to another plan")
        if not isinstance(self.applied_page_request_ids, tuple):
            raise LiteratureError("applied citation page IDs must be a tuple")
        applied = tuple(sorted(set(self.applied_page_request_ids)))
        if len(applied) != len(self.applied_page_request_ids):
            raise LiteratureError("applied citation page IDs must be unique")
        pages_by_id = {value.request.request_id: value for value in self.pages}
        if not set(applied).issubset(pages_by_id):
            raise LiteratureError("applied citation page ID is unknown")
        if any(
            pages_by_id[value].status is not RetrievalStatus.AVAILABLE
            for value in applied
        ):
            raise LiteratureError("only available citation pages may be applied")
        if not isinstance(self.pending, tuple) or not all(
            isinstance(value, CitationPageCursor) for value in self.pending
        ):
            raise LiteratureError("citation execution pending cursors are malformed")
        pending_keys = tuple((value.task_id, value.next_page_number, value.cursor) for value in self.pending)
        if len(set(pending_keys)) != len(pending_keys):
            raise LiteratureError("citation execution contains duplicate pending cursors")
        if len({value.task_id for value in self.pending}) != len(self.pending):
            raise LiteratureError("a citation task may have only one pending cursor")
        collections = (
            ("active", self.active_task_ids),
            ("deferred", self.deferred_task_ids),
            ("completed", self.completed_task_ids),
            ("failed", self.failed_task_ids),
        )
        normalized: dict[str, tuple[str, ...]] = {}
        for name, values in collections:
            if not isinstance(values, tuple):
                raise LiteratureError(f"citation execution {name} task IDs must be a tuple")
            unique = tuple(sorted(set(values)))
            if len(unique) != len(values):
                raise LiteratureError(f"citation execution {name} task IDs must be unique")
            normalized[name] = unique
        active = normalized["active"]
        deferred = normalized["deferred"]
        completed = normalized["completed"]
        failed = normalized["failed"]
        for value in active + deferred + completed + failed:
            _require_hash(value, "citation execution task_id")
        if set(active).intersection(deferred):
            raise LiteratureError("citation task cannot be active and deferred")
        if not isinstance(self.truncations, tuple) or not all(
            isinstance(value, CitationTaskTruncation) for value in self.truncations
        ):
            raise LiteratureError("citation task truncations are malformed")
        truncations = tuple(sorted(self.truncations, key=lambda value: value.task_id))
        truncated_ids = tuple(value.task_id for value in truncations)
        if len(set(truncated_ids)) != len(truncated_ids):
            raise LiteratureError("citation task may have only one terminal truncation")
        terminal_sets = (
            set(completed),
            set(failed),
            set(truncated_ids),
            {value.task_id for value in self.pending},
        )
        for index, left in enumerate(terminal_sets):
            if any(left.intersection(right) for right in terminal_sets[index + 1 :]):
                raise LiteratureError("citation task terminal/pending states overlap")
        if set(active) != set().union(*terminal_sets):
            raise LiteratureError("active citation tasks are not completely partitioned")
        if any(value.request.task_id not in set(active) for value in self.pages):
            raise LiteratureError("citation execution page references a non-active task")
        for truncation in truncations:
            terminal_page = pages_by_id.get(truncation.terminal_page_request_id)
            if truncation.reason is CitationTruncationReason.PERSISTENCE_PARENT_BUDGET:
                if terminal_page is not None:
                    raise LiteratureError(
                        "persistence-parent truncation must precede gateway fetch"
                    )
            elif terminal_page is None or terminal_page.request.task_id != truncation.task_id:
                raise LiteratureError("citation truncation is not bound to its terminal page")
        try:
            status = self.status if isinstance(self.status, CitationExecutionStatus) else CitationExecutionStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("citation execution status is invalid") from exc
        if (self.previous_execution_sha256 is None) != (
            self.previous_execution_artifact_hash is None
        ):
            raise LiteratureError("previous execution content/artifact bindings must be paired")
        if self.previous_execution_sha256 is not None:
            _require_hash(self.previous_execution_sha256, "previous_execution_sha256")
            _require_hash(
                self.previous_execution_artifact_hash,
                "previous_execution_artifact_hash",
            )
        reasons = {value.reason for value in truncations}
        if CitationTruncationReason.PERSISTENCE_PARENT_BUDGET in reasons:
            expected_status = CitationExecutionStatus.PARTIAL_PERSISTENCE_BUDGET
        elif CitationTruncationReason.GRAPH_BUDGET in reasons:
            expected_status = CitationExecutionStatus.PARTIAL_GRAPH_BUDGET
        elif reasons.intersection(
            {
                CitationTruncationReason.CURSOR_CYCLE,
                CitationTruncationReason.GRAPH_CONFLICT,
            }
        ):
            expected_status = CitationExecutionStatus.PARTIAL_EVIDENCE_ANOMALY
        elif self.pending or CitationTruncationReason.PAGE_LIMIT in reasons:
            expected_status = CitationExecutionStatus.PARTIAL_PAGE_BUDGET
        elif deferred:
            expected_status = CitationExecutionStatus.PARTIAL_TASK_LIMIT
        elif failed:
            expected_status = CitationExecutionStatus.COMPLETED_WITH_FAILURES
        else:
            expected_status = CitationExecutionStatus.COMPLETE
        if status is not expected_status:
            raise LiteratureError("citation execution status is inconsistent with task state")
        if self.schema_version != "citation-expansion-execution/v2":
            raise LiteratureError("unsupported citation execution schema")
        object.__setattr__(self, "pages", tuple(self.pages))
        object.__setattr__(self, "applied_page_request_ids", applied)
        object.__setattr__(self, "pending", tuple(sorted(self.pending, key=lambda value: (value.task_id, value.next_page_number, value.cursor or ""))))
        object.__setattr__(self, "active_task_ids", active)
        object.__setattr__(self, "deferred_task_ids", deferred)
        object.__setattr__(self, "completed_task_ids", completed)
        object.__setattr__(self, "failed_task_ids", failed)
        object.__setattr__(self, "truncations", truncations)
        object.__setattr__(self, "status", status)
        if (
            self.pending
            and self.previous_execution_artifact_hash is None
            and len(self.parent_artifact_hashes) >= MAX_ARTIFACT_PARENTS
        ):
            raise LiteratureError(
                "fresh citation execution leaves no registry parent slot for resume custody"
            )
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "citation expansion execution",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_sha256": self.plan_sha256,
            "plan_artifact_hash": self.plan_artifact_hash,
            "base_graph_sha256": self.base_graph_sha256,
            "base_graph_artifact_hash": self.base_graph_artifact_hash,
            "graph": self.graph.to_dict(),
            "pages": [value.to_dict() for value in self.pages],
            "applied_page_request_ids": list(self.applied_page_request_ids),
            "pending": [value.to_dict() for value in self.pending],
            "active_task_ids": list(self.active_task_ids),
            "deferred_task_ids": list(self.deferred_task_ids),
            "completed_task_ids": list(self.completed_task_ids),
            "failed_task_ids": list(self.failed_task_ids),
            "truncations": [value.to_dict() for value in self.truncations],
            "status": self.status.value,
            "previous_execution_sha256": self.previous_execution_sha256,
            "previous_execution_artifact_hash": self.previous_execution_artifact_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationExpansionExecution:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "plan_sha256",
                    "plan_artifact_hash",
                    "base_graph_sha256",
                    "base_graph_artifact_hash",
                    "graph",
                    "pages",
                    "applied_page_request_ids",
                    "pending",
                    "active_task_ids",
                    "deferred_task_ids",
                    "completed_task_ids",
                    "failed_task_ids",
                    "truncations",
                    "status",
                    "previous_execution_sha256",
                    "previous_execution_artifact_hash",
                }
            ),
            "citation expansion execution",
        )
        pages = value["pages"]
        applied = value["applied_page_request_ids"]
        pending = value["pending"]
        active = value["active_task_ids"]
        deferred = value["deferred_task_ids"]
        completed = value["completed_task_ids"]
        failed = value["failed_task_ids"]
        truncations = value["truncations"]
        if not all(
            isinstance(item, (list, tuple))
            for item in (
                pages,
                applied,
                pending,
                active,
                deferred,
                completed,
                failed,
                truncations,
            )
        ):
            raise LiteratureError("citation execution collections must be lists")
        return cls(
            plan_sha256=value["plan_sha256"],
            plan_artifact_hash=value["plan_artifact_hash"],
            base_graph_sha256=value["base_graph_sha256"],
            base_graph_artifact_hash=value["base_graph_artifact_hash"],
            graph=CitationGraph.from_dict(value["graph"]),
            pages=tuple(CitationExpansionPageReceipt.from_dict(item) for item in pages),
            applied_page_request_ids=tuple(applied),
            pending=tuple(CitationPageCursor.from_dict(item) for item in pending),
            active_task_ids=tuple(active),
            deferred_task_ids=tuple(deferred),
            completed_task_ids=tuple(completed),
            failed_task_ids=tuple(failed),
            truncations=tuple(CitationTaskTruncation.from_dict(item) for item in truncations),
            status=value["status"],
            previous_execution_sha256=value["previous_execution_sha256"],
            previous_execution_artifact_hash=value[
                "previous_execution_artifact_hash"
            ],
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        # The base-graph artifact is the content-addressed collection root for
        # seed provenance.  Page captures add only their exact raw/response
        # artifacts here; repeating every base-node parent would make a valid
        # persisted graph impossible to resume near the registry fan-in limit.
        return tuple(
            sorted(
                {self.plan_artifact_hash, self.base_graph_artifact_hash}
                | {
                    artifact_hash
                    for page in self.pages
                    for artifact_hash in (page.raw_artifact_hash, page.response_artifact_hash)
                    if artifact_hash is not None
                }
                | (
                    {self.previous_execution_artifact_hash}
                    if self.previous_execution_artifact_hash is not None
                    else set()
                )
            )
        )


def _citation_adapter(source: ScholarlySource) -> ScholarlyAdapter:
    if source is ScholarlySource.OPENALEX:
        return OpenAlexAdapter()
    if source is ScholarlySource.SEMANTIC_SCHOLAR:
        return SemanticScholarAdapter()
    raise LiteratureError("citation page source has no approved graph adapter")


def _coerce_citation_envelope(
    captured: object,
    request: CitationPageRequest,
) -> GatewayEnvelope:
    if isinstance(captured, GatewayEnvelope):
        envelope = captured
    elif isinstance(captured, CapturedGatewayResponse):
        envelope = GatewayEnvelope(
            source=captured.source,
            request_id=captured.request_id,
            status=captured.status,
            payload=captured.payload,
            raw_artifact_hash=captured.raw_artifact_hash,
            response_artifact_hash=captured.response_artifact_hash,
            failure_reason=captured.failure_reason,
            license=captured.license,
            full_text_status=getattr(captured, "full_text_status", None),
        )
    else:
        raise LiteratureError("gateway response does not satisfy captured-response protocol")
    if envelope.source is not request.source or envelope.request_id != request.request_id:
        raise LiteratureError("citation page response is not bound to its request")
    return envelope


def normalize_citation_expansion_page(
    request: CitationPageRequest,
    envelope: GatewayEnvelope,
) -> CitationExpansionPageReceipt:
    """Normalize a controlled graph page containing ``works`` and ``next_cursor``."""

    if not isinstance(request, CitationPageRequest):
        raise LiteratureError("citation page normalization requires CitationPageRequest")
    if not isinstance(envelope, GatewayEnvelope):
        raise LiteratureError("citation page normalization requires GatewayEnvelope")
    if envelope.source is not request.source or envelope.request_id != request.request_id:
        raise LiteratureError("citation page envelope is not bound to its request")
    if envelope.status is not RetrievalStatus.AVAILABLE:
        return CitationExpansionPageReceipt(
            request=request,
            status=envelope.status,
            nodes=(),
            edges=(),
            next_cursor=None,
            raw_artifact_hash=envelope.raw_artifact_hash,
            response_artifact_hash=envelope.response_artifact_hash,
            failure_reason=envelope.failure_reason or envelope.status.value,
        )
    payload = envelope.payload_dict
    if payload is None or frozenset(payload) != frozenset({"works", "next_cursor"}):
        raise LiteratureError("citation page payload must contain only works and next_cursor")
    works = payload["works"]
    if not isinstance(works, (list, tuple)) or len(works) > _MAX_JSON_ITEMS:
        raise LiteratureError("citation page works must be a bounded list")
    adapter = _citation_adapter(request.source)
    nodes = []
    for work in works:
        if not isinstance(work, Mapping):
            raise LiteratureError("citation page work must be an object")
        work_envelope = GatewayEnvelope(
            source=request.source,
            request_id=request.request_id,
            status=RetrievalStatus.AVAILABLE,
            payload=work,
            raw_artifact_hash=envelope.raw_artifact_hash,
            response_artifact_hash=envelope.response_artifact_hash,
            license=envelope.license,
            full_text_status=FullTextStatus.METADATA_ONLY,
        )
        nodes.append(CitationGraphNode.from_record(adapter.normalize(work_envelope)))
    observations_hash = envelope.response_artifact_hash or envelope.raw_artifact_hash
    assert observations_hash is not None
    edges = []
    for node in nodes:
        citing, cited = (
            (request.origin_node_id, node.node_id)
            if request.traversal is CitationTraversal.REFERENCES
            else (node.node_id, request.origin_node_id)
        )
        edges.append(
            CitationGraphEdge(
                citing_node_id=citing,
                cited_node_id=cited,
                observations=(
                    CitationEdgeObservation(
                        source=request.source,
                        request_id=request.request_id,
                        evidence_artifact_hash=observations_hash,
                    ),
                ),
            )
        )
    return CitationExpansionPageReceipt(
        request=request,
        status=RetrievalStatus.AVAILABLE,
        nodes=tuple(nodes),
        edges=tuple(edges),
        next_cursor=payload["next_cursor"],
        raw_artifact_hash=envelope.raw_artifact_hash,
        response_artifact_hash=envelope.response_artifact_hash,
        failure_reason=None,
    )


def _merge_citation_page(graph: CitationGraph, page: CitationExpansionPageReceipt) -> CitationGraph:
    nodes = {value.node_id: value for value in graph.nodes}
    for node in page.nodes:
        previous = nodes.get(node.node_id)
        if previous is None:
            nodes[node.node_id] = node
            continue
        stable_metadata = (
            previous.source,
            previous.source_record_id,
            previous.title,
        ) == (
            node.source,
            node.source_record_id,
            node.title,
        )
        compatible_year = (
            previous.publication_year is None
            or node.publication_year is None
            or previous.publication_year == node.publication_year
        )
        previous_identifiers = set(previous.identifiers)
        new_identifiers = set(node.identifiers)
        compatible_identity = (
            previous_identifiers.issubset(new_identifiers)
            or new_identifiers.issubset(previous_identifiers)
        )
        if not stable_metadata or not compatible_year or not compatible_identity:
            raise LiteratureError(
                "citation node occurrence has conflicting metadata within one snapshot"
            )
        # Repeated provider observations remain fully present in page receipts
        # and edge observations.  The graph view deterministically retains the
        # richest identifier set, breaking ties by normalized record hash.
        nodes[node.node_id] = min(
            (previous, node),
            key=lambda value: (
                {
                    FullTextStatus.AVAILABLE: 0,
                    FullTextStatus.METADATA_ONLY: 1,
                    FullTextStatus.UNAVAILABLE: 2,
                    FullTextStatus.LICENSE_RESTRICTED: 3,
                }[value.full_text_status],
                -len(value.identifiers),
                0 if value.publication_year is not None else 1,
                value.record_sha256,
            ),
        )
    relationships = {
        (value.citing_node_id, value.cited_node_id): value for value in graph.edges
    }
    for new_edge in page.edges:
        key = (new_edge.citing_node_id, new_edge.cited_node_id)
        previous = relationships.get(key)
        if previous is None:
            relationships[key] = new_edge
        else:
            relationships[key] = CitationGraphEdge(
                citing_node_id=key[0],
                cited_node_id=key[1],
                observations=tuple(
                    sorted(set(previous.observations + new_edge.observations))
                ),
            )
    return CitationGraph(tuple(nodes.values()), tuple(relationships.values()))


def _citation_capture_parent_hashes(
    pages: Sequence[CitationExpansionPageReceipt],
) -> set[str]:
    return {
        artifact_hash
        for page in pages
        for artifact_hash in (page.raw_artifact_hash, page.response_artifact_hash)
        if artifact_hash is not None
    }


def _citation_persistence_parent_budget_exhausted(
    graph: CitationGraph,
    pages: Sequence[CitationExpansionPageReceipt],
    *,
    plan_artifact_hash: str,
    base_graph_artifact_hash: str,
    previous_execution_artifact_hash: str | None,
) -> bool:
    """Reserve exact registry slots before another audited page capture.

    An available page contributes distinct raw and normalized response
    artifacts.  The final graph also reserves one parent for its authoritative
    execution wrapper.  Preflight avoids performing I/O that could not be
    represented by an immutable registry record.
    """

    graph_parent_count = len(set(graph.parent_artifact_hashes))
    graph_lacks_capture_slots = graph_parent_count + 2 + 1 > MAX_ARTIFACT_PARENTS
    execution_parents = {
        plan_artifact_hash,
        base_graph_artifact_hash,
        *_citation_capture_parent_hashes(pages),
    }
    if previous_execution_artifact_hash is not None:
        execution_parents.add(previous_execution_artifact_hash)
    # A fresh execution that can still yield work must leave one slot for the
    # immutable previous-execution parent used by its first resume.  Resumed
    # executions already carry that one lineage slot; the next resume replaces
    # it with the latest execution artifact rather than accumulating ancestors.
    resume_custody_slots = 1 if previous_execution_artifact_hash is None else 0
    execution_lacks_capture_slots = (
        len(execution_parents) + 2 + resume_custody_slots
        > MAX_ARTIFACT_PARENTS
    )
    return graph_lacks_capture_slots or execution_lacks_capture_slots


def _citation_merge_truncation_reason(
    error: LiteratureError,
) -> CitationTruncationReason:
    if "artifact-registry parent bound" in str(error):
        return CitationTruncationReason.GRAPH_BUDGET
    return CitationTruncationReason.GRAPH_CONFLICT


def verify_citation_expansion_execution(
    plan: CitationExpansionPlan,
    base_graph: CitationGraph,
    execution: CitationExpansionExecution,
    *,
    plan_artifact_hash: str,
    base_graph_artifact_hash: str,
) -> None:
    """Re-derive page chains, task partition, budgets, and graph fold."""

    if not isinstance(plan, CitationExpansionPlan):
        raise LiteratureError("citation execution verifier requires a plan")
    if not isinstance(base_graph, CitationGraph):
        raise LiteratureError("citation execution verifier requires a base graph")
    if not isinstance(execution, CitationExpansionExecution):
        raise LiteratureError("citation execution verifier requires an execution")
    plan_artifact_hash = _require_hash(
        plan_artifact_hash,
        "expected plan_artifact_hash",
    )
    base_graph_artifact_hash = _require_hash(
        base_graph_artifact_hash,
        "expected base_graph_artifact_hash",
    )
    if (
        execution.plan_sha256 != plan.sha256
        or execution.plan_artifact_hash != plan_artifact_hash
        or execution.base_graph_sha256 != base_graph.sha256
        or execution.base_graph_artifact_hash != base_graph_artifact_hash
    ):
        raise LiteratureError("citation execution authority bindings do not match")
    active_ids = tuple(sorted(value.task_id for value in plan.tasks))
    deferred_ids = tuple(sorted(value.task_id for value in plan.deferred_tasks))
    if execution.active_task_ids != active_ids or execution.deferred_task_ids != deferred_ids:
        raise LiteratureError("citation execution task inventory does not match the plan")
    base_nodes = {value.node_id: value for value in base_graph.nodes}
    for task in plan.tasks + plan.deferred_tasks:
        origin = base_nodes.get(task.origin_node_id)
        if origin is None:
            raise LiteratureError("citation execution base graph omits a planned origin")
        if (
            task.acquisition_request_ids != (origin.request_id,)
            or set(task.parent_artifact_hashes)
            != set(origin.parent_artifact_hashes)
            or task.request.identifier not in origin.identifiers
        ):
            raise LiteratureError(
                "citation expansion task is not bound to its exact acquired origin"
            )
    if len(execution.pages) > plan.policy.max_total_page_requests:
        raise LiteratureError("citation execution exceeds cumulative page budget")
    task_by_id = {value.task_id: value for value in plan.tasks}
    pages_by_task: dict[str, list[CitationExpansionPageReceipt]] = {
        value: [] for value in active_ids
    }
    for page in execution.pages:
        task = task_by_id.get(page.request.task_id)
        if task is None:
            raise LiteratureError("citation execution page has no planned task")
        pages_by_task[task.task_id].append(page)
    pending_by_task = {value.task_id: value for value in execution.pending}
    truncation_by_task = {value.task_id: value for value in execution.truncations}
    requested_cursors_by_task: dict[str, set[str | None]] = {
        value: set() for value in active_ids
    }
    for task_id, task_pages in pages_by_task.items():
        if len(task_pages) > plan.policy.max_pages_per_task:
            raise LiteratureError("citation task exceeds its page budget")
        expected_cursor: str | None = None
        for page_number, page in enumerate(task_pages, start=1):
            expected_request = CitationPageRequest.for_task(
                plan,
                task_by_id[task_id],
                page_number=page_number,
                cursor=expected_cursor,
            )
            if page.request.to_dict() != expected_request.to_dict():
                raise LiteratureError("citation page chain is non-contiguous or replayed")
            if page.request.cursor in requested_cursors_by_task[task_id]:
                raise LiteratureError("citation page chain reuses a requested cursor")
            requested_cursors_by_task[task_id].add(page.request.cursor)
            expected_cursor = page.next_cursor
            if page.status is not RetrievalStatus.AVAILABLE and page_number != len(task_pages):
                raise LiteratureError("citation task continues after a terminal failure")
            if page.status is RetrievalStatus.AVAILABLE and page.next_cursor is None and page_number != len(task_pages):
                raise LiteratureError("citation task continues after terminal pagination")
        pending = pending_by_task.get(task_id)
        if pending is not None:
            if (
                pending.next_page_number != len(task_pages) + 1
                or pending.cursor != expected_cursor
                or pending.next_page_number > plan.policy.max_pages_per_task
                or (task_pages and task_pages[-1].status is not RetrievalStatus.AVAILABLE)
                or (task_pages and expected_cursor is None)
            ):
                raise LiteratureError("pending citation cursor does not continue its page chain")
        if task_id in execution.completed_task_ids:
            if not task_pages or task_pages[-1].status is not RetrievalStatus.AVAILABLE or expected_cursor is not None:
                raise LiteratureError("completed citation task lacks a terminal available page")
        if task_id in execution.failed_task_ids:
            if not task_pages or task_pages[-1].status is RetrievalStatus.AVAILABLE:
                raise LiteratureError("failed citation task lacks a terminal failure page")
        truncation = truncation_by_task.get(task_id)
        if truncation is not None:
            if truncation.reason is CitationTruncationReason.PERSISTENCE_PARENT_BUDGET:
                if any(
                    value.request.request_id
                    == truncation.terminal_page_request_id
                    for value in task_pages
                ):
                    raise LiteratureError(
                        "persistence-parent truncation occurred after gateway fetch"
                    )
                continue
            if (
                not task_pages
                or truncation.terminal_page_request_id
                != task_pages[-1].request.request_id
            ):
                raise LiteratureError("citation truncation is not the task's terminal page")
            terminal_page = task_pages[-1]
            if terminal_page.status is not RetrievalStatus.AVAILABLE:
                raise LiteratureError("only an available page may carry a truncation")
            requested_cursors = requested_cursors_by_task[task_id]
            if truncation.reason is CitationTruncationReason.CURSOR_CYCLE:
                if (
                    terminal_page.next_cursor is None
                    or terminal_page.next_cursor not in requested_cursors
                ):
                    raise LiteratureError("cursor-cycle truncation lacks a repeated cursor")
            elif truncation.reason is CitationTruncationReason.PAGE_LIMIT:
                if (
                    terminal_page.next_cursor is None
                    or terminal_page.next_cursor in requested_cursors
                    or terminal_page.request.page_number
                    != plan.policy.max_pages_per_task
                ):
                    raise LiteratureError("page-limit truncation does not exhaust its task budget")

    # Reproduce the deterministic task scheduler.  A persisted execution may
    # stop between pages, but it may not reorder tasks or invent a resume cursor.
    scheduled = [CitationPageCursor(value, 1, None) for value in active_ids]
    scheduled_graph = base_graph
    page_index = 0
    while scheduled:
        scheduled.sort(
            key=lambda value: (
                value.task_id,
                value.next_page_number,
                value.cursor or "",
            )
        )
        cursor = scheduled.pop(0)
        expected_request = CitationPageRequest.for_task(
            plan,
            task_by_id[cursor.task_id],
            page_number=cursor.next_page_number,
            cursor=cursor.cursor,
        )
        truncation = truncation_by_task.get(cursor.task_id)
        if (
            page_index >= len(execution.pages)
            or execution.pages[page_index].request.to_dict()
            != expected_request.to_dict()
        ):
            if (
                truncation is not None
                and truncation.reason
                is CitationTruncationReason.PERSISTENCE_PARENT_BUDGET
                and truncation.terminal_page_request_id
                == expected_request.request_id
            ):
                if not _citation_persistence_parent_budget_exhausted(
                    scheduled_graph,
                    execution.pages[:page_index],
                    plan_artifact_hash=plan_artifact_hash,
                    base_graph_artifact_hash=base_graph_artifact_hash,
                    previous_execution_artifact_hash=(
                        execution.previous_execution_artifact_hash
                    ),
                ):
                    raise LiteratureError(
                        "persistence-parent truncation has available registry capacity"
                    )
                continue
            scheduled.append(cursor)
            break
        page = execution.pages[page_index]
        page_index += 1
        is_truncation_page = (
            truncation is not None
            and truncation.terminal_page_request_id == page.request.request_id
        )
        if page.status is RetrievalStatus.AVAILABLE:
            try:
                scheduled_candidate = _merge_citation_page(scheduled_graph, page)
            except LiteratureError:
                scheduled_candidate = None
            if (
                scheduled_candidate is not None
                and len(scheduled_candidate.nodes) <= plan.policy.max_nodes
                and len(scheduled_candidate.edges) <= plan.policy.max_edges
                and (
                    truncation is None
                    or truncation.reason
                    not in {
                        CitationTruncationReason.GRAPH_BUDGET,
                        CitationTruncationReason.GRAPH_CONFLICT,
                    }
                )
            ):
                scheduled_graph = scheduled_candidate
        if (
            page.status is RetrievalStatus.AVAILABLE
            and page.next_cursor is not None
            and not is_truncation_page
        ):
            scheduled.append(
                CitationPageCursor(
                    cursor.task_id,
                    cursor.next_page_number + 1,
                    page.next_cursor,
                )
            )
    if page_index != len(execution.pages):
        raise LiteratureError("citation execution contains an unscheduled page")
    expected_pending = tuple(
        sorted(
            scheduled,
            key=lambda value: (
                value.task_id,
                value.next_page_number,
                value.cursor or "",
            ),
        )
    )
    if expected_pending != execution.pending:
        raise LiteratureError("citation execution pending state is not scheduler-derived")

    # Re-fold every accepted page and independently derive graph-budget and
    # graph-conflict truncations.  Merely labelling a page as truncated must
    # never allow valid evidence to be silently discarded.
    expected_applied: set[str] = set()
    folded_graph = base_graph
    for page in execution.pages:
        if page.status is not RetrievalStatus.AVAILABLE:
            continue
        truncation = truncation_by_task.get(page.request.task_id)
        terminal_reason = (
            truncation.reason
            if truncation is not None
            and truncation.terminal_page_request_id == page.request.request_id
            else None
        )
        try:
            candidate_graph = _merge_citation_page(folded_graph, page)
        except LiteratureError as exc:
            expected_reason = _citation_merge_truncation_reason(exc)
            if terminal_reason is not expected_reason:
                raise LiteratureError(
                    "citation graph merge failure lacks the required typed truncation"
                ) from exc
            continue
        exceeds_graph_budget = (
            len(candidate_graph.nodes) > plan.policy.max_nodes
            or len(candidate_graph.edges) > plan.policy.max_edges
        )
        if exceeds_graph_budget:
            if terminal_reason is not CitationTruncationReason.GRAPH_BUDGET:
                raise LiteratureError(
                    "citation graph budget breach lacks the required truncation"
                )
            continue
        if terminal_reason in {
            CitationTruncationReason.GRAPH_BUDGET,
            CitationTruncationReason.GRAPH_CONFLICT,
        }:
            raise LiteratureError("citation execution falsely discards an applicable page")
        folded_graph = candidate_graph
        expected_applied.add(page.request.request_id)
    if set(execution.applied_page_request_ids) != expected_applied:
        raise LiteratureError("citation execution applied-page inventory is invalid")
    if folded_graph.canonical_bytes != execution.graph.canonical_bytes:
        raise LiteratureError("citation execution graph is not the deterministic page fold")
    if len(execution.graph.nodes) > plan.policy.max_nodes or len(execution.graph.edges) > plan.policy.max_edges:
        raise LiteratureError("citation execution graph exceeds policy")


def execute_citation_expansion(
    plan: CitationExpansionPlan,
    gateway: LiteratureGateway,
    base_graph: CitationGraph,
    *,
    plan_artifact_hash: str,
    base_graph_artifact_hash: str,
    previous: CitationExpansionExecution | None = None,
    previous_execution_artifact_hash: str | None = None,
    page_request_allowance: int | None = None,
) -> CitationExpansionExecution:
    """Execute/resume bounded pages through the gateway with cumulative budgets."""

    if not isinstance(plan, CitationExpansionPlan):
        raise LiteratureError("citation execution requires CitationExpansionPlan")
    if not isinstance(gateway, LiteratureGateway):
        raise LiteratureError("citation execution gateway is invalid")
    if not isinstance(base_graph, CitationGraph):
        raise LiteratureError("citation execution base graph is invalid")
    plan_artifact_hash = _require_hash(
        plan_artifact_hash,
        "citation execution plan_artifact_hash",
    )
    base_graph_artifact_hash = _require_hash(
        base_graph_artifact_hash,
        "citation execution base_graph_artifact_hash",
    )
    assert plan_artifact_hash is not None
    assert base_graph_artifact_hash is not None
    base_node_ids = {value.node_id for value in base_graph.nodes}
    if any(
        task.origin_node_id not in base_node_ids
        for task in plan.tasks + plan.deferred_tasks
    ):
        raise LiteratureError("citation execution base graph omits a planned origin")
    if (
        len(base_graph.nodes) > plan.policy.max_nodes
        or len(base_graph.edges) > plan.policy.max_edges
    ):
        raise LiteratureError("citation execution base graph exceeds policy")
    if page_request_allowance is not None and (
        isinstance(page_request_allowance, bool)
        or not isinstance(page_request_allowance, int)
        or page_request_allowance <= 0
    ):
        raise LiteratureError("page_request_allowance must be positive")
    task_by_id = {value.task_id: value for value in plan.tasks}
    if previous is None:
        if previous_execution_artifact_hash is not None:
            raise LiteratureError("previous artifact supplied without previous execution")
        graph = base_graph
        pages: list[CitationExpansionPageReceipt] = []
        pending = [CitationPageCursor(value.task_id, 1, None) for value in plan.tasks]
        applied: set[str] = set()
        completed: set[str] = set()
        failed: set[str] = set()
        truncations: dict[str, CitationTaskTruncation] = {}
        previous_sha = None
        previous_artifact = None
        original_base_sha = base_graph.sha256
    else:
        if not isinstance(previous, CitationExpansionExecution):
            raise LiteratureError("previous citation execution is malformed")
        previous_execution_artifact_hash = _require_hash(
            previous_execution_artifact_hash,
            "previous_execution_artifact_hash",
        )
        assert previous_execution_artifact_hash is not None
        verify_citation_expansion_execution(
            plan,
            base_graph,
            previous,
            plan_artifact_hash=plan_artifact_hash,
            base_graph_artifact_hash=base_graph_artifact_hash,
        )
        if not previous.pending or len(previous.pages) >= plan.policy.max_total_page_requests:
            return previous
        graph = previous.graph
        pages = list(previous.pages)
        pending = list(previous.pending)
        applied = set(previous.applied_page_request_ids)
        completed = set(previous.completed_task_ids)
        failed = set(previous.failed_task_ids)
        truncations = {value.task_id: value for value in previous.truncations}
        previous_sha = previous.sha256
        previous_artifact = previous_execution_artifact_hash
        original_base_sha = previous.base_graph_sha256
    seen_page_keys = {
        (value.request.task_id, value.request.cursor) for value in pages
    }
    pages_at_start = len(pages)
    call_allowance = (
        plan.policy.max_total_page_requests
        if page_request_allowance is None
        else page_request_allowance
    )
    while (
        pending
        and len(pages) < plan.policy.max_total_page_requests
        and len(pages) - pages_at_start < call_allowance
    ):
        pending.sort(key=lambda value: (value.task_id, value.next_page_number, value.cursor or ""))
        cursor = pending.pop(0)
        task = task_by_id.get(cursor.task_id)
        if task is None:
            raise LiteratureError("pending citation cursor references an inactive task")
        if cursor.next_page_number > plan.policy.max_pages_per_task:
            raise LiteratureError("pending citation cursor already exceeds page policy")
        page_key = (cursor.task_id, cursor.cursor)
        if page_key in seen_page_keys:
            raise LiteratureError("citation execution attempted to replay a page cursor")
        request = CitationPageRequest.for_task(
            plan,
            task,
            page_number=cursor.next_page_number,
            cursor=cursor.cursor,
        )
        if _citation_persistence_parent_budget_exhausted(
            graph,
            pages,
            plan_artifact_hash=plan_artifact_hash,
            base_graph_artifact_hash=base_graph_artifact_hash,
            previous_execution_artifact_hash=previous_artifact,
        ):
            truncations[task.task_id] = CitationTaskTruncation(
                task.task_id,
                CitationTruncationReason.PERSISTENCE_PARENT_BUDGET,
                request.request_id,
            )
            continue
        captured: object | None = None
        try:
            captured = gateway.fetch(request)  # type: ignore[arg-type]
        except Exception as exc:
            page = CitationExpansionPageReceipt(
                request=request,
                status=RetrievalStatus.FAILED,
                nodes=(),
                edges=(),
                next_cursor=None,
                raw_artifact_hash=None,
                response_artifact_hash=None,
                failure_reason=f"gateway retrieval failure: {type(exc).__name__}",
            )
        else:
            captured_raw_hash = _captured_custody_hash(captured, "raw_artifact_hash")
            captured_response_hash = _captured_custody_hash(
                captured,
                "response_artifact_hash",
            )
            try:
                envelope = _coerce_citation_envelope(captured, request)
                page = normalize_citation_expansion_page(request, envelope)
            except (LiteratureError, TypeError, ValueError, KeyError) as exc:
                page = CitationExpansionPageReceipt(
                    request=request,
                    status=RetrievalStatus.MALFORMED,
                    nodes=(),
                    edges=(),
                    next_cursor=None,
                    raw_artifact_hash=captured_raw_hash,
                    response_artifact_hash=captured_response_hash,
                    failure_reason=f"captured page validation failure: {type(exc).__name__}",
                )
        pages.append(page)
        seen_page_keys.add(page_key)
        if page.status is not RetrievalStatus.AVAILABLE:
            failed.add(task.task_id)
            continue
        try:
            candidate_graph = _merge_citation_page(graph, page)
        except LiteratureError as exc:
            truncations[task.task_id] = CitationTaskTruncation(
                task.task_id,
                _citation_merge_truncation_reason(exc),
                page.request.request_id,
            )
            continue
        if (
            len(candidate_graph.nodes) > plan.policy.max_nodes
            or len(candidate_graph.edges) > plan.policy.max_edges
        ):
            truncations[task.task_id] = CitationTaskTruncation(
                task.task_id,
                CitationTruncationReason.GRAPH_BUDGET,
                page.request.request_id,
            )
            continue
        graph = candidate_graph
        applied.add(page.request.request_id)
        if page.next_cursor is None:
            completed.add(task.task_id)
        elif (task.task_id, page.next_cursor) in seen_page_keys:
            truncations[task.task_id] = CitationTaskTruncation(
                task.task_id,
                CitationTruncationReason.CURSOR_CYCLE,
                page.request.request_id,
            )
        elif cursor.next_page_number >= plan.policy.max_pages_per_task:
            truncations[task.task_id] = CitationTaskTruncation(
                task.task_id,
                CitationTruncationReason.PAGE_LIMIT,
                page.request.request_id,
            )
        else:
            pending.append(
                CitationPageCursor(
                    task.task_id,
                    cursor.next_page_number + 1,
                    page.next_cursor,
                )
            )
    reasons = {value.reason for value in truncations.values()}
    if CitationTruncationReason.PERSISTENCE_PARENT_BUDGET in reasons:
        status = CitationExecutionStatus.PARTIAL_PERSISTENCE_BUDGET
    elif CitationTruncationReason.GRAPH_BUDGET in reasons:
        status = CitationExecutionStatus.PARTIAL_GRAPH_BUDGET
    elif reasons.intersection(
        {
            CitationTruncationReason.CURSOR_CYCLE,
            CitationTruncationReason.GRAPH_CONFLICT,
        }
    ):
        status = CitationExecutionStatus.PARTIAL_EVIDENCE_ANOMALY
    elif pending or CitationTruncationReason.PAGE_LIMIT in reasons:
        status = CitationExecutionStatus.PARTIAL_PAGE_BUDGET
    elif plan.deferred_tasks:
        status = CitationExecutionStatus.PARTIAL_TASK_LIMIT
    elif failed:
        status = CitationExecutionStatus.COMPLETED_WITH_FAILURES
    else:
        status = CitationExecutionStatus.COMPLETE
    execution = CitationExpansionExecution(
        plan_sha256=plan.sha256,
        plan_artifact_hash=plan_artifact_hash,
        base_graph_sha256=original_base_sha,
        base_graph_artifact_hash=base_graph_artifact_hash,
        graph=graph,
        pages=tuple(pages),
        applied_page_request_ids=tuple(sorted(applied)),
        pending=tuple(pending),
        active_task_ids=tuple(sorted(task_by_id)),
        deferred_task_ids=plan.deferred_task_ids,
        completed_task_ids=tuple(sorted(completed)),
        failed_task_ids=tuple(sorted(failed)),
        truncations=tuple(truncations.values()),
        status=status,
        previous_execution_sha256=previous_sha,
        previous_execution_artifact_hash=previous_artifact,
    )
    verify_citation_expansion_execution(
        plan,
        base_graph,
        execution,
        plan_artifact_hash=plan_artifact_hash,
        base_graph_artifact_hash=base_graph_artifact_hash,
    )
    return execution


@dataclass(frozen=True, slots=True)
class GeneralWebFallbackPolicy:
    allow_general_web: bool
    allowed_purposes: tuple[GeneralWebPurpose, ...]
    required_scholarly_sources: tuple[ScholarlySource, ...] = (
        ScholarlySource.OPENALEX,
        ScholarlySource.SEMANTIC_SCHOLAR,
    )
    minimum_scholarly_rounds: int = 2
    schema_version: str = "general-web-fallback-policy/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.allow_general_web, bool):
            raise LiteratureError("allow_general_web must be boolean")
        if not isinstance(self.allowed_purposes, tuple):
            raise LiteratureError("allowed web purposes must be a tuple")
        try:
            purposes = tuple(
                value if isinstance(value, GeneralWebPurpose) else GeneralWebPurpose(value)
                for value in self.allowed_purposes
            )
            sources = tuple(
                value if isinstance(value, ScholarlySource) else ScholarlySource(value)
                for value in self.required_scholarly_sources
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("general-web fallback policy enum is invalid") from exc
        if len(set(purposes)) != len(purposes):
            raise LiteratureError("allowed web purposes must be unique")
        if self.allow_general_web and not purposes:
            raise LiteratureError("enabled web fallback requires explicit allowed purposes")
        if not sources or len(set(sources)) != len(sources):
            raise LiteratureError("required scholarly sources must be unique and non-empty")
        if ScholarlySource.MERGED in sources:
            raise LiteratureError("merged records are not a queried scholarly source")
        if (
            isinstance(self.minimum_scholarly_rounds, bool)
            or not isinstance(self.minimum_scholarly_rounds, int)
            or self.minimum_scholarly_rounds <= 0
        ):
            raise LiteratureError("minimum_scholarly_rounds must be positive")
        if self.schema_version != "general-web-fallback-policy/v1":
            raise LiteratureError("unsupported general-web fallback policy schema")
        object.__setattr__(self, "allowed_purposes", tuple(sorted(purposes, key=lambda value: value.value)))
        object.__setattr__(self, "required_scholarly_sources", tuple(sorted(sources, key=lambda value: value.value)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allow_general_web": self.allow_general_web,
            "allowed_purposes": [value.value for value in self.allowed_purposes],
            "required_scholarly_sources": [
                value.value for value in self.required_scholarly_sources
            ],
            "minimum_scholarly_rounds": self.minimum_scholarly_rounds,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True, slots=True)
class ScholarlyAttemptReceipt:
    source: ScholarlySource
    request_id: str
    status: RetrievalStatus
    receipt_artifact_hash: str

    def __post_init__(self) -> None:
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
            status = self.status if isinstance(self.status, RetrievalStatus) else RetrievalStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise LiteratureError("scholarly attempt receipt enum is invalid") from exc
        if source is ScholarlySource.MERGED:
            raise LiteratureError("merged state is not a scholarly attempt source")
        _require_hash(self.request_id, "scholarly attempt request_id")
        _require_hash(self.receipt_artifact_hash, "scholarly attempt receipt_artifact_hash")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "status", status)

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source.value,
            "request_id": self.request_id,
            "status": self.status.value,
            "receipt_artifact_hash": self.receipt_artifact_hash,
        }


@dataclass(frozen=True, slots=True)
class ScholarlySearchSummary:
    goal_id: str
    citation_expansion_plan_sha256: str
    investigation_history_sha256: str
    sufficiency_assessment_artifact_hash: str
    scholarly_rounds_completed: int
    attempts: tuple[ScholarlyAttemptReceipt, ...]
    records_acquired: int
    full_text_records_reviewed: int
    scholarly_evidence_sufficient: bool
    scholarly_sources_exhausted: bool
    insufficiency_reasons: tuple[str, ...]
    evidence_artifact_hashes: tuple[str, ...]
    schema_version: str = "scholarly-search-summary/v1"

    def __post_init__(self) -> None:
        goal_id = _clean_text(self.goal_id, "scholarly search goal_id")
        _require_hash(
            self.citation_expansion_plan_sha256,
            "scholarly search citation_expansion_plan_sha256",
        )
        _require_hash(
            self.investigation_history_sha256,
            "scholarly search investigation_history_sha256",
        )
        _require_hash(
            self.sufficiency_assessment_artifact_hash,
            "scholarly search sufficiency_assessment_artifact_hash",
        )
        for name in (
            "scholarly_rounds_completed",
            "records_acquired",
            "full_text_records_reviewed",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LiteratureError(f"{name} must be a non-negative integer")
        if self.full_text_records_reviewed > self.records_acquired:
            raise LiteratureError("full-text review count exceeds acquired records")
        if not isinstance(self.attempts, tuple) or not self.attempts:
            raise LiteratureError("scholarly search requires typed attempt receipts")
        if not all(isinstance(value, ScholarlyAttemptReceipt) for value in self.attempts):
            raise LiteratureError("scholarly search attempt receipt is malformed")
        attempts = tuple(
            sorted(
                self.attempts,
                key=lambda value: (
                    value.source.value,
                    value.request_id,
                    value.status.value,
                    value.receipt_artifact_hash,
                ),
            )
        )
        attempt_ids = tuple((value.source, value.request_id) for value in attempts)
        if len(set(attempt_ids)) != len(attempt_ids):
            raise LiteratureError("scholarly search contains duplicate request attempts")
        for name in ("scholarly_evidence_sufficient", "scholarly_sources_exhausted"):
            if not isinstance(getattr(self, name), bool):
                raise LiteratureError(f"{name} must be boolean")
        if not isinstance(self.insufficiency_reasons, tuple):
            raise LiteratureError("insufficiency reasons must be a tuple")
        reasons = tuple(
            _clean_text(value, "scholarly insufficiency reason")
            for value in self.insufficiency_reasons
        )
        if len(set(reasons)) != len(reasons):
            raise LiteratureError("scholarly insufficiency reasons must be unique")
        if self.scholarly_evidence_sufficient and reasons:
            raise LiteratureError("sufficient scholarly evidence cannot claim insufficiency")
        if self.scholarly_sources_exhausted and not self.scholarly_evidence_sufficient and not reasons:
            raise LiteratureError("exhausted insufficient search requires explicit reasons")
        transient_or_blocked = {
            RetrievalStatus.UNAVAILABLE,
            RetrievalStatus.RATE_LIMITED,
            RetrievalStatus.FAILED,
            RetrievalStatus.MALFORMED,
        }
        if self.scholarly_sources_exhausted and any(
            value.status in transient_or_blocked for value in attempts
        ):
            raise LiteratureError(
                "failed, unavailable, malformed, or rate-limited attempts are not exhaustion"
            )
        if not isinstance(self.evidence_artifact_hashes, tuple) or not self.evidence_artifact_hashes:
            raise LiteratureError("scholarly search summary requires captured provenance")
        evidence_values = set(self.evidence_artifact_hashes)
        if len(evidence_values) != len(self.evidence_artifact_hashes):
            raise LiteratureError("scholarly search evidence hashes must be unique")
        for value in evidence_values:
            _require_hash(value, "scholarly search evidence_artifact_hash")
        if self.schema_version != "scholarly-search-summary/v1":
            raise LiteratureError("unsupported scholarly search summary schema")
        evidence_values.update(value.receipt_artifact_hash for value in attempts)
        evidence_values.add(self.sufficiency_assessment_artifact_hash)
        evidence = tuple(sorted(evidence_values))
        object.__setattr__(self, "goal_id", goal_id)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "insufficiency_reasons", reasons)
        object.__setattr__(self, "evidence_artifact_hashes", evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "goal_id": self.goal_id,
            "citation_expansion_plan_sha256": self.citation_expansion_plan_sha256,
            "investigation_history_sha256": self.investigation_history_sha256,
            "sufficiency_assessment_artifact_hash": self.sufficiency_assessment_artifact_hash,
            "scholarly_rounds_completed": self.scholarly_rounds_completed,
            "attempts": [value.to_dict() for value in self.attempts],
            "records_acquired": self.records_acquired,
            "full_text_records_reviewed": self.full_text_records_reviewed,
            "scholarly_evidence_sufficient": self.scholarly_evidence_sufficient,
            "scholarly_sources_exhausted": self.scholarly_sources_exhausted,
            "insufficiency_reasons": list(self.insufficiency_reasons),
            "evidence_artifact_hashes": list(self.evidence_artifact_hashes),
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))

    @property
    def queried_sources(self) -> tuple[ScholarlySource, ...]:
        return tuple(sorted({value.source for value in self.attempts}, key=lambda value: value.value))


@dataclass(frozen=True, slots=True)
class GeneralWebFallbackDecision:
    goal_id: str
    purpose: GeneralWebPurpose
    status: GeneralWebFallbackStatus
    policy_sha256: str
    scholarly_summary_sha256: str
    citation_expansion_plan_sha256: str
    evidence_artifact_hashes: tuple[str, ...]
    reason: str
    schema_version: str = "general-web-fallback-decision/v1"

    def __post_init__(self) -> None:
        goal_id = _clean_text(self.goal_id, "web fallback goal_id")
        try:
            purpose = (
                self.purpose
                if isinstance(self.purpose, GeneralWebPurpose)
                else GeneralWebPurpose(self.purpose)
            )
            status = (
                self.status
                if isinstance(self.status, GeneralWebFallbackStatus)
                else GeneralWebFallbackStatus(self.status)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("general-web fallback decision enum is invalid") from exc
        _require_hash(self.policy_sha256, "web fallback policy_sha256")
        _require_hash(self.scholarly_summary_sha256, "web fallback summary_sha256")
        _require_hash(
            self.citation_expansion_plan_sha256,
            "web fallback citation_expansion_plan_sha256",
        )
        if not isinstance(self.evidence_artifact_hashes, tuple) or not self.evidence_artifact_hashes:
            raise LiteratureError("web fallback decision requires evidence provenance")
        evidence = tuple(sorted(set(self.evidence_artifact_hashes)))
        if len(evidence) != len(self.evidence_artifact_hashes):
            raise LiteratureError("web fallback decision evidence must be unique")
        for value in evidence:
            _require_hash(value, "web fallback evidence_artifact_hash")
        reason = _clean_text(self.reason, "web fallback decision reason")
        if self.schema_version != "general-web-fallback-decision/v1":
            raise LiteratureError("unsupported general-web fallback decision schema")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "goal_id", goal_id)
        object.__setattr__(self, "evidence_artifact_hashes", evidence)
        object.__setattr__(self, "reason", reason)

    @property
    def may_use_general_web(self) -> bool:
        return self.status is GeneralWebFallbackStatus.ALLOWED_AFTER_SCHOLARLY_INSUFFICIENCY

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "goal_id": self.goal_id,
            "purpose": self.purpose.value,
            "status": self.status.value,
            "policy_sha256": self.policy_sha256,
            "scholarly_summary_sha256": self.scholarly_summary_sha256,
            "citation_expansion_plan_sha256": self.citation_expansion_plan_sha256,
            "evidence_artifact_hashes": list(self.evidence_artifact_hashes),
            "reason": self.reason,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


def decide_general_web_fallback(
    policy: GeneralWebFallbackPolicy,
    summary: ScholarlySearchSummary,
    purpose: GeneralWebPurpose,
) -> GeneralWebFallbackDecision:
    """Return a provenance-bound decision; this function never performs web I/O."""

    if not isinstance(policy, GeneralWebFallbackPolicy):
        raise LiteratureError("general-web fallback policy is invalid")
    if not isinstance(summary, ScholarlySearchSummary):
        raise LiteratureError("scholarly search summary is invalid")
    try:
        selected_purpose = (
            purpose if isinstance(purpose, GeneralWebPurpose) else GeneralWebPurpose(purpose)
        )
    except (TypeError, ValueError) as exc:
        raise LiteratureError("general-web fallback purpose is invalid") from exc
    if summary.scholarly_evidence_sufficient:
        status = GeneralWebFallbackStatus.SCHOLARLY_EVIDENCE_SUFFICIENT
        reason = "Scholarly evidence is sufficient; general-web fallback is forbidden."
    elif (
        not summary.scholarly_sources_exhausted
        or summary.scholarly_rounds_completed < policy.minimum_scholarly_rounds
        or not set(policy.required_scholarly_sources).issubset(summary.queried_sources)
    ):
        status = GeneralWebFallbackStatus.MORE_SCHOLARLY_SEARCH_REQUIRED
        reason = "Required scholarly rounds or sources have not been exhausted."
    elif not policy.allow_general_web or selected_purpose not in policy.allowed_purposes:
        status = GeneralWebFallbackStatus.BLOCKED_BY_POLICY
        reason = "The explicit policy does not allow this general-web purpose."
    else:
        status = GeneralWebFallbackStatus.ALLOWED_AFTER_SCHOLARLY_INSUFFICIENCY
        reason = "Captured scholarly search is insufficient and exhausted under policy."
    return GeneralWebFallbackDecision(
        goal_id=summary.goal_id,
        purpose=selected_purpose,
        status=status,
        policy_sha256=policy.sha256,
        scholarly_summary_sha256=summary.sha256,
        citation_expansion_plan_sha256=summary.citation_expansion_plan_sha256,
        evidence_artifact_hashes=summary.evidence_artifact_hashes,
        reason=reason,
    )


@dataclass(frozen=True, slots=True)
class CitationReference:
    reference_text: str
    identifier: ScholarlyIdentifier | None = None
    title: str | None = None
    authors: tuple[str, ...] = ()
    publication_year: int | None = None

    def __post_init__(self) -> None:
        reference_text = _clean_text(self.reference_text, "reference_text")
        if self.identifier is not None and not isinstance(self.identifier, ScholarlyIdentifier):
            raise LiteratureError("citation identifier must be ScholarlyIdentifier or None")
        title = _clean_text(self.title, "citation title", optional=True)
        if not isinstance(self.authors, tuple) or any(not isinstance(value, str) for value in self.authors):
            raise LiteratureError("citation authors must be a tuple of strings")
        authors = tuple(_clean_text(value, "citation author") for value in self.authors)
        if self.publication_year is not None and (
            isinstance(self.publication_year, bool)
            or not isinstance(self.publication_year, int)
            or not 1000 <= self.publication_year <= 3000
        ):
            raise LiteratureError("citation publication_year is invalid")
        object.__setattr__(self, "reference_text", reference_text)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "authors", authors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference_text": self.reference_text,
            "identifier": (
                self.identifier.to_dict() if self.identifier is not None else None
            ),
            "title": self.title,
            "authors": list(self.authors),
            "publication_year": self.publication_year,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CitationReference:
        _exact_keys(
            value,
            frozenset(
                {
                    "reference_text",
                    "identifier",
                    "title",
                    "authors",
                    "publication_year",
                }
            ),
            "citation reference",
        )
        authors = value["authors"]
        if not isinstance(authors, (list, tuple)):
            raise LiteratureError("citation reference authors must be a list")
        identifier = value["identifier"]
        return cls(
            reference_text=value["reference_text"],
            identifier=(
                ScholarlyIdentifier.from_dict(identifier)
                if identifier is not None
                else None
            ),
            title=value["title"],
            authors=tuple(authors),
            publication_year=value["publication_year"],
        )


@dataclass(frozen=True, slots=True)
class PassageLocator:
    section_id: str
    passage_id: str
    start_char: int
    end_char: int
    passage_sha256: str
    source_artifact_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "section_id", _clean_text(self.section_id, "locator section_id"))
        object.__setattr__(self, "passage_id", _clean_text(self.passage_id, "locator passage_id"))
        if (
            isinstance(self.start_char, bool)
            or isinstance(self.end_char, bool)
            or not isinstance(self.start_char, int)
            or not isinstance(self.end_char, int)
            or self.start_char < 0
            or self.end_char <= self.start_char
        ):
            raise LiteratureError("locator offsets are invalid")
        _require_hash(self.passage_sha256, "locator passage_sha256")
        _require_hash(self.source_artifact_hash, "locator source_artifact_hash")

    @classmethod
    def for_passage(cls, passage: FullTextPassage) -> PassageLocator:
        return cls(
            passage.section_id,
            passage.passage_id,
            passage.start_char,
            passage.end_char,
            passage.passage_sha256,
            passage.source_artifact_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "passage_id": self.passage_id,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "passage_sha256": self.passage_sha256,
            "source_artifact_hash": self.source_artifact_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PassageLocator:
        _exact_keys(
            value,
            frozenset(
                {
                    "section_id",
                    "passage_id",
                    "start_char",
                    "end_char",
                    "passage_sha256",
                    "source_artifact_hash",
                }
            ),
            "passage locator",
        )
        return cls(
            section_id=value["section_id"],
            passage_id=value["passage_id"],
            start_char=value["start_char"],
            end_char=value["end_char"],
            passage_sha256=value["passage_sha256"],
            source_artifact_hash=value["source_artifact_hash"],
        )


@dataclass(frozen=True, slots=True)
class SemanticAssessment:
    claim_sha256: str
    passage_sha256: str
    source_artifact_hash: str
    locator_sha256: str
    supports_claim: bool
    assessment_artifact_hash: str
    verifier_id: str

    def __post_init__(self) -> None:
        _require_hash(self.claim_sha256, "semantic claim_sha256")
        _require_hash(self.passage_sha256, "semantic passage_sha256")
        _require_hash(self.source_artifact_hash, "semantic source_artifact_hash")
        _require_hash(self.locator_sha256, "semantic locator_sha256")
        _require_hash(self.assessment_artifact_hash, "semantic assessment_artifact_hash")
        _clean_text(self.verifier_id, "semantic verifier_id")
        if not isinstance(self.supports_claim, bool):
            raise LiteratureError("supports_claim must be boolean")

    @classmethod
    def for_claim(
        cls,
        claim_text: str,
        passage: FullTextPassage,
        *,
        supports_claim: bool,
        assessment_artifact_hash: str,
        verifier_id: str,
    ) -> SemanticAssessment:
        claim = _clean_text(claim_text, "claim_text")
        assert claim is not None
        return cls(
            _sha256(claim),
            passage.passage_sha256,
            passage.source_artifact_hash,
            passage.locator_sha256,
            supports_claim,
            assessment_artifact_hash,
            verifier_id,
        )


@dataclass(frozen=True, slots=True)
class ContextAssessment:
    claim_sha256: str
    passage_sha256: str
    source_artifact_hash: str
    locator_sha256: str
    context_sha256: str
    contradicts_claim: bool
    assessment_artifact_hash: str
    verifier_id: str

    def __post_init__(self) -> None:
        _require_hash(self.claim_sha256, "context claim_sha256")
        _require_hash(self.passage_sha256, "context passage_sha256")
        _require_hash(self.source_artifact_hash, "context source_artifact_hash")
        _require_hash(self.locator_sha256, "context locator_sha256")
        _require_hash(self.context_sha256, "context context_sha256")
        _require_hash(self.assessment_artifact_hash, "context assessment_artifact_hash")
        _clean_text(self.verifier_id, "context verifier_id")
        if not isinstance(self.contradicts_claim, bool):
            raise LiteratureError("contradicts_claim must be boolean")

    @classmethod
    def for_claim(
        cls,
        claim_text: str,
        passage: FullTextPassage,
        *,
        contradicts_claim: bool,
        assessment_artifact_hash: str,
        verifier_id: str,
    ) -> ContextAssessment:
        claim = _clean_text(claim_text, "claim_text")
        assert claim is not None
        return cls(
            _sha256(claim),
            passage.passage_sha256,
            passage.source_artifact_hash,
            passage.locator_sha256,
            passage.context_sha256,
            contradicts_claim,
            assessment_artifact_hash,
            verifier_id,
        )


@dataclass(frozen=True, slots=True)
class ReferenceVerification:
    level: VerificationLevel
    reference_identifier: ScholarlyIdentifier | None
    matched_source_record_id: str | None
    metadata_mismatches: tuple[str, ...]
    failure_reasons: tuple[str, ...]
    locator: PassageLocator | None
    parent_artifact_hashes: tuple[str, ...]
    retrieval_status: RetrievalStatus | None = None
    retrieval_source: ScholarlySource | None = None
    retrieval_request_id: str | None = None
    retrieval_failure_reason: str | None = None
    raw_artifact_hash: str | None = None
    response_artifact_hash: str | None = None

    def __post_init__(self) -> None:
        try:
            level = (
                self.level
                if isinstance(self.level, VerificationLevel)
                else VerificationLevel(self.level)
            )
            retrieval_status = (
                self.retrieval_status
                if isinstance(self.retrieval_status, RetrievalStatus)
                else RetrievalStatus(self.retrieval_status)
                if self.retrieval_status is not None
                else None
            )
            retrieval_source = (
                self.retrieval_source
                if isinstance(self.retrieval_source, ScholarlySource)
                else ScholarlySource(self.retrieval_source)
                if self.retrieval_source is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("verification level or retrieval context is invalid") from exc
        if self.reference_identifier is not None and not isinstance(
            self.reference_identifier,
            ScholarlyIdentifier,
        ):
            raise LiteratureError("verification reference identifier is malformed")
        matched_source_record_id = _clean_text(
            self.matched_source_record_id,
            "verification matched_source_record_id",
            optional=True,
        )
        if not isinstance(self.metadata_mismatches, tuple) or any(
            not isinstance(value, str) for value in self.metadata_mismatches
        ):
            raise LiteratureError("verification metadata mismatches are malformed")
        if not isinstance(self.failure_reasons, tuple) or any(
            not isinstance(value, str) for value in self.failure_reasons
        ):
            raise LiteratureError("verification failure reasons are malformed")
        if self.locator is not None and not isinstance(self.locator, PassageLocator):
            raise LiteratureError("verification locator is malformed")
        request_id = _require_hash(
            self.retrieval_request_id,
            "verification retrieval_request_id",
            optional=True,
        )
        raw_hash = _require_hash(
            self.raw_artifact_hash,
            "verification raw_artifact_hash",
            optional=True,
        )
        response_hash = _require_hash(
            self.response_artifact_hash,
            "verification response_artifact_hash",
            optional=True,
        )
        failure_reason = _clean_text(
            self.retrieval_failure_reason,
            "verification retrieval_failure_reason",
            optional=True,
        )
        if not isinstance(self.parent_artifact_hashes, tuple):
            raise LiteratureError("verification parents must be a tuple")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        if len(parents) != len(self.parent_artifact_hashes):
            raise LiteratureError("verification parents must be unique")
        for value in parents:
            _require_hash(value, "verification parent_artifact_hash")
        _require_persistable_parent_count(parents, "reference verification")
        if raw_hash is not None and raw_hash not in parents:
            raise LiteratureError("verification provenance omits raw artifact")
        if response_hash is not None and response_hash not in parents:
            raise LiteratureError("verification provenance omits response artifact")
        object.__setattr__(self, "level", level)
        object.__setattr__(self, "retrieval_status", retrieval_status)
        object.__setattr__(self, "retrieval_source", retrieval_source)
        object.__setattr__(self, "matched_source_record_id", matched_source_record_id)
        object.__setattr__(self, "retrieval_request_id", request_id)
        object.__setattr__(self, "retrieval_failure_reason", failure_reason)
        object.__setattr__(self, "raw_artifact_hash", raw_hash)
        object.__setattr__(self, "response_artifact_hash", response_hash)
        object.__setattr__(self, "parent_artifact_hashes", parents)

    @property
    def semantically_supported(self) -> bool:
        return self.level >= VerificationLevel.LEVEL_4

    @property
    def context_noncontradictory(self) -> bool:
        return self.level >= VerificationLevel.LEVEL_5

    @property
    def passage_structurally_grounded(self) -> bool:
        """Whether an exact passage occurrence is located, independent of support."""

        return self.level >= VerificationLevel.LEVEL_3

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": int(self.level),
            "reference_identifier": (
                self.reference_identifier.to_dict()
                if self.reference_identifier is not None
                else None
            ),
            "matched_source_record_id": self.matched_source_record_id,
            "metadata_mismatches": list(self.metadata_mismatches),
            "failure_reasons": list(self.failure_reasons),
            "locator": self.locator.to_dict() if self.locator is not None else None,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
            "retrieval_status": (
                self.retrieval_status.value
                if self.retrieval_status is not None
                else None
            ),
            "retrieval_source": (
                self.retrieval_source.value
                if self.retrieval_source is not None
                else None
            ),
            "retrieval_request_id": self.retrieval_request_id,
            "retrieval_failure_reason": self.retrieval_failure_reason,
            "raw_artifact_hash": self.raw_artifact_hash,
            "response_artifact_hash": self.response_artifact_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ReferenceVerification:
        _exact_keys(
            value,
            frozenset(
                {
                    "level",
                    "reference_identifier",
                    "matched_source_record_id",
                    "metadata_mismatches",
                    "failure_reasons",
                    "locator",
                    "parent_artifact_hashes",
                    "retrieval_status",
                    "retrieval_source",
                    "retrieval_request_id",
                    "retrieval_failure_reason",
                    "raw_artifact_hash",
                    "response_artifact_hash",
                }
            ),
            "reference verification",
        )
        for name in (
            "metadata_mismatches",
            "failure_reasons",
            "parent_artifact_hashes",
        ):
            if not isinstance(value[name], (list, tuple)):
                raise LiteratureError(f"verification {name} must be a list")
        identifier = value["reference_identifier"]
        locator = value["locator"]
        return cls(
            level=value["level"],
            reference_identifier=(
                ScholarlyIdentifier.from_dict(identifier)
                if identifier is not None
                else None
            ),
            matched_source_record_id=value["matched_source_record_id"],
            metadata_mismatches=tuple(value["metadata_mismatches"]),
            failure_reasons=tuple(value["failure_reasons"]),
            locator=(PassageLocator.from_dict(locator) if locator is not None else None),
            parent_artifact_hashes=tuple(value["parent_artifact_hashes"]),
            retrieval_status=value["retrieval_status"],
            retrieval_source=value["retrieval_source"],
            retrieval_request_id=value["retrieval_request_id"],
            retrieval_failure_reason=value["retrieval_failure_reason"],
            raw_artifact_hash=value["raw_artifact_hash"],
            response_artifact_hash=value["response_artifact_hash"],
        )


@dataclass(frozen=True, slots=True)
class ScholarlyRelevanceAssessment:
    """Target-bound, persistable keep/filter decision for one graph occurrence."""

    goal_id: str
    target_sha256: str
    node_id: str
    canonical_work_key: str
    record_sha256: str
    methodology_relevance: int
    problem_alignment: int
    disconfirming_evidence: bool
    retained: bool
    retained_source_id: str | None
    decision_reason: str
    source_parent_artifact_hashes: tuple[str, ...]
    schema_version: str = "scholarly-relevance-assessment/v1"

    def __post_init__(self) -> None:
        goal_id = _clean_text(self.goal_id, "relevance assessment goal_id")
        _require_hash(self.target_sha256, "relevance assessment target_sha256")
        if not isinstance(self.node_id, str) or _CITATION_NODE_RE.fullmatch(
            self.node_id
        ) is None:
            raise LiteratureError("relevance assessment node identity is invalid")
        if (
            not isinstance(self.canonical_work_key, str)
            or _CITATION_WORK_RE.fullmatch(self.canonical_work_key) is None
        ):
            raise LiteratureError("relevance assessment work identity is invalid")
        _require_hash(self.record_sha256, "relevance assessment record_sha256")
        for name in ("methodology_relevance", "problem_alignment"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 5
            ):
                raise LiteratureError(f"relevance assessment {name} is invalid")
        if not isinstance(self.disconfirming_evidence, bool):
            raise LiteratureError(
                "relevance assessment disconfirming_evidence must be boolean"
            )
        if not isinstance(self.retained, bool):
            raise LiteratureError("relevance assessment retained must be boolean")
        retained_source_id = _clean_text(
            self.retained_source_id,
            "relevance assessment retained_source_id",
            optional=True,
        )
        if self.retained != (retained_source_id is not None):
            raise LiteratureError(
                "relevance assessment retained/source binding is inconsistent"
            )
        decision_reason = _clean_text(
            self.decision_reason,
            "relevance assessment decision_reason",
        )
        if (
            not isinstance(self.source_parent_artifact_hashes, tuple)
            or not self.source_parent_artifact_hashes
        ):
            raise LiteratureError("relevance assessment requires source provenance")
        parents = tuple(sorted(set(self.source_parent_artifact_hashes)))
        if len(parents) != len(self.source_parent_artifact_hashes):
            raise LiteratureError(
                "relevance assessment source provenance must be unique"
            )
        for parent in parents:
            _require_hash(parent, "relevance assessment source parent")
        _require_persistable_parent_count(parents, "relevance assessment")
        if self.schema_version != "scholarly-relevance-assessment/v1":
            raise LiteratureError("unsupported scholarly relevance schema")
        object.__setattr__(self, "goal_id", goal_id)
        object.__setattr__(self, "retained_source_id", retained_source_id)
        object.__setattr__(self, "decision_reason", decision_reason)
        object.__setattr__(self, "source_parent_artifact_hashes", parents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "goal_id": self.goal_id,
            "target_sha256": self.target_sha256,
            "node_id": self.node_id,
            "canonical_work_key": self.canonical_work_key,
            "record_sha256": self.record_sha256,
            "methodology_relevance": self.methodology_relevance,
            "problem_alignment": self.problem_alignment,
            "disconfirming_evidence": self.disconfirming_evidence,
            "retained": self.retained,
            "retained_source_id": self.retained_source_id,
            "decision_reason": self.decision_reason,
            "source_parent_artifact_hashes": list(
                self.source_parent_artifact_hashes
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlyRelevanceAssessment:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "goal_id",
                    "target_sha256",
                    "node_id",
                    "canonical_work_key",
                    "record_sha256",
                    "methodology_relevance",
                    "problem_alignment",
                    "disconfirming_evidence",
                    "retained",
                    "retained_source_id",
                    "decision_reason",
                    "source_parent_artifact_hashes",
                }
            ),
            "scholarly relevance assessment",
        )
        parents = value["source_parent_artifact_hashes"]
        if not isinstance(parents, (list, tuple)):
            raise LiteratureError(
                "scholarly relevance assessment parents must be a list"
            )
        return cls(
            goal_id=value["goal_id"],
            target_sha256=value["target_sha256"],
            node_id=value["node_id"],
            canonical_work_key=value["canonical_work_key"],
            record_sha256=value["record_sha256"],
            methodology_relevance=value["methodology_relevance"],
            problem_alignment=value["problem_alignment"],
            disconfirming_evidence=value["disconfirming_evidence"],
            retained=value["retained"],
            retained_source_id=value["retained_source_id"],
            decision_reason=value["decision_reason"],
            source_parent_artifact_hashes=tuple(parents),
            schema_version=value["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class EvidenceRankingCandidate:
    """A normalized record or graph-only occurrence plus target-bound review."""

    record: ScholarlyRecord | CitationGraphNode
    target_sha256: str
    methodology_relevance: int
    problem_alignment: int
    disconfirming_evidence: bool
    relevance_assessment_artifact_hash: str
    verification: ReferenceVerification | None
    verification_target_sha256: str | None
    verification_artifact_hash: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.record, (ScholarlyRecord, CitationGraphNode)):
            raise LiteratureError(
                "evidence ranking candidate requires a record or citation node"
            )
        _require_hash(self.target_sha256, "evidence ranking target_sha256")
        for name in ("methodology_relevance", "problem_alignment"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
                raise LiteratureError(f"{name} must be an integer from 1 through 5")
        if not isinstance(self.disconfirming_evidence, bool):
            raise LiteratureError("disconfirming_evidence must be boolean")
        _require_hash(
            self.relevance_assessment_artifact_hash,
            "relevance_assessment_artifact_hash",
        )
        if self.verification is None:
            if self.verification_target_sha256 is not None or self.verification_artifact_hash is not None:
                raise LiteratureError("verification binding exists without verification")
            return
        if not isinstance(self.verification, ReferenceVerification):
            raise LiteratureError("candidate verification is malformed")
        if isinstance(self.record, CitationGraphNode):
            raise LiteratureError(
                "graph-only evidence cannot claim passage/reference verification"
            )
        _require_hash(
            self.verification_target_sha256,
            "verification_target_sha256",
        )
        _require_hash(
            self.verification_artifact_hash,
            "verification_artifact_hash",
        )
        if self.verification_target_sha256 != self.target_sha256:
            raise LiteratureError("verification is bound to a different ranking target")
        verification = self.verification
        if verification.level >= VerificationLevel.LEVEL_1:
            if verification.matched_source_record_id != self.record.source_record_id:
                raise LiteratureError("verification is bound to a different scholarly record")
            if not set(self.record.parent_artifact_hashes).issubset(
                verification.parent_artifact_hashes
            ):
                raise LiteratureError("verification omits scholarly record provenance")
        if (
            verification.retrieval_request_id is not None
            and verification.retrieval_request_id != self.record.request_id
        ):
            raise LiteratureError("verification request does not match ranked record")
        if (
            verification.raw_artifact_hash is not None
            and verification.raw_artifact_hash != self.record.raw_artifact_hash
        ):
            raise LiteratureError("verification raw artifact does not match ranked record")
        if (
            verification.response_artifact_hash is not None
            and verification.response_artifact_hash != self.record.response_artifact_hash
        ):
            raise LiteratureError("verification response artifact does not match ranked record")


@dataclass(frozen=True, slots=True)
class RankedScholarlyEvidence:
    position: int
    node_id: str
    canonical_work_key: str
    source: ScholarlySource
    source_fitness: SourceFitnessTier
    evidence_support: EvidenceSupportTier
    verification_level: VerificationLevel
    record_sha256: str
    methodology_relevance: int
    problem_alignment: int
    disconfirming_evidence: bool
    relevance_assessment_artifact_hash: str
    verification_artifact_hash: str | None
    parent_artifact_hashes: tuple[str, ...]
    reasons: tuple[str, ...]
    schema_version: str = "ranked-scholarly-evidence/v1"

    def __post_init__(self) -> None:
        if isinstance(self.position, bool) or not isinstance(self.position, int) or self.position <= 0:
            raise LiteratureError("evidence rank position must be positive")
        if not isinstance(self.node_id, str) or _CITATION_NODE_RE.fullmatch(self.node_id) is None:
            raise LiteratureError("ranked evidence node identity is invalid")
        if (
            not isinstance(self.canonical_work_key, str)
            or _CITATION_WORK_RE.fullmatch(self.canonical_work_key) is None
        ):
            raise LiteratureError("ranked evidence canonical work identity is invalid")
        try:
            source = self.source if isinstance(self.source, ScholarlySource) else ScholarlySource(self.source)
            source_fitness = (
                self.source_fitness
                if isinstance(self.source_fitness, SourceFitnessTier)
                else SourceFitnessTier(self.source_fitness)
            )
            evidence_support = (
                self.evidence_support
                if isinstance(self.evidence_support, EvidenceSupportTier)
                else EvidenceSupportTier(self.evidence_support)
            )
            level = (
                self.verification_level
                if isinstance(self.verification_level, VerificationLevel)
                else VerificationLevel(self.verification_level)
            )
        except (TypeError, ValueError) as exc:
            raise LiteratureError("ranked evidence enum is invalid") from exc
        _require_hash(self.record_sha256, "ranked evidence record_sha256")
        for name in ("methodology_relevance", "problem_alignment"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
                raise LiteratureError(f"ranked {name} is invalid")
        if not isinstance(self.disconfirming_evidence, bool):
            raise LiteratureError("ranked disconfirming_evidence must be boolean")
        _require_hash(
            self.relevance_assessment_artifact_hash,
            "ranked relevance_assessment_artifact_hash",
        )
        _require_hash(
            self.verification_artifact_hash,
            "ranked verification_artifact_hash",
            optional=True,
        )
        if not isinstance(self.parent_artifact_hashes, tuple) or not self.parent_artifact_hashes:
            raise LiteratureError("ranked evidence requires provenance")
        parents = tuple(sorted(set(self.parent_artifact_hashes)))
        if len(parents) != len(self.parent_artifact_hashes):
            raise LiteratureError("ranked evidence provenance must be unique")
        for value in parents:
            _require_hash(value, "ranked evidence parent_artifact_hash")
        if not isinstance(self.reasons, tuple) or not self.reasons:
            raise LiteratureError("ranked evidence requires explicit reasons")
        reasons = tuple(_clean_text(value, "evidence ranking reason") for value in self.reasons)
        expected_support = _support_tier(level)
        if evidence_support is not expected_support:
            raise LiteratureError(
                "ranked evidence support tier disagrees with verification level"
            )
        if self.relevance_assessment_artifact_hash not in parents:
            raise LiteratureError(
                "ranked evidence provenance omits its relevance assessment"
            )
        if self.verification_artifact_hash is None:
            if level is not VerificationLevel.LEVEL_0:
                raise LiteratureError(
                    "ranked evidence claims verification without an artifact"
                )
        elif self.verification_artifact_hash not in parents:
            raise LiteratureError(
                "ranked evidence provenance omits its verification artifact"
            )
        expected_reasons = (
            f"claim-support depth is {expected_support.value} (LEVEL_{int(level)})",
            f"retrieval fitness is {source_fitness.value}",
            "retrieval fitness does not establish semantic claim support",
        )
        if reasons != expected_reasons:
            raise LiteratureError(
                "ranked evidence reasons disagree with its deterministic tiers"
            )
        if self.schema_version != "ranked-scholarly-evidence/v1":
            raise LiteratureError("unsupported ranked evidence schema")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "source_fitness", source_fitness)
        object.__setattr__(self, "evidence_support", evidence_support)
        object.__setattr__(self, "verification_level", level)
        object.__setattr__(self, "parent_artifact_hashes", parents)
        object.__setattr__(self, "reasons", reasons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "position": self.position,
            "node_id": self.node_id,
            "canonical_work_key": self.canonical_work_key,
            "source": self.source.value,
            "source_fitness": self.source_fitness.value,
            "evidence_support": self.evidence_support.value,
            "verification_level": int(self.verification_level),
            "record_sha256": self.record_sha256,
            "methodology_relevance": self.methodology_relevance,
            "problem_alignment": self.problem_alignment,
            "disconfirming_evidence": self.disconfirming_evidence,
            "relevance_assessment_artifact_hash": self.relevance_assessment_artifact_hash,
            "verification_artifact_hash": self.verification_artifact_hash,
            "parent_artifact_hashes": list(self.parent_artifact_hashes),
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RankedScholarlyEvidence:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "position",
                    "node_id",
                    "canonical_work_key",
                    "source",
                    "source_fitness",
                    "evidence_support",
                    "verification_level",
                    "record_sha256",
                    "methodology_relevance",
                    "problem_alignment",
                    "disconfirming_evidence",
                    "relevance_assessment_artifact_hash",
                    "verification_artifact_hash",
                    "parent_artifact_hashes",
                    "reasons",
                }
            ),
            "ranked scholarly evidence",
        )
        parents = value["parent_artifact_hashes"]
        reasons = value["reasons"]
        if not isinstance(parents, (list, tuple)) or not isinstance(
            reasons,
            (list, tuple),
        ):
            raise LiteratureError(
                "ranked scholarly evidence provenance/reasons must be lists"
            )
        return cls(
            position=value["position"],
            node_id=value["node_id"],
            canonical_work_key=value["canonical_work_key"],
            source=value["source"],
            source_fitness=value["source_fitness"],
            evidence_support=value["evidence_support"],
            verification_level=value["verification_level"],
            record_sha256=value["record_sha256"],
            methodology_relevance=value["methodology_relevance"],
            problem_alignment=value["problem_alignment"],
            disconfirming_evidence=value["disconfirming_evidence"],
            relevance_assessment_artifact_hash=value[
                "relevance_assessment_artifact_hash"
            ],
            verification_artifact_hash=value["verification_artifact_hash"],
            parent_artifact_hashes=tuple(parents),
            reasons=tuple(reasons),
            schema_version=value["schema_version"],
        )


def _support_tier(level: VerificationLevel) -> EvidenceSupportTier:
    if level >= VerificationLevel.LEVEL_5:
        return EvidenceSupportTier.CONTEXT_CHECKED_SUPPORT
    if level >= VerificationLevel.LEVEL_4:
        return EvidenceSupportTier.PASSAGE_SUPPORT
    if level >= VerificationLevel.LEVEL_3:
        return EvidenceSupportTier.PASSAGE_LOCATED
    if level >= VerificationLevel.LEVEL_2:
        return EvidenceSupportTier.METADATA_MATCHED
    if level >= VerificationLevel.LEVEL_1:
        return EvidenceSupportTier.RESOLVED_WORK
    return EvidenceSupportTier.CAPTURED_RECORD_ONLY


def _source_fitness(record: ScholarlyRecord) -> SourceFitnessTier:
    if record.conflicts:
        return SourceFitnessTier.CONFLICTED_METADATA
    if record.full_text_status is FullTextStatus.AVAILABLE and record.passages:
        return SourceFitnessTier.FULL_TEXT_CAPTURED
    return SourceFitnessTier.METADATA_CAPTURED


@dataclass(frozen=True, slots=True)
class ScholarlyEvidenceRanking:
    goal_id: str
    target_sha256: str
    ranked: tuple[RankedScholarlyEvidence, ...]
    policy_id: str = "claim-depth-then-relevance-then-retrieval/v1"
    schema_version: str = "scholarly-evidence-ranking/v1"

    def __post_init__(self) -> None:
        goal_id = _clean_text(self.goal_id, "evidence ranking goal_id")
        _require_hash(self.target_sha256, "evidence ranking target_sha256")
        if not isinstance(self.ranked, tuple) or not self.ranked:
            raise LiteratureError("evidence ranking snapshot requires ranked candidates")
        if not all(isinstance(value, RankedScholarlyEvidence) for value in self.ranked):
            raise LiteratureError("evidence ranking snapshot is malformed")
        if tuple(value.position for value in self.ranked) != tuple(range(1, len(self.ranked) + 1)):
            raise LiteratureError("evidence ranking positions must be contiguous")
        if len({value.node_id for value in self.ranked}) != len(self.ranked):
            raise LiteratureError("evidence ranking snapshot contains duplicate occurrences")
        if len({value.canonical_work_key for value in self.ranked}) != len(self.ranked):
            raise LiteratureError("evidence ranking snapshot contains duplicate works")
        if self.policy_id != "claim-depth-then-relevance-then-retrieval/v1":
            raise LiteratureError("unsupported evidence ranking policy")
        if self.schema_version != "scholarly-evidence-ranking/v1":
            raise LiteratureError("unsupported evidence ranking schema")
        object.__setattr__(self, "goal_id", goal_id)
        _require_persistable_parent_count(
            self.parent_artifact_hashes,
            "scholarly evidence ranking",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "goal_id": self.goal_id,
            "target_sha256": self.target_sha256,
            "ranked": [value.to_dict() for value in self.ranked],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScholarlyEvidenceRanking:
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "policy_id",
                    "goal_id",
                    "target_sha256",
                    "ranked",
                }
            ),
            "scholarly evidence ranking",
        )
        ranked = value["ranked"]
        if not isinstance(ranked, (list, tuple)):
            raise LiteratureError("scholarly evidence ranking entries must be a list")
        return cls(
            goal_id=value["goal_id"],
            target_sha256=value["target_sha256"],
            ranked=tuple(RankedScholarlyEvidence.from_dict(item) for item in ranked),
            policy_id=value["policy_id"],
            schema_version=value["schema_version"],
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def sha256(self) -> str:
        return _sha256(self.canonical_bytes)

    @property
    def parent_artifact_hashes(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    artifact_hash
                    for value in self.ranked
                    for artifact_hash in value.parent_artifact_hashes
                }
            )
        )


def rank_scholarly_evidence(
    candidates: Sequence[EvidenceRankingCandidate],
    *,
    goal_id: str,
    target_sha256: str,
) -> ScholarlyEvidenceRanking:
    """Return a deterministic lexicographic ranking with no opaque score.

    Claim-support depth dominates retrieval fitness.  Consequently a metadata
    record can never be described as passage support merely because its source
    is operationally preferred.
    """

    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)):
        raise LiteratureError("evidence ranking candidates must be a sequence")
    if not candidates:
        raise LiteratureError("evidence ranking requires at least one candidate")
    if len(candidates) > _MAX_JSON_ITEMS:
        raise LiteratureError("evidence ranking candidate set is too large")
    if not all(isinstance(value, EvidenceRankingCandidate) for value in candidates):
        raise LiteratureError("evidence ranking candidate is malformed")
    normalized_goal_id = _clean_text(goal_id, "evidence ranking goal_id")
    target_sha256 = _require_hash(target_sha256, "evidence ranking target_sha256")
    assert target_sha256 is not None
    prepared = []
    seen_nodes: set[str] = set()
    seen_works: set[str] = set()
    fitness_order = {
        SourceFitnessTier.FULL_TEXT_CAPTURED: 0,
        SourceFitnessTier.METADATA_CAPTURED: 1,
        SourceFitnessTier.CONFLICTED_METADATA: 2,
    }
    for candidate in candidates:
        if candidate.target_sha256 != target_sha256:
            raise LiteratureError("candidate is bound to a different ranking target")
        node = (
            candidate.record
            if isinstance(candidate.record, CitationGraphNode)
            else CitationGraphNode.from_record(candidate.record)
        )
        if node.node_id in seen_nodes:
            raise LiteratureError("evidence ranking contains duplicate scholarly occurrences")
        seen_nodes.add(node.node_id)
        if node.canonical_work_key in seen_works:
            raise LiteratureError("evidence ranking contains duplicate scholarly works")
        seen_works.add(node.canonical_work_key)
        level = (
            candidate.verification.level
            if candidate.verification is not None
            else VerificationLevel.LEVEL_0
        )
        if isinstance(candidate.record, CitationGraphNode):
            fitness = (
                SourceFitnessTier.FULL_TEXT_CAPTURED
                if candidate.record.full_text_status is FullTextStatus.AVAILABLE
                else SourceFitnessTier.METADATA_CAPTURED
            )
            conflict_count = 0
        else:
            fitness = _source_fitness(candidate.record)
            conflict_count = len(candidate.record.conflicts)
        parents = set(candidate.record.parent_artifact_hashes)
        if candidate.verification is not None:
            parents.update(candidate.verification.parent_artifact_hashes)
            assert candidate.verification_artifact_hash is not None
            parents.add(candidate.verification_artifact_hash)
        parents.add(candidate.relevance_assessment_artifact_hash)
        support = _support_tier(level)
        reasons = (
            f"claim-support depth is {support.value} (LEVEL_{int(level)})",
            f"retrieval fitness is {fitness.value}",
            "retrieval fitness does not establish semantic claim support",
        )
        prepared.append(
            (
                (
                    -int(level),
                    -candidate.problem_alignment,
                    -candidate.methodology_relevance,
                    0 if candidate.disconfirming_evidence else 1,
                    fitness_order[fitness],
                    conflict_count,
                    node.node_id,
                ),
                node,
                level,
                fitness,
                support,
                tuple(sorted(parents)),
                reasons,
                candidate,
            )
        )
    prepared.sort(key=lambda value: value[0])
    ranked = tuple(
        RankedScholarlyEvidence(
            position=index,
            node_id=node.node_id,
            canonical_work_key=node.canonical_work_key,
            source=node.source,
            source_fitness=fitness,
            evidence_support=support,
            verification_level=level,
            record_sha256=node.record_sha256,
            methodology_relevance=candidate.methodology_relevance,
            problem_alignment=candidate.problem_alignment,
            disconfirming_evidence=candidate.disconfirming_evidence,
            relevance_assessment_artifact_hash=candidate.relevance_assessment_artifact_hash,
            verification_artifact_hash=candidate.verification_artifact_hash,
            parent_artifact_hashes=parents,
            reasons=reasons,
        )
        for index, (
            _,
            node,
            level,
            fitness,
            support,
            parents,
            reasons,
            candidate,
        ) in enumerate(prepared, start=1)
    )
    return ScholarlyEvidenceRanking(
        goal_id=normalized_goal_id,
        target_sha256=target_sha256,
        ranked=ranked,
    )


def _record_passage(record: ScholarlyRecord, locator: PassageLocator) -> FullTextPassage | None:
    matches = tuple(
        passage
        for passage in record.passages
        if passage.section_id == locator.section_id
        and passage.passage_id == locator.passage_id
        and passage.start_char == locator.start_char
        and passage.end_char == locator.end_char
        and passage.passage_sha256 == locator.passage_sha256
        and passage.source_artifact_hash == locator.source_artifact_hash
    )
    return matches[0] if len(matches) == 1 else None


def verify_reference(
    reference: CitationReference,
    record: ScholarlyRecord | AcquisitionResult | None,
    *,
    claim_text: str | None = None,
    locator: PassageLocator | None = None,
    semantic_assessment: SemanticAssessment | None = None,
    context_assessment: ContextAssessment | None = None,
) -> ReferenceVerification:
    """Compute the maximum justified verification depth, never skipping levels.

    An :class:`AcquisitionResult` may be supplied in place of its ``record`` so
    that failed/nonexistent retrievals retain typed status and custody context.
    LEVEL_3 means only that an exact passage occurrence is structurally located
    for an exact claim; semantic support remains false until LEVEL_4.
    """

    if not isinstance(reference, CitationReference):
        raise LiteratureError("verify_reference requires CitationReference")
    failures: list[str] = []
    mismatches: list[str] = []
    parents: set[str] = set()
    level = VerificationLevel.LEVEL_0
    matched_id: str | None = None
    retrieval_status: RetrievalStatus | None = None
    retrieval_source: ScholarlySource | None = None
    retrieval_request_id: str | None = None
    retrieval_failure_reason: str | None = None
    raw_artifact_hash: str | None = None
    response_artifact_hash: str | None = None

    if isinstance(record, AcquisitionResult):
        acquisition = record
        retrieval_status = acquisition.status
        retrieval_source = acquisition.source
        retrieval_request_id = acquisition.request.request_id
        retrieval_failure_reason = acquisition.failure_reason
        raw_artifact_hash = acquisition.raw_artifact_hash
        response_artifact_hash = acquisition.response_artifact_hash
        parents.update(
            value
            for value in (raw_artifact_hash, response_artifact_hash)
            if value is not None
        )
        record = acquisition.record
        if record is not None:
            parents.update(record.parent_artifact_hashes)
    elif isinstance(record, ScholarlyRecord):
        retrieval_status = RetrievalStatus.AVAILABLE
        retrieval_source = record.source
        retrieval_request_id = record.request_id
        raw_artifact_hash = record.raw_artifact_hash
        response_artifact_hash = record.response_artifact_hash
        parents.update(record.parent_artifact_hashes)

    def report(
        *,
        report_level: VerificationLevel | None = None,
        report_identifier: ScholarlyIdentifier | None = reference.identifier,
        report_mismatches: tuple[str, ...] | None = None,
        report_failures: tuple[str, ...] | None = None,
        report_locator: PassageLocator | None = None,
    ) -> ReferenceVerification:
        return ReferenceVerification(
            level if report_level is None else report_level,
            report_identifier,
            matched_id,
            tuple(mismatches) if report_mismatches is None else report_mismatches,
            tuple(failures) if report_failures is None else report_failures,
            report_locator,
            tuple(sorted(parents)),
            retrieval_status,
            retrieval_source,
            retrieval_request_id,
            retrieval_failure_reason,
            raw_artifact_hash,
            response_artifact_hash,
        )

    if reference.identifier is None:
        failures.append("reference has no normalized scholarly identifier")
        return report(report_identifier=None, report_mismatches=())

    if record is None:
        if retrieval_status is None:
            failures.append("reference did not resolve to a scholarly record")
        else:
            failures.append(
                "reference retrieval did not produce a scholarly record: "
                + retrieval_status.value
            )
        return report(report_mismatches=())
    if not isinstance(record, ScholarlyRecord):
        raise LiteratureError("record must be ScholarlyRecord or None")
    parents.update(record.parent_artifact_hashes)
    identifier_values = record.identifiers_of_kind(reference.identifier.kind)
    identifier_conflict = any(
        field_name.startswith("identifier.") for field_name in record.conflicted_fields
    )
    if reference.identifier.value not in identifier_values or identifier_conflict:
        failures.append("reference identifier does not resolve unambiguously")
        return report(report_mismatches=())
    level = VerificationLevel.LEVEL_1
    matched_id = record.source_record_id

    if reference.title is None:
        mismatches.append("title:missing_expected_metadata")
    elif _match_text(reference.title) != _match_text(record.title):
        mismatches.append("title:mismatch")
    if not reference.authors:
        mismatches.append("authors:missing_expected_metadata")
    elif tuple(_match_text(value) for value in reference.authors) != tuple(
        _match_text(value) for value in record.authors
    ):
        mismatches.append("authors:mismatch")
    if reference.publication_year is None:
        mismatches.append("publication_year:missing_expected_metadata")
    elif reference.publication_year != record.publication_year:
        mismatches.append("publication_year:mismatch")
    for field_name in ("title", "authors", "publication_year"):
        if field_name in record.conflicted_fields:
            mismatches.append(f"{field_name}:conflicting_sources")
    if mismatches:
        failures.append("bibliographic metadata did not match")
        return report(report_mismatches=tuple(sorted(set(mismatches))))
    level = VerificationLevel.LEVEL_2

    if locator is None:
        failures.append("no exact full-text passage locator")
        return report(report_mismatches=())
    if not isinstance(locator, PassageLocator):
        raise LiteratureError("locator must be PassageLocator")
    if record.full_text_status is not FullTextStatus.AVAILABLE:
        failures.append("full text is not available for passage verification")
        return report(report_mismatches=())
    passage = _record_passage(record, locator)
    if passage is None:
        failures.append("section/passage locator does not resolve exactly")
        return report(report_mismatches=())
    claim = _clean_text(claim_text, "claim_text", optional=True)
    if claim is None:
        failures.append("LEVEL_3 requires an exact claim for the located passage")
        return report(report_mismatches=(), report_locator=locator)
    level = VerificationLevel.LEVEL_3
    expected_claim_hash = _sha256(claim)
    if semantic_assessment is None:
        failures.append(
            "no semantic support assessment; LEVEL_3 is structural grounding only"
        )
        return report(report_mismatches=(), report_locator=locator)
    if not isinstance(semantic_assessment, SemanticAssessment):
        raise LiteratureError("semantic_assessment must be SemanticAssessment")
    parents.add(semantic_assessment.assessment_artifact_hash)
    if (
        semantic_assessment.claim_sha256 != expected_claim_hash
        or semantic_assessment.passage_sha256 != passage.passage_sha256
        or semantic_assessment.source_artifact_hash != passage.source_artifact_hash
        or semantic_assessment.locator_sha256 != passage.locator_sha256
    ):
        failures.append("semantic assessment is bound to a different claim or passage")
        return report(report_mismatches=(), report_locator=locator)
    if not semantic_assessment.supports_claim:
        failures.append("exact passage does not semantically support the claim")
        return report(report_mismatches=(), report_locator=locator)
    level = VerificationLevel.LEVEL_4

    if not passage.context_before and not passage.context_after:
        failures.append("no surrounding context was captured")
        return report(report_mismatches=(), report_locator=locator)
    if context_assessment is None:
        failures.append("no surrounding-context assessment")
        return report(report_mismatches=(), report_locator=locator)
    if not isinstance(context_assessment, ContextAssessment):
        raise LiteratureError("context_assessment must be ContextAssessment")
    parents.add(context_assessment.assessment_artifact_hash)
    if context_assessment.assessment_artifact_hash == semantic_assessment.assessment_artifact_hash:
        failures.append("surrounding context requires a distinct assessment artifact")
        return report(report_mismatches=(), report_locator=locator)
    if (
        context_assessment.claim_sha256 != expected_claim_hash
        or context_assessment.passage_sha256 != passage.passage_sha256
        or context_assessment.source_artifact_hash != passage.source_artifact_hash
        or context_assessment.locator_sha256 != passage.locator_sha256
        or context_assessment.context_sha256 != passage.context_sha256
    ):
        failures.append("context assessment is bound to different evidence")
        return report(report_mismatches=(), report_locator=locator)
    if context_assessment.contradicts_claim:
        failures.append("surrounding context materially contradicts the claim")
        return report(report_mismatches=(), report_locator=locator)
    level = VerificationLevel.LEVEL_5
    return report(
        report_mismatches=(),
        report_failures=(),
        report_locator=locator,
    )


__all__ = [
    "ScholarlySearchPlanV2",
    "ScholarlySearchPageRequest",
    "ScholarlySearchResultV2",
    "ScholarlySearchProgress",
    "ScholarlySearchStopReason",
    "require_scholarly_search_cursor",
    "normalize_scholarly_search_page",
    "derive_scholarly_search_progress",
    "AcquisitionResult",
    "ArxivAdapter",
    "CitationEdgeObservation",
    "CitationExecutionStatus",
    "CitationExpansionExecution",
    "CitationExpansionPageReceipt",
    "CitationExpansionPlan",
    "CitationExpansionPolicy",
    "CitationExpansionTask",
    "CitationGraph",
    "CitationGraphEdge",
    "CitationGraphNode",
    "CitationPageCursor",
    "CitationPageRequest",
    "CitationReference",
    "CitationTaskTruncation",
    "CitationTraversal",
    "CitationTruncationReason",
    "CapturedGatewayResponse",
    "ContextAssessment",
    "CrossrefAdapter",
    "EvidenceRankingCandidate",
    "EvidenceSupportTier",
    "FullTextPassage",
    "FullTextStatus",
    "GatewayEnvelope",
    "GeneralWebFallbackDecision",
    "GeneralWebFallbackPolicy",
    "GeneralWebFallbackStatus",
    "GeneralWebPurpose",
    "IdentifierKind",
    "IdentifierNormalizationError",
    "LiteratureError",
    "LiteratureGateway",
    "MetadataConflict",
    "OpenAlexAdapter",
    "PMCAdapter",
    "PassageLocator",
    "ProvenancedValue",
    "PubMedAdapter",
    "RankedScholarlyEvidence",
    "ReferenceVerification",
    "RetrievalStatus",
    "ScholarlyAdapter",
    "ScholarlyAttemptReceipt",
    "ScholarlyEvidenceRanking",
    "ScholarlyIdentifier",
    "ScholarlyRelevanceAssessment",
    "ScholarlyRecord",
    "ScholarlyRequest",
    "ScholarlyRole",
    "ScholarlySearchFilter",
    "ScholarlySearchHit",
    "ScholarlySearchHitResolutionBinding",
    "ScholarlySearchPlan",
    "ScholarlySearchPurpose",
    "ScholarlySearchRequest",
    "ScholarlySearchResult",
    "ScholarlySearchSelection",
    "ScholarlySearchSelectionPolicy",
    "ScholarlySearchSummary",
    "ScholarlySource",
    "SemanticAssessment",
    "SemanticScholarAdapter",
    "SourceFitnessTier",
    "VerificationLevel",
    "acquire_scholarly_record",
    "decide_general_web_fallback",
    "execute_citation_expansion",
    "execute_scholarly_search",
    "merge_scholarly_records",
    "normalize_identifier",
    "normalize_citation_expansion_page",
    "normalize_scholarly_search_result",
    "plan_citation_expansion",
    "rank_scholarly_evidence",
    "scholarly_record_sha256",
    "verify_citation_expansion_execution",
    "verify_reference",
]
