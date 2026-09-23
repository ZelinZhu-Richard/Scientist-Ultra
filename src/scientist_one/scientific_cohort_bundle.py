"""Source-owned complete-cohort R0-R7 composition, distinct from V1 bundles.

The plural reproduction audit fixes the cohort before leaf selection. Missing
checks remain explicit obligations, not issued placeholder authorities. All
persisted values are replayed through the existing registry and ledger owners;
constructing a DTO or evaluating its finite status projection grants nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime
import hashlib
from itertools import islice
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactRecord, ArtifactRegistry, MAX_ARTIFACT_PARENTS, MAX_REGISTRY_RECORDS
from .evaluators import (
    AuthorityScope, AuthorityStatus, CategoryScoreStatus, EvaluatorClass, RCheck,
    MAX_READINESS_CATEGORIES, REQUIRED_R_AUTHORITIES, R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
    _IDENTIFIER_PATTERN, _SHA256_PATTERN, _canonical_json_artifact,
    _derive_complete_challenger_status, _derive_reproduction_cohort_status,
    _ledger_prefix_is_current, _paper_authority_bundle, _r_check_read_snapshot,
    _reproduction_cohort_clean_outcomes, _resolve_r_check_authority_source,
    _rubric_binding, _rubric_category_ids, _validate_runtime,
    resolve_readiness_category_score_authority,
)
from .ledger import EventLedger
from .models import thaw_json, utc_now
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads


R_CHECK_AUTHORITY_BUNDLE_SCHEMA_V2 = "r-check-authority-bundle/v2"
R_CHECK_AUTHORITY_BUNDLE_REGISTRY_SCHEMA_V2 = "2.0"
MAX_COHORT_BUNDLE_BYTES = 1024 * 1024
MAX_COHORT_BUNDLE_OBLIGATIONS = 4096
_COMMAND = ("scientist-one", "bundle-cohort-r-check-authorities")
_GLOBAL_IDENTITIES = (
    (RCheck.R0, EvaluatorClass.E0),
    (RCheck.R5, EvaluatorClass.E2),
    (RCheck.R5, EvaluatorClass.E3),
    (RCheck.R6, EvaluatorClass.E2),
    (RCheck.R6, EvaluatorClass.E3),
    (RCheck.R7, EvaluatorClass.E3),
)


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a native nonempty string")
    return value


def _sha(value: Any, label: str = "cohort SHA-256") -> str:
    if _SHA256_PATTERN.fullmatch(_text(value, label)) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if _IDENTIFIER_PATTERN.fullmatch(_text(value, label)) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _index(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an exact nonnegative integer")
    return value


def _hash_tuple(value: Any, label: str, *, maximum: int = MAX_ARTIFACT_PARENTS,
                allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum or (not value and not allow_empty):
        raise ValueError(f"{label} is not a bounded exact tuple")
    for item in value:
        _sha(item, label)
    if len(set(value)) != len(value):
        raise ValueError(f"{label} contains duplicate sources")
    return value


def _selected_hashes(values: Iterable[str], label: str, maximum: int) -> tuple[str, ...]:
    # Consume at most one over the limit, including generators. Never truncate
    # an over-cap selection into a smaller apparently complete bundle.
    selected = tuple(islice(values, maximum + 1))
    return _hash_tuple(selected, label, maximum=maximum)


def _mapping(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != names:
        raise ValueError(f"{label} has missing, unknown, or non-native fields")
    return value


def _enum(value: Any, enum_type: Any) -> Any:
    return enum_type(_text(value, "cohort enum"))


def _json_hash_tuple(value: Any, label: str, *, maximum: int = MAX_ARTIFACT_PARENTS,
                     allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not list:
        raise ValueError(f"{label} must be a JSON array")
    return _hash_tuple(tuple(value), label, maximum=maximum, allow_empty=allow_empty)


@dataclass(frozen=True, slots=True)
class CohortCheckOutcome:
    """One fixed obligation; optional leaf identity is not a placeholder receipt."""

    r_check: RCheck
    evaluator_class: EvaluatorClass
    subject_artifact_sha256s: tuple[str, ...]
    authority_artifact_sha256: str | None
    authority_artifact_record_hash: str | None
    status: AuthorityStatus
    scope: AuthorityScope
    reason_code: str

    def __post_init__(self) -> None:
        if (type(self.r_check) is not RCheck or type(self.evaluator_class) is not EvaluatorClass
                or self.evaluator_class not in REQUIRED_R_AUTHORITIES[self.r_check]
                or type(self.status) is not AuthorityStatus or type(self.scope) is not AuthorityScope):
            raise ValueError("cohort obligation has an unsupported typed identity or outcome")
        _hash_tuple(self.subject_artifact_sha256s, "cohort obligation subjects", maximum=3, allow_empty=False)
        if (self.authority_artifact_sha256 is None) != (self.authority_artifact_record_hash is None):
            raise ValueError("cohort obligation leaf artifact and record must be paired")
        if self.authority_artifact_sha256 is not None:
            _sha(self.authority_artifact_sha256)
            _sha(self.authority_artifact_record_hash)
        elif self.status is AuthorityStatus.PASS:
            raise ValueError("an omitted cohort leaf cannot pass")
        if self.status is AuthorityStatus.PASS and self.scope is not AuthorityScope.SCIENTIFIC:
            raise ValueError("a non-scientific cohort obligation cannot pass")
        _identifier(self.reason_code, "cohort obligation reason")

    @property
    def identity(self) -> tuple[str, str, tuple[str, ...]]:
        return self.r_check.value, self.evaluator_class.value, self.subject_artifact_sha256s

    def to_dict(self) -> dict[str, Any]:
        return {
            "r_check": self.r_check.value, "evaluator_class": self.evaluator_class.value,
            "subject_artifact_sha256s": list(self.subject_artifact_sha256s),
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "authority_artifact_record_hash": self.authority_artifact_record_hash,
            "status": self.status.value, "scope": self.scope.value, "reason_code": self.reason_code,
        }

    @classmethod
    def from_dict(cls, value: Any) -> CohortCheckOutcome:
        value = _mapping(value, {item.name for item in fields(cls)}, "cohort obligation")
        return cls(
            _enum(value["r_check"], RCheck), _enum(value["evaluator_class"], EvaluatorClass),
            _json_hash_tuple(value["subject_artifact_sha256s"], "cohort subjects", maximum=3, allow_empty=False),
            value["authority_artifact_sha256"], value["authority_artifact_record_hash"],
            _enum(value["status"], AuthorityStatus), _enum(value["scope"], AuthorityScope), value["reason_code"],
        )


@dataclass(frozen=True, slots=True)
class CohortSemanticAuditBinding:
    category: str
    authority_artifact_sha256: str
    authority_artifact_record_hash: str

    def __post_init__(self) -> None:
        from .gates import ChallengeCategory, _SEMANTIC_CHALLENGER_CATEGORIES

        if ChallengeCategory(_text(self.category, "semantic category")) not in _SEMANTIC_CHALLENGER_CATEGORIES:
            raise ValueError("cohort semantic category has no full semantic audit owner")
        _sha(self.authority_artifact_sha256)
        _sha(self.authority_artifact_record_hash)

    def to_dict(self) -> dict[str, str]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Any) -> CohortSemanticAuditBinding:
        return cls(**_mapping(value, {item.name for item in fields(cls)}, "cohort semantic binding"))


@dataclass(frozen=True, slots=True)
class _CohortDeterministicReviewBinding:
    """Ephemeral identity from full owners, not a new persisted authority."""

    category: str
    review_artifact_sha256: str
    review_artifact_record_hash: str
    alternative_authority_artifact_sha256: str | None = None
    alternative_authority_artifact_record_hash: str | None = None

    def __post_init__(self) -> None:
        if _text(self.category, "deterministic category") not in {
            "ALTERNATIVE_EXPLANATION", "EXTERNAL_VALIDITY",
        }:
            raise ValueError("cohort deterministic binding has another category")
        _sha(self.review_artifact_sha256)
        _sha(self.review_artifact_record_hash)
        if (self.alternative_authority_artifact_sha256 is None) != (
            self.alternative_authority_artifact_record_hash is None
        ):
            raise ValueError("cohort alternative authority artifact and record must be paired")
        if self.alternative_authority_artifact_sha256 is not None:
            if self.category != "ALTERNATIVE_EXPLANATION":
                raise ValueError("another deterministic category cannot name alternative authority")
            _sha(self.alternative_authority_artifact_sha256)
            _sha(self.alternative_authority_artifact_record_hash)


@dataclass(frozen=True, slots=True)
class _CohortChallengerLeafReplay:
    """Retained full-source output; constructing it does not authenticate it."""

    status: AuthorityStatus
    reason_code: str
    deterministic_reviews: tuple[_CohortDeterministicReviewBinding, ...]

    def __post_init__(self) -> None:
        if type(self.status) is not AuthorityStatus:
            raise ValueError("cohort Challenger replay status must be typed")
        _identifier(self.reason_code, "cohort Challenger replay reason")
        if (type(self.deterministic_reviews) is not tuple or len(self.deterministic_reviews) > 2
                or any(type(item) is not _CohortDeterministicReviewBinding for item in self.deterministic_reviews)):
            raise ValueError("cohort deterministic reviews must be bounded closed bindings")
        for item in self.deterministic_reviews:
            _CohortDeterministicReviewBinding.__post_init__(item)
        categories = tuple(item.category for item in self.deterministic_reviews)
        if categories != tuple(sorted(set(categories))):
            raise ValueError("cohort deterministic review categories repeat or are unordered")


def _require_deterministic_review_identity_join(
    selected: _CohortDeterministicReviewBinding,
    paper: _CohortDeterministicReviewBinding,
) -> None:
    """Closed pure comparison; neither argument can confer source authority."""
    if (type(selected) is not _CohortDeterministicReviewBinding
            or type(paper) is not _CohortDeterministicReviewBinding):
        raise ValueError("cohort deterministic review join requires closed bindings")
    _CohortDeterministicReviewBinding.__post_init__(selected)
    _CohortDeterministicReviewBinding.__post_init__(paper)
    if (selected.category != paper.category
            or selected.review_artifact_sha256 != paper.review_artifact_sha256
            or selected.review_artifact_record_hash != paper.review_artifact_record_hash):
        raise ValueError("paper and cohort leaves use different same-category deterministic reviews")
    # A raw selected review does not pretend to provide the missing aggregate.
    # A selected aggregate, however, must be the exact paper dimension source,
    # even when another plan/authority can legitimately reuse the same review.
    if selected.alternative_authority_artifact_sha256 is not None and (
        selected.alternative_authority_artifact_sha256 != paper.alternative_authority_artifact_sha256
        or selected.alternative_authority_artifact_record_hash != paper.alternative_authority_artifact_record_hash
    ):
        raise ValueError("paper and cohort leaves use different alternative aggregate authorities")


def _status_projection(obligations: tuple[CohortCheckOutcome, ...]) -> tuple[tuple[RCheck, AuthorityStatus], ...]:
    result = []
    for check in RCheck:
        selected = tuple(row for row in obligations if row.r_check is check)
        if not selected or {row.evaluator_class for row in selected} != REQUIRED_R_AUTHORITIES[check]:
            raise ValueError("cohort status projection omits a required evaluator obligation")
        status = (AuthorityStatus.FAIL if any(row.status is AuthorityStatus.FAIL for row in selected)
                  else AuthorityStatus.PASS if all(row.status is AuthorityStatus.PASS for row in selected)
                  else AuthorityStatus.UNTESTED)
        result.append((check, status))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class RCheckAuthorityBundleV2:
    run_id: str
    scope: AuthorityScope
    reproduction_audit_artifact_sha256: str
    reproduction_audit_artifact_record_hash: str
    assessment_id: str
    research_state_snapshot_artifact_sha256: str
    research_state_snapshot_artifact_record_hash: str
    claim_graph_artifact_sha256: str
    claim_graph_artifact_record_hash: str
    central_claim_ids: tuple[str, ...]
    authority_artifact_sha256s: tuple[str, ...]
    obligations: tuple[CohortCheckOutcome, ...]
    semantic_audit_bindings: tuple[CohortSemanticAuditBinding, ...]
    rubric_artifact_sha256: str
    rubric_record_hash: str
    rubric_ledger_event_id: str
    rubric_ledger_event_hash: str
    rubric_ledger_event_index: int
    category_statuses: tuple[tuple[str, CategoryScoreStatus], ...]
    category_scope: AuthorityScope
    category_score_authority_artifact_sha256s: tuple[str, ...]
    paper_verification_artifact_sha256: str | None
    paper_verification_artifact_record_hash: str | None
    candidate_artifact_sha256: str | None
    ledger_prefix_head_hash: str
    ledger_prefix_event_count: int

    def __post_init__(self) -> None:
        _identifier(self.run_id, "cohort run ID")
        _identifier(self.assessment_id, "cohort assessment ID")
        for name in (
            "reproduction_audit_artifact_sha256", "reproduction_audit_artifact_record_hash",
            "research_state_snapshot_artifact_sha256", "research_state_snapshot_artifact_record_hash",
            "claim_graph_artifact_sha256", "claim_graph_artifact_record_hash",
            "rubric_artifact_sha256", "rubric_record_hash", "rubric_ledger_event_hash", "ledger_prefix_head_hash",
        ):
            _sha(getattr(self, name), name)
        if type(self.scope) is not AuthorityScope or type(self.category_scope) is not AuthorityScope:
            raise ValueError("cohort bundle scopes must be typed")
        if type(self.central_claim_ids) is not tuple or not 1 <= len(self.central_claim_ids) <= 128:
            raise ValueError("cohort claims must be a bounded nonempty tuple")
        for claim_id in self.central_claim_ids:
            _identifier(claim_id, "cohort claim ID")
        if self.central_claim_ids != tuple(sorted(set(self.central_claim_ids))):
            raise ValueError("cohort claims must be unique and sorted")
        _hash_tuple(self.authority_artifact_sha256s, "cohort leaf authorities")
        _hash_tuple(self.category_score_authority_artifact_sha256s, "cohort score authorities", maximum=MAX_READINESS_CATEGORIES)
        if self.authority_artifact_sha256s != tuple(sorted(self.authority_artifact_sha256s)):
            raise ValueError("cohort leaf identities must have canonical order")
        if (type(self.obligations) is not tuple or not 1 <= len(self.obligations) <= MAX_COHORT_BUNDLE_OBLIGATIONS
                or any(type(row) is not CohortCheckOutcome for row in self.obligations)):
            raise ValueError("cohort obligations are absent, oversized, or not closed typed rows")
        for row in self.obligations:
            CohortCheckOutcome.__post_init__(row)
        identities = tuple(row.identity for row in self.obligations)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("cohort obligations must be unique and ordered")
        if {row.authority_artifact_sha256 for row in self.obligations if row.authority_artifact_sha256 is not None} != set(self.authority_artifact_sha256s):
            raise ValueError("cohort leaves must be exactly the authorities used by its obligations")
        records: dict[str, str] = {}
        for row in self.obligations:
            if row.authority_artifact_sha256 is not None:
                prior = records.setdefault(row.authority_artifact_sha256, row.authority_artifact_record_hash)
                if prior != row.authority_artifact_record_hash:
                    raise ValueError("shared cohort leaf has different record identities")
        _status_projection(self.obligations)
        expected_scope = (AuthorityScope.SCIENTIFIC if all(row.scope is AuthorityScope.SCIENTIFIC for row in self.obligations)
                          else AuthorityScope.SYSTEM_FIXTURE)
        if self.scope is not expected_scope:
            raise ValueError("cohort bundle scope differs from its complete obligation projection")
        if (type(self.semantic_audit_bindings) is not tuple or not 1 <= len(self.semantic_audit_bindings) <= 12
                or any(type(item) is not CohortSemanticAuditBinding for item in self.semantic_audit_bindings)):
            raise ValueError("cohort semantic sources must be bounded typed bindings")
        for item in self.semantic_audit_bindings:
            CohortSemanticAuditBinding.__post_init__(item)
        categories = tuple(item.category for item in self.semantic_audit_bindings)
        if (categories != tuple(sorted(set(categories)))
                or len({item.authority_artifact_sha256 for item in self.semantic_audit_bindings}) != len(categories)
                or tuple(item for item in self.semantic_audit_bindings if item.category == "REPRODUCTION") != (
                    CohortSemanticAuditBinding("REPRODUCTION", self.reproduction_audit_artifact_sha256,
                                               self.reproduction_audit_artifact_record_hash),)):
            raise ValueError("cohort semantic category sources differ or omit the exact plural anchor")
        _identifier(self.rubric_ledger_event_id, "rubric event ID")
        _index(self.rubric_ledger_event_index, "rubric event index")
        _index(self.ledger_prefix_event_count, "cohort ledger prefix", minimum=1)
        if self.rubric_ledger_event_index >= self.ledger_prefix_event_count:
            raise ValueError("cohort prefix does not contain its rubric")
        if (type(self.category_statuses) is not tuple or not 1 <= len(self.category_statuses) <= MAX_READINESS_CATEGORIES
                or any(type(row) is not tuple or len(row) != 2 for row in self.category_statuses)):
            raise ValueError("cohort category scoring projection is malformed")
        for category_id, status in self.category_statuses:
            _identifier(category_id, "rubric category ID")
            if type(status) is not CategoryScoreStatus:
                raise ValueError("cohort category status must be typed")
        if len({name for name, _status in self.category_statuses}) != len(self.category_statuses):
            raise ValueError("cohort rubric category IDs repeat")
        if len(self.category_score_authority_artifact_sha256s) not in {0, len(self.category_statuses)}:
            raise ValueError("cohort score sources must be empty or complete")
        if not self.category_score_authority_artifact_sha256s and any(status is not CategoryScoreStatus.UNTESTED for _, status in self.category_statuses):
            raise ValueError("omitted cohort scores cannot be scored")
        if (self.category_scope is AuthorityScope.SCIENTIFIC) != (
            bool(self.category_score_authority_artifact_sha256s)
            and all(status is CategoryScoreStatus.SCORED for _, status in self.category_statuses)
        ):
            raise ValueError("cohort category scope contradicts complete score outcomes")
        paper_values = (self.paper_verification_artifact_sha256, self.paper_verification_artifact_record_hash,
                        self.candidate_artifact_sha256)
        if any(value is None for value in paper_values) and not all(value is None for value in paper_values):
            raise ValueError("cohort paper, record, and candidate must be present together")
        for value in paper_values:
            if value is not None:
                _sha(value)
        if self.category_score_authority_artifact_sha256s and self.candidate_artifact_sha256 is None:
            raise ValueError("cohort scores lack their exact paper candidate")
        _hash_tuple(self.parent_artifact_sha256s, "cohort bundle direct parents", allow_empty=False)

    @property
    def parent_artifact_sha256s(self) -> tuple[str, ...]:
        return (self.reproduction_audit_artifact_sha256, self.rubric_artifact_sha256,
                *self.authority_artifact_sha256s, *self.category_score_authority_artifact_sha256s)

    @property
    def statuses(self) -> tuple[tuple[RCheck, AuthorityStatus], ...]:
        return _status_projection(self.obligations)

    @property
    def status_by_r_check(self) -> dict[str, str]:
        return {check.value: status.value for check, status in self.statuses}

    @property
    def mandatory_pass(self) -> bool:
        return all(status is AuthorityStatus.PASS for _, status in self.statuses)

    @property
    def scientific_mandatory_pass(self) -> bool:
        return self.scope is AuthorityScope.SCIENTIFIC and self.mandatory_pass

    @property
    def category_status_by_id(self) -> dict[str, str]:
        return {name: status.value for name, status in self.category_statuses}

    @property
    def readiness_scope(self) -> AuthorityScope:
        return (AuthorityScope.SCIENTIFIC if self.scope is self.category_scope is AuthorityScope.SCIENTIFIC
                else AuthorityScope.SYSTEM_FIXTURE)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"schema_version": R_CHECK_AUTHORITY_BUNDLE_SCHEMA_V2,
                                 "kind": "R_CHECK_AUTHORITY_BUNDLE"}
        for item in fields(self):
            member = getattr(self, item.name)
            if item.name in {"obligations", "semantic_audit_bindings"}:
                value[item.name] = [row.to_dict() for row in member]
            elif item.name == "category_statuses":
                value[item.name] = [{"category_id": name, "status": status.value} for name, status in member]
            elif type(member) is AuthorityScope:
                value[item.name] = member.value
            elif type(member) is tuple:
                value[item.name] = list(member)
            else:
                value[item.name] = member
        value.update(statuses=self.status_by_r_check, human_independence_claimed=False, e4_synthesized=False)
        return value

    @classmethod
    def from_dict(cls, value: Any) -> RCheckAuthorityBundleV2:
        value = _mapping(value, {item.name for item in fields(cls)} | {
            "schema_version", "kind", "statuses", "human_independence_claimed", "e4_synthesized",
        }, "cohort bundle")
        if (type(value["schema_version"]) is not str or value["schema_version"] != R_CHECK_AUTHORITY_BUNDLE_SCHEMA_V2
                or type(value["kind"]) is not str or value["kind"] != "R_CHECK_AUTHORITY_BUNDLE"
                or value["human_independence_claimed"] is not False or value["e4_synthesized"] is not False):
            raise ValueError("cohort bundle version or authority claims are invalid")
        arguments = {item.name: value[item.name] for item in fields(cls)}
        limits = {"central_claim_ids": 128, "authority_artifact_sha256s": MAX_ARTIFACT_PARENTS,
                  "obligations": MAX_COHORT_BUNDLE_OBLIGATIONS, "semantic_audit_bindings": 12,
                  "category_statuses": MAX_READINESS_CATEGORIES,
                  "category_score_authority_artifact_sha256s": MAX_READINESS_CATEGORIES}
        for name in ("central_claim_ids", "authority_artifact_sha256s", "obligations",
                     "semantic_audit_bindings", "category_statuses", "category_score_authority_artifact_sha256s"):
            if type(arguments[name]) is not list or len(arguments[name]) > limits[name]:
                raise ValueError("cohort bundle collection must be a bounded JSON array")
            arguments[name] = tuple(arguments[name])
        arguments["obligations"] = tuple(CohortCheckOutcome.from_dict(row) for row in arguments["obligations"])
        arguments["semantic_audit_bindings"] = tuple(CohortSemanticAuditBinding.from_dict(row) for row in arguments["semantic_audit_bindings"])
        arguments["category_statuses"] = tuple(
            (row["category_id"], _enum(row["status"], CategoryScoreStatus))
            for item in arguments["category_statuses"]
            for row in (_mapping(item, {"category_id", "status"}, "cohort category status"),)
        )
        for name in ("scope", "category_scope"):
            arguments[name] = _enum(arguments[name], AuthorityScope)
        result = cls(**arguments)
        statuses = _mapping(value["statuses"], {check.value for check in RCheck}, "cohort statuses")
        if any(type(status) is not str for status in statuses.values()) or statuses != result.status_by_r_check:
            raise ValueError("cohort statuses differ from complete obligations")
        return result


def _bundle_bytes(bundle: RCheckAuthorityBundleV2) -> bytes:
    if type(bundle) is not RCheckAuthorityBundleV2:
        raise ValueError("cohort bundle requires its exact V2 type")
    # Replay constructors before serializing; they reject scalar/collection
    # substitutions without calling custom conversion or equality hooks.
    RCheckAuthorityBundleV2.__post_init__(bundle)
    raw = canonical_json_bytes(bundle.to_dict()) + b"\n"
    if len(raw) > MAX_COHORT_BUNDLE_BYTES:
        raise ValueError("complete cohort bundle exceeds its one-MiB receipt bound")
    return raw


def _require_owned_event(events: tuple[Any, ...], event_id: str, event_hash: str, index: int) -> int:
    _index(index, "cohort source event index")
    if (index >= len(events) or events[index].event_id != event_id or events[index].event_hash != event_hash
            or not _ledger_prefix_is_current(events, index + 1, event_hash)):
        raise ValueError("cohort source admission/checkpoint is absent, corrected, or substituted")
    return index


def _cohort_source_indexes(cohort: Any, designs: tuple[Any, ...], events: tuple[Any, ...]) -> tuple[int, ...]:
    """Retain real owner-returned checkpoints even when every leaf is omitted."""
    source = cohort.audit_source
    authority = source.authority
    selected = [
        _require_owned_event(events, source.publication_event_id, source.publication_event_hash, source.publication_event_index),
        _require_owned_event(events, source.slot.event_id, source.slot.event_hash, source.slot.event_index),
        _require_owned_event(events, authority.verification_event_id, authority.verification_event_hash, authority.verification_event_index),
    ]
    for binding in source.canonical_scope.state.entries:
        selected.append(_require_owned_event(events, binding.materialization_event_id,
                                            binding.materialization_event_hash, binding.materialization_event_index))
    for publication in source.canonical_scope.clean_publications:
        selected.append(_require_owned_event(events, publication.event_id, publication.event_hash, publication.event_index))
    for package in source.canonical_scope.package_authorities:
        clean = package.clean_rerun_authority
        selected.append(_require_owned_event(events, clean.verification_event_id, clean.verification_event_hash, clean.verification_event_index))
    for design in designs:
        if design.source is None:
            continue
        owned = design.source
        selected.append(_require_owned_event(events, owned.execution.ledger_event_id,
                                            owned.execution.ledger_event_hash, owned.execution.ledger_event_index))
        selected.append(_require_owned_event(events, owned.protocol_publication.ledger_event_id,
                                            owned.protocol_publication.ledger_event_hash, owned.protocol_publication.ledger_event_index))
        selected.append(_require_owned_event(events, owned.freeze.design_freeze_event_id,
                                            owned.freeze.design_freeze_event_hash, owned.freeze.design_freeze_event_index))
        for question in design.questions:
            selected.append(_require_owned_event(events, question.gate.gate_event_id,
                                                question.gate.gate_event_hash, question.gate.gate_event_index))
    return tuple(selected)


def _remember_semantic_source(cohort: Any, sources: dict[Any, Any], source: Any) -> None:
    """Exact joins over completed full owners, never authority from a cache."""
    from .gates import _semantic_challenger_audit_authority_round_key, _semantic_challenger_audit_round_key

    if (source.entry_snapshot != cohort.audit_source.entry_snapshot
            or _semantic_challenger_audit_authority_round_key(source.authority) != cohort.round_key
            or _semantic_challenger_audit_round_key(source.slot) != cohort.round_key):
        raise ValueError("cohort semantic audit belongs to another full source round")
    category = source.authority.category
    previous = sources.get(category)
    if previous is not None and (previous.record != source.record or previous.authority != source.authority):
        raise ValueError("cohort semantic category has competing exact authority sources")
    sources[category] = source


def _require_semantic_source(registry: ArtifactRegistry, ledger: EventLedger, cohort: Any,
                             sources: dict[Any, Any], digest: str) -> Any:
    from .scientific_r_checks import _require_scientific_audit_cohort

    # Reuse is local to this complete paired read and comes only from an actual
    # full owner invocation. No public parameter accepts this internal map.
    existing = tuple(source for source in sources.values() if source.record.sha256 == digest)
    if existing:
        return existing[0]
    source = _require_scientific_audit_cohort(
        registry, ledger, run_id=cohort.round_key.run_id, semantic_audit_artifact_sha256=digest,
    ).audit_source
    _remember_semantic_source(cohort, sources, source)
    return source


def _same_round_publication_selectors(events: tuple[Any, ...], cohort: Any, category: Any) -> tuple[str, ...]:
    """Candidate index only; every selected source still needs its full owner."""
    key = cohort.round_key
    hashes = set()
    for event in events:
        value = thaw_json(event.metadata).get("semantic_challenge_audit_authority_publication")
        if isinstance(value, Mapping) and (
            value.get("run_id") == key.run_id and value.get("assessment_id") == key.assessment_id
            and value.get("category") == category.value
            and value.get("research_state_snapshot_artifact_hash") == key.research_state_snapshot_artifact_hash
            and value.get("claim_graph_artifact_hash") == key.claim_graph_artifact_hash
            and value.get("central_claim_ids") == list(key.central_claim_ids)
        ):
            hashes.update(event.artifact_hashes)
    if len(hashes) != 1:
        raise ValueError("paper semantic category lacks one exact same-round publication candidate")
    return tuple(hashes)


def _require_paper_state_join(cohort: Any, paper_source: Any) -> None:
    """Pure identity join of full owner outputs, not a canonical state resolver."""
    from .paper_pipeline import _require_paper_state_binding_join

    initial = cohort.audit_source.canonical_scope.state
    final = paper_source.state_authority
    bundle = paper_source.bundle
    if (bundle.run_id != cohort.round_key.run_id or final.run_id != cohort.round_key.run_id
            or bundle.claim_graph_hash != cohort.round_key.claim_graph_artifact_hash
            or bundle.central_claim_ids != cohort.round_key.central_claim_ids
            or final.snapshot_artifact_sha256 != bundle.research_state_hash):
        raise ValueError("paper bundle has another cohort, graph, claims, or frozen state")
    _require_paper_state_binding_join(initial, final)
    # Type membership is only a restriction. The full anchor's ordinary drift
    # owner and the full paper bound-state owner authenticate allowed additions.
    # F need not be a later snapshot than S: an earlier whole-at-issuance state
    # can retain this exact core. Its real chronology remains owner-validated.


def _require_paper_deterministic_review_joins(
    registry: ArtifactRegistry, ledger: EventLedger, cohort: Any, soundness: Any,
    challenger_sources: tuple[_CohortChallengerLeafReplay, ...],
) -> None:
    """Join selected full leaf sources to the already full-owned paper sources."""
    from .gates import (
        SoundnessAuthorityKind, SoundnessDimension, _load_soundness_dimension_receipt,
    )

    selected: dict[str, _CohortDeterministicReviewBinding] = {}
    for source in challenger_sources:
        if type(source) is not _CohortChallengerLeafReplay:
            raise ValueError("cohort paper requires closed Challenger source companions")
        _CohortChallengerLeafReplay.__post_init__(source)
        for binding in source.deterministic_reviews:
            if selected.setdefault(binding.category, binding) != binding:
                raise ValueError("cohort leaves use competing deterministic category sources")
    if not selected:
        return
    paper_reviews = {
        review.category.value: digest
        for review, digest in zip(soundness.challenger_reviews, soundness.challenger_review_hashes, strict=True)
    }
    alternative_record = None
    alternative = selected.get("ALTERNATIVE_EXPLANATION")
    if alternative is not None and alternative.alternative_authority_artifact_sha256 is not None:
        dimensions = tuple(
            (status, digest)
            for (dimension, status), digest in zip(soundness.dimensions, soundness.dimension_receipt_hashes, strict=True)
            if dimension is SoundnessDimension.ALTERNATIVE_EXPLANATIONS
        )
        if len(dimensions) != 1:
            raise ValueError("paper soundness lacks its exact alternative dimension")
        status, digest = dimensions[0]
        # Use the ordinary full dimension/source owner, not a declaration-only
        # parse. This alternative-only edge remains upstream of soundness.
        dimension = _load_soundness_dimension_receipt(
            registry, digest, ledger=ledger, run_id=cohort.round_key.run_id,
            expected_assessment_id=cohort.round_key.assessment_id,
            expected_claim_graph_artifact_hash=cohort.round_key.claim_graph_artifact_hash,
            expected_central_claim_ids=cohort.round_key.central_claim_ids,
        )
        if (dimension.dimension is not SoundnessDimension.ALTERNATIVE_EXPLANATIONS
                or dimension.status is not status
                or dimension.authority_kind is not SoundnessAuthorityKind.DETERMINISTIC
                or dimension.authority_artifact_hash is None):
            raise ValueError("paper alternative dimension does not retain the selected aggregate source")
        alternative_record = registry.get_metadata(dimension.authority_artifact_hash)
    for category, binding in selected.items():
        review_hash = paper_reviews.get(category)
        if review_hash is None:
            raise ValueError("paper soundness omits a selected deterministic review category")
        review_record = registry.get_metadata(review_hash)
        paper_alternative = alternative_record if category == "ALTERNATIVE_EXPLANATION" else None
        _require_deterministic_review_identity_join(binding, _CohortDeterministicReviewBinding(
            category, review_record.sha256, review_record.record_hash,
            paper_alternative.sha256 if paper_alternative else None,
            paper_alternative.record_hash if paper_alternative else None,
        ))


def _require_cohort_paper(registry: ArtifactRegistry, ledger: EventLedger, cohort: Any,
                          semantic_sources: dict[Any, Any], digest: str, events: tuple[Any, ...],
                          challenger_sources: tuple[_CohortChallengerLeafReplay, ...]) -> tuple[Any, Any, Any]:
    from .gates import _SEMANTIC_CHALLENGER_CATEGORIES, require_scientific_soundness_assessment
    from .paper_pipeline import require_paper_verification, _require_paper_verification_bundle_source

    record = registry.get_metadata(digest)
    verification = require_paper_verification(registry, ledger, run_id=cohort.round_key.run_id,
                                             verification_artifact_hash=digest)
    bundle = _paper_authority_bundle(registry, record, cohort.round_key.run_id)
    # Verification may legitimately return a diagnostic FAIL before proving a
    # bundle. Demand the unconditional full source replay for adverse papers too.
    source = _require_paper_verification_bundle_source(registry, ledger, bundle)
    if source.issued_bundle.sha256 != record.parent_artifacts[1]:
        raise ValueError("paper verification substitutes its issued source bundle")
    _require_paper_state_join(cohort, source)
    # Non-confirmatory claims may still have run-bound Soundness. The full
    # owner, not confirmation tuple length, rejects run-less or foreign sources.
    soundness = require_scientific_soundness_assessment(
        registry, ledger=ledger, assessment_artifact_hash=bundle.soundness_assessment_hash,
        expected_assessment_id=cohort.round_key.assessment_id, expected_run_id=cohort.round_key.run_id,
    )
    if (soundness.claim_graph_artifact_hash != cohort.round_key.claim_graph_artifact_hash
            or soundness.central_claim_ids != cohort.round_key.central_claim_ids
            or soundness.confirmatory_claim_authority_hashes != bundle.confirmatory_claim_authority_hashes):
        raise ValueError("paper soundness has another cohort authority")
    for review, review_hash in zip(soundness.challenger_reviews, soundness.challenger_review_hashes, strict=True):
        if review.category not in _SEMANTIC_CHALLENGER_CATEGORIES:
            continue
        if review.category not in semantic_sources:
            (selector,) = _same_round_publication_selectors(events, cohort, review.category)
            _require_semantic_source(registry, ledger, cohort, semantic_sources, selector)
        audit = semantic_sources[review.category].authority
        if (audit.challenger_review_artifact_hash != review_hash
                or registry.get_metadata(review_hash).record_hash != audit.challenger_review_artifact_record_hash):
            raise ValueError("paper and cohort leaves use different same-category review authorities")
    _require_paper_deterministic_review_joins(registry, ledger, cohort, soundness, challenger_sources)
    return record, verification, source


def _leaf_outcome(leaf: Any, subjects: tuple[str, ...], *, owned_status: AuthorityStatus | None = None,
                  owned_reason: str | None = None) -> CohortCheckOutcome:
    authority = leaf.authority
    status = authority.status
    reason = authority.reason_code
    if owned_status is AuthorityStatus.FAIL:
        status, reason = owned_status, owned_reason
    elif owned_status is AuthorityStatus.UNTESTED and status is AuthorityStatus.PASS:
        status, reason = owned_status, owned_reason
    if status is AuthorityStatus.PASS and authority.scope is not AuthorityScope.SCIENTIFIC:
        status, reason = AuthorityStatus.UNTESTED, "MATCHED_LEAF_NOT_SCIENTIFIC_AUTHORITY"
    return CohortCheckOutcome(authority.r_check, authority.evaluator_class, subjects,
                              leaf.record.sha256, leaf.record.record_hash, status, authority.scope, reason)


def _require_complete_challenger_leaf(registry: ArtifactRegistry, ledger: EventLedger, cohort: Any,
                                      leaf: Any) -> _CohortChallengerLeafReplay:
    from .gates import (
        ChallengeCategory, _load_challenger_category_review, require_alternative_explanations_authority,
    )

    payloads = tuple(_canonical_json_artifact(registry, record) for record in leaf.source_records)
    status, reason, checks = _derive_complete_challenger_status(
        registry, ledger, cohort.round_key.run_id, leaf.authority.r_check,
        leaf.source_records, payloads, leaf.authority.scope, [],
    )
    # A diagnostic FAIL does not authenticate any source or its membership.
    # This marker is reached only after all selected ordinary source owners,
    # including alternative attempts and deterministic findings, finish replay.
    if ("complete_challenger_audit_owner_replay", "PASS") not in checks:
        raise ValueError("selected Challenger leaf lacks complete source-owner replay")
    reviews = []
    for record in leaf.source_records:
        if record.logical_type == "challenger_category_review":
            review = _load_challenger_category_review(registry, record.sha256, ledger=ledger)
            reviews.append(_CohortDeterministicReviewBinding(
                review.category.value, record.sha256, record.record_hash,
            ))
        elif record.logical_type == "alternative_explanations_scientific_authority":
            alternative = require_alternative_explanations_authority(
                registry, ledger, authority_artifact_hash=record.sha256,
                expected_assessment_id=cohort.round_key.assessment_id,
                expected_run_id=cohort.round_key.run_id,
                expected_claim_graph_artifact_hash=cohort.round_key.claim_graph_artifact_hash,
                expected_central_claim_ids=cohort.round_key.central_claim_ids,
            )
            review_record = registry.get_metadata(alternative.challenger_review_artifact_hash)
            if review_record.record_hash != alternative.challenger_review_artifact_record_hash:
                raise ValueError("selected alternative aggregate substitutes its exact review record")
            reviews.append(_CohortDeterministicReviewBinding(
                ChallengeCategory.ALTERNATIVE_EXPLANATION.value, review_record.sha256, review_record.record_hash,
                record.sha256, record.record_hash,
            ))
    return _CohortChallengerLeafReplay(status, reason, tuple(sorted(reviews, key=lambda item: item.category)))


def _derive_r_check_authority_bundle_v2(
    registry: ArtifactRegistry, ledger: EventLedger, *, run_id: str,
    reproduction_audit_artifact_sha256: str, authority_artifact_sha256s: Iterable[str],
    rubric_artifact_sha256: str, category_score_authority_artifact_sha256s: Iterable[str] = (),
) -> tuple[RCheckAuthorityBundleV2, tuple[ArtifactRecord, ...], tuple[Any, Any]]:
    from .gates import (ChallengeCategory, SemanticReproductionCohortAuditAuthority,
                        _SemanticReproductionCohortAuditReplay)
    from .scientific_r_checks import (
        _require_scientific_audit_cohort, _require_scientific_cohort_designs,
        _cohort_scientific_check_targets, _cohort_scientific_leaf_coverage,
    )

    _identifier(run_id, "cohort run ID")
    _sha(reproduction_audit_artifact_sha256)
    _sha(rubric_artifact_sha256)
    leaf_hashes = tuple(sorted(_selected_hashes(authority_artifact_sha256s, "cohort leaf selection", MAX_ARTIFACT_PARENTS - 2)))
    score_hashes = _selected_hashes(category_score_authority_artifact_sha256s, "cohort score selection", MAX_READINESS_CATEGORIES)
    _hash_tuple((reproduction_audit_artifact_sha256, rubric_artifact_sha256, *leaf_hashes, *score_hashes),
                "complete cohort direct parents", allow_empty=False)
    before = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    # Fix the mandatory plural anchor, whole canonical cohort, every Run/design,
    # and complete scientific targets before inspecting any submitted leaf.
    cohort = _require_scientific_audit_cohort(registry, ledger, run_id=run_id,
                                            semantic_audit_artifact_sha256=reproduction_audit_artifact_sha256)
    source = cohort.audit_source
    if (type(source) is not _SemanticReproductionCohortAuditReplay
            or type(source.authority) is not SemanticReproductionCohortAuditAuthority
            or source.record.schema_version != "2.0" or source.entry_snapshot != before
            or source.authority.category is not ChallengeCategory.REPRODUCTION):
        raise ValueError("V2 cohort requires the full new plural REPRODUCTION anchor even for a singleton")
    designs = _require_scientific_cohort_designs(registry, ledger, cohort=cohort)
    targets = _cohort_scientific_check_targets(cohort, designs)
    if len(targets) + len(_GLOBAL_IDENTITIES) > MAX_COHORT_BUNDLE_OBLIGATIONS:
        raise ValueError("complete cohort obligation count exceeds its early bound")
    source_indexes = list(_cohort_source_indexes(cohort, designs, events))
    clean_outcomes = _reproduction_cohort_clean_outcomes(run_id, source.authority, source.canonical_scope.package_authorities)
    anchor_status, anchor_reason = _derive_reproduction_cohort_status(
        clean_outcomes, source.authority.status,
        AuthorityScope.SCIENTIFIC if source.authority.scientific_source_qualified else AuthorityScope.SYSTEM_FIXTURE,
    )
    rubric_record, rubric_binding, rubric = _rubric_binding(registry, events, rubric_artifact_sha256)
    category_ids = _rubric_category_ids(rubric)
    if len(category_ids) > MAX_READINESS_CATEGORIES or len(score_hashes) not in {0, len(category_ids)}:
        raise ValueError("cohort scores must be empty or cover the complete bounded rubric")
    leaf_sources = tuple(_resolve_r_check_authority_source(
        registry, ledger, authority_artifact_sha256=digest, run_id=run_id,
    ) for digest in leaf_hashes)
    if any(leaf.entry_snapshot != before or not leaf.source_records for leaf in leaf_sources):
        raise ValueError("selected cohort leaf is source-free or belongs to another replay snapshot")
    scientific_leaves = tuple(leaf for leaf in leaf_sources if leaf.authority.r_check in {RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4})
    rows = [CohortCheckOutcome(
        item.target.r_check, item.target.evaluator_class, item.target.subject_artifact_sha256s,
        item.authority_artifact_sha256, item.authority_artifact_record_hash, item.status, item.scope, item.reason_code,
    ) for item in _cohort_scientific_leaf_coverage(cohort, designs, scientific_leaves)]
    global_rows = {identity: CohortCheckOutcome(
        *identity, (source.record.sha256,), None, None, AuthorityStatus.UNTESTED, AuthorityScope.SYSTEM_FIXTURE,
        "SCIENTIFIC_ABLATION_OWNER_UNAVAILABLE" if identity == (RCheck.R5, EvaluatorClass.E2) else "REQUIRED_COHORT_LEAF_MISSING",
    ) for identity in _GLOBAL_IDENTITIES}
    semantic_sources = {ChallengeCategory.REPRODUCTION: source}
    paper_hashes: set[str] = set()
    paper_requirements: list[tuple[Any, str]] = []
    challenger_sources: list[_CohortChallengerLeafReplay] = []
    seen_globals = set()
    for leaf in leaf_sources:
        for binding in leaf.authority.source_bindings:
            source_indexes.append(_require_owned_event(events, binding.ledger_event_id,
                                                       binding.ledger_event_hash, binding.ledger_event_index))
        for record in leaf.source_records:
            if record.logical_type == "semantic_challenge_audit_authority":
                _require_semantic_source(registry, ledger, cohort, semantic_sources, record.sha256)
        identity = leaf.authority.r_check, leaf.authority.evaluator_class
        if leaf.authority.r_check in {RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4}:
            continue
        if identity not in global_rows or identity in seen_globals:
            raise ValueError("selected cohort leaf is unrelated or competes for a global obligation")
        seen_globals.add(identity)
        by_type = {record.logical_type: record for record in leaf.source_records}
        owned_status = None
        owned_reason = None
        if identity == (RCheck.R5, EvaluatorClass.E2):
            raise ValueError("selected R5/E2 leaf has no scientific ablation source owner")
        if identity == (RCheck.R7, EvaluatorClass.E3):
            if tuple(record.sha256 for record in leaf.source_records) != (source.record.sha256,):
                raise ValueError("R7 must consume the exact complete plural reproduction anchor")
            owned_status, owned_reason = anchor_status, anchor_reason
        elif identity in {(RCheck.R5, EvaluatorClass.E3), (RCheck.R6, EvaluatorClass.E3)}:
            challenger = _require_complete_challenger_leaf(registry, ledger, cohort, leaf)
            challenger_sources.append(challenger)
            owned_status, owned_reason = challenger.status, challenger.reason_code
        elif identity == (RCheck.R0, EvaluatorClass.E0):
            if len(leaf.source_records) != 2 or set(by_type) != {"canonical_research_state_final_snapshot", "paper_verification"}:
                raise ValueError("cohort R0 requires its exact paper and final-state sources")
            paper_hashes.add(by_type["paper_verification"].sha256)
            paper_requirements.append((leaf, by_type["canonical_research_state_final_snapshot"].sha256))
        elif identity == (RCheck.R6, EvaluatorClass.E2):
            if (len(leaf.source_records) != 2 or set(by_type) != {"claim_evidence_graph", "paper_verification"}
                    or by_type["claim_evidence_graph"].sha256 != source.authority.claim_graph_artifact_hash
                    or by_type["claim_evidence_graph"].record_hash != source.authority.claim_graph_artifact_record_hash):
                raise ValueError("cohort R6/E2 requires the exact anchor graph and paper")
            paper_hashes.add(by_type["paper_verification"].sha256)
            paper_requirements.append((leaf, ""))
        global_rows[identity] = _leaf_outcome(leaf, (source.record.sha256,), owned_status=owned_status, owned_reason=owned_reason)
    # Known owner-authenticated adverse reproduction cannot be hidden by leaving
    # out R7. A passing anchor is not a replacement for the required R7 leaf.
    if anchor_status is AuthorityStatus.FAIL:
        old = global_rows[(RCheck.R7, EvaluatorClass.E3)]
        global_rows[(RCheck.R7, EvaluatorClass.E3)] = replace(
            old, status=AuthorityStatus.FAIL, reason_code=anchor_reason,
        )

    score_pairs = []
    candidate_hashes = set()
    for digest in score_hashes:
        score = resolve_readiness_category_score_authority(registry, ledger, authority_artifact_sha256=digest, run_id=run_id)
        record = registry.get_metadata(digest)
        if (score.rubric_binding.artifact_sha256 != rubric_record.sha256
                or score.rubric_binding.artifact_record_hash != rubric_record.record_hash):
            raise ValueError("cohort score names another exact rubric")
        papers = tuple(binding for binding in score.evidence_bindings if binding.logical_type == "paper_verification")
        if len(papers) != 1:
            raise ValueError("every cohort score requires one exact paper-verification source, including untested scores")
        paper_hashes.add(papers[0].artifact_sha256)
        candidate_hashes.add(score.candidate_binding.artifact_sha256)
        for binding in (score.candidate_binding, *score.evidence_bindings, score.semantic_judgment_binding):
            source_indexes.append(_require_owned_event(events, binding.ledger_event_id, binding.ledger_event_hash, binding.ledger_event_index))
        score_pairs.append((score, record))
    score_by_id = {score.category_id: (score, record) for score, record in score_pairs}
    if score_pairs and (len(score_by_id) != len(score_pairs) or set(score_by_id) != set(category_ids)):
        raise ValueError("cohort scores omit or repeat rubric categories")
    if len(paper_hashes) > 1 or len(candidate_hashes) > 1:
        raise ValueError("cohort R0/R6/readiness sources use different paper verifications or candidates")
    paper_record = None
    candidate_hash = None
    if paper_hashes:
        paper_record, verification, paper_source = _require_cohort_paper(
            registry, ledger, cohort, semantic_sources, next(iter(paper_hashes)), events, tuple(challenger_sources),
        )
        candidate_hash = paper_record.parent_artifacts[0]
        if candidate_hashes and candidate_hashes != {candidate_hash}:
            raise ValueError("cohort score candidate differs from its exact verified paper")
        for leaf, final_hash in paper_requirements:
            if final_hash and final_hash != paper_source.bundle.research_state_hash:
                raise ValueError("cohort R0 paper and canonical final snapshot differ")
            if verification.passed is not True:
                identity = leaf.authority.r_check, leaf.authority.evaluator_class
                global_rows[identity] = _leaf_outcome(leaf, (source.record.sha256,), owned_status=AuthorityStatus.FAIL,
                                                       owned_reason="COHORT_PAPER_VERIFICATION_FAILED")
    for semantic_source in semantic_sources.values():
        source_indexes.append(_require_owned_event(events, semantic_source.publication_event_id,
                                                   semantic_source.publication_event_hash, semantic_source.publication_event_index))
    if rubric_binding.ledger_event_index > min(source_indexes):
        raise ValueError("readiness rubric was not frozen before the cohort's actual source admissions/checkpoints")
    rows.extend(global_rows.values())
    obligations = tuple(sorted(rows, key=lambda row: row.identity))
    ordered_scores = tuple(score_by_id[name] for name in category_ids) if score_pairs else ()
    category_statuses = (tuple((score.category_id, score.status) for score, _record in ordered_scores) if ordered_scores
                         else tuple((name, CategoryScoreStatus.UNTESTED) for name in category_ids))
    category_scope = (AuthorityScope.SCIENTIFIC if ordered_scores and all(
        score.scope is AuthorityScope.SCIENTIFIC and score.status is CategoryScoreStatus.SCORED for score, _record in ordered_scores
    ) else AuthorityScope.SYSTEM_FIXTURE)
    latest_index = max(rubric_binding.ledger_event_index, *source_indexes)
    bundle = RCheckAuthorityBundleV2(
        run_id=run_id,
        scope=AuthorityScope.SCIENTIFIC if all(row.scope is AuthorityScope.SCIENTIFIC for row in obligations) else AuthorityScope.SYSTEM_FIXTURE,
        reproduction_audit_artifact_sha256=source.record.sha256, reproduction_audit_artifact_record_hash=source.record.record_hash,
        assessment_id=source.authority.assessment_id,
        research_state_snapshot_artifact_sha256=source.authority.research_state_snapshot_artifact_hash,
        research_state_snapshot_artifact_record_hash=source.authority.research_state_snapshot_artifact_record_hash,
        claim_graph_artifact_sha256=source.authority.claim_graph_artifact_hash,
        claim_graph_artifact_record_hash=source.authority.claim_graph_artifact_record_hash,
        central_claim_ids=source.authority.central_claim_ids, authority_artifact_sha256s=leaf_hashes,
        obligations=obligations,
        semantic_audit_bindings=tuple(CohortSemanticAuditBinding(category.value, item.record.sha256, item.record.record_hash)
                                      for category, item in sorted(semantic_sources.items(), key=lambda pair: pair[0].value)),
        rubric_artifact_sha256=rubric_record.sha256, rubric_record_hash=rubric_record.record_hash,
        rubric_ledger_event_id=rubric_binding.ledger_event_id, rubric_ledger_event_hash=rubric_binding.ledger_event_hash,
        rubric_ledger_event_index=rubric_binding.ledger_event_index,
        category_statuses=category_statuses, category_scope=category_scope,
        category_score_authority_artifact_sha256s=tuple(record.sha256 for _score, record in ordered_scores),
        paper_verification_artifact_sha256=paper_record.sha256 if paper_record else None,
        paper_verification_artifact_record_hash=paper_record.record_hash if paper_record else None,
        candidate_artifact_sha256=candidate_hash,
        ledger_prefix_head_hash=events[latest_index].event_hash, ledger_prefix_event_count=latest_index + 1,
    )
    _bundle_bytes(bundle)
    parents = (source.record, rubric_record, *(leaf.record for leaf in leaf_sources),
               *(record for _score, record in ordered_scores))
    if tuple(record.sha256 for record in parents) != bundle.parent_artifact_sha256s:
        raise ValueError("cohort bundle direct source ordering differs")
    if _r_check_read_snapshot(registry, ledger) != before:
        raise ValueError("cohort bundle sources changed during complete owner replay")
    return bundle, parents, before


def _timestamp(value: Any) -> datetime:
    _text(value, "cohort source timestamp")
    if not value.endswith("Z"):
        raise ValueError("cohort source timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("cohort source timestamp is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("cohort source timestamp must be UTC")
    return parsed


def _bundle_record(registry: ArtifactRegistry, bundle: RCheckAuthorityBundleV2,
                   raw: bytes, created_at: str) -> ArtifactRecord:
    digest = hashlib.sha256(raw).hexdigest()
    relative = registry._object_relative(digest).as_posix()
    return ArtifactRecord(
        sha256=digest, path=relative, relative_path=relative,
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
        schema_version=R_CHECK_AUTHORITY_BUNDLE_REGISTRY_SCHEMA_V2,
        mime_type="application/json", size=len(raw),
        origin=f"complete source-owned R0-R7 cohort bundle for {bundle.run_id}",
        creator_role=Role.ORCHESTRATOR, creation_command=_COMMAND,
        parent_artifacts=bundle.parent_artifact_sha256s,
        validation_result="PASS", frozen=True, created_at=created_at,
    )


def _preflight_bundle_publication(
    registry: ArtifactRegistry, bundle: RCheckAuthorityBundleV2,
    parents: tuple[ArtifactRecord, ...], snapshot: tuple[Any, Any],
) -> tuple[bytes, ArtifactRecord, bool]:
    """Finite metadata/capacity checks, not a source authority or public issuer."""
    raw = _bundle_bytes(bundle)
    if (type(parents) is not tuple or any(type(record) is not ArtifactRecord for record in parents)
            or tuple(record.sha256 for record in parents) != bundle.parent_artifact_sha256s):
        raise ValueError("cohort publication lacks its exact complete direct source records")
    known = {record.sha256: record for record in snapshot[0].records}
    if any(known.get(record.sha256) != record for record in parents):
        raise ValueError("cohort publication source record was substituted")
    digest = hashlib.sha256(raw).hexdigest()
    existing = known.get(digest)
    record = _bundle_record(registry, bundle, raw, existing.created_at if existing else utc_now())
    if existing is not None and (existing != record or registry.get_bytes(digest) != raw):
        raise ValueError("cohort bundle bytes occupy a different immutable registry identity")
    if snapshot[0].count + int(existing is None) > MAX_REGISTRY_RECORDS:
        raise ValueError("cohort bundle would exceed registry capacity")
    events = snapshot[1].events
    if (not _ledger_prefix_is_current(events, bundle.ledger_prefix_event_count, bundle.ledger_prefix_head_hash)
            or _timestamp(record.created_at) < _timestamp(events[bundle.ledger_prefix_event_count - 1].timestamp)
            or any(_timestamp(record.created_at) < _timestamp(parent.created_at) for parent in parents)):
        raise ValueError("cohort bundle publication predates or loses its source chronology")
    return raw, record, existing is None


def register_r_check_authority_bundle_v2(
    registry: ArtifactRegistry, ledger: EventLedger, *, run_id: str,
    reproduction_audit_artifact_sha256: str, authority_artifact_sha256s: Iterable[str],
    rubric_artifact_sha256: str, category_score_authority_artifact_sha256s: Iterable[str] = (),
) -> ArtifactRecord:
    """Publish one fully rederived bounded cohort bundle with paired source CAS."""
    bundle, parents, before = _derive_r_check_authority_bundle_v2(
        registry, ledger, run_id=run_id,
        reproduction_audit_artifact_sha256=reproduction_audit_artifact_sha256,
        authority_artifact_sha256s=authority_artifact_sha256s,
        rubric_artifact_sha256=rubric_artifact_sha256,
        category_score_authority_artifact_sha256s=category_score_authority_artifact_sha256s,
    )
    raw, expected_record, new_record = _preflight_bundle_publication(registry, bundle, parents, before)
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            current_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            current_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if (current_registry, current_ledger) != before or not current_ledger.valid:
                raise ValueError("cohort bundle sources changed before publication; retry")
            record = expected_record
            if new_record:
                record = registry._put_bytes_locked(
                    registry_guard, raw,
                    logical_type=expected_record.logical_type, schema_version=expected_record.schema_version,
                    mime_type=expected_record.mime_type, origin=expected_record.origin,
                    creator_role=expected_record.creator_role, creation_command=expected_record.creation_command,
                    parent_artifacts=expected_record.parent_artifacts, validation_result="PASS", frozen=True,
                    created_at=expected_record.created_at,
                )
            registry._verify_mutation_namespace(registry_guard)
            after_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            after_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            expected_records = {item.sha256: item for item in before[0].records}
            expected_records[record.sha256] = expected_record
            if (record != expected_record or after_registry.count != before[0].count + int(new_record)
                    or {item.sha256: item for item in after_registry.records} != expected_records
                    or after_ledger != before[1]):
                raise ValueError("cohort bundle publication has an unexpected registry/ledger delta")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    fresh = resolve_r_check_authority_bundle_v2(registry, ledger, bundle_artifact_sha256=record.sha256, run_id=run_id)
    if fresh != bundle or _r_check_read_snapshot(registry, ledger) != (after_registry, after_ledger):
        raise ValueError("cohort bundle changed after publication and full readback; retry")
    return record


def resolve_r_check_authority_bundle_v2(
    registry: ArtifactRegistry, ledger: EventLedger, *, bundle_artifact_sha256: str, run_id: str,
) -> RCheckAuthorityBundleV2:
    """Recompute every source, membership, omitted check, and exact V2 byte."""
    _identifier(run_id, "cohort run ID")
    _sha(bundle_artifact_sha256)
    before = _r_check_read_snapshot(registry, ledger)
    events = _validate_runtime(registry, ledger, run_id)
    registry.verify(bundle_artifact_sha256, raise_on_error=True)
    record = registry.get_metadata(bundle_artifact_sha256)
    if (record.logical_type != R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE
            or record.schema_version != R_CHECK_AUTHORITY_BUNDLE_REGISTRY_SCHEMA_V2
            or record.size > MAX_COHORT_BUNDLE_BYTES):
        raise ValueError("cohort bundle registry format is unsupported")
    raw = registry.get_bytes(record.sha256)
    stated = RCheckAuthorityBundleV2.from_dict(safe_json_loads(raw, max_bytes=MAX_COHORT_BUNDLE_BYTES))
    if raw != _bundle_bytes(stated) or stated.run_id != run_id:
        raise ValueError("cohort bundle has noncanonical bytes or another run")
    expected, parents, replay_snapshot = _derive_r_check_authority_bundle_v2(
        registry, ledger, run_id=run_id,
        reproduction_audit_artifact_sha256=stated.reproduction_audit_artifact_sha256,
        authority_artifact_sha256s=stated.authority_artifact_sha256s,
        rubric_artifact_sha256=stated.rubric_artifact_sha256,
        category_score_authority_artifact_sha256s=stated.category_score_authority_artifact_sha256s,
    )
    if (replay_snapshot != before or stated != expected
            or record != _bundle_record(registry, expected, raw, record.created_at)
            or not _ledger_prefix_is_current(events, expected.ledger_prefix_event_count, expected.ledger_prefix_head_hash)):
        raise ValueError("cohort bundle differs from its complete current source resolution")
    checked_raw, checked_record, new_record = _preflight_bundle_publication(registry, expected, parents, before)
    if new_record or checked_raw != raw or checked_record != record or _r_check_read_snapshot(registry, ledger) != before:
        raise ValueError("cohort bundle target or sources changed during full readback")
    return expected
