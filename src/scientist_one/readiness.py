"""Frozen paper-readiness rubric scoring and terminal-label policy."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any

from .evaluators import (
    AuthorityScope,
    AuthorityStatus,
    AuditSummary,
    CategoryScoreStatus,
    EvaluatorClass,
    FROZEN_READINESS_RUBRIC_LOGICAL_TYPE,
    RCheckAuthorityBundle,
    _r_check_read_snapshot,
    resolve_r_check_authority,
    resolve_readiness_category_score_authority,
)
from .roles import Role
from .security import safe_json_loads


_SUPPORTED_BLOCKING_CONDITIONS = (
    "security_gate_failure",
    "critical_e2_or_e3_objection",
    "primary_reproduction_failure",
    "unsupported_material_claim",
    "fabricated_or_unverifiable_citation",
    "contaminated_confirmatory_reserve",
    "category_below_minimum",
)


@dataclass(frozen=True)
class ReadinessResult:
    score: float | None
    category_scores: dict[str, float | None]
    category_statuses: dict[str, str]
    passed: bool
    blockers: tuple[str, ...]
    maximum_label: str
    authority_scope: AuthorityScope
    authority_bundle_sha256: str
    rubric_sha256: str


def register_frozen_readiness_rubric(registry: Any, rubric_bytes: bytes) -> Any:
    """Validate and freeze the exact rubric bytes before evidence evaluation.

    The returned artifact still must be admitted to the run ledger before any
    evidence consumed by an R-check authority. Bundle construction enforces
    that temporal ordering.
    """

    from .artifacts import ArtifactRegistry

    if type(registry) is not ArtifactRegistry:
        raise ValueError("readiness rubric requires exact ArtifactRegistry")
    if (
        not isinstance(rubric_bytes, bytes)
        or not rubric_bytes
        or len(rubric_bytes) > 1024 * 1024
    ):
        raise ValueError("rubric bytes are invalid or oversized")
    try:
        rubric = safe_json_loads(rubric_bytes, max_bytes=1024 * 1024)
    except Exception as exc:
        raise ValueError("rubric bytes are not safe JSON") from exc
    _validate_rubric(rubric)
    if rubric["frozen_before_evaluation"] is not True:
        raise ValueError("rubric must be frozen before evaluation")
    return registry.put_bytes(
        rubric_bytes,
        logical_type=FROZEN_READINESS_RUBRIC_LOGICAL_TYPE,
        origin="frozen paper-readiness rubric authority",
        creator_role=Role.PROTOCOL_DESIGNER,
        creation_command=("scientist-one", "freeze-paper-readiness-rubric"),
        schema_version="paper-readiness-rubric/v1",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def evaluate_readiness(
    audit: AuditSummary,
    *,
    registry: Any,
    ledger: Any,
    run_id: str,
) -> ReadinessResult:
    if not isinstance(audit, AuditSummary):
        raise ValueError("audit must be an AuditSummary")
    if audit.authority_bundle_artifact_sha256 is None:
        raise ValueError("readiness requires an R-check authority bundle")
    entry_snapshot = _r_check_read_snapshot(registry, ledger)
    try:
        bundle = audit.resolve_bundle(registry, ledger, run_id=run_id)
        authorities = tuple(
            resolve_r_check_authority(
                registry,
                ledger,
                authority_artifact_sha256=digest,
                run_id=run_id,
            )
            for digest in bundle.authority_artifact_sha256s
        )
        category_authorities = tuple(
            resolve_readiness_category_score_authority(
                registry,
                ledger,
                authority_artifact_sha256=digest,
                run_id=run_id,
            )
            for digest in (
                bundle.category_score_authority_artifact_sha256s
            )
        )
        rubric_record = registry.get_metadata(bundle.rubric_artifact_sha256)
        payload = registry.get_bytes(bundle.rubric_artifact_sha256)
        rubric = safe_json_loads(payload, max_bytes=1024 * 1024)
    except Exception as exc:
        raise ValueError("readiness authority cannot be freshly resolved") from exc
    _validate_rubric(rubric)
    if (
        rubric["frozen_before_evaluation"] is not True
        or rubric_record.sha256 != bundle.rubric_artifact_sha256
        or rubric_record.record_hash != bundle.rubric_record_hash
    ):
        raise ValueError("readiness rubric differs from its frozen authority")
    category_ids = tuple(category["id"] for category in rubric["categories"])
    category_statuses = bundle.category_status_by_id
    by_category = {
        authority.category_id: authority
        for authority in category_authorities
    }
    if tuple(category_statuses) != category_ids or (
        category_authorities
        and (
            len(by_category) != len(category_authorities)
            or set(by_category) != set(category_ids)
            or tuple(
                by_category[category_id].status.value
                for category_id in category_ids
            )
            != tuple(category_statuses.values())
        )
    ) or (
        not category_authorities
        and set(category_statuses.values()) != {
            CategoryScoreStatus.UNTESTED.value
        }
    ):
        raise ValueError("readiness category authority differs from the frozen bundle")
    category_scores: dict[str, float | None] = {}
    blockers: list[str] = []
    for category in rubric["categories"]:
        category_id = category["id"]
        authority = by_category.get(category_id)
        fraction = (
            authority.authoritative_score_fraction
            if authority is not None
            else None
        )
        if fraction is None:
            category_scores[category_id] = None
            blockers.append(f"category_untested:{category_id}")
            continue
        category_scores[category_id] = fraction * float(category["weight"])
        if fraction < float(category["minimum_fraction"]):
            blockers.append(f"category_below_minimum:{category_id}")
    score = (
        sum(float(value) for value in category_scores.values())
        if category_scores
        and all(value is not None for value in category_scores.values())
        else None
    )
    if score is not None and score < float(rubric["candidate_threshold"]):
        blockers.append("candidate_threshold_not_met")
    statuses = bundle.status_by_r_check
    objection_sources = _readiness_objection_sources(bundle, authorities)
    facts = {
        "security_gate_failure": statuses["R0"] != "PASS",
        "critical_e2_or_e3_objection": any(
            authority.evaluator_class
            in {EvaluatorClass.E2, EvaluatorClass.E3}
            and authority.status is AuthorityStatus.FAIL
            for authority in objection_sources
        ),
        "mandatory_r_check_failure": not bundle.mandatory_pass,
        "primary_reproduction_failure": statuses["R7"] != "PASS",
        "unsupported_material_claim": statuses["R6"] != "PASS",
        "fabricated_or_unverifiable_citation": statuses["R6"] != "PASS",
        "contaminated_confirmatory_reserve": statuses["R3"] != "PASS",
    }
    blockers.extend(key for key, value in facts.items() if value)
    readiness_scope = bundle.readiness_scope
    if readiness_scope is AuthorityScope.SYSTEM_FIXTURE:
        blockers.append("SYSTEM_FIXTURE_NOT_SCIENTIFIC_AUTHORITY")
        blockers.append("NOVELTY_UNVERIFIED")
    passed = (
        readiness_scope is AuthorityScope.SCIENTIFIC
        and bundle.mandatory_pass
        and score is not None
        and score >= float(rubric["candidate_threshold"])
        and not blockers
    )
    if readiness_scope is AuthorityScope.SYSTEM_FIXTURE:
        maximum_label = (
            "COMPLETE_DEMO_ONLY"
            if bundle.mandatory_pass and not blockers
            else "INCONCLUSIVE"
        )
    elif passed:
        maximum_label = "READY_FOR_HUMAN_REVIEW"
    else:
        maximum_label = "INCONCLUSIVE"
    result = ReadinessResult(
        score,
        category_scores,
        category_statuses,
        passed,
        tuple(dict.fromkeys(blockers)),
        maximum_label,
        readiness_scope,
        audit.authority_bundle_artifact_sha256,
        bundle.rubric_artifact_sha256,
    )
    if _r_check_read_snapshot(registry, ledger) != entry_snapshot:
        raise ValueError("readiness authorities changed during complete owner replay")
    return result


def _readiness_objection_sources(bundle: Any, authorities: tuple[Any, ...]) -> tuple[Any, ...]:
    """Project freshly resolved obligations, never just selected V2 leaves.

    This is a pure downstream view; evaluate_readiness must first perform all
    normal owner replays and finally verify its paired entry snapshot.
    """

    if type(bundle) is RCheckAuthorityBundle:
        return authorities
    from .scientific_cohort_bundle import RCheckAuthorityBundleV2

    if type(bundle) is RCheckAuthorityBundleV2:
        return bundle.obligations
    raise ValueError("readiness bundle has no supported full authority profile")


def _validate_rubric(value: Any) -> None:
    required = {
        "schema_version",
        "frozen_before_evaluation",
        "candidate_threshold",
        "mandatory_r_checks",
        "blocking_conditions",
        "categories",
        "label_rules",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("rubric schema is incomplete or has unknown fields")
    if value["schema_version"] != "1.0":
        raise ValueError("unsupported rubric schema")
    threshold = value["candidate_threshold"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(float(threshold))
        or not 0 <= float(threshold) <= 100
    ):
        raise ValueError("candidate threshold is invalid")
    if value["mandatory_r_checks"] != [f"R{index}" for index in range(8)]:
        raise ValueError("rubric must require R0-R7 exactly")
    conditions = value["blocking_conditions"]
    if (
        not isinstance(conditions, list)
        or conditions != list(_SUPPORTED_BLOCKING_CONDITIONS)
    ):
        raise ValueError("rubric blocking conditions differ from supported policy")
    categories = value["categories"]
    if not isinstance(categories, list) or not categories:
        raise ValueError("rubric categories are missing")
    identifiers: list[str] = []
    total_weight = 0.0
    for category in categories:
        if not isinstance(category, dict) or set(category) != {
            "id",
            "weight",
            "minimum_fraction",
        }:
            raise ValueError("rubric category schema is invalid")
        identifier = category["id"]
        weight = category["weight"]
        minimum = category["minimum_fraction"]
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("rubric category identifier is invalid")
        if any(
            isinstance(number, bool)
            or not isinstance(number, (int, float))
            or not math.isfinite(float(number))
            for number in (weight, minimum)
        ):
            raise ValueError("rubric category numbers are invalid")
        if float(weight) <= 0 or not 0 <= float(minimum) <= 1:
            raise ValueError("rubric category bounds are invalid")
        identifiers.append(identifier)
        total_weight += float(weight)
    if len(set(identifiers)) != len(identifiers) or not math.isclose(total_weight, 100.0):
        raise ValueError("rubric category identifiers or weights are invalid")
    label_rules = value["label_rules"]
    if (
        not isinstance(label_rules, dict)
        or set(label_rules) != {"novelty_unverified", "synthetic_only", "e4_absent"}
        or any(not isinstance(item, str) or not item for item in label_rules.values())
    ):
        raise ValueError("rubric label rules are invalid")
