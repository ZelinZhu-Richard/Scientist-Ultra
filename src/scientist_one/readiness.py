"""Frozen paper-readiness rubric scoring and terminal-label policy."""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any, Mapping

from .errors import PathSecurityError, UnsafeSerializationError
from .evaluators import AuditSummary
from .security import read_confined_bytes, safe_json_loads


@dataclass(frozen=True)
class ReadinessResult:
    score: float
    category_scores: dict[str, float]
    passed: bool
    blockers: tuple[str, ...]
    maximum_label: str


def evaluate_readiness(
    rubric_path: Path,
    scores: Mapping[str, float],
    audit: AuditSummary,
    *,
    root: Path,
    rubric_bytes: bytes | None = None,
    security_passed: bool,
    reproduction_passed: bool,
    claims_complete: bool,
    citations_verified: bool,
    reserve_clean: bool,
    novelty_verified: bool,
    synthetic_only: bool,
) -> ReadinessResult:
    try:
        if rubric_bytes is None:
            canonical_root = root.resolve(strict=True)
            candidate = rubric_path if rubric_path.is_absolute() else canonical_root / rubric_path
            relative = candidate.relative_to(canonical_root)
            payload = read_confined_bytes(
                canonical_root,
                relative,
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
            )
            if payload is None:
                raise ValueError("rubric is absent")
        else:
            if not isinstance(rubric_bytes, bytes) or len(rubric_bytes) > 1024 * 1024:
                raise ValueError("rubric bytes are invalid or oversized")
            payload = rubric_bytes
        rubric = safe_json_loads(payload, max_bytes=1024 * 1024)
    except (OSError, ValueError, PathSecurityError, UnsafeSerializationError) as exc:
        raise ValueError("rubric cannot be safely loaded inside the project root") from exc
    _validate_rubric(rubric)
    if rubric["frozen_before_evaluation"] is not True:
        raise ValueError("rubric must be frozen before evaluation")
    if not isinstance(audit, AuditSummary):
        raise ValueError("audit must be an AuditSummary")
    gates = {
        "security_passed": security_passed,
        "reproduction_passed": reproduction_passed,
        "claims_complete": claims_complete,
        "citations_verified": citations_verified,
        "reserve_clean": reserve_clean,
        "novelty_verified": novelty_verified,
        "synthetic_only": synthetic_only,
    }
    if any(not isinstance(value, bool) for value in gates.values()):
        raise ValueError("readiness gate inputs must be booleans")
    category_scores: dict[str, float] = {}
    blockers: list[str] = []
    total = 0.0
    for category in rubric["categories"]:
        category_id = category["id"]
        raw_fraction = scores.get(category_id, 0.0)
        if isinstance(raw_fraction, bool) or not isinstance(raw_fraction, (int, float)):
            raise ValueError(f"score is not numeric: {category_id}")
        fraction = float(raw_fraction)
        if not math.isfinite(fraction):
            raise ValueError(f"score is not finite: {category_id}")
        if not 0.0 <= fraction <= 1.0:
            raise ValueError(f"score outside [0,1]: {category_id}")
        weighted = fraction * float(category["weight"])
        category_scores[category_id] = weighted
        total += weighted
        if fraction < float(category["minimum_fraction"]):
            blockers.append(f"category_below_minimum:{category_id}")
    facts = {
        "security_gate_failure": not security_passed,
        "mandatory_r_check_failure": not audit.mandatory_pass(),
        "primary_reproduction_failure": not reproduction_passed,
        "unsupported_material_claim": not claims_complete,
        "fabricated_or_unverifiable_citation": not citations_verified,
        "contaminated_confirmatory_reserve": not reserve_clean,
    }
    blockers.extend(key for key, value in facts.items() if value)
    if novelty_verified is False:
        blockers.append("NOVELTY_UNVERIFIED")
    passed = total >= float(rubric["candidate_threshold"]) and not blockers
    if synthetic_only:
        maximum_label = "COMPLETE_DEMO_ONLY"
    elif not novelty_verified:
        maximum_label = "NOVELTY_UNVERIFIED"
    elif passed:
        maximum_label = "READY_FOR_HUMAN_REVIEW"
    else:
        maximum_label = "INCONCLUSIVE"
    return ReadinessResult(round(total, 6), category_scores, passed, tuple(blockers), maximum_label)


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
        or not conditions
        or any(not isinstance(item, str) or not item for item in conditions)
        or len(set(conditions)) != len(conditions)
    ):
        raise ValueError("rubric blocking conditions are invalid")
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
