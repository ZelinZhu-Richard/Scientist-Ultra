"""Existing-wire publication of an external-validity scope inventory.

The upstream boundary owns the complete scientific sources. This companion
owns their exact execution/review projection and atomic registry publication,
never a scientific external-validity PASS or a new authority family.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Callable

from .artifacts import ArtifactRecord, ArtifactRegistry, MAX_ARTIFACT_PARENTS, MAX_REGISTRY_RECORDS
from .errors import ValidationError
from .ledger import EventLedger
from .models import Role, utc_now
from .scientific_design import _locked_checked_result_authority_snapshot
from .security import canonical_json_bytes, safe_json_loads


def is_scientific_external_validity_execution(receipt: Any) -> bool:
    """Exact procedure routing only; constructing a receipt grants nothing."""
    from .gates import ChallengeCategory, ChallengerExecutorKind
    from .scientific_external_validity import (
        SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID,
        SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION,
    )

    return (
        receipt.category is ChallengeCategory.EXTERNAL_VALIDITY
        and receipt.executor_kind is ChallengerExecutorKind.DETERMINISTIC
        and receipt.procedure_id == SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID
        and receipt.procedure_version == SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION
    )


def _require_execution_shape(receipt: Any) -> None:
    from .gates import ChallengerAttackExecutionReceipt

    if type(receipt) is not ChallengerAttackExecutionReceipt:
        raise ValidationError("scientific external inventory requires the exact execution receipt")
    ChallengerAttackExecutionReceipt.__post_init__(receipt)
    if (
        not is_scientific_external_validity_execution(receipt)
        or receipt.finding_artifact_hashes != ()
        or receipt.semantic_judgment_hash is not None
        or type(receipt.evidence_hashes) is not tuple
        or len(receipt.evidence_hashes) < 2
        or receipt.evidence_hashes[1:] != tuple(sorted(receipt.evidence_hashes[1:]))
        or type(receipt.result_artifact_hashes) is not tuple
        or not receipt.result_artifact_hashes
        or receipt.result_artifact_hashes != tuple(sorted(receipt.result_artifact_hashes))
        or receipt.target_claim_ids != tuple(sorted(receipt.target_claim_ids))
    ):
        raise ValidationError("scientific external inventory has another fixed procedure shape")
    _execution_parents(receipt)


def _execution_parents(receipt: Any) -> tuple[str, ...]:
    parents = (receipt.claim_graph_artifact_hash, *receipt.evidence_hashes, *receipt.result_artifact_hashes)
    if len(parents) > MAX_ARTIFACT_PARENTS or len(set(parents)) != len(parents):
        raise ValidationError("scientific external inventory exceeds exact parent capacity")
    return parents


def _require_review_shape(review: Any, execution: Any) -> None:
    from .gates import ChallengerCategoryReview, ChallengerExecutionStatus
    from .scientific_external_validity import (
        SCIENTIFIC_EXTERNAL_VALIDITY_ATTACK, SCIENTIFIC_EXTERNAL_VALIDITY_CONCLUSION,
    )

    _require_execution_shape(execution)
    if type(review) is not ChallengerCategoryReview:
        raise ValidationError("scientific external inventory requires the exact category review")
    ChallengerCategoryReview.__post_init__(review)
    if (
        review.execution_status is not ChallengerExecutionStatus.EXECUTED
        or review.deterministic is not True
        or review.review_id != execution.review_id
        or review.category is not execution.category
        or review.claim_graph_artifact_hash != execution.claim_graph_artifact_hash
        or review.target_claim_ids != execution.target_claim_ids
        or review.evidence_hashes != execution.evidence_hashes
        or review.finding_artifact_hashes != ()
        or review.attack != SCIENTIFIC_EXTERNAL_VALIDITY_ATTACK
        or review.conclusion != SCIENTIFIC_EXTERNAL_VALIDITY_CONCLUSION
        or review.execution_receipt_hash != hashlib.sha256(
            canonical_json_bytes(execution.to_dict()) + b"\n"
        ).hexdigest()
    ):
        raise ValidationError("scientific external review must retain exact sources and untested adequacy")


def require_scientific_external_validity_execution(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any, *,
    require_whole_current: bool = False,
) -> Any:
    """Replay the complete source owner before comparing the retained inventory."""
    from .scientific_external_validity import require_scientific_external_validity_boundary

    _require_execution_shape(receipt)
    boundary = require_scientific_external_validity_boundary(
        registry, ledger, expected_ledger_run_id=receipt.run_id,
        snapshot_artifact_sha256=receipt.evidence_hashes[0],
        claim_graph_artifact_sha256=receipt.claim_graph_artifact_hash,
        central_claim_ids=receipt.target_claim_ids,
        require_whole_current=require_whole_current,
    )
    if (receipt.evidence_hashes != boundary.evidence_hashes
            or receipt.result_artifact_hashes != tuple(sha for sha, _ in boundary.result_test_bindings)):
        raise ValidationError("scientific external inventory omits or substitutes complete owned sources")
    return boundary


def _publication_fields(receipt: Any, *, review: bool) -> tuple[str, str, str, tuple[str, ...], tuple[str, ...]]:
    from .gates import (
        CHALLENGER_ATTACK_EXECUTION_LOGICAL_TYPE, CHALLENGER_ATTACK_EXECUTION_SCHEMA_VERSION,
        CHALLENGER_CATEGORY_REVIEW_LOGICAL_TYPE, CHALLENGER_CATEGORY_REVIEW_SCHEMA_VERSION,
    )
    if review:
        parents = (receipt.claim_graph_artifact_hash, *receipt.evidence_hashes, receipt.execution_receipt_hash)
        return (
            CHALLENGER_CATEGORY_REVIEW_LOGICAL_TYPE, CHALLENGER_CATEGORY_REVIEW_SCHEMA_VERSION,
            "exact typed Challenger attack-category checklist entry",
            ("scientist-one", "record-challenger-category-review"), parents,
        )
    return (
        CHALLENGER_ATTACK_EXECUTION_LOGICAL_TYPE, CHALLENGER_ATTACK_EXECUTION_SCHEMA_VERSION,
        "registry-replayed exact Challenger attack execution",
        ("scientist-one", "record-challenger-execution"), _execution_parents(receipt),
    )


def _preflight_publication(
    registry: ArtifactRegistry, snapshot: Any, receipt: Any, *, review: bool, created_at: str,
) -> tuple[bytes, ArtifactRecord | None, ArtifactRecord]:
    """Pure bytes/metadata projection; completed full source replay is separate."""
    from .gates import MAX_GATE_RECEIPT_BYTES

    logical_type, schema_version, origin, command, parents = _publication_fields(receipt, review=review)
    if len(parents) > MAX_ARTIFACT_PARENTS or len(set(parents)) != len(parents):
        raise ValidationError("scientific external publication exceeds parent capacity")
    raw = canonical_json_bytes(receipt.to_dict()) + b"\n"
    safe_json_loads(raw, max_bytes=MAX_GATE_RECEIPT_BYTES, max_items=50_000)
    digest = hashlib.sha256(raw).hexdigest()
    indexed = {item.sha256: item for item in snapshot.records}
    existing = indexed.get(digest)
    if snapshot.count + int(existing is None) > MAX_REGISTRY_RECORDS:
        raise ValidationError("scientific external publication exceeds registry capacity")
    timestamp = existing.created_at if existing is not None else created_at
    if any(sha not in indexed or _time(indexed[sha].created_at) > _time(timestamp) for sha in parents):
        raise ValidationError("scientific external publication sources are absent or postdate publication")
    planned = ArtifactRecord(
        sha256=digest, path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(), size=len(raw),
        mime_type="application/json", logical_type=logical_type, schema_version=schema_version,
        origin=origin, creator_role=Role.ADVERSARIAL_REVIEWER,
        creation_command=command, parent_artifacts=parents,
        validation_result="PASS", frozen=True, created_at=timestamp,
    )
    if existing is not None and (existing != planned or registry.get_bytes(digest) != raw):
        raise ValidationError("scientific external content slot has different bytes or metadata")
    return raw, existing, planned


def _time(value: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ValidationError("scientific external chronology requires UTC timestamps")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("scientific external timestamp is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValidationError("scientific external timestamp is not UTC")
    return parsed


def _publish(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any, before: Any, *,
    review: bool, readback: Callable[[str], Any],
) -> ArtifactRecord:
    raw, existing, planned = _preflight_publication(
        registry, before[0], receipt, review=review, created_at=utc_now(),
    )
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            locked_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if (locked_registry, locked_ledger) != before or not locked_ledger.valid:
                raise ValidationError("scientific external sources changed before publication")
            record = existing
            if record is None:
                record = registry._put_bytes_locked(
                    registry_guard, raw, logical_type=planned.logical_type, origin=planned.origin,
                    creator_role=planned.creator_role, creation_command=planned.creation_command,
                    parent_artifacts=planned.parent_artifacts, schema_version=planned.schema_version,
                    mime_type=planned.mime_type, validation_result=planned.validation_result,
                    frozen=planned.frozen, created_at=planned.created_at,
                )
            after_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            after_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            expected = {item.sha256: item for item in before[0].records}
            expected[record.sha256] = record
            if (record != planned or after_registry.count != before[0].count + int(existing is None)
                    or {item.sha256: item for item in after_registry.records} != expected
                    or after_ledger != before[1]):
                raise ValidationError("scientific external publication produced an unexpected source delta")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    if readback(record.sha256) != receipt:
        raise ValidationError("scientific external publication differs from complete readback")
    if _locked_checked_result_authority_snapshot(registry, ledger) != (after_registry, after_ledger):
        raise ValidationError("scientific external sources changed after publication")
    return record


def register_scientific_external_validity_execution(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any,
) -> ArtifactRecord:
    from .gates import _load_challenger_attack_execution_receipt

    before = _locked_checked_result_authority_snapshot(registry, ledger)
    boundary = require_scientific_external_validity_execution(
        registry, ledger, receipt, require_whole_current=True,
    )
    if boundary.entry_snapshot != before:
        raise ValidationError("scientific external execution sources changed during replay")
    return _publish(
        registry, ledger, receipt, before, review=False,
        readback=lambda sha: _load_challenger_attack_execution_receipt(registry, sha, ledger=ledger),
    )


def require_scientific_external_validity_execution_record(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any, record: ArtifactRecord,
) -> Any:
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    boundary = require_scientific_external_validity_execution(registry, ledger, receipt)
    _, existing, planned = _preflight_publication(
        registry, before[0], receipt, review=False, created_at=record.created_at,
    )
    if (boundary.entry_snapshot != before or existing != record or planned != record
            or _locked_checked_result_authority_snapshot(registry, ledger) != before):
        raise ValidationError("scientific external execution publication changed during readback")
    return boundary


def register_scientific_external_validity_review(
    registry: ArtifactRegistry, ledger: EventLedger, review: Any,
) -> ArtifactRecord:
    from .gates import _load_challenger_attack_execution_receipt, _load_challenger_category_review

    before = _locked_checked_result_authority_snapshot(registry, ledger)
    execution = _load_challenger_attack_execution_receipt(registry, review.execution_receipt_hash, ledger=ledger)
    _require_review_shape(review, execution)
    boundary = require_scientific_external_validity_execution(
        registry, ledger, execution, require_whole_current=True,
    )
    if boundary.entry_snapshot != before:
        raise ValidationError("scientific external review sources changed during replay")
    return _publish(
        registry, ledger, review, before, review=True,
        readback=lambda sha: _load_challenger_category_review(registry, sha, ledger=ledger),
    )


def require_scientific_external_validity_review_record(
    registry: ArtifactRegistry, ledger: EventLedger, review: Any, record: ArtifactRecord,
) -> Any:
    from .gates import _load_challenger_attack_execution_receipt

    before = _locked_checked_result_authority_snapshot(registry, ledger)
    execution = _load_challenger_attack_execution_receipt(registry, review.execution_receipt_hash, ledger=ledger)
    _require_review_shape(review, execution)
    boundary = require_scientific_external_validity_execution(registry, ledger, execution)
    _, existing, planned = _preflight_publication(
        registry, before[0], review, review=True, created_at=record.created_at,
    )
    if (boundary.entry_snapshot != before or existing != record or planned != record
            or _locked_checked_result_authority_snapshot(registry, ledger) != before):
        raise ValidationError("scientific external review publication changed during readback")
    return boundary


def require_scientific_external_validity_audit_join(boundary: Any, audit: Any) -> None:
    """Pure exact join of completed owners; this does not authenticate either DTO."""
    from .gates import SemanticChallengeAuditAuthority, SemanticReproductionCohortAuditAuthority
    from .scientific_external_validity import ScientificExternalValidityBoundary

    if (type(boundary) is not ScientificExternalValidityBoundary
            or type(audit) not in {SemanticChallengeAuditAuthority, SemanticReproductionCohortAuditAuthority}):
        raise ValidationError("scientific external audit join requires completed exact owner outputs")
    audit.__post_init__()
    if (
        boundary.state.run_id != audit.run_id
        or boundary.state.snapshot_artifact_sha256 != boundary.snapshot_record.sha256
        or boundary.state.snapshot_artifact_record_hash != boundary.snapshot_record.record_hash
        or boundary.snapshot_record.sha256 != audit.research_state_snapshot_artifact_hash
        or boundary.snapshot_record.record_hash != audit.research_state_snapshot_artifact_record_hash
        or boundary.graph_record.sha256 != audit.claim_graph_artifact_hash
        or boundary.graph_record.record_hash != audit.claim_graph_artifact_record_hash
        or tuple(sorted(item.research_object.object_id for item in boundary.state.entries
                        if item.research_object.object_type == "Claim")) != audit.central_claim_ids
        or boundary.result_test_bindings != tuple(zip(
            audit.result_artifact_hashes, audit.result_artifact_record_hashes, strict=True,
        ))
        or boundary.state.ledger_event_count - 1 >= audit.slot_event_index
    ):
        raise ValidationError("scientific external inventory names another complete audit cohort")


def require_scientific_external_validity_soundness_join(
    registry: ArtifactRegistry, ledger: EventLedger | None, reviews: tuple[Any, ...], *, run_id: str | None,
) -> None:
    """Join an already loaded new boundary to executed same-S semantic reviews.

    Historical fixture reviews retain their old behavior. A new inventory
    cannot imply review coverage of another snapshot. Unexecuted categories
    retain the ordinary incomplete Soundness outcome, not an assertion of
    snapshot coverage. The upstream boundary never calls this downstream
    join or enters semantic audit replay.
    """
    from .gates import (
        ChallengeCategory, ChallengerExecutionStatus, _SEMANTIC_CHALLENGER_CATEGORIES,
        _load_challenger_attack_execution_receipt,
    )

    external = next(review for review in reviews if review.category is ChallengeCategory.EXTERNAL_VALIDITY)
    if external.execution_status is not ChallengerExecutionStatus.EXECUTED:
        return
    execution = _load_challenger_attack_execution_receipt(registry, external.execution_receipt_hash, ledger=ledger)
    if not is_scientific_external_validity_execution(execution):
        return
    if type(ledger) is not EventLedger or type(run_id) is not str or execution.run_id != run_id:
        raise ValidationError("scientific external Soundness join requires the exact run and ledger")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    boundary = require_scientific_external_validity_execution_record(
        registry, ledger, execution, registry.get_metadata(external.execution_receipt_hash),
    )
    for review in reviews:
        if (review.category not in _SEMANTIC_CHALLENGER_CATEGORIES
                or review.execution_status is not ChallengerExecutionStatus.EXECUTED):
            continue
        snapshots = tuple(registry.get_metadata(sha) for sha in review.evidence_hashes
                          if registry.get_metadata(sha).logical_type in {
                              "canonical_research_state_snapshot", "canonical_research_state_final_snapshot",
                          })
        if (snapshots != (boundary.snapshot_record,)
                or review.claim_graph_artifact_hash != boundary.graph_record.sha256
                or tuple(sorted(review.target_claim_ids)) != execution.target_claim_ids):
            raise ValidationError("scientific external Soundness inventory differs from an executed review")
    if boundary.entry_snapshot != before or _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ValidationError("scientific external Soundness sources changed during join")
