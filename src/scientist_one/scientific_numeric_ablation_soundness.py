"""Existing-wire Soundness publication for complete descriptive ablation replay.

Numerical coverage is operational evidence. This module cannot issue a
scientific ABLATIONS PASS, an audit, or an independent approval. It reuses the
ordinary issued canonical snapshot, dimension-receipt family and registry.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .artifacts import ArtifactRecord, ArtifactRegistry, MAX_REGISTRY_RECORDS
from .errors import ArtifactError
from .ledger import EventLedger
from .models import Role, utc_now
from .scientific_design import _locked_checked_result_authority_snapshot
from .scientific_numeric_ablation import ScientificNumericAblationError
from .scientific_numeric_ablation_authority import _time
from .scientific_numeric_ablation_cohort import (
    NATIVE_ABLATION_COVERAGE_RATIONALE, NATIVE_ABLATION_COVERAGE_RULE,
    ScientificNumericAblationCohort, require_scientific_numeric_ablation_cohort,
)
from .security import canonical_json_bytes, safe_json_loads


_ORIGIN = "registry-bound per-dimension scientific soundness review"
_COMMAND = ("scientist-one", "record-soundness-dimension")
_MAX_BYTES = 4 * 1024 * 1024


def is_native_numeric_ablation_dimension(registry: ArtifactRegistry, receipt: Any) -> bool:
    """Route by dimension and source family only; never infer source authority."""

    from .gates import SoundnessDimension

    if receipt.dimension is not SoundnessDimension.ABLATIONS or receipt.authority_artifact_hash is None:
        return False
    try:
        record = registry.get_metadata(receipt.authority_artifact_hash)
    except ArtifactError as exc:
        # Never fall through after a miss: a concurrent snapshot publication
        # could otherwise reach the legacy non-CAS registrar without this
        # profile's fixed interpretation and whole-current replay.
        raise ScientificNumericAblationError("soundness dimension authority is absent") from exc
    return record.logical_type in {
        "canonical_research_state_snapshot", "canonical_research_state_final_snapshot",
    }


def require_native_numeric_ablation_dimension_shape(receipt: Any) -> None:
    """Closed interpretation of the existing v2 receipt; no DTO grants authority."""

    from .gates import (
        DimensionStatus, SoundnessAuthorityKind, SoundnessDimension,
        SoundnessDimensionEvidenceReceipt,
    )

    if type(receipt) is not SoundnessDimensionEvidenceReceipt:
        raise ScientificNumericAblationError("native ablation dimension requires the exact existing receipt")
    SoundnessDimensionEvidenceReceipt.__post_init__(receipt)
    if (receipt.dimension is not SoundnessDimension.ABLATIONS
            or receipt.authority_kind is not SoundnessAuthorityKind.DETERMINISTIC
            or receipt.status is not DimensionStatus.UNTESTED
            or receipt.governing_rule != NATIVE_ABLATION_COVERAGE_RULE
            or receipt.rationale != NATIVE_ABLATION_COVERAGE_RATIONALE
            or type(receipt.authority_artifact_hash) is not str
            or type(receipt.evidence_hashes) is not tuple
            or len(receipt.evidence_hashes) > 255
            or receipt.evidence_hashes != tuple(sorted(receipt.evidence_hashes))):
        raise ScientificNumericAblationError("native ablation dimension must retain closed untested scientific adequacy")


def _preflight_dimension_publication(
    registry: ArtifactRegistry, snapshot: Any, receipt: Any,
    cohort: ScientificNumericAblationCohort, *, created_at: str,
) -> tuple[bytes, ArtifactRecord | None, ArtifactRecord]:
    """Pure publication checks using completed replay outputs, not an owner."""

    from .gates import SOUNDNESS_DIMENSION_RECEIPT_LOGICAL_TYPE, SOUNDNESS_DIMENSION_RECEIPT_SCHEMA_VERSION

    require_native_numeric_ablation_dimension_shape(receipt)
    if (type(cohort) is not ScientificNumericAblationCohort
            or receipt.authority_artifact_hash != cohort.snapshot_record.sha256
            or receipt.evidence_hashes != cohort.evidence_hashes):
        raise ScientificNumericAblationError("native dimension differs from its complete owned cohort")
    raw = canonical_json_bytes(receipt.to_dict()) + b"\n"
    safe_json_loads(raw, max_bytes=_MAX_BYTES, max_items=50_000)
    digest = hashlib.sha256(raw).hexdigest()
    indexed = {item.sha256: item for item in snapshot.records}
    existing = indexed.get(digest)
    if snapshot.count + int(existing is None) > MAX_REGISTRY_RECORDS:
        raise ScientificNumericAblationError("native dimension exceeds registry capacity")
    timestamp = existing.created_at if existing is not None else created_at
    sources = ((cohort.snapshot_record.sha256, cohort.snapshot_record.record_hash),
               *zip(cohort.evidence_hashes, cohort.evidence_record_hashes, strict=True))
    if any(indexed.get(sha) is None or indexed[sha].record_hash != record_hash
           or _time(indexed[sha].created_at) > _time(timestamp) for sha, record_hash in sources):
        raise ScientificNumericAblationError("native dimension sources changed or postdate publication")
    planned = ArtifactRecord(
        sha256=digest, path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=SOUNDNESS_DIMENSION_RECEIPT_LOGICAL_TYPE,
        schema_version=SOUNDNESS_DIMENSION_RECEIPT_SCHEMA_VERSION, mime_type="application/json",
        size=len(raw), origin=_ORIGIN, creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_COMMAND, parent_artifacts=tuple(sha for sha, _ in sources),
        validation_result="PASS", frozen=True, created_at=timestamp,
    )
    if existing is not None and (existing != planned or registry.get_bytes(digest) != raw):
        raise ScientificNumericAblationError("native dimension content slot has different bytes or metadata")
    return raw, existing, planned


def register_native_numeric_ablation_dimension(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any, *, run_id: str,
) -> ArtifactRecord:
    """Fresh whole-current coverage, exact projection, then paired CAS publication.

    This is the native branch of the existing dimension registrar. Its fixed
    interpretation is replayed again by the ordinary dimension reader. There
    is no supplied cohort/eligibility grant or new ledger publication family.
    """

    from .gates import _load_soundness_dimension_receipt

    require_native_numeric_ablation_dimension_shape(receipt)
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    cohort = require_scientific_numeric_ablation_cohort(
        registry, ledger, expected_ledger_run_id=run_id,
        snapshot_artifact_sha256=receipt.authority_artifact_hash, require_whole_current=True,
    )
    if cohort.entry_snapshot != before:
        raise ScientificNumericAblationError("native dimension sources changed during whole-cohort replay")
    raw, existing, planned = _preflight_dimension_publication(
        registry, before[0], receipt, cohort, created_at=utc_now(),
    )
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            locked_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if (locked_registry, locked_ledger) != before or not locked_ledger.valid:
                raise ScientificNumericAblationError("native dimension sources changed before commit")
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
            expected_records = {item.sha256: item for item in before[0].records}
            expected_records[record.sha256] = record
            if (record != planned or after_registry.count != before[0].count + int(existing is None)
                    or {item.sha256: item for item in after_registry.records} != expected_records
                    or after_ledger != before[1]):
                raise ScientificNumericAblationError("native dimension commit produced an unexpected source delta")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    if _load_soundness_dimension_receipt(registry, record.sha256, ledger=ledger, run_id=run_id) != receipt:
        raise ScientificNumericAblationError("native dimension differs from full fresh readback")
    if _locked_checked_result_authority_snapshot(registry, ledger) != (after_registry, after_ledger):
        raise ScientificNumericAblationError("native dimension sources changed after commit")
    return record


def require_native_numeric_ablation_dimension_record(
    registry: ArtifactRegistry, ledger: EventLedger, receipt: Any,
    record: ArtifactRecord, *, run_id: str,
) -> None:
    """Full bound replay and exact existing publication metadata/bytes."""

    require_native_numeric_ablation_dimension_shape(receipt)
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    cohort = require_scientific_numeric_ablation_cohort(
        registry, ledger, expected_ledger_run_id=run_id,
        snapshot_artifact_sha256=receipt.authority_artifact_hash,
    )
    _, existing, planned = _preflight_dimension_publication(
        registry, before[0], receipt, cohort, created_at=record.created_at,
    )
    if (cohort.entry_snapshot != before or existing != record or planned != record
            or _locked_checked_result_authority_snapshot(registry, ledger) != before):
        raise ScientificNumericAblationError("native dimension publication changed during full readback")


def _require_numeric_ablation_audit_cohort_join(
    cohort: ScientificNumericAblationCohort, audit: Any, *, run_id: str,
) -> None:
    """Pure exact join of completed owner outputs, never source admission."""

    from .gates import ChallengeCategory, SemanticReproductionCohortAuditAuthority

    if (type(cohort) is not ScientificNumericAblationCohort
            or type(audit) is not SemanticReproductionCohortAuditAuthority):
        raise ScientificNumericAblationError("native coverage requires the exact plural audit cohort")
    SemanticReproductionCohortAuditAuthority.__post_init__(audit)
    if (audit.category is not ChallengeCategory.REPRODUCTION
            or audit.procedure_version != "3.0"
            or cohort.state.run_id != run_id or audit.run_id != run_id
            or cohort.snapshot_record.sha256 != audit.research_state_snapshot_artifact_hash
            or cohort.snapshot_record.record_hash != audit.research_state_snapshot_artifact_record_hash
            or cohort.state.snapshot_artifact_sha256 != cohort.snapshot_record.sha256
            or cohort.state.snapshot_artifact_record_hash != cohort.snapshot_record.record_hash
            or cohort.state.ledger_event_count - 1 >= audit.slot_event_index
            or cohort.result_test_bindings != tuple(zip(
                audit.result_artifact_hashes, audit.result_artifact_record_hashes, strict=True))):
        raise ScientificNumericAblationError("native coverage and reproduction audit name different complete cohorts")


def _native_numeric_ablation_declared_in_owned_state(registry: ArtifactRegistry, state: Any) -> bool:
    """Applicability-only read AFTER full plural ownership, never an owner.

    Every Result-bound Run's retained spec is examined. Presence is tested
    prospectively, not inferred from surviving Ablations, V4 or outcome labels.
    Any native signal selects the strict complete cohort; only complete absence
    permits the old non-native R5/E2 behavior. Malformed presence is not absence.
    """

    from .evaluators import _canonical_json_artifact
    from .experiments import _parse_frozen_run_spec, SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY
    from .models import thaw_json
    from .research_state import Ablation, ResearchStateAuthoritySnapshot, Result, Run
    from .scientific_numeric_ablation import SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY
    from .scientific_numeric_ablation_authority_value import SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA

    if type(state) is not ResearchStateAuthoritySnapshot:
        raise ScientificNumericAblationError("native applicability requires the fully owned canonical snapshot")
    if any(type(item.research_object) is Ablation
           and thaw_json(item.research_object.metadata).get("schema_version")
           == SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA for item in state.entries):
        return True
    results = tuple(item.research_object for item in state.entries if type(item.research_object) is Result)
    runs = {item.research_object.object_id: item for item in state.entries if type(item.research_object) is Run}
    if not results:
        raise ScientificNumericAblationError("native applicability cannot classify an empty Result cohort")
    for result in results:
        parents = tuple(parent for parent in result.parents if parent.object_type == "Run")
        if ({parent.object_id for parent in parents} != set(result.run_ids)
                or any(parent.object_id not in runs
                       or parent.content_hash != runs[parent.object_id].research_object.content_hash
                       or not parent.evaluated for parent in parents)):
            raise ScientificNumericAblationError("native applicability Result-to-Run ancestry differs")
    for run_id in sorted({run_id for result in results for run_id in result.run_ids}):
        run = runs.get(run_id)
        if run is None:
            raise ScientificNumericAblationError("native applicability is missing a Result-bound Run")
        sources = tuple((sha, record_hash, logical_type, role)
                        for sha, record_hash, logical_type, role in zip(
                            run.authority_artifact_hashes, run.authority_artifact_record_hashes,
                            run.authority_logical_types, run.authority_creator_roles, strict=True)
                        if logical_type in {"frozen_run_spec", "autonomous_implementation.frozen_run_spec"})
        if len(sources) != 1:
            raise ScientificNumericAblationError("native applicability requires the Run's exact retained spec")
        sha, record_hash, logical_type, role = sources[0]
        record = registry.get_metadata(sha)
        if (record.record_hash != record_hash or record.logical_type != logical_type
                or record.creator_role is not role):
            raise ScientificNumericAblationError("native applicability spec descriptor changed after full ownership")
        spec = _parse_frozen_run_spec(_canonical_json_artifact(registry, record))
        if spec.run_id != run_id or spec.experiment_id != run.research_object.experiment_id:
            raise ScientificNumericAblationError("native applicability spec names another Result-bound Run")
        metadata = thaw_json(spec.metadata)
        if (SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY in metadata
                or (SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY in metadata and spec.required_ablations)):
            return True
    return False


def _require_soundness_ablation_applicability_state(
    registry: ArtifactRegistry, ledger: EventLedger, record: ArtifactRecord, *, run_id: str,
) -> Any:
    """Full issued bound S plus audit-free core drift, without assuming native.

    This precedes choosing an ablation profile; numerical cohort admission
    limits cannot be imposed on older non-native states merely to classify them.
    No downstream audit, Soundness, R5 or scientific approval is entered here.
    """

    from .gates import _require_bound_snapshot_no_post_snapshot_core_drift
    from .research_state import (
        _read_canonical_research_state_snapshot, _require_research_state_snapshot_issuance,
        resolve_bound_research_state_authority,
    )

    current, state_hashes, _, payload = _read_canonical_research_state_snapshot(registry, record.sha256)
    if current != record or record.logical_type != "canonical_research_state_snapshot":
        raise ScientificNumericAblationError("Soundness applicability requires its exact ordinary snapshot")
    index, issuance = _require_research_state_snapshot_issuance(
        ledger.validate(raise_on_error=True), snapshot_record=record, snapshot_value=payload,
    )
    state = resolve_bound_research_state_authority(
        registry, ledger, run_id=run_id, snapshot_artifact_hash=record.sha256,
        state_artifact_hashes=state_hashes, ledger_head_hash=issuance.event_hash,
        ledger_event_count=index + 1, expected_code_version=payload["repository_code_version"],
        expected_configuration_hash=payload["repository_configuration_hash"],
    )
    _require_bound_snapshot_no_post_snapshot_core_drift(registry, ledger, state=state)
    return state


def _soundness_ablation_snapshot_selectors(
    registry: ArtifactRegistry, reproduction_review: Any, reproduction_receipt: Any,
    *, run_id: str | None,
) -> tuple[ArtifactRecord, ...]:
    """Union exact reviewed/R7 snapshot selectors; no source authority is granted."""

    from .evaluators import _canonical_json_artifact
    from .gates import (
        ChallengeCategory, SemanticChallengeAuditAuthority, SemanticReproductionCohortAuditAuthority,
    )

    snapshot_records = {record.sha256: record for sha in reproduction_review.evidence_hashes
                        if (record := registry.get_metadata(sha)).logical_type in {
                            "canonical_research_state_snapshot", "canonical_research_state_final_snapshot",
                        }}
    # An older review may have no S even though the separately resolved R7
    # source audits native work. Its exact source tuple is a second selector,
    # never authority by itself; every selected S is fully replayed below.
    for sha in reproduction_receipt.evidence_hashes:
        source = registry.get_metadata(sha)
        if source.logical_type != "semantic_challenge_audit_authority":
            continue
        payload = _canonical_json_artifact(registry, source)
        family = (source.schema_version, payload.get("schema_version"))
        if family == ("1.0", "semantic-challenge-audit-authority/v1"):
            selector = SemanticChallengeAuditAuthority.from_dict(payload)
        elif family == ("2.0", "semantic-challenge-audit-authority/v2"):
            selector = SemanticReproductionCohortAuditAuthority.from_dict(payload)
        else:
            raise ScientificNumericAblationError("Soundness reproduction audit selector has mixed versions")
        record = registry.get_metadata(selector.research_state_snapshot_artifact_hash)
        if (selector.run_id != run_id or selector.category is not ChallengeCategory.REPRODUCTION
                or record.record_hash != selector.research_state_snapshot_artifact_record_hash):
            raise ScientificNumericAblationError("Soundness reproduction audit snapshot selector changed")
        snapshot_records[record.sha256] = record
    return tuple(snapshot_records[sha] for sha in sorted(snapshot_records))


def require_native_numeric_ablation_soundness_join(
    registry: ArtifactRegistry, ledger: EventLedger | None, *, run_id: str | None,
    assessment_id: str, claim_graph_artifact_hash: str, central_claim_ids: tuple[str, ...],
    ablation_receipt: Any, reproduction_receipt: Any,
    reproduction_review_hash: str, reproduction_review: Any,
    replay_peers: tuple[Any, ...] | None,
) -> None:
    """Derive applicability from reviewed S, then enforce the native round join.

    Caller selection of an older A receipt cannot suppress declared native
    obligations. The full-owned REPRODUCTION review and separately resolved
    R7 source supply coherent S selectors for full applicability replay.
    Static round replay uses only its existing fully replayed REPRODUCTION
    peer; public replay acquires the full plural owner. No peer is manufactured.
    """

    from .evaluators import _canonical_json_artifact, _replay_semantic_audit_source_with_packages
    from .gates import ChallengeCategory, SoundnessAuthorityKind, SoundnessDimension

    native_selected = is_native_numeric_ablation_dimension(registry, ablation_receipt)
    snapshot_records = _soundness_ablation_snapshot_selectors(
        registry, reproduction_review, reproduction_receipt, run_id=run_id,
    )
    if not snapshot_records and not native_selected:
        return  # Old review/fixture without canonical S gains no native coverage.
    if len(snapshot_records) != 1:
        raise ScientificNumericAblationError("Soundness ablation applicability requires one exact reviewed snapshot")
    snapshot_record = snapshot_records[0]
    if type(ledger) is not EventLedger or type(run_id) is not str:
        raise ScientificNumericAblationError("Soundness ablation applicability requires its exact EventLedger and run")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    state = _require_soundness_ablation_applicability_state(
        registry, ledger, snapshot_record, run_id=run_id,
    )
    native_required = _native_numeric_ablation_declared_in_owned_state(registry, state)
    if not native_selected and not native_required:
        if _locked_checked_result_authority_snapshot(registry, ledger) != before:
            raise ScientificNumericAblationError("Soundness non-native applicability sources changed")
        return
    require_native_numeric_ablation_dimension_shape(ablation_receipt)
    if ablation_receipt.authority_artifact_hash != snapshot_record.sha256:
        raise ScientificNumericAblationError("native Soundness must use its reviewed whole-cohort snapshot")
    if (reproduction_receipt.dimension is not SoundnessDimension.REPRODUCIBILITY
            or reproduction_receipt.authority_kind is not SoundnessAuthorityKind.DETERMINISTIC
            or reproduction_receipt.authority_artifact_hash is None
            or len(reproduction_receipt.evidence_hashes) != 1):
        raise ScientificNumericAblationError("native Soundness requires one exact plural reproduction audit source")
    audit_record = registry.get_metadata(reproduction_receipt.evidence_hashes[0])
    if (audit_record.logical_type != "semantic_challenge_audit_authority"
            or audit_record.schema_version != "2.0"):
        raise ScientificNumericAblationError("native Soundness cannot use a legacy or mixed reproduction audit")
    peer = None
    if replay_peers is not None:
        peers = tuple(item for item in replay_peers
                      if item.authority.category is ChallengeCategory.REPRODUCTION)
        if len(peers) != 1 or peers[0].record != audit_record:
            raise ScientificNumericAblationError("native Soundness requires its exact replayed reproduction peer")
        peer = peers[0]
    audit, _ = _replay_semantic_audit_source_with_packages(
        registry, ledger, run_id, audit_record, _canonical_json_artifact(registry, audit_record),
        expected_category=ChallengeCategory.REPRODUCTION, _replayed_peer=peer,
    )
    cohort = require_scientific_numeric_ablation_cohort(
        registry, ledger, expected_ledger_run_id=run_id,
        snapshot_artifact_sha256=ablation_receipt.authority_artifact_hash,
    )
    _require_numeric_ablation_audit_cohort_join(cohort, audit, run_id=run_id)
    _require_native_numeric_ablation_round_join(
        cohort, audit, ablation_receipt=ablation_receipt,
        assessment_id=assessment_id, claim_graph_record=registry.get_metadata(claim_graph_artifact_hash),
        central_claim_ids=central_claim_ids,
        review_record=registry.get_metadata(reproduction_review_hash), review=reproduction_review,
        execution_record=registry.get_metadata(reproduction_review.execution_receipt_hash),
    )
    if (cohort.entry_snapshot != before
            or _locked_checked_result_authority_snapshot(registry, ledger) != before):
        raise ScientificNumericAblationError("native Soundness sources changed during round composition")


def _require_native_numeric_ablation_round_join(
    cohort: ScientificNumericAblationCohort, audit: Any, *, ablation_receipt: Any,
    assessment_id: str, claim_graph_record: ArtifactRecord, central_claim_ids: tuple[str, ...],
    review_record: ArtifactRecord, review: Any, execution_record: ArtifactRecord,
) -> None:
    """Pure exact joins over full replay outputs; no input grants authority."""

    from .gates import ChallengeCategory, ChallengerCategoryReview, SemanticReproductionCohortAuditAuthority

    require_native_numeric_ablation_dimension_shape(ablation_receipt)
    if (type(cohort) is not ScientificNumericAblationCohort
            or type(audit) is not SemanticReproductionCohortAuditAuthority
            or type(review) is not ChallengerCategoryReview
            or any(type(record) is not ArtifactRecord
                   for record in (claim_graph_record, review_record, execution_record))):
        raise ScientificNumericAblationError("native Soundness round joins require exact replay outputs")
    if (ablation_receipt.authority_artifact_hash != cohort.snapshot_record.sha256
            or ablation_receipt.evidence_hashes != cohort.evidence_hashes
            or audit.assessment_id != assessment_id
            or audit.claim_graph_artifact_hash != claim_graph_record.sha256
            or audit.claim_graph_artifact_record_hash != claim_graph_record.record_hash
            or audit.central_claim_ids != central_claim_ids
            or audit.challenger_review_artifact_hash != review_record.sha256
            or audit.challenger_review_artifact_record_hash != review_record.record_hash
            or review.category is not ChallengeCategory.REPRODUCTION
            or review.claim_graph_artifact_hash != claim_graph_record.sha256
            or tuple(sorted(review.target_claim_ids)) != central_claim_ids
            or audit.challenger_execution_artifact_hash != review.execution_receipt_hash
            or audit.challenger_execution_artifact_hash != execution_record.sha256
            or audit.challenger_execution_artifact_record_hash != execution_record.record_hash
            or audit.evidence_artifact_hashes != review.evidence_hashes
            or audit.finding_artifact_hashes != review.finding_artifact_hashes):
        raise ScientificNumericAblationError("native Soundness coverage differs from the exact assessed reproduction round")
