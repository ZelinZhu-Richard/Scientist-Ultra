"""Outcome-neutral, source-owned descriptive numeric ablation publication.

This is downstream of a current canonical Result and the complete executed
intervention owner. It never interprets a descriptive effect as scientific
component removal, robustness, significance or superiority. The existing
registry and canonical materializer remain the only publication systems.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from .artifacts import ArtifactRecord, ArtifactRegistry, MAX_REGISTRY_RECORDS
from .ledger import EventLedger
from .models import Role, utc_now, validate_identifier, validate_sha256
from .scientific_design import (
    SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
    ScientificResultCanonicalProjectionV4,
    _find_scientific_ablation_implementation,
    _load_scientific_ablation_state,
    _locked_checked_result_authority_snapshot,
    _projection_source_artifact_sha256,
    _scientific_ablation_custody_bindings,
    _scientific_ablation_state_binding,
    require_scientific_result_canonical_projection_v3,
    require_scientific_result_promotion_authority_v3,
)
from .scientific_numeric_ablation import ScientificNumericAblationError
from .scientific_numeric_ablation_execution import (
    ScientificNumericAblationExecutionBinding,
    require_scientific_numeric_ablation_execution,
)
from .security import safe_json_loads


_ORIGIN = "source-owned descriptive numeric ablation authority"
_COMMAND = ("scientist-one", "validate-scientific-numeric-ablation")
_LOGICAL_TYPE = "scientific_ablation_authority"
_METADATA_SCHEMA = "2.0"
_MAX_BYTES = 4 * 1024 * 1024


def _require_primary_grid_join(
    numeric: ScientificNumericAblationExecutionBinding,
    primary: ScientificResultCanonicalProjectionV4,
) -> None:
    """Pure integer joins, not authentication of supplied DTOs."""

    if (type(numeric) is not ScientificNumericAblationExecutionBinding
            or type(primary) is not ScientificResultCanonicalProjectionV4):
        raise ScientificNumericAblationError("numeric authority requires native primary and execution views")
    projection = numeric.projection
    rows = primary.numeric_result.rows
    if (primary.seed_order != projection.seed_order
            or primary.numeric_result.plan.unit_ids != projection.paired_unit_ids
            or primary.numeric_result.plan.seed_order != projection.seed_order
            or primary.sample_size != len(projection.paired_unit_ids)
            or primary.metric_id != numeric.prospective_binding.policy.metric_id
            or primary.hypothesis_id != numeric.spec.hypothesis_id
            or primary.baseline_id != numeric.prospective_binding.policy.interventions[0].baseline_condition_id
            or primary.frozen_run_spec_artifact_sha256 != numeric.spec_record.sha256
            or primary.output_manifest_artifact_sha256 != numeric.manifest_record.sha256
            or primary.scientific_execution_authority_artifact_sha256 != numeric.execution_record.sha256
            or primary.contract_artifact_sha256 != numeric.prospective_binding.reference_binding.contract_record.sha256):
        raise ScientificNumericAblationError("numeric authority differs from the complete primary source grid")
    if not numeric.entries:
        raise ScientificNumericAblationError("numeric authority cannot establish vacuous intervention coverage")
    for entry in numeric.entries:
        grid = entry.grid
        if (grid.seed_order != primary.seed_order
                or grid.unit_ids != projection.paired_unit_ids
                or grid.unit_hashes != projection.paired_unit_hashes
                or len(rows) != len(grid.unit_counts)):
            raise ScientificNumericAblationError("numeric authority changed ordered primary unit identities")
        if any((unit.unit_id, unit.seed_count, unit.candidate_correct_count, unit.baseline_correct_count)
               != (row.unit_id, row.seed_count, row.candidate_correct_count, row.reference_correct_count)
               for unit, row in zip(grid.unit_counts, rows, strict=True)):
            raise ScientificNumericAblationError("numeric authority changed integer primary row counts")


def _time(value: str) -> datetime:
    # Source record constructors and full owners validate UTC syntax; require
    # that property here too so offsets/naive timestamps cannot change order.
    if type(value) is not str or not value.endswith("Z"):
        raise ScientificNumericAblationError("numeric authority chronology requires UTC text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScientificNumericAblationError("numeric authority timestamp is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ScientificNumericAblationError("numeric authority timestamp is not UTC")
    return parsed


def build_scientific_numeric_ablation_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_ablation_id: str,
    result_state_artifact_sha256: str,
    run_state_artifact_sha256: str,
    method_state_artifact_sha256: str,
    experiment_state_artifact_sha256: str,
):
    """Replay current parents and every intervention before selecting one.

    Inputs only select existing canonical state. There is no caller supplied
    verdict, numeric companion, primary outcome or scientific eligibility.
    """

    from .research_state import RecordStatus, resolve_current_research_state_bindings
    from .scientific_numeric_ablation_authority_value import (
        ScientificNumericAblationAuthority,
        numeric_ablation_slot_hash,
    )

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ScientificNumericAblationError("numeric authority requires exact registry and ledger")
    for value in (expected_ledger_run_id, expected_execution_run_id, expected_ablation_id):
        if type(value) is not str:
            raise ScientificNumericAblationError("numeric authority selectors require native identifiers")
        validate_identifier(value, "numeric authority selector")
    state_hashes = (result_state_artifact_sha256, run_state_artifact_sha256,
                    method_state_artifact_sha256, experiment_state_artifact_sha256)
    for digest in state_hashes:
        if type(digest) is not str:
            raise ScientificNumericAblationError("numeric authority state selectors require native hashes")
        validate_sha256(digest, "numeric authority state selector")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    loaded = tuple(_load_scientific_ablation_state(registry, digest, expected_object_type=kind)
                   for digest, kind in zip(state_hashes, ("Result", "Run", "Method", "Experiment"), strict=True))
    (result_record, result), (run_record, run), (method_record, method), (experiment_record, experiment) = loaded
    scoped = resolve_current_research_state_bindings(
        registry, ledger, run_id=expected_ledger_run_id,
        state_artifact_hashes=(result_record.sha256, experiment_record.sha256),
    )
    result_entry = scoped.binding_for_artifact(result_record.sha256)
    experiment_entry = scoped.binding_for_artifact(experiment_record.sha256)
    if (result_entry.research_object != result or experiment_entry.research_object != experiment
            or result_entry.artifact_record_hash != result_record.record_hash
            or experiment_entry.artifact_record_hash != experiment_record.record_hash
            or result_entry.scientific_evidence_eligible is not True):
        raise ScientificNumericAblationError("numeric authority requires the exact current eligible Result")

    # These parents were fully replayed by the scoped Result owner. Join the
    # selected records exactly; a Method with a similarly named component is
    # not interchangeable with its actual frozen source definition.
    def require_parent(child, kind, parent) -> None:
        matches = tuple(item for item in child.parents if item.object_type == kind)
        if (len(matches) != 1 or matches[0].object_id != parent.object_id
                or matches[0].content_hash != parent.content_hash or matches[0].evaluated is not True):
            raise ScientificNumericAblationError("numeric authority canonical parent was substituted")

    implementation_refs = tuple(item for item in experiment.parents if item.object_type == "Implementation")
    if len(implementation_refs) != 1:
        raise ScientificNumericAblationError("numeric authority lacks one canonical Implementation")
    _, implementation = _find_scientific_ablation_implementation(
        registry, object_id=implementation_refs[0].object_id, content_hash=implementation_refs[0].content_hash,
    )
    require_parent(result, "Run", run)
    require_parent(run, "Experiment", experiment)
    require_parent(experiment, "Implementation", implementation)
    require_parent(implementation, "Method", method)
    if (result.run_ids != (run.object_id,) or run.object_id != expected_execution_run_id
            or run.experiment_id != experiment.object_id
            or experiment.implementation_id != implementation.object_id
            or implementation.method_id != method.object_id
            or result.status is not RecordStatus.COMPLETE or run.status is not RecordStatus.COMPLETE
            or method.status is not RecordStatus.FROZEN or experiment.status is not RecordStatus.FROZEN):
        raise ScientificNumericAblationError("numeric authority canonical lifecycle or identities differ")
    promotion_records = tuple(registry.get_metadata(digest) for digest in result.evaluation_artifact_hashes
                              if registry.get_metadata(digest).logical_type
                              == SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3)
    if len(promotion_records) != 1:
        raise ScientificNumericAblationError("numeric authority requires one outcome-neutral Result promotion")
    promotion_record = promotion_records[0]
    resolution = require_scientific_result_promotion_authority_v3(
        registry, ledger, promotion_receipt_artifact_sha256=promotion_record.sha256,
        expected_ledger_run_id=expected_ledger_run_id, expected_execution_run_id=expected_execution_run_id,
        expected_result_id=result.object_id,
    )
    primary = require_scientific_result_canonical_projection_v3(
        registry, ledger, promotion_receipt_artifact_sha256=promotion_record.sha256,
        expected_ledger_run_id=expected_ledger_run_id, expected_execution_run_id=expected_execution_run_id,
        expected_result_id=result.object_id, canonical_state_code_version=scoped.code_version,
    )
    assessment = resolution.assessment
    if (type(primary) is not ScientificResultCanonicalProjectionV4 or not assessment.is_bounded_mean
            or resolution.scientific_evidence_eligible is not True
            or primary.outcome is not resolution.outcome
            or primary.experiment_id != experiment.object_id
            or primary.result_id != result.object_id):
        raise ScientificNumericAblationError("numeric authority requires the native outcome-neutral primary owner")
    # Decode only to select the domain source; no decoded field provides
    # authority until the full executed owner below reopens this exact record.
    domain_source_selector = _projection_source_artifact_sha256(
        registry, assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
    )
    numeric = require_scientific_numeric_ablation_execution(
        registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        generic_ml_projection_artifact_sha256=assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
        scientific_execution_authority_artifact_sha256=assessment.scientific_execution_authority_artifact_sha256,
        scientific_domain_evidence_source_artifact_sha256=domain_source_selector,
        expected_contract_artifact_sha256=assessment.contract_artifact_sha256,
        expected_output_manifest_artifact_sha256=assessment.output_manifest_artifact_sha256,
    )
    prospective = numeric.prospective_binding
    if (numeric.projection.scientific_domain_evidence_source_artifact_sha256 != domain_source_selector
            or numeric.projection_record.sha256 != assessment.generic_ml_paired_metric_projection_authority_artifact_sha256
            or numeric.projection_record.record_hash != assessment.generic_ml_paired_metric_projection_authority_record_hash
            or numeric.execution_record.record_hash != assessment.scientific_execution_authority_record_hash
            or prospective.reference_binding.contract_record.record_hash != assessment.contract_record_hash
            or prospective.policy.method_id != method.object_id
            or prospective.method_record.sha256 not in method.authority_artifact_hashes
            or registry.get_metadata(prospective.method_record.sha256) != prospective.method_record
            or primary.statistical_use_authority_artifact_sha256 != prospective.reference_binding.statistical_use_record.sha256
            or primary.statistical_use_authority_record_hash != prospective.reference_binding.statistical_use_record.record_hash):
        raise ScientificNumericAblationError("numeric authority source records or Method definition differ")
    _require_primary_grid_join(numeric, primary)
    entries = tuple(item for item in numeric.entries if item.grid.intervention.ablation_id == expected_ablation_id)
    if len(entries) != 1:
        raise ScientificNumericAblationError("numeric authority obligation is absent or ambiguous")
    entry = entries[0]
    grid = entry.grid
    if (grid.intervention.component_id not in method.component_ids
            or grid.intervention.hypothesis_id not in experiment.hypothesis_ids
            or entry.output_record.sha256 not in run.output_artifact_hashes
            or entry.output_record.sha256 not in primary.output_artifact_sha256s):
        raise ScientificNumericAblationError("numeric authority intervention differs from the actual Method or Run")
    state_bindings = tuple(_scientific_ablation_state_binding(ledger, scoped=scoped, record=record, state=state)
                           for record, state in loaded)
    assessment_record = registry.get_metadata(primary.checked_result_assessment_artifact_sha256)
    scientific_records = (prospective.reference_binding.contract_record, promotion_record, assessment_record,
                          numeric.execution_record, numeric.projection_record, entry.output_record)
    sources = (*scientific_records, *(record for record, _state in loaded))
    custody_hashes, custody_records = _scientific_ablation_custody_bindings(registry, tuple(item.sha256 for item in sources))
    custody = dict(zip(custody_hashes, custody_records, strict=True))
    if any(custody.get(item.sha256) != item.record_hash for item in numeric.source_records):
        raise ScientificNumericAblationError("numeric authority custody omits a consumed execution source")
    pairs = {}
    for prefix, record in zip(("contract", "promotion", "assessment", "execution", "projection", "ablation_output"),
                              scientific_records, strict=True):
        pairs[f"{prefix}_artifact_sha256"] = record.sha256
        pairs[f"{prefix}_record_hash"] = record.record_hash
    slot = numeric_ablation_slot_hash(
        ledger_run_id=expected_ledger_run_id, execution_run_id=expected_execution_run_id,
        result_artifact_sha256=result_record.sha256,
        contract_artifact_sha256=scientific_records[0].sha256, ablation_id=expected_ablation_id,
    )
    receipt = ScientificNumericAblationAuthority(
        authority_id="numeric-ablation-authority:" + slot,
        ledger_run_id=expected_ledger_run_id, execution_run_id=expected_execution_run_id,
        intervention=grid.intervention, metric_id=prospective.policy.metric_id,
        **pairs, state_bindings=state_bindings,
        unit_count=len(grid.unit_counts), seed_order=grid.seed_order,
        changed_coefficient_counts=tuple(item.changed_coefficient_count for item in grid.seed_results),
        activity_sequence=entry.activity_sequence,
        candidate_correct_total=sum(item.candidate_correct_count for item in grid.unit_counts),
        baseline_correct_total=sum(item.baseline_correct_count for item in grid.unit_counts),
        ablated_correct_total=sum(item.ablated_correct_count for item in grid.unit_counts),
        source_artifact_hashes=tuple(item.sha256 for item in sources),
        source_artifact_record_hashes=tuple(item.record_hash for item in sources),
        custody_artifact_hashes=custody_hashes, custody_artifact_record_hashes=custody_records,
    )
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificNumericAblationError("numeric authority sources changed during replay; retry")
    return receipt


def _read_native_record(registry: ArtifactRegistry, record: ArtifactRecord):
    """Closed metadata/byte decoding only; full source replay is mandatory."""

    from .scientific_numeric_ablation_authority_value import ScientificNumericAblationAuthority

    if (type(record) is not ArtifactRecord or record.logical_type != _LOGICAL_TYPE
            or record.schema_version != _METADATA_SCHEMA or record.origin != _ORIGIN
            or record.creation_command != _COMMAND or record.creator_role is not Role.SCIENTIFIC_REVIEWER
            or record.validation_result != "PASS" or record.frozen is not True
            or record.mime_type != "application/json" or not 0 < record.size <= _MAX_BYTES):
        raise ScientificNumericAblationError("numeric authority metadata is not canonical")
    registry.verify(record.sha256, raise_on_error=True)
    raw = registry.get_bytes(record.sha256)
    value = ScientificNumericAblationAuthority.from_dict(safe_json_loads(raw, max_bytes=_MAX_BYTES, max_items=50_000))
    if (raw != value.canonical_bytes() or len(raw) != record.size
            or record.parent_artifacts != value.source_artifact_hashes):
        raise ScientificNumericAblationError("numeric authority bytes or direct parents differ")
    if any(_time(registry.get_metadata(digest).created_at) > _time(record.created_at)
           for digest in value.custody_artifact_hashes):
        raise ScientificNumericAblationError("numeric authority predates a custody source")
    return value


def _same_slot_selector(value, expected) -> bool:
    """Untrusted selectors detect occupied slots; they never grant authority.

    Recognize both legacy and native payloads. A malformed matching candidate
    is an occupied/conflicting slot, not an ignorable non-authority.
    """

    if type(value) is not dict:
        return False
    if value.get("authority_id") == expected.authority_id:
        return True
    intervention = value.get("intervention")
    obligation = (intervention.get("ablation_id") if type(intervention) is dict
                  else value.get("ablation_id"))
    states = value.get("state_bindings")
    result = states[0] if type(states) is list and states and type(states[0]) is dict else {}
    return (value.get("ledger_run_id") == expected.ledger_run_id
            and value.get("execution_run_id") == expected.execution_run_id
            and value.get("contract_artifact_sha256") == expected.contract_artifact_sha256
            and obligation == expected.intervention.ablation_id
            and result.get("artifact_sha256") == expected.state_bindings[0].artifact_sha256)


def _matching_slots(registry: ArtifactRegistry, snapshot, expected) -> tuple[ArtifactRecord, ...]:
    matches = []
    for record in snapshot.records:
        if record.logical_type != _LOGICAL_TYPE:
            continue
        # One common bounded selector pass includes v1/v2. An undecodable
        # family member cannot be proven unrelated and fails closed. This is
        # custody/slot checking, not full replay of unrelated source owners.
        value = safe_json_loads(registry.get_bytes(record.sha256), max_bytes=_MAX_BYTES, max_items=50_000)
        if _same_slot_selector(value, expected):
            if _read_native_record(registry, record) != expected:
                raise ScientificNumericAblationError("numeric authority semantic slot contains another outcome or profile")
            matches.append(record)
    if len(matches) > 1:
        raise ScientificNumericAblationError("numeric authority semantic slot is ambiguous")
    return tuple(matches)


def _source_arguments(receipt) -> dict[str, str]:
    return {
        "expected_ledger_run_id": receipt.ledger_run_id,
        "expected_execution_run_id": receipt.execution_run_id,
        "expected_ablation_id": receipt.intervention.ablation_id,
        **{f"{kind}_state_artifact_sha256": binding.artifact_sha256
           for kind, binding in zip(("result", "run", "method", "experiment"), receipt.state_bindings, strict=True)},
    }


def require_scientific_numeric_ablation_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_ablation_id: str,
    authority_artifact_sha256: str,
):
    """Reopen one source-owned descriptive authority at a stable live pair."""

    for value in (expected_ledger_run_id, expected_execution_run_id, expected_ablation_id):
        if type(value) is not str:
            raise ScientificNumericAblationError("numeric authority expected IDs require native text")
        validate_identifier(value, "numeric authority expected ID")
    if type(authority_artifact_sha256) is not str:
        raise ScientificNumericAblationError("numeric authority hash requires native text")
    validate_sha256(authority_artifact_sha256, "numeric authority hash")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    record = registry.get_metadata(authority_artifact_sha256)
    receipt = _read_native_record(registry, record)
    if (receipt.ledger_run_id != expected_ledger_run_id or receipt.execution_run_id != expected_execution_run_id
            or receipt.intervention.ablation_id != expected_ablation_id):
        raise ScientificNumericAblationError("numeric authority selector names another run or obligation")
    expected = build_scientific_numeric_ablation_authority(registry, ledger, **_source_arguments(receipt))
    if receipt != expected or _matching_slots(registry, before[0], expected) != (record,):
        raise ScientificNumericAblationError("numeric authority differs from full fresh source replay")
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificNumericAblationError("numeric authority sources changed during readback; retry")
    return receipt


def _preflight_publication(registry: ArtifactRegistry, snapshot, receipt, *, created_at: str):
    """Pure byte/metadata capacity and slot preflight; no DTO is a grant."""

    raw = receipt.canonical_bytes()
    if not 0 < len(raw) <= _MAX_BYTES:
        raise ScientificNumericAblationError("numeric authority exceeds byte capacity")
    # Count/depth limits must be checked on the bytes that will be persisted,
    # not merely on an independently constructed Python mapping.
    safe_json_loads(raw, max_bytes=_MAX_BYTES, max_items=50_000)
    digest = hashlib.sha256(raw).hexdigest()
    matches = _matching_slots(registry, snapshot, receipt)
    existing = matches[0] if matches else None
    collision = next((item for item in snapshot.records if item.sha256 == digest), None)
    if collision != existing or (existing is not None and registry.get_bytes(digest) != raw):
        raise ScientificNumericAblationError("numeric authority bytes occupy another metadata identity")
    if snapshot.count + int(existing is None) > MAX_REGISTRY_RECORDS:
        raise ScientificNumericAblationError("numeric authority exceeds registry capacity")
    timestamp = existing.created_at if existing is not None else created_at
    if any(_time(registry.get_metadata(source).created_at) > _time(timestamp)
           for source in receipt.custody_artifact_hashes):
        raise ScientificNumericAblationError("numeric authority would predate a custody source")
    # Exact actual registry paths and metadata validated before its first write.
    planned = ArtifactRecord(
        sha256=digest, path=registry._object_relative(digest).as_posix(),
        relative_path=registry._object_relative(digest).as_posix(),
        metadata_path=registry._metadata_relative(digest).as_posix(),
        logical_type=_LOGICAL_TYPE, schema_version=_METADATA_SCHEMA, mime_type="application/json",
        size=len(raw), origin=_ORIGIN, creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_COMMAND, parent_artifacts=receipt.source_artifact_hashes,
        validation_result="PASS", frozen=True, created_at=timestamp,
    )
    if existing is not None and existing != planned:
        raise ScientificNumericAblationError("numeric authority idempotent metadata differs")
    return raw, existing, planned


def register_scientific_numeric_ablation_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_ablation_id: str,
    result_state_artifact_sha256: str,
    run_state_artifact_sha256: str,
    method_state_artifact_sha256: str,
    experiment_state_artifact_sha256: str,
) -> ArtifactRecord:
    """Source replay then paired compare-and-swap; registry-only publication."""

    before = _locked_checked_result_authority_snapshot(registry, ledger)
    receipt = build_scientific_numeric_ablation_authority(
        registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id, expected_ablation_id=expected_ablation_id,
        result_state_artifact_sha256=result_state_artifact_sha256,
        run_state_artifact_sha256=run_state_artifact_sha256,
        method_state_artifact_sha256=method_state_artifact_sha256,
        experiment_state_artifact_sha256=experiment_state_artifact_sha256,
    )
    raw, existing, planned = _preflight_publication(registry, before[0], receipt, created_at=utc_now())
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(registry_guard, raise_on_error=True)
            locked_ledger = ledger._validate_bytes(ledger._read_raw_locked(ledger_guard))
            if (locked_registry, locked_ledger) != before or not locked_ledger.valid:
                raise ScientificNumericAblationError("numeric authority sources changed before commit; retry")
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
                raise ScientificNumericAblationError("numeric authority commit produced an unexpected source delta")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    if require_scientific_numeric_ablation_authority(
        registry, ledger, expected_ledger_run_id=receipt.ledger_run_id,
        expected_execution_run_id=receipt.execution_run_id, expected_ablation_id=receipt.intervention.ablation_id,
        authority_artifact_sha256=record.sha256,
    ) != receipt:
        raise ScientificNumericAblationError("numeric authority publication differs from full readback")
    if _locked_checked_result_authority_snapshot(registry, ledger) != (after_registry, after_ledger):
        raise ScientificNumericAblationError("numeric authority sources changed after commit; retry")
    return record
