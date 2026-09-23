"""Fresh downstream replay of the complete declared numeric intervention set.

This companion issues nothing. Existing execution, projection/domain and
prospective owners supply authority; the pure operator supplies the exact
prediction relation. Call this owner afresh, never accept a constructed DTO
as evidence. It belongs after full Generic-ML projection and before Result
admission, never inside a prospective or projection source resolver.

Successful replay establishes that the authenticated observed output bytes
equal the declared weight-zeroing operation over the complete frozen grid.
It does not establish producer internals, meaningful component removal,
mechanistic adequacy, inferential significance or scientific PASS.
"""

from __future__ import annotations

from dataclasses import dataclass

from .artifacts import ArtifactRecord, ArtifactRegistry
from .experiments import (
    COMPLETE_GENERIC_ML_ACTIVITY_PROFILE,
    FrozenRunSpec,
    OutputManifest,
    ScientificDatasetAccessPurpose,
    ScientificExecutionActivity,
    ScientificExecutionActivityKind,
    ScientificExecutionArtifactBinding,
    ScientificExecutionAuthority,
    _locked_scientific_execution_snapshot,
    _require_scientific_execution_snapshot_unchanged,
    require_scientific_execution_activity,
    require_scientific_execution_authority,
    require_scientific_execution_run_spec,
)
from .generic_ml_ablation import GenericMLAblationGrid, derive_generic_ml_ablation_grid
from .generic_ml_ablation_output import (
    GENERIC_ML_ABLATION_OUTPUT_SCHEMA,
    MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES,
    require_generic_ml_ablation_output,
)
from .generic_ml_projection import (
    GenericMLPairedMetricProjectionAuthority,
    parse_bounded_integer_classification_dataset,
    parse_frozen_model_configuration,
    require_generic_ml_paired_metric_projection_authority,
)
from .ledger import EventLedger
from .models import Role, validate_identifier, validate_sha256
from .scientific_numeric_ablation import (
    GenericMLAblationPolicy,
    ScientificNumericAblationBinding,
    ScientificNumericAblationError,
    resolve_scientific_numeric_ablation_binding,
)
from .security import safe_json_loads


@dataclass(frozen=True, slots=True)
class ScientificNumericAblationExecutionEntry:
    output_record: ArtifactRecord
    activity_sequence: int
    grid: GenericMLAblationGrid


@dataclass(frozen=True, slots=True)
class ScientificNumericAblationExecutionBinding:
    """Ephemeral replay result; it is not an independently issued authority."""

    prospective_binding: ScientificNumericAblationBinding
    execution: ScientificExecutionAuthority
    projection: GenericMLPairedMetricProjectionAuthority
    spec: FrozenRunSpec
    execution_record: ArtifactRecord
    projection_record: ArtifactRecord
    spec_record: ArtifactRecord
    manifest_record: ArtifactRecord
    activity_record: ArtifactRecord
    entries: tuple[ScientificNumericAblationExecutionEntry, ...]
    source_records: tuple[ArtifactRecord, ...]


def _records_once(records: tuple[ArtifactRecord, ...]) -> tuple[ArtifactRecord, ...]:
    """Deterministic exact deduplication, not authority for supplied records."""

    if type(records) is not tuple or any(type(record) is not ArtifactRecord for record in records):
        raise ScientificNumericAblationError("numeric execution sources require exact native records")
    by_hash = {record.sha256: record for record in records}
    if any(by_hash[record.sha256] != record for record in records):
        raise ScientificNumericAblationError("numeric execution sources have conflicting record identities")
    return tuple(by_hash.values())


def _binding(record: ArtifactRecord) -> ScientificExecutionArtifactBinding:
    return ScientificExecutionArtifactBinding(record.sha256, record.record_hash)


def _require_complete_inventory(
    policy: GenericMLAblationPolicy,
    spec: FrozenRunSpec,
    manifest: OutputManifest,
    projection: GenericMLPairedMetricProjectionAuthority,
) -> None:
    """Pure complete ordered joins, without authenticating supplied DTOs."""

    if (type(policy) is not GenericMLAblationPolicy or type(spec) is not FrozenRunSpec
            or type(manifest) is not OutputManifest
            or type(projection) is not GenericMLPairedMetricProjectionAuthority):
        raise ScientificNumericAblationError("numeric inventory requires exact native DTOs")
    GenericMLAblationPolicy.__post_init__(policy)
    expected_ids = tuple(item.ablation_id for item in policy.interventions)
    if (spec.required_ablations != expected_ids
            or tuple(item.ablation_id for item in manifest.ablations) != expected_ids
            or any(item.status != "PASS" for item in manifest.ablations)
            or tuple(item.artifact_sha256 for item in manifest.ablations)
            != projection.ablation_output_artifact_sha256s
            or len(projection.ablation_output_record_hashes) != len(expected_ids)):
        raise ScientificNumericAblationError("numeric output inventory omits, reorders or substitutes an obligation")
    # The full projection owns the exact four domain outputs per seed. Join
    # its entire partition, not a caller-selected subset of PASS ablations.
    all_outputs = (*projection.domain_consumed_output_artifact_sha256s,
                   *projection.ablation_output_artifact_sha256s)
    if (len(projection.domain_consumed_output_artifact_sha256s) != 4 * len(spec.seeds)
            or len(set(all_outputs)) != len(all_outputs)
            or len(manifest.artifacts) != len(all_outputs)
            or {item.sha256 for item in manifest.artifacts} != set(all_outputs)):
        raise ScientificNumericAblationError("numeric execution differs from the complete domain/output partition")


def _require_ablation_activity(
    activity: ScientificExecutionActivity,
    policy: GenericMLAblationPolicy,
    *,
    input_records: tuple[ArtifactRecord, ...],
    output_records: tuple[ArtifactRecord, ...],
    dataset_record: ArtifactRecord,
    confirmatory_split_record: ArtifactRecord,
) -> tuple[int, ...]:
    """Pure exact action joins; full execution owns capture authenticity.

    Repeated truthful feature reads are allowed. Every intervention must
    follow one such read and have exactly one whole-grid producer. This
    helper does not independently interpret unrelated activity purposes.
    """

    if type(activity) is not ScientificExecutionActivity or type(policy) is not GenericMLAblationPolicy:
        raise ScientificNumericAblationError("numeric activity requires exact native DTOs")
    ScientificExecutionActivity.__post_init__(activity)
    GenericMLAblationPolicy.__post_init__(policy)
    if activity.capture_profile != COMPLETE_GENERIC_ML_ACTIVITY_PROFILE:
        raise ScientificNumericAblationError("numeric activity lacks exhaustive capture")
    _records_once((*input_records, *output_records, dataset_record, confirmatory_split_record))
    expected_inputs = tuple(_binding(record) for record in input_records)
    features = []
    producers = []
    for row in activity.activity_rows:
        if row.dataset_access_purpose is ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS:
            raise ScientificNumericAblationError("numeric backend activity accessed confirmatory labels")
        if row.dataset_access_purpose is ScientificDatasetAccessPurpose.CONFIRMATORY_FEATURES:
            if (row.kind is not ScientificExecutionActivityKind.DATASET_READ
                    or row.dataset_artifact_binding != _binding(dataset_record)
                    or row.split_artifact_binding != _binding(confirmatory_split_record)
                    or row.seed is not None or row.condition_id is not None or row.ablation_id is not None
                    or row.input_artifact_bindings or row.output_artifact_bindings):
                raise ScientificNumericAblationError("numeric feature access has a substituted source or action shape")
            features.append(row.sequence)
        if row.kind is ScientificExecutionActivityKind.ABLATION_EXECUTION:
            producers.append(row)
    if len(producers) != len(policy.interventions) or len(output_records) != len(policy.interventions):
        raise ScientificNumericAblationError("numeric activity lacks exactly one producer per intervention")
    by_id = {row.ablation_id: row for row in producers}
    if len(by_id) != len(producers) or set(by_id) != {item.ablation_id for item in policy.interventions}:
        raise ScientificNumericAblationError("numeric activity has duplicate or foreign ablation producers")
    sequences = []
    for intervention, record in zip(policy.interventions, output_records, strict=True):
        row = by_id[intervention.ablation_id]
        if (row.seed is not None or row.condition_id != intervention.intervention_condition_id
                or row.dataset_artifact_binding is not None or row.split_artifact_binding is not None
                or row.dataset_access_purpose is not None
                or row.input_artifact_bindings != expected_inputs
                or row.output_artifact_bindings != (_binding(record),)
                or not any(sequence < row.sequence for sequence in features)):
            raise ScientificNumericAblationError("numeric producer differs from its complete frozen inputs or feature chronology")
        sequences.append(row.sequence)
    return tuple(sequences)


def _require_grid_projection_join(
    grid: GenericMLAblationGrid,
    projection: GenericMLPairedMetricProjectionAuthority,
    changed_counts: tuple[int, ...],
) -> None:
    """Pure complete C/B correctness join; zero/reversed A effects are valid."""

    if type(grid) is not GenericMLAblationGrid or type(projection) is not GenericMLPairedMetricProjectionAuthority:
        raise ScientificNumericAblationError("numeric grid join requires exact native DTOs")
    GenericMLAblationGrid.__post_init__(grid)
    if (grid.seed_order != projection.seed_order or grid.unit_ids != projection.paired_unit_ids
            or grid.unit_hashes != projection.paired_unit_hashes or grid.reference_labels != projection.reference_labels
            or tuple(item.changed_coefficient_count for item in grid.seed_results) != changed_counts
            or len(projection.seed_projections) != len(grid.seed_results)):
        raise ScientificNumericAblationError("numeric grid differs from complete prospective/projection coordinates")
    for seed, paired in zip(grid.seed_results, projection.seed_projections, strict=True):
        if (seed.seed != paired.seed or paired.paired_unit_ids != grid.unit_ids
                or paired.paired_unit_hashes != grid.unit_hashes or paired.reference_labels != grid.reference_labels
                or paired.candidate_condition_id != grid.intervention.candidate_condition_id
                or paired.baseline_condition_id != grid.intervention.baseline_condition_id
                or paired.candidate_values != tuple(float(value == label) for value, label in
                                                    zip(seed.candidate_predictions, grid.reference_labels, strict=True))
                or paired.baseline_values != tuple(float(value == label) for value, label in
                                                   zip(seed.baseline_predictions, grid.reference_labels, strict=True))):
            raise ScientificNumericAblationError("numeric grid differs from the freshly owned paired correctness vectors")


def require_scientific_numeric_ablation_execution(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    generic_ml_projection_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    scientific_domain_evidence_source_artifact_sha256: str,
    expected_contract_artifact_sha256: str,
    expected_output_manifest_artifact_sha256: str,
) -> ScientificNumericAblationExecutionBinding:
    """Replay full existing owners and exact observed bytes without writing.

    SHA arguments are anti-substitution selectors, not grants. The ordinary
    registry integrity pass retains its existing per-object safety bound;
    the compact codec's 8 MiB bound describes accepted numeric output bytes,
    not a global allocation cap for earlier provenance verification.
    """

    from .scientific_design import require_frozen_evaluation_contract

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ScientificNumericAblationError("numeric execution requires exact registry and ledger")
    for label, value in (("ledger run", expected_ledger_run_id), ("execution run", expected_execution_run_id)):
        if type(value) is not str:
            raise ScientificNumericAblationError(f"{label} requires native text")
        validate_identifier(value, label)
    for value in (generic_ml_projection_artifact_sha256, scientific_execution_authority_artifact_sha256,
                  scientific_domain_evidence_source_artifact_sha256, expected_contract_artifact_sha256,
                  expected_output_manifest_artifact_sha256):
        if type(value) is not str:
            raise ScientificNumericAblationError("numeric execution selectors require native SHA-256 text")
        validate_sha256(value, "numeric execution selector")
    before = _locked_scientific_execution_snapshot(registry, ledger, expected_ledger_run_id)
    execution = require_scientific_execution_authority(
        registry, ledger, authority_artifact_sha256=scientific_execution_authority_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id, expected_execution_run_id=expected_execution_run_id,
    )
    spec = require_scientific_execution_run_spec(
        registry, frozen_run_spec_artifact_sha256=execution.frozen_run_spec_artifact_sha256,
    )
    prospective = resolve_scientific_numeric_ablation_binding(
        registry, spec=spec, expected_contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    if type(prospective) is not ScientificNumericAblationBinding:
        raise ScientificNumericAblationError("executed numeric ablations lack their full prospective policy/source owner")
    projection = require_generic_ml_paired_metric_projection_authority(
        registry, ledger, projection_artifact_sha256=generic_ml_projection_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id, expected_execution_run_id=expected_execution_run_id,
        expected_domain_evidence_source_artifact_sha256=scientific_domain_evidence_source_artifact_sha256,
        expected_contract_artifact_sha256=expected_contract_artifact_sha256,
        expected_output_manifest_artifact_sha256=expected_output_manifest_artifact_sha256,
    )
    execution_record = registry.get_metadata(scientific_execution_authority_artifact_sha256)
    projection_record = registry.get_metadata(generic_ml_projection_artifact_sha256)
    spec_record = registry.get_metadata(execution.frozen_run_spec_artifact_sha256)
    manifest_record = registry.get_metadata(expected_output_manifest_artifact_sha256)
    reference = prospective.reference_binding
    configuration_record, evaluator_record = reference.input_records[2:4]
    if (reference.run_id != expected_ledger_run_id or reference.execution_run_id != expected_execution_run_id
            or reference.frozen_run_spec_sha256 != spec.sha256
            or execution.output_manifest_artifact_sha256 != manifest_record.sha256
            or execution.output_manifest_record_hash != manifest_record.record_hash
            or projection.projection_record_hash != projection_record.record_hash
            or projection.scientific_execution_authority_artifact_sha256 != execution_record.sha256
            or projection.scientific_execution_authority_record_hash != execution_record.record_hash
            or projection.frozen_run_spec_artifact_sha256 != spec_record.sha256
            or projection.frozen_run_spec_record_hash != spec_record.record_hash
            or execution.frozen_run_spec_sha256 != spec.sha256
            or projection.output_manifest_record_hash != manifest_record.record_hash
            or projection.frozen_model_configuration_artifact_sha256 != configuration_record.sha256
            or projection.frozen_model_configuration_record_hash != configuration_record.record_hash
            or projection.evaluator_artifact_sha256 != evaluator_record.sha256
            or projection.evaluator_record_hash != evaluator_record.record_hash
            or projection.dataset_authority_artifact_sha256 != reference.dataset_record.sha256
            or projection.dataset_authority_record_hash != reference.dataset_record.record_hash
            or projection.dataset_raw_artifact_sha256 != reference.raw_data_record.sha256
            or projection.dataset_raw_record_hash != reference.raw_data_record.record_hash
            or projection.evaluation_contract_record_hash != reference.contract_record.record_hash
            or len(projection.split_authority_artifact_sha256s) != 4
            or len(projection.split_authority_record_hashes) != 4
            or projection.split_authority_artifact_sha256s[3] != reference.confirmatory_split_record.sha256
            or projection.split_authority_record_hashes[3] != reference.confirmatory_split_record.record_hash
            or projection.seed_order != spec.seeds
            or execution.execution_activity_artifact_sha256 != projection.scientific_execution_activity_artifact_sha256
            or execution.execution_activity_record_hash != projection.scientific_execution_activity_record_hash):
        raise ScientificNumericAblationError("numeric execution/projection/prospective source identities differ")
    activity_record = registry.get_metadata(projection.scientific_execution_activity_artifact_sha256)
    if activity_record.record_hash != projection.scientific_execution_activity_record_hash:
        raise ScientificNumericAblationError("numeric activity record was substituted")
    activity = require_scientific_execution_activity(
        registry, activity_artifact_sha256=activity_record.sha256,
        expected_ledger_run_id=expected_ledger_run_id, expected_execution_run_id=expected_execution_run_id,
        expected_preparation_artifact_sha256=execution.preparation_artifact_sha256,
        expected_frozen_run_spec_artifact_sha256=spec_record.sha256,
        expected_output_manifest_artifact_sha256=manifest_record.sha256,
    )
    manifest = OutputManifest.from_mapping(safe_json_loads(registry.get_bytes(manifest_record.sha256)))
    _require_complete_inventory(prospective.policy, spec, manifest, projection)
    outputs = tuple(registry.get_metadata(digest) for digest in projection.ablation_output_artifact_sha256s)
    descriptors = {item.sha256: item for item in manifest.artifacts}
    execution_outputs = dict(zip(execution.output_artifact_sha256s, execution.output_artifact_record_hashes, strict=True))
    for record, expected_hash in zip(outputs, projection.ablation_output_record_hashes, strict=True):
        descriptor = descriptors[record.sha256]
        if (record.record_hash != expected_hash or execution_outputs.get(record.sha256) != expected_hash
                or descriptor.logical_type != "ablation_output" or descriptor.size != record.size
                or not 0 < record.size <= MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
                or record.logical_type != "experiment_output.ablation_output"
                or record.schema_version != GENERIC_ML_ABLATION_OUTPUT_SCHEMA or record.mime_type != "application/json"
                or record.creator_role is not Role.EXPERIMENT_RUNNER or record.validation_result != "PASS"
                or record.frozen is not True or record.parent_artifacts != (manifest_record.sha256, spec_record.sha256)):
            raise ScientificNumericAblationError("numeric output metadata differs from its exact execution/projection binding")
    model_bindings = tuple((item.seed, item.candidate_model_artifact_sha256, item.candidate_model_record_hash,
                            item.baseline_model_artifact_sha256, item.baseline_model_record_hash)
                           for item in projection.seed_projections)
    model_records = tuple(registry.get_metadata(digest) for item in model_bindings for digest in (item[1], item[3]))
    if tuple(record.record_hash for record in model_records) != tuple(value for item in model_bindings for value in (item[2], item[4])):
        raise ScientificNumericAblationError("numeric frozen model record identities differ")
    sequences = _require_ablation_activity(
        activity, prospective.policy,
        input_records=(reference.input_records[1], configuration_record, evaluator_record,
                       prospective.method_record, *model_records),
        output_records=outputs, dataset_record=reference.dataset_record,
        confirmatory_split_record=reference.confirmatory_split_record,
    )
    contract = require_frozen_evaluation_contract(registry, contract_artifact_sha256=expected_contract_artifact_sha256)
    raw_rows = parse_bounded_integer_classification_dataset(registry.get_bytes(reference.raw_data_record.sha256))
    by_id = {row.unit_id: row for row in raw_rows}
    try:
        rows = tuple(by_id[unit_id] for unit_id in reference.confirmatory_split_authority.member_unit_ids)
    except KeyError as exc:
        raise ScientificNumericAblationError("numeric confirmatory split names an absent raw row") from exc
    if (tuple(row.unit_id for row in rows) != projection.paired_unit_ids
            or tuple(row.unit_hash for row in rows) != projection.paired_unit_hashes
            or tuple(row.label for row in rows) != projection.reference_labels
            or tuple(row.unit_hash for row in rows) != reference.confirmatory_split_authority.member_unit_hashes):
        raise ScientificNumericAblationError("numeric split/raw/projection rows differ")
    baseline_id = prospective.policy.interventions[0].baseline_condition_id
    models = parse_frozen_model_configuration(
        registry.get_bytes(configuration_record.sha256),
        contract_artifact_sha256=expected_contract_artifact_sha256, contract_sha256=contract.sha256,
        dataset_id=contract.dataset.dataset_id, dataset_split_id=contract.dataset.confirmatory_split_id,
        evaluator_id=contract.candidate_conditions.evaluator, metric_id=contract.primary_metric.metric_id,
        metric_unit=contract.primary_metric.unit.value, metric_scope=contract.primary_metric.scope.value,
        executed_baseline_ids=(baseline_id,), seed_order=spec.seeds,
        candidate_condition_id=spec.experiment_id, baseline_condition_id=baseline_id,
        expected_class_labels=tuple(sorted({row.label for row in raw_rows})), feature_count=len(raw_rows[0].features),
    )
    entries = []
    for intervention, output, sequence, changed_counts in zip(
        prospective.policy.interventions, outputs, sequences, prospective.changed_coefficient_counts, strict=True,
    ):
        grid = derive_generic_ml_ablation_grid(
            intervention, model_pairs=models, rows=rows, expected_seed_order=spec.seeds,
            expected_unit_ids=projection.paired_unit_ids, expected_unit_hashes=projection.paired_unit_hashes,
        )
        _require_grid_projection_join(grid, projection, changed_counts)
        require_generic_ml_ablation_output(
            registry.get_bytes(output.sha256), grid, execution_run_id=spec.run_id,
            frozen_run_spec_artifact_sha256=spec_record.sha256, frozen_run_spec_record_hash=spec_record.record_hash,
            frozen_run_spec_sha256=spec.sha256, configuration_artifact_sha256=configuration_record.sha256,
            configuration_record_hash=configuration_record.record_hash, evaluator_artifact_sha256=evaluator_record.sha256,
            evaluator_record_hash=evaluator_record.record_hash,
            confirmatory_split_authority_artifact_sha256=reference.confirmatory_split_record.sha256,
            confirmatory_split_authority_record_hash=reference.confirmatory_split_record.record_hash,
            method_definition_artifact_sha256=prospective.method_record.sha256,
            method_definition_record_hash=prospective.method_record.record_hash,
            # Record hashes stay in full projection/activity replay. The
            # observed bytes precede the manifest that parents model records.
            seed_model_bindings=tuple((item[0], item[1], item[3]) for item in model_bindings),
        )
        entries.append(ScientificNumericAblationExecutionEntry(output, sequence, grid))
    if sum(item.grid.reference_product_count for item in entries) != prospective.joint_reference_products:
        raise ScientificNumericAblationError("complete numeric replay differs from the prospective joint work")
    source_records = _records_once((
        *prospective.source_records, execution_record, projection_record, spec_record, manifest_record, activity_record,
        *(registry.get_metadata(digest) for digest in projection_record.parent_artifacts), *model_records, *outputs,
    ))
    result = ScientificNumericAblationExecutionBinding(
        prospective, execution, projection, spec, execution_record, projection_record, spec_record,
        manifest_record, activity_record, tuple(entries), source_records,
    )
    _require_scientific_execution_snapshot_unchanged(registry, ledger, expected_ledger_run_id, *before)
    return result
