"""Prospective numeric-ablation policy replay, without execution authority.

The existing frozen spec owns the declaration. Its existing Method,
statistical-use, Dataset and configuration owners supply provenance; this
module creates no artifact, event, signature or alternative source of truth.
Before execution it inspects identities, Dataset shape/class closure, fixed
coefficients and bounded work counts. Dataset labels are read to validate the
frozen model class closure, never to select the policy/features or compute
held-out predictions, accuracy or effects; no row labels leave this binding.

The declared feature group is an operational intervention, not proof that it
implements the scientific meaning of a named Method component. Executed
numeric outputs, canonical ablations and complete scientific coverage require
separate downstream replay. A returned prospective binding is not that replay.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from .artifacts import ArtifactRecord, ArtifactRegistry
from .errors import ValidationError
from .generic_ml_ablation import (
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS,
    GenericMLFeatureIntervention,
    _require_grid_capacity,
)
from .generic_ml_projection import (
    GenericMLReferenceWork,
    parse_bounded_integer_classification_dataset,
    parse_frozen_model_configuration,
)
from .models import thaw_json, validate_identifier, validate_sha256

if TYPE_CHECKING:
    from .experiments import (
        FrozenRunSpec,
        ScientificMethodDefinitionBinding,
        ScientificReferenceWorkBinding,
    )


SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY = "scientific_numeric_ablation_policy"
GENERIC_ML_ABLATION_POLICY_SCHEMA = "generic-ml-feature-intervention-policy/v1"
# Bounds declaration parsing and later one-output/one-activity-per-intervention
# state. This headroom is NOT an exact future parent/JSON/closure preflight.
MAX_GENERIC_ML_NUMERIC_ABLATIONS = 64


class ScientificNumericAblationError(ValidationError):
    """The prospective declaration or its freshly reopened sources differ."""


def _identifier(value: object, label: str) -> str:
    if type(value) is not str:
        raise ScientificNumericAblationError(f"{label} requires native identifier text")
    return validate_identifier(value, label)


@dataclass(frozen=True, slots=True)
class GenericMLAblationPolicy:
    """A closed inert declaration; no execution or scientific adequacy claim."""

    method_id: str
    metric_id: str
    interventions: tuple[GenericMLFeatureIntervention, ...]
    schema_version: str = GENERIC_ML_ABLATION_POLICY_SCHEMA
    scope: str = GENERIC_ML_FEATURE_INTERVENTION_SCOPE

    def __post_init__(self) -> None:
        if type(self) is not GenericMLAblationPolicy:
            raise ScientificNumericAblationError("policy requires its exact native DTO type")
        _identifier(self.method_id, "method_id")
        _identifier(self.metric_id, "metric_id")
        for value, expected in (
            (self.schema_version, GENERIC_ML_ABLATION_POLICY_SCHEMA),
            (self.scope, GENERIC_ML_FEATURE_INTERVENTION_SCOPE),
        ):
            if type(value) is not str or value != expected:
                raise ScientificNumericAblationError("unsupported exact numeric ablation profile")
        if (type(self.interventions) is not tuple
                or not 1 <= len(self.interventions) <= MAX_GENERIC_ML_NUMERIC_ABLATIONS
                or any(type(item) is not GenericMLFeatureIntervention for item in self.interventions)):
            raise ScientificNumericAblationError("policy requires a bounded native intervention tuple")
        # Native leaves are revalidated and result-owned, including when a
        # caller later mutates a nominally frozen input via object.__setattr__.
        owned = tuple(replace(item) for item in self.interventions)
        if len({item.ablation_id for item in owned}) != len(owned):
            raise ScientificNumericAblationError("policy ablation IDs are duplicated")
        if len({item.intervention_condition_id for item in owned}) != len(owned):
            raise ScientificNumericAblationError("policy intervention conditions are duplicated")
        object.__setattr__(self, "interventions", owned)

    def to_dict(self) -> dict[str, object]:
        if type(self) is not GenericMLAblationPolicy:
            raise ScientificNumericAblationError("policy codec requires its exact native DTO type")
        owned = replace(self)
        return {
            "schema_version": owned.schema_version,
            "scope": owned.scope,
            "method_id": owned.method_id,
            "metric_id": owned.metric_id,
            "interventions": [item.to_dict() for item in owned.interventions],
        }

    @classmethod
    def from_dict(cls, value: object) -> GenericMLAblationPolicy:
        if (cls is not GenericMLAblationPolicy or type(value) is not dict
                or len(value) != 5 or any(type(key) is not str for key in value)
                or set(value) != {"schema_version", "scope", "method_id", "metric_id", "interventions"}):
            raise ScientificNumericAblationError("numeric ablation policy codec is not closed and native")
        declarations = value["interventions"]
        if (type(declarations) is not list
                or not 1 <= len(declarations) <= MAX_GENERIC_ML_NUMERIC_ABLATIONS):
            raise ScientificNumericAblationError("policy codec requires a bounded native intervention list")
        return cls(
            method_id=value["method_id"], metric_id=value["metric_id"],
            schema_version=value["schema_version"], scope=value["scope"],
            interventions=tuple(GenericMLFeatureIntervention.from_dict(item) for item in declarations),
        )


def _require_policy_context(
    policy: GenericMLAblationPolicy,
    *,
    required_ablation_ids: tuple[str, ...],
    hypothesis_id: str,
    method_id: str,
    method_component_ids: tuple[str, ...],
    metric_id: str,
    candidate_condition_id: str,
    baseline_condition_id: str,
) -> None:
    """Pure exact joins; supplied values alone provide no source authority."""

    if type(policy) is not GenericMLAblationPolicy:
        raise ScientificNumericAblationError("policy context requires its exact native DTO")
    owned = replace(policy)
    for label, value in (
        ("hypothesis_id", hypothesis_id), ("method_id", method_id),
        ("metric_id", metric_id), ("candidate condition", candidate_condition_id),
        ("baseline condition", baseline_condition_id),
    ):
        _identifier(value, label)
    for label, values, maximum in (
        ("required ablations", required_ablation_ids, MAX_GENERIC_ML_NUMERIC_ABLATIONS),
        ("Method components", method_component_ids, 1256),
    ):
        if type(values) is not tuple or not 1 <= len(values) <= maximum:
            raise ScientificNumericAblationError(f"{label} requires a bounded native tuple")
        for value in values:
            _identifier(value, label)
        if len(set(values)) != len(values):
            raise ScientificNumericAblationError(f"{label} is duplicated")
    if (owned.method_id != method_id or owned.metric_id != metric_id
            or tuple(item.ablation_id for item in owned.interventions) != required_ablation_ids
            or any(
                item.hypothesis_id != hypothesis_id
                or item.component_id not in method_component_ids
                or item.candidate_condition_id != candidate_condition_id
                or item.baseline_condition_id != baseline_condition_id
                for item in owned.interventions
            )):
        raise ScientificNumericAblationError("policy differs from the complete frozen Method/ablation context")


def _joint_reference_products(work: GenericMLReferenceWork, ablation_count: int) -> int:
    """Budget the actual three-grid pure replay across ALL declarations."""

    if (type(work) is not GenericMLReferenceWork or type(ablation_count) is not int
            or not 1 <= ablation_count <= MAX_GENERIC_ML_NUMERIC_ABLATIONS):
        raise ScientificNumericAblationError("joint work requires exact bounded native inputs")
    work = replace(work)
    per_intervention = _require_grid_capacity(
        work.unit_count, work.seed_count, work.class_count, work.feature_count,
    )
    products = ablation_count * per_intervention
    if products > MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS:
        raise ScientificNumericAblationError("complete ablation set exceeds joint reference-product capacity")
    return products


@dataclass(frozen=True, slots=True)
class ScientificNumericAblationBinding:
    """Ephemeral full-source output, never an independently issued authority.

    Call the resolver afresh; a constructed companion cannot prove provenance.
    Coefficient-change counts describe fixed inputs, not held-out outcomes.
    """

    policy: GenericMLAblationPolicy
    reference_binding: ScientificReferenceWorkBinding
    method_binding: ScientificMethodDefinitionBinding
    method_record: ArtifactRecord
    joint_reference_products: int
    changed_coefficient_counts: tuple[tuple[int, ...], ...]

    @property
    def source_records(self) -> tuple[ArtifactRecord, ...]:
        records = (*self.reference_binding.source_records, self.method_record)
        by_hash = {record.sha256: record for record in records}
        if any(by_hash[record.sha256] != record for record in records):
            raise ScientificNumericAblationError("prospective ablation sources have conflicting identities")
        return tuple(by_hash.values())


def resolve_scientific_numeric_ablation_binding(
    registry: ArtifactRegistry,
    *,
    spec: FrozenRunSpec,
    expected_contract_artifact_sha256: str,
) -> ScientificNumericAblationBinding | None:
    """Replay only prospective sources, without future execution backedges.

    Absence preserves legacy specs or an empty reference-profile obligation
    set, not permission to use producer PASS as numeric evidence. A fixed-model
    run requiring ablations must freeze this policy; it cannot add one after
    results. Malformed presence cannot downgrade to absence.
    Exact output/parent/activity/JSON budgets remain the responsibility of the
    later execution and authority publication paths, before their first write.
    """

    from .experiments import (
        FrozenRunSpec,
        SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY,
        ScientificMethodDefinitionBinding,
        ScientificReferenceWorkBinding,
        _locked_scientific_execution_snapshot,
        _require_scientific_execution_snapshot_unchanged,
        _scientific_statistical_use_context,
        resolve_scientific_method_definition_binding,
        resolve_scientific_reference_work_binding,
    )
    from .scientific_design import require_frozen_evaluation_contract

    if type(registry) is not ArtifactRegistry or type(spec) is not FrozenRunSpec:
        raise ScientificNumericAblationError("numeric ablation binding requires exact registry and spec")
    metadata = thaw_json(spec.metadata)
    if SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY not in metadata:
        if SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY in metadata and spec.required_ablations:
            raise ScientificNumericAblationError("fixed-model required ablations lack their prospective numeric policy")
        return None
    policy = GenericMLAblationPolicy.from_dict(metadata[SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY])
    validate_sha256(expected_contract_artifact_sha256, "numeric ablation contract SHA-256")
    context = _scientific_statistical_use_context(registry, spec)
    if context is None:
        raise ScientificNumericAblationError("numeric ablation policy requires prospective statistical use")
    ledger, run_id, _statistical_sha, _statistical_record = context
    before = _locked_scientific_execution_snapshot(registry, ledger, run_id)
    reference = resolve_scientific_reference_work_binding(
        registry, spec=spec, expected_contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    if type(reference) is not ScientificReferenceWorkBinding:
        raise ScientificNumericAblationError("numeric ablation policy requires the complete reference-work owner")
    method = resolve_scientific_method_definition_binding(registry, spec=spec)
    if type(method) is not ScientificMethodDefinitionBinding:
        raise ScientificNumericAblationError("numeric ablation policy requires the complete Method-definition owner")
    contract = require_frozen_evaluation_contract(
        registry, contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    method_record = registry.get_metadata(method.method_definition_artifact_sha256)
    if (reference.run_id != run_id or reference.execution_run_id != spec.run_id
            or reference.frozen_run_spec_sha256 != spec.sha256
            or reference.contract_record != registry.get_metadata(expected_contract_artifact_sha256)
            or method_record.record_hash != method.method_definition_record_hash):
        raise ScientificNumericAblationError("numeric ablation prospective source identity changed")
    if any(item.required and item.hypothesis_id != spec.hypothesis_id for item in contract.ablations):
        raise ScientificNumericAblationError("fixed-model numeric profile cannot omit foreign required ablations")
    required = tuple(
        item.ablation_id for item in contract.ablations
        if item.required and item.hypothesis_id == spec.hypothesis_id
    )
    if spec.required_ablations != required:
        raise ScientificNumericAblationError("spec differs from the complete required hypothesis ablation set")
    baselines = tuple(
        item for item in contract.baseline_registry.entries
        if item.status.value not in {"CONTEXT_ONLY", "INCOMPATIBLE"}
    )
    if len(baselines) != 1:
        raise ScientificNumericAblationError("numeric ablation policy requires exactly one full comparator")
    _require_policy_context(
        policy, required_ablation_ids=required, hypothesis_id=spec.hypothesis_id,
        method_id=method.method_id, method_component_ids=method.component_ids,
        metric_id=contract.primary_metric.metric_id, candidate_condition_id=spec.experiment_id,
        baseline_condition_id=baselines[0].baseline_id,
    )
    joint_products = _joint_reference_products(reference.reference_work, len(policy.interventions))
    # The existing parser owns full Dataset/model class and parameter closure.
    # It does not run inference. Do not call derive_generic_ml_ablation_grid here.
    rows = parse_bounded_integer_classification_dataset(registry.get_bytes(reference.raw_data_record.sha256))
    models = parse_frozen_model_configuration(
        registry.get_bytes(reference.input_records[2].sha256),
        contract_artifact_sha256=expected_contract_artifact_sha256, contract_sha256=contract.sha256,
        dataset_id=contract.dataset.dataset_id, dataset_split_id=contract.dataset.confirmatory_split_id,
        evaluator_id=contract.candidate_conditions.evaluator, metric_id=contract.primary_metric.metric_id,
        metric_unit=contract.primary_metric.unit.value, metric_scope=contract.primary_metric.scope.value,
        executed_baseline_ids=(baselines[0].baseline_id,), seed_order=spec.seeds,
        candidate_condition_id=spec.experiment_id, baseline_condition_id=baselines[0].baseline_id,
        expected_class_labels=tuple(sorted({row.label for row in rows})), feature_count=len(rows[0].features),
    )
    changed_counts = []
    for intervention in policy.interventions:
        if intervention.feature_indices[-1] >= reference.reference_work.feature_count:
            raise ScientificNumericAblationError("declared feature lies outside the complete model shape")
        per_seed = tuple(
            sum(weights[index] != 0 for weights in candidate.weights for index in intervention.feature_indices)
            for candidate, _baseline in models
        )
        if not any(per_seed):
            raise ScientificNumericAblationError("whole declared seed grid is a coefficient no-op")
        changed_counts.append(per_seed)
    binding = ScientificNumericAblationBinding(
        policy=policy, reference_binding=reference, method_binding=method, method_record=method_record,
        joint_reference_products=joint_products, changed_coefficient_counts=tuple(changed_counts),
    )
    binding.source_records  # Check exact deduplication before returning full-source facts.
    _require_scientific_execution_snapshot_unchanged(registry, ledger, run_id, *before)
    return binding
