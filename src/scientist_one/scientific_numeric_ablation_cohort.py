"""Complete snapshot-owned numerical intervention coverage, not adequacy.

This read-only companion reuses the issued canonical snapshot and the existing
source owners. It issues no aggregate, approval or scientific PASS. In
particular, a complete cohort of descriptive feature interventions does not
establish that the frozen scientific questions were adequately ablated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactRecord, ArtifactRegistry
from .ledger import EventLedger
from .models import thaw_json, validate_identifier, validate_sha256
from .research_state import (
    Ablation, Dataset, Experiment, Implementation, Method, Metric,
    ResearchStateAuthorityBinding, ResearchStateAuthoritySnapshot, Result, Run,
    StatisticalTest,
)
from .scientific_numeric_ablation import ScientificNumericAblationError
from .scientific_numeric_ablation_authority_value import (
    SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA,
    ScientificNumericAblationAuthority,
)


NATIVE_ABLATION_COVERAGE_RULE = "NATIVE_FIXED_POLICY_ABLATION_COVERAGE_V1"
NATIVE_ABLATION_COVERAGE_RATIONALE = (
    "All required declared feature-weight interventions were replayed for the "
    "complete bound Result/Test cohort. Scientific adequacy for the research "
    "claims, semantic component removal, and general robustness remain untested."
)
_EVIDENCE_TYPES = frozenset({"Result", "StatisticalTest", "Ablation"})
# Closed initial computational scope, NOT a measured runtime/primitive-work
# ceiling. Full snapshot resolution also replays retained historical revisions
# and packages, so counting only S's selected current leaves is insufficient.
_RETAINED_HISTORY_LIMITS = (
    ("research_state.result", 32),
    ("research_state.statistical_test", 32),
    ("research_state.ablation", 64),
    ("research_state.reproducibility_package", 32),
)


def _preflight_cohort_history(
    records: tuple[ArtifactRecord, ...], state_hashes: tuple[str, ...],
) -> None:
    """Metadata-only rejection guard before expensive owners; never evidence."""

    if (type(records) is not tuple or len(records) > 10_000
            or any(type(item) is not ArtifactRecord for item in records)
            or type(state_hashes) is not tuple or not 0 < len(state_hashes) <= 256
            or any(type(item) is not str for item in state_hashes)
            or len(set(state_hashes)) != len(state_hashes)):
        raise ScientificNumericAblationError("numeric cohort selectors exceed their bounded shape")
    indexed = {item.sha256: item for item in records}
    if len(indexed) != len(records) or any(digest not in indexed for digest in state_hashes):
        raise ScientificNumericAblationError("numeric cohort snapshot selectors are absent or ambiguous")
    for logical_type, limit in _RETAINED_HISTORY_LIMITS:
        if sum(item.logical_type == logical_type for item in records) > limit:
            raise ScientificNumericAblationError(
                "numeric cohort retained history exceeds supported computational scope"
            )
    evidence_count = sum(indexed[digest].logical_type in {
        "research_state.result", "research_state.statistical_test", "research_state.ablation",
    } for digest in state_hashes)
    if evidence_count > 255:
        raise ScientificNumericAblationError("numeric cohort evidence plus snapshot exceeds parent capacity")


@dataclass(frozen=True, slots=True)
class _NumericCohortMember:
    """Structural joins only; constructing this object grants no authority."""

    result: ResearchStateAuthorityBinding
    statistical_test: ResearchStateAuthorityBinding
    run: ResearchStateAuthorityBinding
    experiment: ResearchStateAuthorityBinding
    implementation: ResearchStateAuthorityBinding
    method: ResearchStateAuthorityBinding
    dataset: ResearchStateAuthorityBinding
    metric: ResearchStateAuthorityBinding
    ablations: tuple[ResearchStateAuthorityBinding, ...]


@dataclass(frozen=True, slots=True)
class ScientificNumericAblationCohort:
    """Ephemeral full replay output, never independently issued authority."""

    state: ResearchStateAuthoritySnapshot
    snapshot_record: ArtifactRecord
    members: tuple[_NumericCohortMember, ...]
    ablation_authorities: tuple[ScientificNumericAblationAuthority, ...]
    evidence_hashes: tuple[str, ...]
    evidence_record_hashes: tuple[str, ...]
    entry_snapshot: Any

    @property
    def result_test_bindings(self) -> tuple[tuple[str, str], ...]:
        return tuple(sorted(
            (entry.artifact_sha256, entry.artifact_record_hash)
            for member in self.members
            for entry in (member.result, member.statistical_test)
        ))


def _cohort_inventory(
    state: ResearchStateAuthoritySnapshot,
) -> tuple[_NumericCohortMember, ...]:
    """Pure complete inventory, not authentication of a supplied snapshot DTO.

    No eligibility or outcome filter is permitted. Unsupported members refuse
    the complete route instead of silently reducing its reported population.
    """

    from .scientific_design import (
        SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4,
        SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4,
    )

    if (type(state) is not ResearchStateAuthoritySnapshot
            or not 0 < len(state.entries) <= 256
            or any(type(item) is not ResearchStateAuthorityBinding for item in state.entries)):
        raise ScientificNumericAblationError("numeric cohort requires a bounded exact snapshot")
    ResearchStateAuthoritySnapshot.__post_init__(state)

    def inventory(kind: type) -> tuple[ResearchStateAuthorityBinding, ...]:
        selected = tuple(sorted(
            (item for item in state.entries if item.research_object.object_type == kind.__name__),
            key=lambda item: item.artifact_sha256,
        ))
        if any(type(item.research_object) is not kind for item in selected):
            raise ScientificNumericAblationError("numeric cohort object type was substituted")
        return selected

    def parent(binding: ResearchStateAuthorityBinding, kind: type, relation: str):
        refs = tuple(item for item in binding.research_object.parents
                     if item.object_type == kind.__name__)
        if (len(refs) != 1 or refs[0].relation != relation or refs[0].evaluated is not True):
            raise ScientificNumericAblationError("numeric cohort lacks an exact evaluated parent")
        selected = state.object(kind.__name__, refs[0].object_id)
        if (type(selected.research_object) is not kind
                or selected.research_object.content_hash != refs[0].content_hash):
            raise ScientificNumericAblationError("numeric cohort parent revision was substituted")
        return selected

    results, tests, ablations = inventory(Result), inventory(StatisticalTest), inventory(Ablation)
    if not results or not tests:
        raise ScientificNumericAblationError("numeric cohort Result/Test coverage cannot be vacuous")
    if len(results) + len(tests) + len(ablations) > 255:
        raise ScientificNumericAblationError("numeric cohort evidence plus snapshot exceeds parent capacity")
    tests_by_result = {}
    for test in tests:
        result = parent(test, Result, "tests")
        if (len(test.research_object.parents) != 1
                or test.research_object.result_ids != (result.research_object.object_id,)
                or result.artifact_sha256 in tests_by_result):
            raise ScientificNumericAblationError("numeric cohort requires exactly one Test per Result")
        tests_by_result[result.artifact_sha256] = test
    if set(tests_by_result) != {item.artifact_sha256 for item in results}:
        raise ScientificNumericAblationError("numeric cohort has an uncovered or unrelated Result/Test")

    ablations_by_result: dict[str, list[ResearchStateAuthorityBinding]] = {}
    for ablation in ablations:
        value = ablation.research_object
        if thaw_json(value.metadata).get("schema_version") != SCIENTIFIC_NUMERIC_ABLATION_CANONICAL_SCHEMA:
            raise ScientificNumericAblationError("numeric cohort contains an unsupported Ablation")
        result = parent(ablation, Result, "evaluates")
        experiment = parent(ablation, Experiment, "ablates")
        run = parent(result, Run, "aggregates")
        actual_experiment = parent(run, Experiment, "executes")
        if (len(value.parents) != 2 or experiment != actual_experiment
                or value.result_ids != (result.research_object.object_id,)
                or value.experiment_ids != (experiment.research_object.object_id,)):
            raise ScientificNumericAblationError("numeric cohort Ablation was joined to another Result")
        ablations_by_result.setdefault(result.artifact_sha256, []).append(ablation)

    members = []
    for result in results:
        test = tests_by_result[result.artifact_sha256]
        if (thaw_json(result.research_object.metadata).get("schema_version")
                != SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4
                or thaw_json(test.research_object.metadata).get("schema_version")
                != SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4):
            raise ScientificNumericAblationError("numeric cohort Result/Test profile is unsupported")
        run = parent(result, Run, "aggregates")
        metric = parent(result, Metric, "reports")
        experiment = parent(run, Experiment, "executes")
        implementation = parent(experiment, Implementation, "uses")
        method = parent(implementation, Method, "implements")
        dataset = parent(experiment, Dataset, "uses")
        if (len(result.research_object.parents) != 2
                or result.research_object.run_ids != (run.research_object.object_id,)
                or result.research_object.metric_id != metric.research_object.object_id
                or len(run.research_object.parents) != 1
                or run.research_object.experiment_id != experiment.research_object.object_id
                or run.research_object.dataset_ids != (dataset.research_object.object_id,)
                or experiment.research_object.dataset_ids != run.research_object.dataset_ids
                or experiment.research_object.implementation_id != implementation.research_object.object_id
                or len(implementation.research_object.parents) != 1
                or implementation.research_object.method_id != method.research_object.object_id):
            raise ScientificNumericAblationError("numeric cohort execution ancestry was substituted")
        members.append(_NumericCohortMember(
            result, test, run, experiment, implementation, method, dataset, metric,
            tuple(ablations_by_result.get(result.artifact_sha256, ())),
        ))
    return tuple(members)


def _require_complete_observations(
    member: _NumericCohortMember,
    numeric: Any,
    receipts: tuple[ScientificNumericAblationAuthority, ...],
) -> None:
    """Pure bijection from full replay companions, with no effect filtering."""

    from .scientific_numeric_ablation_execution import ScientificNumericAblationExecutionBinding

    if (type(member) is not _NumericCohortMember
            or type(numeric) is not ScientificNumericAblationExecutionBinding
            or type(receipts) is not tuple
            or any(type(item) is not ScientificNumericAblationAuthority for item in receipts)):
        raise ScientificNumericAblationError("numeric cohort coverage requires exact replay companions")
    required = tuple(item.ablation_id for item in numeric.prospective_binding.policy.interventions)
    observed = tuple(item.intervention.ablation_id for item in receipts)
    if (not required or len(set(required)) != len(required)
            or len(observed) != len(required) or set(observed) != set(required)
            or len(member.ablations) != len(required)):
        raise ScientificNumericAblationError("numeric cohort omits or duplicates required interventions")
    sources = {entry.grid.intervention.ablation_id: entry for entry in numeric.entries}
    if set(sources) != set(required) or len(sources) != len(numeric.entries):
        raise ScientificNumericAblationError("numeric cohort numeric inventory differs from frozen policy")
    for ablation, receipt in zip(member.ablations, receipts, strict=True):
        ScientificNumericAblationAuthority.__post_init__(receipt)
        entry = sources[receipt.intervention.ablation_id]
        expected_state = (member.result, member.run, member.method, member.experiment)
        if (receipt.execution_run_id != member.run.research_object.object_id
                or receipt.contract_artifact_sha256 != numeric.prospective_binding.reference_binding.contract_record.sha256
                or receipt.contract_record_hash != numeric.prospective_binding.reference_binding.contract_record.record_hash
                or receipt.execution_artifact_sha256 != numeric.execution_record.sha256
                or receipt.execution_record_hash != numeric.execution_record.record_hash
                or receipt.projection_artifact_sha256 != numeric.projection_record.sha256
                or receipt.projection_record_hash != numeric.projection_record.record_hash
                or receipt.ablation_output_artifact_sha256 != entry.output_record.sha256
                or receipt.ablation_output_record_hash != entry.output_record.record_hash
                or receipt.intervention != entry.grid.intervention
                or receipt.activity_sequence != entry.activity_sequence
                or receipt.unit_count != len(entry.grid.unit_counts)
                or receipt.seed_order != entry.grid.seed_order
                or receipt.changed_coefficient_counts != tuple(
                    item.changed_coefficient_count for item in entry.grid.seed_results)
                or receipt.candidate_correct_total != sum(
                    item.candidate_correct_count for item in entry.grid.unit_counts)
                or receipt.baseline_correct_total != sum(
                    item.baseline_correct_count for item in entry.grid.unit_counts)
                or receipt.ablated_correct_total != sum(
                    item.ablated_correct_count for item in entry.grid.unit_counts)
                or receipt.metric_id != member.metric.research_object.object_id
                or ablation.research_object.object_id != receipt.canonical_object_id
                or thaw_json(ablation.research_object.metadata) != receipt.canonical_metadata()
                or ablation.scientific_evidence_eligible is not False):
            raise ScientificNumericAblationError("numeric cohort observation source or projection was substituted")
        for binding, expected in zip(receipt.state_bindings, expected_state, strict=True):
            if (binding.artifact_sha256 != expected.artifact_sha256
                    or binding.artifact_record_hash != expected.artifact_record_hash
                    or binding.object_type != expected.research_object.object_type
                    or binding.object_id != expected.research_object.object_id
                    or binding.content_hash != expected.research_object.content_hash
                    or binding.revision != expected.research_object.revision
                    or binding.materialization_event_id != expected.materialization_event_id
                    or binding.materialization_event_hash != expected.materialization_event_hash
                    or binding.materialization_event_index != expected.materialization_event_index):
                raise ScientificNumericAblationError("numeric cohort observation names another canonical revision")


def require_scientific_numeric_ablation_cohort(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    snapshot_artifact_sha256: str,
    require_whole_current: bool = False,
) -> ScientificNumericAblationCohort:
    """Replay every Result/Test/required native intervention in one issued S.

    Registration must request whole-current proof; immutable readback reopens
    the entire bound snapshot plus the audit-free current scientific-core
    drift check. The snapshot decoder is only a selector. This path never
    enters a Challenger audit, Soundness, R5 or an audit-cohort source owner.
    """

    from .gates import _require_bound_snapshot_no_post_snapshot_core_drift
    from .research_state import (
        _read_canonical_research_state_snapshot,
        _require_research_state_snapshot_issuance,
        resolve_bound_research_state_authority, resolve_research_state_authority,
    )
    from .scientific_design import (
        SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
        ScientificResultCanonicalProjectionV4,
        _locked_checked_result_authority_snapshot, _projection_source_artifact_sha256,
        require_scientific_result_canonical_projection_v3,
        require_scientific_result_promotion_authority_v3,
    )
    from .scientific_numeric_ablation_authority import (
        _require_primary_grid_join, require_scientific_numeric_ablation_authority,
    )
    from .scientific_numeric_ablation_execution import require_scientific_numeric_ablation_execution

    if (type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger
            or type(require_whole_current) is not bool
            or type(expected_ledger_run_id) is not str or type(snapshot_artifact_sha256) is not str):
        raise ScientificNumericAblationError("numeric cohort requires exact runtime and selectors")
    validate_identifier(expected_ledger_run_id, "numeric cohort ledger run")
    validate_sha256(snapshot_artifact_sha256, "numeric cohort snapshot")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    snapshot_record, state_hashes, _, value = _read_canonical_research_state_snapshot(
        registry, snapshot_artifact_sha256,
    )
    if snapshot_record.logical_type != "canonical_research_state_snapshot":
        raise ScientificNumericAblationError("numeric cohort requires an ordinary issued snapshot")
    issuance_index, issuance_event = _require_research_state_snapshot_issuance(
        before[1], snapshot_record=snapshot_record, snapshot_value=value,
    )
    _preflight_cohort_history(tuple(registry.list_records()), state_hashes)
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificNumericAblationError("numeric cohort sources changed during selector preflight")
    if require_whole_current:
        state = resolve_research_state_authority(
            registry, ledger, run_id=expected_ledger_run_id,
            snapshot_artifact_hash=snapshot_artifact_sha256,
        )
    else:
        state = resolve_bound_research_state_authority(
            registry, ledger, run_id=expected_ledger_run_id,
            snapshot_artifact_hash=snapshot_artifact_sha256, state_artifact_hashes=state_hashes,
            ledger_head_hash=issuance_event.event_hash, ledger_event_count=issuance_index + 1,
            expected_code_version=value["repository_code_version"],
            expected_configuration_hash=value["repository_configuration_hash"],
        )
    _require_bound_snapshot_no_post_snapshot_core_drift(registry, ledger, state=state)
    members = _cohort_inventory(state)
    authorities = []
    for member in members:
        result, test, run = (item.research_object for item in (
            member.result, member.statistical_test, member.run,
        ))
        records = tuple(registry.get_metadata(digest) for digest in result.evaluation_artifact_hashes)
        promotions = tuple(record for record in records
                           if record.logical_type == SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3)
        if (len(promotions) != 1 or member.result.scientific_evidence_eligible is not True
                or member.statistical_test.scientific_evidence_eligible is not True):
            raise ScientificNumericAblationError("numeric cohort contains an unsupported scientific Result/Test")
        promotion = promotions[0]
        selectors = dict(
            promotion_receipt_artifact_sha256=promotion.sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=run.object_id, expected_result_id=result.object_id,
        )
        resolution = require_scientific_result_promotion_authority_v3(registry, ledger, **selectors)
        primary = require_scientific_result_canonical_projection_v3(
            registry, ledger, **selectors, canonical_state_code_version=state.code_version,
        )
        if (type(primary) is not ScientificResultCanonicalProjectionV4
                or resolution.scientific_evidence_eligible is not True
                or not resolution.assessment.is_bounded_mean
                or thaw_json(result.metadata) != primary.state_metadata
                or thaw_json(test.metadata) != primary.statistical_state_metadata
                or test.source_artifact_hashes != primary.statistical_state_source_artifact_hashes
                or thaw_json(test.method_configuration) != primary.statistical_state_method_configuration
                or thaw_json(test.outcome) != primary.statistical_state_outcome):
            raise ScientificNumericAblationError("numeric cohort Test differs from its exact primary projection")
        assessment = resolution.assessment
        numeric = require_scientific_numeric_ablation_execution(
            registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=run.object_id,
            generic_ml_projection_artifact_sha256=assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
            scientific_execution_authority_artifact_sha256=assessment.scientific_execution_authority_artifact_sha256,
            scientific_domain_evidence_source_artifact_sha256=_projection_source_artifact_sha256(
                registry, assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
            ),
            expected_contract_artifact_sha256=assessment.contract_artifact_sha256,
            expected_output_manifest_artifact_sha256=assessment.output_manifest_artifact_sha256,
        )
        _require_primary_grid_join(numeric, primary)
        receipts = []
        for binding in member.ablations:
            ablation = binding.research_object
            if len(ablation.authority_artifact_hashes) != 1:
                raise ScientificNumericAblationError("numeric cohort lacks one native observation authority")
            metadata = thaw_json(ablation.metadata)
            receipt = require_scientific_numeric_ablation_authority(
                registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
                expected_execution_run_id=run.object_id,
                expected_ablation_id=metadata["intervention"]["ablation_id"],
                authority_artifact_sha256=ablation.authority_artifact_hashes[0],
            )
            if (receipt.promotion_artifact_sha256 != promotion.sha256
                    or receipt.promotion_record_hash != promotion.record_hash
                    or receipt.assessment_artifact_sha256 != primary.checked_result_assessment_artifact_sha256
                    or receipt.assessment_record_hash != registry.get_metadata(
                        primary.checked_result_assessment_artifact_sha256).record_hash):
                raise ScientificNumericAblationError("numeric cohort primary owner was substituted")
            receipts.append(receipt)
        _require_complete_observations(member, numeric, tuple(receipts))
        authorities.extend(receipts)
    if not authorities:
        raise ScientificNumericAblationError("numeric cohort intervention coverage cannot be vacuous")
    evidence = tuple(sorted(
        (item.artifact_sha256, item.artifact_record_hash)
        for item in state.entries if item.research_object.object_type in _EVIDENCE_TYPES
    ))
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificNumericAblationError("numeric cohort sources changed during complete replay")
    return ScientificNumericAblationCohort(
        state, snapshot_record, members, tuple(authorities),
        tuple(item[0] for item in evidence), tuple(item[1] for item in evidence), before,
    )
