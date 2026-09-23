"""Complete source-owned external-validity boundary, never external adequacy.

This nonissuing companion inspects one ordinary issued canonical snapshot.
Current admitted Generic-ML sources establish within-Dataset observations, not
an externally validated population or generalization claim. Completing this
deterministic inventory therefore never issues scientific PASS, a finding, or
an approval. Challenger publication and downstream audit joins remain separate.
"""

from __future__ import annotations

from dataclasses import dataclass

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .ledger import EventLedger, LedgerValidationResult
from .models import ValidationError, thaw_json, validate_identifier, validate_sha256
from .research_state import (
    Claim,
    ResearchStateAuthorityBinding,
    ResearchStateAuthoritySnapshot,
    Result,
    Run,
    StatisticalTest,
)
from .security import canonical_json_bytes


SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID = "external-validity-boundary-audit"
SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION = "2.0"
SCIENTIFIC_EXTERNAL_VALIDITY_ATTACK = (
    "Replay the complete canonical Result and StatisticalTest cohort against "
    "source-owned domain evidence and frozen generalization scope."
)
SCIENTIFIC_EXTERNAL_VALIDITY_CONCLUSION = (
    "Deterministic source and scope inventory completed. External scientific "
    "validity and generalization adequacy remain UNTESTED."
)


class ScientificExternalValidityError(ValidationError):
    """The requested complete source-owned boundary could not be replayed."""


@dataclass(frozen=True, slots=True)
class ScientificExternalValidityBoundary:
    """Ephemeral full replay output; construction is not scientific authority."""

    state: ResearchStateAuthoritySnapshot
    snapshot_record: ArtifactRecord
    graph_record: ArtifactRecord
    domain_records: tuple[ArtifactRecord, ...]
    result_test_bindings: tuple[tuple[str, str], ...]
    evidence_hashes: tuple[str, ...]
    entry_snapshot: tuple[RegistryValidationResult, LedgerValidationResult]

    @property
    def evidence_record_hashes(self) -> tuple[str, ...]:
        return tuple(record.record_hash for record in (self.snapshot_record, *self.domain_records))

    @property
    def scientific_adequacy(self) -> str:
        return "UNTESTED"


def _preflight_boundary_selectors(
    records: tuple[ArtifactRecord, ...], state_hashes: tuple[str, ...],
) -> None:
    """Reject oversized/absent selectors before full owners, never admit them.

These are existing registry and retained-root capacity limits, not a measured
runtime or primitive-operation ceiling for recursive scientific replay.
"""

    if (
        type(records) is not tuple
        or len(records) > MAX_REGISTRY_RECORDS
        or any(type(record) is not ArtifactRecord for record in records)
        or type(state_hashes) is not tuple
        or not 0 < len(state_hashes) <= MAX_ARTIFACT_PARENTS
        or any(type(digest) is not str for digest in state_hashes)
        or len(set(state_hashes)) != len(state_hashes)
    ):
        raise ScientificExternalValidityError("external-validity selectors exceed bounded shape")
    indexed = {record.sha256: record for record in records}
    if len(indexed) != len(records) or any(digest not in indexed for digest in state_hashes):
        raise ScientificExternalValidityError("external-validity snapshot selectors are absent or ambiguous")
    result_count = sum(indexed[digest].logical_type == "research_state.result" for digest in state_hashes)
    test_count = sum(indexed[digest].logical_type == "research_state.statistical_test" for digest in state_hashes)
    # One graph, S, every Result/Test, and at most one domain root per Result.
    if not result_count or not test_count or 2 + 2 * result_count + test_count > MAX_ARTIFACT_PARENTS:
        raise ScientificExternalValidityError("external-validity Result/Test closure is empty or exceeds parent capacity")


def _current_binding_record(
    registry: ArtifactRegistry, binding: ResearchStateAuthorityBinding,
) -> ArtifactRecord:
    record = registry.get_metadata(binding.artifact_sha256)
    if type(record) is not ArtifactRecord or record.record_hash != binding.artifact_record_hash:
        raise ScientificExternalValidityError("external-validity canonical metadata changed")
    actual = tuple(registry.get_metadata(digest) for digest in binding.authority_artifact_hashes)
    if (
        tuple(record.record_hash for record in actual) != binding.authority_artifact_record_hashes
        or tuple(record.logical_type for record in actual) != binding.authority_logical_types
        or tuple(record.creator_role for record in actual) != binding.authority_creator_roles
    ):
        raise ScientificExternalValidityError("external-validity canonical source records changed")
    return record


def _result_test_members(
    state: ResearchStateAuthoritySnapshot,
) -> tuple[tuple[ResearchStateAuthorityBinding, ResearchStateAuthorityBinding, ResearchStateAuthorityBinding], ...]:
    """Complete structural inventory of an already owned S, with no outcome filter."""

    if (
        type(state) is not ResearchStateAuthoritySnapshot
        or type(state.entries) is not tuple
        or not 0 < len(state.entries) <= MAX_ARTIFACT_PARENTS
        or any(type(item) is not ResearchStateAuthorityBinding for item in state.entries)
    ):
        raise ScientificExternalValidityError("external-validity requires an exact complete snapshot")
    results = tuple(sorted(
        (item for item in state.entries if type(item.research_object) is Result),
        key=lambda item: item.artifact_sha256,
    ))
    tests = tuple(item for item in state.entries if type(item.research_object) is StatisticalTest)
    if not results or not tests:
        raise ScientificExternalValidityError("external-validity Result/Test coverage cannot be vacuous")
    tests_by_result: dict[str, ResearchStateAuthorityBinding] = {}
    for binding in tests:
        test = binding.research_object
        if (len(test.parents) != 1 or len(test.result_ids) != 1
                or test.parents[0].object_type != "Result"
                or test.parents[0].object_id != test.result_ids[0]
                or test.parents[0].relation != "tests" or test.parents[0].evaluated is not True):
            raise ScientificExternalValidityError("external-validity Test lacks its exact evaluated Result")
        result = state.object("Result", test.result_ids[0])
        if (type(result.research_object) is not Result
                or result.research_object.content_hash != test.parents[0].content_hash
                or result.artifact_sha256 in tests_by_result):
            raise ScientificExternalValidityError("external-validity Test is duplicated or joins another Result")
        tests_by_result[result.artifact_sha256] = binding
    if set(tests_by_result) != {binding.artifact_sha256 for binding in results}:
        raise ScientificExternalValidityError("external-validity contains an uncovered or unrelated Result/Test")
    members = []
    for binding in results:
        result = binding.research_object
        parents = tuple(parent for parent in result.parents if parent.object_type == "Run")
        if (len(result.run_ids) != 1 or len(parents) != 1
                or parents[0].object_id != result.run_ids[0]
                or parents[0].relation != "aggregates" or parents[0].evaluated is not True):
            raise ScientificExternalValidityError("external-validity Result lacks its exact execution Run")
        run = state.object("Run", result.run_ids[0])
        if type(run.research_object) is not Run or run.research_object.content_hash != parents[0].content_hash:
            raise ScientificExternalValidityError("external-validity Run revision was substituted")
        members.append((binding, tests_by_result[binding.artifact_sha256], run))
    return tuple(members)


def _require_member_domain(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    state: ResearchStateAuthoritySnapshot,
    result_binding: ResearchStateAuthorityBinding,
    test_binding: ResearchStateAuthorityBinding,
    run_binding: ResearchStateAuthorityBinding,
) -> ArtifactRecord:
    """Use full existing owners, then join their exact canonical/source views."""

    from .domains import (
        SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
        SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        DomainEvidenceScope,
        DomainKind,
        DomainValidityStatus,
        GenericMLFixedModelValidityEvidence,
        GenericMLValidityEvidence,
        ResolvedDomainValidity,
    )
    from .experiments import FrozenRunSpec, require_scientific_execution_run_spec
    from .generic_ml_projection import GENERIC_ML_COMPARISON_SCOPE, GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
    from .scientific_design import (
        SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
        CheckedResultAssessment,
        ScientificResultCanonicalProjectionV3,
        ScientificResultCanonicalProjectionV4,
        ScientificResultPromotionResolutionV3,
        _require_result_promotion_domain_authority,
        require_scientific_result_canonical_projection_v3,
        require_scientific_result_promotion_authority_v3,
    )

    for binding in (result_binding, test_binding, run_binding):
        _current_binding_record(registry, binding)
        if binding.scientific_evidence_eligible is not True:
            raise ScientificExternalValidityError("external-validity contains an unsupported scientific Result/Test/Run")
    result, test, run = (binding.research_object for binding in (result_binding, test_binding, run_binding))
    records = tuple(registry.get_metadata(digest) for digest in result.evaluation_artifact_hashes)
    promotions = tuple(record for record in records if record.logical_type == SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3)
    if len(promotions) != 1:
        raise ScientificExternalValidityError("external-validity requires one outcome-neutral Result promotion")
    promotion = promotions[0]
    selectors = dict(
        promotion_receipt_artifact_sha256=promotion.sha256,
        expected_ledger_run_id=state.run_id,
        expected_execution_run_id=run.object_id,
        expected_result_id=result.object_id,
    )
    resolution = require_scientific_result_promotion_authority_v3(registry, ledger, **selectors)
    primary = require_scientific_result_canonical_projection_v3(
        registry, ledger, **selectors, canonical_state_code_version=state.code_version,
    )
    if (type(resolution) is not ScientificResultPromotionResolutionV3
            or type(primary) not in (ScientificResultCanonicalProjectionV3, ScientificResultCanonicalProjectionV4)
            or type(resolution.assessment) is not CheckedResultAssessment
            or resolution.scientific_evidence_eligible is not True):
        raise ScientificExternalValidityError("external-validity primary source profile is unsupported")
    assessment = resolution.assessment
    if (
        resolution.receipt_artifact_sha256 != promotion.sha256
        or resolution.ledger_run_id != state.run_id or resolution.execution_run_id != run.object_id
        or resolution.result_id != result.object_id
        or primary.ledger_run_id != state.run_id or primary.execution_run_id != run.object_id
        or primary.result_id != result.object_id or primary.experiment_id != run.experiment_id
        or primary.promotion_receipt_artifact_sha256 != promotion.sha256
        or primary.contract_artifact_sha256 != assessment.contract_artifact_sha256
        or primary.scientific_execution_authority_artifact_sha256 != assessment.scientific_execution_authority_artifact_sha256
        or primary.frozen_run_spec_artifact_sha256 != assessment.frozen_run_spec_artifact_sha256
        or primary.output_manifest_artifact_sha256 != assessment.output_manifest_artifact_sha256
        or primary.aggregate_result_sha256 != assessment.aggregate_result_sha256
        or primary.statistical_analysis_sha256 != assessment.statistical_analysis_sha256
        or primary.outcome is not assessment.outcome
        or assessment.is_bounded_mean is not (type(primary) is ScientificResultCanonicalProjectionV4)
        or not assessment.is_projection_backed
        or result.metric_id != primary.metric_id
        or result.source_artifact_hashes != primary.state_source_artifact_hashes
        or result.evaluation_artifact_hashes != primary.state_evaluation_artifact_hashes
        or result.authority_artifact_hashes != primary.state_authority_artifact_hashes
        or test.test_name != primary.contract_primary_test
        or test.null_hypothesis != primary.null_hypothesis or test.alternative != primary.alternative
        or test.source_artifact_hashes != primary.statistical_state_source_artifact_hashes
        or test.authority_artifact_hashes != tuple(sorted(primary.statistical_state_source_artifact_hashes))
        or any(canonical_json_bytes(thaw_json(actual)) != canonical_json_bytes(expected) for actual, expected in (
            (result.value, primary.state_value), (result.uncertainty, primary.state_uncertainty),
            (result.metadata, primary.state_metadata), (test.metadata, primary.statistical_state_metadata),
            (test.method_configuration, primary.statistical_state_method_configuration),
            (test.outcome, primary.statistical_state_outcome),
        ))
    ):
        raise ScientificExternalValidityError("external-validity Result/Test differs from its complete primary source")
    for digest, record_hash in (
        (assessment.contract_artifact_sha256, assessment.contract_record_hash),
        (assessment.scientific_execution_authority_artifact_sha256, assessment.scientific_execution_authority_record_hash),
        (assessment.aggregate_result_sha256, assessment.aggregate_record_hash),
        (assessment.statistical_analysis_sha256, assessment.statistical_record_hash),
        (assessment.generic_ml_paired_metric_projection_authority_artifact_sha256, assessment.generic_ml_paired_metric_projection_authority_record_hash),
        (assessment.domain_validity_receipt_artifact_sha256, assessment.domain_validity_receipt_record_hash),
    ):
        if type(digest) is not str or type(record_hash) is not str or registry.get_metadata(digest).record_hash != record_hash:
            raise ScientificExternalValidityError("external-validity checked source record identity differs")
    spec = require_scientific_execution_run_spec(
        registry, frozen_run_spec_artifact_sha256=assessment.frozen_run_spec_artifact_sha256,
    )
    if (type(spec) is not FrozenRunSpec or spec.run_id != run.object_id
            or spec.experiment_id != primary.experiment_id or spec.hypothesis_id != assessment.hypothesis_id
            or spec.seeds != primary.seed_order
            or assessment.frozen_run_spec_artifact_sha256 not in run_binding.authority_artifact_hashes
            or assessment.scientific_execution_authority_artifact_sha256 not in run_binding.authority_artifact_hashes):
        raise ScientificExternalValidityError("external-validity frozen policy names another execution")
    domain = _require_result_promotion_domain_authority(
        registry, ledger, artifact_sha256=assessment.domain_validity_receipt_artifact_sha256,
        expected_run_id=state.run_id, expected_result_id=result.object_id,
        expected_projection_artifact_sha256=assessment.generic_ml_paired_metric_projection_authority_artifact_sha256,
    )
    if (type(domain) is not ResolvedDomainValidity
            or domain.domain is not DomainKind.GENERIC_ML
            or domain.scope is not DomainEvidenceScope.SCIENTIFIC_EVIDENCE
            or domain.outcome.status is not DomainValidityStatus.PASS
            or domain.run_id != state.run_id or domain.object_id != result.object_id
            or domain.receipt_artifact_sha256 != assessment.domain_validity_receipt_artifact_sha256
            or domain.projection_artifact_sha256 != assessment.generic_ml_paired_metric_projection_authority_artifact_sha256):
        raise ScientificExternalValidityError("external-validity domain owner differs from the primary Result")
    evidence = domain.evidence
    if type(evidence) is GenericMLFixedModelValidityEvidence:
        evidence = evidence.legacy_evidence
    if (type(evidence) is not GenericMLValidityEvidence
            or evidence.generalization_claimed is not False
            or evidence.external_validation_performed is not None):
        raise ScientificExternalValidityError("external-validity requires the closed within-Dataset evidence profile")
    # The full assessment/domain projection owners above already join this
    # exact spec to the prospective plan, Dataset, raw observations and output
    # replay. Inspecting its policy here narrows scope; it grants no authority.
    policy = thaw_json(spec.metadata).get("scientific_domain_policy")
    policy_keys = {
        "schema_version", "domain", "source_format_id", "source_format_version",
        "preprocessing_fit_split_ids", "checkpoint_selection_split_id", "early_stopping",
        "augmentation", "metric_policy", "generalization_scope",
    }
    if type(policy) is not dict:
        raise ScientificExternalValidityError("external-validity lacks its source-owned frozen domain policy")
    version = policy.get("source_format_version")
    if version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION:
        policy_keys.add("comparison_scope")
    if (set(policy) != policy_keys or policy.get("schema_version") != "scientific-domain-policy/v1"
            or policy.get("domain") != DomainKind.GENERIC_ML.value
            or policy.get("source_format_id") != SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID
            or version not in (SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION, GENERIC_ML_OBSERVATIONS_FORMAT_VERSION)
            or policy.get("generalization_scope") != "WITHIN_DATASET_ONLY"
            or (version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION and policy.get("comparison_scope") != GENERIC_ML_COMPARISON_SCOPE)):
        raise ScientificExternalValidityError("external-validity source policy is not a supported within-Dataset profile")
    return registry.get_metadata(domain.receipt_artifact_sha256)


def require_scientific_external_validity_boundary(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    snapshot_artifact_sha256: str,
    claim_graph_artifact_sha256: str,
    central_claim_ids: tuple[str, ...],
    require_whole_current: bool = False,
) -> ScientificExternalValidityBoundary:
    """Replay one complete source/scope boundary without any downstream audit.

Registration requests the whole-current owner. Historical replay uses the
issued bound S and the shared audit-free core-drift check. Neither path calls
Soundness, R5, E3, a semantic audit owner, or a fake semantic replay DTO.
"""

    from .gates import _require_bound_snapshot_no_post_snapshot_core_drift, _resolve_claim_graph_authority
    from .research_state import (
        _read_canonical_research_state_snapshot,
        _require_research_state_snapshot_issuance,
        resolve_bound_research_state_authority,
        resolve_research_state_authority,
    )
    from .scientific_design import _locked_checked_result_authority_snapshot

    if (type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger
            or type(require_whole_current) is not bool
            or any(type(value) is not str for value in (expected_ledger_run_id, snapshot_artifact_sha256, claim_graph_artifact_sha256))
            or type(central_claim_ids) is not tuple or not 0 < len(central_claim_ids) <= 128
            or any(type(value) is not str for value in central_claim_ids)):
        raise ScientificExternalValidityError("external-validity requires exact runtime and bounded selectors")
    validate_identifier(expected_ledger_run_id, "external-validity ledger run")
    validate_sha256(snapshot_artifact_sha256, "external-validity snapshot")
    validate_sha256(claim_graph_artifact_sha256, "external-validity claim graph")
    for claim_id in central_claim_ids:
        validate_identifier(claim_id, "external-validity claim ID")
    if central_claim_ids != tuple(sorted(set(central_claim_ids))) or snapshot_artifact_sha256 == claim_graph_artifact_sha256:
        raise ScientificExternalValidityError("external-validity selectors are aliased or noncanonical")
    before = _locked_checked_result_authority_snapshot(registry, ledger)
    snapshot_record, state_hashes, _, value = _read_canonical_research_state_snapshot(registry, snapshot_artifact_sha256)
    if snapshot_record.logical_type != "canonical_research_state_snapshot":
        raise ScientificExternalValidityError("external-validity requires an ordinary issued snapshot")
    issuance_index, issuance_event = _require_research_state_snapshot_issuance(
        before[1], snapshot_record=snapshot_record, snapshot_value=value,
    )
    _preflight_boundary_selectors(tuple(registry.list_records()), state_hashes)
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificExternalValidityError("external-validity sources changed during selector preflight")
    if require_whole_current:
        state = resolve_research_state_authority(
            registry, ledger, run_id=expected_ledger_run_id, snapshot_artifact_hash=snapshot_artifact_sha256,
        )
    else:
        state = resolve_bound_research_state_authority(
            registry, ledger, run_id=expected_ledger_run_id, snapshot_artifact_hash=snapshot_artifact_sha256,
            state_artifact_hashes=state_hashes, ledger_head_hash=issuance_event.event_hash,
            ledger_event_count=issuance_index + 1, expected_code_version=value["repository_code_version"],
            expected_configuration_hash=value["repository_configuration_hash"],
        )
    _require_bound_snapshot_no_post_snapshot_core_drift(registry, ledger, state=state)
    if (state.snapshot_artifact_sha256 != snapshot_artifact_sha256
            or state.snapshot_artifact_record_hash != snapshot_record.record_hash
            or state.run_id != expected_ledger_run_id):
        raise ScientificExternalValidityError("external-validity snapshot owner returned another subject")
    graph_claim_ids = tuple(sorted(_resolve_claim_graph_authority(registry, claim_graph_artifact_sha256)))
    graph_record = registry.get_metadata(claim_graph_artifact_sha256)
    claims = tuple(item for item in state.entries if type(item.research_object) is Claim)
    if (not claims or graph_claim_ids != central_claim_ids
            or tuple(sorted(item.research_object.object_id for item in claims)) != central_claim_ids):
        raise ScientificExternalValidityError("external-validity graph must equal the complete canonical Claim set")
    for binding in claims:
        _current_binding_record(registry, binding)
        if (binding.claim_semantics is None
                or binding.claim_semantics.claim_id != binding.research_object.object_id
                or binding.claim_semantics.claim_graph_artifact_hash != graph_record.sha256
                or binding.claim_semantics.claim_graph_artifact_record_hash != graph_record.record_hash):
            raise ScientificExternalValidityError("external-validity Claim semantics name another graph revision")
    members = _result_test_members(state)
    domains: dict[str, ArtifactRecord] = {}
    for result, test, run in members:
        record = _require_member_domain(
            registry, ledger, state=state, result_binding=result, test_binding=test, run_binding=run,
        )
        if record.sha256 in domains and domains[record.sha256] != record:
            raise ScientificExternalValidityError("external-validity domain metadata changed between members")
        domains[record.sha256] = record
    domain_records = tuple(domains[digest] for digest in sorted(domains))
    result_test_bindings = tuple(sorted(
        (binding.artifact_sha256, binding.artifact_record_hash)
        for result, test, _ in members for binding in (result, test)
    ))
    evidence_hashes = (snapshot_artifact_sha256, *(record.sha256 for record in domain_records))
    roots = (claim_graph_artifact_sha256, *evidence_hashes, *(digest for digest, _ in result_test_bindings))
    if len(set(roots)) != len(roots) or len(roots) > MAX_ARTIFACT_PARENTS:
        raise ScientificExternalValidityError("external-validity retained roots overlap or exceed parent capacity")
    if _locked_checked_result_authority_snapshot(registry, ledger) != before:
        raise ScientificExternalValidityError("external-validity sources changed during complete replay")
    return ScientificExternalValidityBoundary(
        state, snapshot_record, graph_record, domain_records, result_test_bindings, evidence_hashes, before,
    )


__all__ = [
    "SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID",
    "SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION",
    "SCIENTIFIC_EXTERNAL_VALIDITY_ATTACK",
    "SCIENTIFIC_EXTERNAL_VALIDITY_CONCLUSION",
    "ScientificExternalValidityError",
    "ScientificExternalValidityBoundary",
    "require_scientific_external_validity_boundary",
]
