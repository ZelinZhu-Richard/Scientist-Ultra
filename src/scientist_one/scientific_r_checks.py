"""Closed joins from source-owned scientific artifacts to R-check results.

This module does not persist authority.  It only composes existing source
owners after freshly replaying each one.  ``None`` means that this module does
not own the exact source-type multiset, so the historical evaluator paths keep
their existing behavior.

Imports of scientific owners are deliberately local.  ``gates`` imports the
evaluator vocabulary, while the evaluator integrates this resolver lazily.
Keeping the dependency lazy prevents an initialization cycle and, more
importantly, makes a pending owner impossible to recognize merely because its
artifact type exists.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
import re
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactRecord, ArtifactRegistry
from .evaluators import AuthorityScope, AuthorityStatus, EvaluatorClass, RCheck
from .ledger import EventLedger


_SHA256 = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_MAX_SOURCES = 8

_QUESTION_ASSESSMENT = "research_question_gate_assessment"
_CONTRACT_FREEZE = "evaluation_contract_freeze_gate_receipt"
_SEMANTIC_AUDIT = "semantic_challenge_audit_authority"
_GENERIC_ML_DOMAIN_VALIDITY = "domain_validity.generic_ml"
_SCIENTIFIC_CONFIRMATORY_TIMELINE_V2 = "scientific_confirmatory_timeline_receipt_v2"
_CANONICAL_RESULT = "research_state.result"
_CANONICAL_STATISTICAL_TEST = "research_state.statistical_test"
_CANONICAL_RUN = "research_state.run"
_CANONICAL_IMPLEMENTATION = "research_state.implementation"
_CANONICAL_METHOD = "research_state.method"
_FROZEN_RUN_SPEC = "frozen_run_spec"


@dataclass(frozen=True, slots=True)
class _ScientificCohortExecution:
    """Exact canonical ancestry, not an execution or validity authority."""

    run: Any
    experiment: Any
    implementation: Any
    method: Any
    dataset: Any


@dataclass(frozen=True, slots=True)
class _ScientificCohortResult:
    result: Any
    statistical_test: Any
    execution: _ScientificCohortExecution
    metric: Any


@dataclass(frozen=True, slots=True)
class _ScientificAuditCohort:
    """Ephemeral complete inventory from one full semantic-audit owner replay.

    This is neither a persisted authority nor a claim that the required leaf
    checks passed. In particular, questions and packages are inventories: their
    protocol joins and reproduction outcomes remain owned by their source
    validators. An extra Run without a Result remains an execution obligation.
    """

    audit_source: Any
    round_key: Any
    questions: tuple[Any, ...]
    claims: tuple[Any, ...]
    results: tuple[_ScientificCohortResult, ...]
    executions: tuple[_ScientificCohortExecution, ...]
    packages: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class _ScientificCohortQuestion:
    """One already-owned canonical Question and its independently replayed gate."""

    question: Any
    gate_record: ArtifactRecord
    gate: Any


@dataclass(frozen=True, slots=True)
class _ScientificCohortDesignSource:
    """Run-owned design closure, with no dependency on a downstream Result."""

    execution_record: ArtifactRecord
    execution: Any
    protocol_record: ArtifactRecord
    protocol: Any
    protocol_publication: _ScientificSourceAdmission
    freeze_record: ArtifactRecord
    freeze: Any
    contract_record: ArtifactRecord
    contract: Any


@dataclass(frozen=True, slots=True)
class _ScientificCohortDesignObligation:
    """Fixed run/design coverage, not evidence that an R1 or R3 leaf passed.

    Missing scientific design/question authority stays an explicit obligation.
    Multiple positive Questions on a shared brief are provenance memberships,
    not proof that the contract uniquely selected each falsification condition.
    """

    execution: _ScientificCohortExecution
    source: _ScientificCohortDesignSource | None
    questions: tuple[_ScientificCohortQuestion, ...]
    unmet_reason: str | None


@dataclass(frozen=True, slots=True)
class _ScientificCohortCheckTarget:
    """An independently fixed R1-R4 coverage cell, not a passing authority."""

    r_check: RCheck
    evaluator_class: EvaluatorClass
    subject_artifact_sha256s: tuple[str, ...]
    design: _ScientificCohortDesignObligation
    member: _ScientificCohortResult | None = None
    question: _ScientificCohortQuestion | None = None

    @property
    def identity(self) -> tuple[Any, ...]:
        return self.r_check.value, self.evaluator_class.value, self.subject_artifact_sha256s


@dataclass(frozen=True, slots=True)
class _ScientificCohortCheckCoverage:
    """Ephemeral matching result; complete bundle ownership remains separate."""

    target: _ScientificCohortCheckTarget
    authority_artifact_sha256: str | None
    authority_artifact_record_hash: str | None
    status: AuthorityStatus
    scope: AuthorityScope
    reason_code: str


def _cohort_scientific_check_targets(
    cohort: _ScientificAuditCohort,
    designs: tuple[_ScientificCohortDesignObligation, ...],
) -> tuple[_ScientificCohortCheckTarget, ...]:
    """Derive all R1-R4 cells before inspecting any caller-selected leaves.

    Inputs are full source replay companions from the caller's paired read.
    This pure structural helper does not authenticate constructed DTOs. Missing
    scientific designs/questions stay visible instead of shrinking coverage.
    The bound prevents quadratic shared-question memberships from expanding a
    small source selection into an unbounded control-plane report.
    """
    if (
        type(cohort) is not _ScientificAuditCohort
        or type(designs) is not tuple
        or not cohort.executions
        or len(designs) != len(cohort.executions)
        or any(type(item) is not _ScientificCohortDesignObligation for item in designs)
    ):
        raise ValueError("scientific check targets require the complete execution designs")
    by_run = {item.execution.run.artifact_sha256: item for item in designs}
    if (
        len(by_run) != len(designs)
        or set(by_run) != {item.run.artifact_sha256 for item in cohort.executions}
        or any(by_run[item.run.artifact_sha256].execution != item for item in cohort.executions)
    ):
        raise ValueError("scientific check designs omit or substitute a cohort execution")
    targets: list[_ScientificCohortCheckTarget] = []

    def add(target: _ScientificCohortCheckTarget) -> None:
        # The eventual V2 receipt must also satisfy its encoded-byte budget;
        # this count is an earlier computation bound, never a truncation rule.
        if len(targets) >= 4096:
            raise ValueError("scientific cohort check coverage exceeds its bounded capacity")
        targets.append(target)

    for execution in cohort.executions:
        run_hash = execution.run.artifact_sha256
        design = by_run[run_hash]
        if design.source is not None and design.questions and design.unmet_reason is None:
            for question in design.questions:
                for evaluator in (EvaluatorClass.E0, EvaluatorClass.E2):
                    add(_ScientificCohortCheckTarget(
                        RCheck.R1, evaluator,
                        (run_hash, question.question.artifact_sha256, design.source.freeze_record.sha256),
                        design, question=question,
                    ))
        else:
            for evaluator in (EvaluatorClass.E0, EvaluatorClass.E2):
                add(_ScientificCohortCheckTarget(RCheck.R1, evaluator, (run_hash,), design))
        for evaluator in (EvaluatorClass.E0, EvaluatorClass.E3):
            add(_ScientificCohortCheckTarget(
                RCheck.R3, evaluator, (run_hash, execution.dataset.artifact_sha256), design,
            ))
    for member in cohort.results:
        design = by_run.get(member.execution.run.artifact_sha256)
        if design is None or design.execution != member.execution:
            raise ValueError("scientific check Result has another execution design")
        for check in (RCheck.R2, RCheck.R4):
            for evaluator in (EvaluatorClass.E0, EvaluatorClass.E2):
                add(_ScientificCohortCheckTarget(
                    check, evaluator,
                    (member.result.artifact_sha256, member.statistical_test.artifact_sha256),
                    design, member=member,
                ))
    identities = tuple(item.identity for item in targets)
    if len(set(identities)) != len(identities):
        raise ValueError("scientific cohort check targets are ambiguous")
    return tuple(sorted(targets, key=lambda item: item.identity))


def _cohort_scientific_leaf_coverage(
    cohort: _ScientificAuditCohort,
    designs: tuple[_ScientificCohortDesignObligation, ...],
    leaf_sources: tuple[Any, ...],
) -> tuple[_ScientificCohortCheckCoverage, ...]:
    """Match full R1-R4 leaf replays without treating their union as the cohort.

    Semantic category/round equality and R0/R5/R6/R7 remain additional bundle
    obligations. These rows alone can never authorize a complete R0-R7 bundle.
    One real R1 leaf may cover several independently established equivalent
    Question/design memberships, but competing leaves for one cell are refused.
    """
    from .evaluators import _RCheckAuthorityReplay

    targets = _cohort_scientific_check_targets(cohort, designs)
    if (
        type(leaf_sources) is not tuple
        or len(leaf_sources) > 256
        or any(type(item) is not _RCheckAuthorityReplay for item in leaf_sources)
        or len({item.record.sha256 for item in leaf_sources}) != len(leaf_sources)
    ):
        raise ValueError("scientific cohort coverage requires unique bounded full leaf replays")
    matched: dict[tuple[Any, ...], Any] = {}
    for leaf in leaf_sources:
        resolution = leaf.scientific_resolution
        if (
            leaf.entry_snapshot != cohort.audit_source.entry_snapshot
            or type(resolution) is not ScientificRCheckResolution
            or leaf.authority.run_id != cohort.round_key.run_id
            or dict(resolution.subject_key).get("run_id") != cohort.round_key.run_id
            or leaf.authority.r_check is not resolution.r_check
            or leaf.authority.evaluator_class is not resolution.evaluator_class
            or resolution.r_check not in {RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4}
        ):
            raise ValueError("scientific cohort leaf lacks the same full source replay view")
        selected = []
        for target in targets:
            if (target.r_check, target.evaluator_class) != (
                resolution.r_check, resolution.evaluator_class,
            ):
                continue
            if target.r_check is RCheck.R1:
                matches = target.question is not None and _cohort_r1_leaf_matches_design(
                    resolution, target.design, target.question,
                )
            elif target.r_check is RCheck.R3:
                matches = _cohort_r3_leaf_matches_execution(resolution, target.design)
            else:
                matches = target.member is not None and _cohort_result_leaf_matches_member(
                    resolution, target.member, target.design,
                )
            if matches:
                selected.append(target)
        if not selected:
            raise ValueError("scientific cohort leaf is unrelated or lacks authenticated membership")
        for target in selected:
            if target.identity in matched:
                raise ValueError("scientific cohort cell has competing evaluator authorities")
            matched[target.identity] = leaf
    rows = []
    for target in targets:
        leaf = matched.get(target.identity)
        if leaf is None:
            design_reason = (
                target.design.unmet_reason
                if target.r_check is RCheck.R1 or target.design.source is None
                else None
            )
            rows.append(_ScientificCohortCheckCoverage(
                target, None, None, AuthorityStatus.UNTESTED, AuthorityScope.SYSTEM_FIXTURE,
                design_reason or "REQUIRED_COHORT_LEAF_MISSING",
            ))
            continue
        authority = leaf.authority
        status = authority.status
        reason = authority.reason_code
        if status is AuthorityStatus.PASS and authority.scope is not AuthorityScope.SCIENTIFIC:
            status = AuthorityStatus.UNTESTED
            reason = "MATCHED_LEAF_NOT_SCIENTIFIC_AUTHORITY"
        rows.append(_ScientificCohortCheckCoverage(
            target, leaf.record.sha256, str(leaf.record.record_hash),
            status, authority.scope, reason,
        ))
    return tuple(rows)


def _scientific_audit_cohort_from_source(source: Any) -> _ScientificAuditCohort:
    """Project a full owner's snapshot, never a caller-selected leaf union.

    The private input is the source owner's completed replay companion. This
    structural projection does not authenticate an arbitrary constructed DTO;
    production entry is `_require_scientific_audit_cohort` below. Keeping these
    joins pure permits explicit non-evidentiary adversarial shape controls.
    """

    from .gates import (
        _SemanticChallengeAuditReplay,
        _SemanticReproductionCohortAuditReplay,
        _semantic_challenger_audit_authority_round_key,
        _semantic_challenger_audit_round_key,
    )
    from .models import thaw_json
    from .research_state import (
        ResearchStateAuthoritySnapshot,
        ResearchStateAuthorityBinding,
    )
    from .scientific_design import (
        SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3,
        SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4,
        SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3,
        SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4,
    )

    if type(source) not in {_SemanticChallengeAuditReplay, _SemanticReproductionCohortAuditReplay}:
        raise ValueError("scientific cohort requires the complete audit source companion")
    state = source.canonical_scope.state
    if type(state) is not ResearchStateAuthoritySnapshot or any(
        type(item) is not ResearchStateAuthorityBinding for item in state.entries
    ):
        raise ValueError("scientific cohort lacks the owner's canonical snapshot")
    round_key = _semantic_challenger_audit_round_key(source.slot)
    if (
        round_key != _semantic_challenger_audit_authority_round_key(source.authority)
        or state.run_id != round_key.run_id
        or state.snapshot_artifact_sha256
        != round_key.research_state_snapshot_artifact_hash
        or state.snapshot_artifact_record_hash
        != round_key.research_state_snapshot_artifact_record_hash
    ):
        raise ValueError("scientific cohort source names another audit round")

    def inventory(object_type: str) -> tuple[Any, ...]:
        return tuple(sorted(
            (item for item in state.entries if item.research_object.object_type == object_type),
            key=lambda item: item.artifact_sha256,
        ))

    claims = inventory("Claim")
    results = inventory("Result")
    statistical_tests = inventory("StatisticalTest")
    whole_result_test_bindings = tuple(sorted(
        (item.artifact_sha256, item.artifact_record_hash)
        for item in (*results, *statistical_tests)
    ))
    if (
        not claims or not results or not statistical_tests
        or tuple(sorted(item.research_object.object_id for item in claims))
        != round_key.central_claim_ids
        or whole_result_test_bindings != tuple(zip(
            round_key.result_artifact_hashes,
            round_key.result_artifact_record_hashes,
            strict=True,
        ))
    ):
        raise ValueError("scientific cohort omits or substitutes an audited Claim/Result/Test")

    def parent(binding: Any, object_type: str, relation: str) -> Any:
        reference = _one_parent(binding.research_object, object_type, relation)
        selected = state.object(reference.object_type, reference.object_id)
        if selected.research_object.content_hash != reference.content_hash:
            raise ValueError("scientific cohort parent is not the exact audited revision")
        return selected

    executions = []
    for run in inventory("Run"):
        experiment = parent(run, "Experiment", "executes")
        implementation = parent(experiment, "Implementation", "uses")
        method = parent(implementation, "Method", "implements")
        dataset = parent(experiment, "Dataset", "uses")
        run_value = run.research_object
        experiment_value = experiment.research_object
        implementation_value = implementation.research_object
        if (
            len(run_value.parents) != 1
            or len(implementation_value.parents) != 1
            or run_value.experiment_id != experiment_value.object_id
            or run_value.dataset_ids != experiment_value.dataset_ids
            or experiment_value.dataset_ids != (dataset.research_object.object_id,)
            or experiment_value.implementation_id != implementation_value.object_id
            or implementation_value.method_id != method.research_object.object_id
        ):
            raise ValueError("scientific cohort execution ancestry is spliced")
        executions.append(_ScientificCohortExecution(
            run, experiment, implementation, method, dataset,
        ))
    execution_by_run = {item.run.artifact_sha256: item for item in executions}
    tests_by_result: dict[str, Any] = {}
    for test in statistical_tests:
        result = parent(test, "Result", "tests")
        if (
            len(test.research_object.parents) != 1
            or test.research_object.result_ids != (result.research_object.object_id,)
            or result.artifact_sha256 in tests_by_result
        ):
            raise ValueError("scientific cohort requires one exact Test per Result")
        tests_by_result[result.artifact_sha256] = test
    if set(tests_by_result) != {item.artifact_sha256 for item in results}:
        raise ValueError("scientific cohort has an untested or unrelated Result")

    members = []
    schema_pairs = {
        (SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3, SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3),
        (SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4, SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4),
    }
    for result in results:
        test = tests_by_result[result.artifact_sha256]
        run = parent(result, "Run", "aggregates")
        metric = parent(result, "Metric", "reports")
        if (
            result.research_object.parents != (
                _one_parent(result.research_object, "Run", "aggregates"),
                _one_parent(result.research_object, "Metric", "reports"),
            )
            or result.research_object.run_ids != (run.research_object.object_id,)
            or result.research_object.metric_id != metric.research_object.object_id
            or run.artifact_sha256 not in execution_by_run
        ):
            raise ValueError("scientific cohort Result lacks its exact execution/Metric")
        # These are the outcome-neutral canonical profiles supported by the
        # scientific leaf owners. Do not reinterpret historical views or drop
        # an unsupported member to obtain a smaller passing cohort.
        pair = (
            thaw_json(result.research_object.metadata).get("schema_version"),
            thaw_json(test.research_object.metadata).get("schema_version"),
        )
        if pair not in schema_pairs:
            raise ValueError("scientific cohort Result/Test profile is unsupported or mixed")
        members.append(_ScientificCohortResult(
            result, test, execution_by_run[run.artifact_sha256], metric,
        ))
    return _ScientificAuditCohort(
        audit_source=source,
        round_key=round_key,
        questions=inventory("ResearchQuestion"),
        claims=claims,
        results=tuple(members),
        executions=tuple(executions),
        packages=inventory("ReproducibilityPackage"),
    )


def _require_scientific_audit_cohort(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    semantic_audit_artifact_sha256: str,
) -> _ScientificAuditCohort:
    """Load the complete source-owned cohort without accepting leaf selectors."""

    from .evaluators import _canonical_json_artifact, _r_check_read_snapshot, _validate_runtime
    from .gates import (
        SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
        SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
        SEMANTIC_REPRODUCTION_COHORT_AUTHORITY_SCHEMA_VERSION,
        SemanticChallengeAuditAuthority,
        SemanticReproductionCohortAuditAuthority,
        _require_semantic_challenge_audit_source,
        _require_semantic_reproduction_cohort_audit_source,
    )

    _validate_runtime(registry, ledger, run_id)
    before = _r_check_read_snapshot(registry, ledger)
    (record,) = _source_records(registry, (semantic_audit_artifact_sha256,))
    if (
        record.logical_type != SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE
        or record.schema_version not in {
            SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
            SEMANTIC_REPRODUCTION_COHORT_AUTHORITY_SCHEMA_VERSION,
        }
    ):
        raise ValueError("scientific cohort audit format is unsupported")
    payload = _canonical_json_artifact(registry, record)
    if record.schema_version == SEMANTIC_REPRODUCTION_COHORT_AUTHORITY_SCHEMA_VERSION:
        stated = SemanticReproductionCohortAuditAuthority.from_dict(payload)
        source = _require_semantic_reproduction_cohort_audit_source(
            registry, ledger,
            authority_artifact_hash=record.sha256,
            expected_run_id=run_id,
            expected_assessment_id=stated.assessment_id,
            expected_research_state_snapshot_artifact_hash=stated.research_state_snapshot_artifact_hash,
            expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
            expected_central_claim_ids=stated.central_claim_ids,
            expected_reproduction_package_bindings=stated.reproduction_package_bindings,
        )
    else:
        stated = SemanticChallengeAuditAuthority.from_dict(payload)
        source = _require_semantic_challenge_audit_source(
            registry, ledger,
            authority_artifact_hash=record.sha256,
            expected_run_id=run_id,
            expected_assessment_id=stated.assessment_id,
            expected_category=stated.category,
            expected_research_state_snapshot_artifact_hash=stated.research_state_snapshot_artifact_hash,
            expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
            expected_central_claim_ids=stated.central_claim_ids,
            expected_reproducibility_package_artifact_hash=stated.reproducibility_package_artifact_hash,
        )
    cohort = _scientific_audit_cohort_from_source(source)
    if _r_check_read_snapshot(registry, ledger) != before:
        raise ValueError("scientific audit cohort changed during complete replay")
    return cohort


def _cohort_protocol_publication_selector(
    events: tuple[Any, ...], *, execution_run_id: str,
) -> str | None:
    """Select only the owner's execution-ID publication slot, never a Result.

    This selector grants no authority. Its output must go through the complete
    protocol owner, which verifies the full event, shared slots and sources.
    """

    candidates = tuple(
        value for event in events
        if isinstance(value := event.metadata.get("scientific_confirmatory_protocol_binding"), Mapping)
        and value.get("execution_run_id") == execution_run_id
    )
    if not candidates:
        return None
    if len(candidates) != 1:
        raise ValueError("cohort execution has competing protocol publications")
    digest = candidates[0].get("binding_artifact_sha256")
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise ValueError("cohort execution protocol publication selector is malformed")
    return digest


def _cohort_design_questions(
    source: _ScientificCohortDesignSource,
    questions: tuple[_ScientificCohortQuestion, ...],
) -> tuple[_ScientificCohortQuestion, ...]:
    """Match fully owned roots before examining any submitted R-check leaves."""

    return tuple(item for item in questions if (
        item.gate.research_brief_sha256 == source.contract.research_brief_sha256
        and item.gate.gate_event_index < source.freeze.design_freeze_event_index
    ))


def _require_scientific_cohort_designs(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    cohort: _ScientificAuditCohort,
) -> tuple[_ScientificCohortDesignObligation, ...]:
    """Derive complete Run/design obligations after the full cohort owner.

    The private companion is a completed replay result, not caller authority.
    It must still describe this paired entry snapshot. No leaf selector,
    result-discovery fallback, registry search by brief body, or positive
    inference from a diagnostic Question is accepted here.
    """

    from .evaluators import _canonical_json_artifact, _r_check_read_snapshot, _validate_runtime
    from .experiments import require_scientific_execution_authority
    from .research_state import (
        ResearchQuestionOutcome,
        SCIENTIFIC_DATASET_AUTHORITY_LOGICAL_TYPE,
        require_current_scientific_execution_run,
    )
    from .scientific_design import (
        ResearchQuestionGateReceipt,
        require_research_question_gate_receipt,
        require_scientific_confirmatory_protocol_binding,
        _matching_scientific_confirmatory_protocol_events,
        require_evaluation_contract_freeze_gate_receipt,
        require_frozen_evaluation_contract,
    )

    if type(cohort) is not _ScientificAuditCohort:
        raise ValueError("design obligations require the complete owned cohort")
    run_id = cohort.round_key.run_id
    _validate_runtime(registry, ledger, run_id)
    before = _r_check_read_snapshot(registry, ledger)
    if cohort.audit_source.entry_snapshot != before:
        raise ValueError("cohort source changed before design-obligation replay")

    def authority_record(binding: Any, logical_type: str) -> ArtifactRecord:
        matches = tuple(
            (digest, record_hash) for digest, record_hash, source_type in zip(
                binding.authority_artifact_hashes,
                binding.authority_artifact_record_hashes,
                binding.authority_logical_types,
                strict=True,
            ) if source_type == logical_type
        )
        if len(matches) != 1:
            raise ValueError("cohort member lacks its exact design source")
        digest, record_hash = matches[0]
        record = registry.get_metadata(digest)
        if record.logical_type != logical_type or record.record_hash != record_hash:
            raise ValueError("cohort design source record changed")
        return record

    questions = []
    for question in cohort.questions:
        if (
            question.research_object.gate_outcome is not ResearchQuestionOutcome.PROCEED
            or question.scientific_evidence_eligible is not True
        ):
            # The canonical non-PROCEED branch owns only brief/state diagnostic
            # facts. It does not own an outcome-neutral scientific Question gate.
            continue
        record = authority_record(question, "research_question_gate_receipt")
        stated = ResearchQuestionGateReceipt.from_dict(_canonical_json_artifact(registry, record))
        gate = require_research_question_gate_receipt(
            registry, ledger, receipt_artifact_sha256=record.sha256,
            expected_run_id=run_id, expected_object_id=stated.object_id,
            expected_question_object_id=question.research_object.object_id,
        )
        if gate != stated or gate.scientific_gate_passed is not True:
            raise ValueError("cohort Question lacks its exact positive scientific gate")
        questions.append(_ScientificCohortQuestion(question, record, gate))

    obligations = []
    for execution in cohort.executions:
        run = execution.run
        if run.scientific_evidence_eligible is not True:
            obligations.append(_ScientificCohortDesignObligation(
                execution, None, (), "SCIENTIFIC_EXECUTION_AUTHORITY_UNAVAILABLE",
            ))
            continue
        owned_run = require_current_scientific_execution_run(
            registry, ledger, run_id=run_id,
            run_state_artifact_sha256=run.artifact_sha256,
            expected_execution_run_id=run.research_object.object_id,
        )
        if owned_run != run:
            raise ValueError("cohort Run changed during execution-owned design replay")
        execution_record = authority_record(run, "scientific_execution_authority")
        authority = require_scientific_execution_authority(
            registry, ledger, authority_artifact_sha256=execution_record.sha256,
            expected_ledger_run_id=run_id,
            expected_execution_run_id=run.research_object.object_id,
        )
        selected = _cohort_protocol_publication_selector(
            before[1].events, execution_run_id=run.research_object.object_id,
        )
        if selected is None:
            obligations.append(_ScientificCohortDesignObligation(
                execution, None, (), "PROSPECTIVE_PROTOCOL_BINDING_UNAVAILABLE",
            ))
            continue
        protocol = require_scientific_confirmatory_protocol_binding(
            registry, ledger, binding_artifact_sha256=selected,
            expected_ledger_run_id=run_id,
            expected_execution_run_id=run.research_object.object_id,
        )
        protocol_record = registry.get_metadata(selected)
        protocol_publications = _matching_scientific_confirmatory_protocol_events(
            before[1].events, binding=protocol,
        )
        if (
            len(protocol_publications) != 1
            or protocol_publications[0][0] >= cohort.audit_source.slot.event_index
        ):
            raise ValueError("cohort protocol publication must precede the audit slot")
        protocol_index, protocol_event, _ = protocol_publications[0]
        protocol_publication = _ScientificSourceAdmission(
            protocol_record.sha256, str(protocol_record.record_hash),
            protocol_event.event_id, protocol_event.event_hash, protocol_index,
        )
        contract = require_frozen_evaluation_contract(
            registry, contract_artifact_sha256=protocol.contract_artifact_sha256,
        )
        contract_record = registry.get_metadata(protocol.contract_artifact_sha256)
        freeze = require_evaluation_contract_freeze_gate_receipt(
            registry, ledger,
            receipt_artifact_sha256=protocol.evaluation_contract_freeze_receipt_artifact_sha256,
            expected_run_id=run_id, expected_contract_id=contract.contract_id,
            contract=contract,
        )
        freeze_record = registry.get_metadata(protocol.evaluation_contract_freeze_receipt_artifact_sha256)
        dataset_record = authority_record(execution.dataset, SCIENTIFIC_DATASET_AUTHORITY_LOGICAL_TYPE)
        spec_record = registry.get_metadata(authority.frozen_run_spec_artifact_sha256)
        if (
            protocol.scientific_execution_preparation_artifact_sha256 != authority.preparation_artifact_sha256
            or protocol.scientific_execution_preparation_record_hash != authority.preparation_record_hash
            or protocol.frozen_run_spec_artifact_sha256 != authority.frozen_run_spec_artifact_sha256
            or protocol.frozen_run_spec_record_hash != spec_record.record_hash
            or protocol.frozen_run_spec_sha256 != authority.frozen_run_spec_sha256
            or protocol.contract_record_hash != contract_record.record_hash
            or protocol.contract_sha256 != contract.sha256
            or protocol.evaluation_contract_freeze_receipt_record_hash != freeze_record.record_hash
            or freeze.contract_artifact_sha256 != contract_record.sha256
            or freeze.contract_record_hash != contract_record.record_hash
            or freeze.contract_sha256 != contract.sha256
            or freeze.frozen_run_spec_artifact_sha256 != spec_record.sha256
            or freeze.frozen_run_spec_record_hash != spec_record.record_hash
            or freeze.frozen_run_spec_sha256 != authority.frozen_run_spec_sha256
            or protocol.experiment_id != execution.experiment.research_object.object_id
            or protocol.dataset_id != execution.dataset.research_object.object_id
            or protocol.dataset_authority_artifact_sha256 != dataset_record.sha256
            or protocol.dataset_authority_record_hash != dataset_record.record_hash
            or protocol.seed_order != run.research_object.random_seeds
        ):
            raise ValueError("cohort design differs from its exact Run/spec/Dataset/protocol owners")
        source = _ScientificCohortDesignSource(
            execution_record, authority, protocol_record, protocol, protocol_publication,
            freeze_record, freeze, contract_record, contract,
        )
        matched_questions = _cohort_design_questions(source, tuple(questions))
        obligations.append(_ScientificCohortDesignObligation(
            execution, source, matched_questions,
            None if matched_questions else "SCIENTIFIC_QUESTION_GATE_UNAVAILABLE_BEFORE_DESIGN",
        ))
    if _r_check_read_snapshot(registry, ledger) != before:
        raise ValueError("cohort sources changed during complete design-obligation replay")
    return tuple(obligations)


def _cohort_r1_leaf_matches_design(
    resolution: ScientificRCheckResolution,
    obligation: _ScientificCohortDesignObligation,
    question: _ScientificCohortQuestion,
) -> bool:
    """Match a freshly resolved leaf to independently fixed design membership.

    This checks coverage identity only, not PASS: an adverse or untested leaf
    retains its own status. The two question gates are intentionally separate;
    their roots/criteria/outcome agree and each checkpoint precedes the freeze.
    """

    if (
        type(resolution) is not ScientificRCheckResolution
        or resolution.r_check is not RCheck.R1
        or resolution.evaluator_class not in {EvaluatorClass.E0, EvaluatorClass.E2}
        or type(obligation) is not _ScientificCohortDesignObligation
        or obligation.source is None or obligation.unmet_reason is not None
        or type(question) is not _ScientificCohortQuestion
        or question not in obligation.questions
    ):
        return False
    source = obligation.source
    gate = question.gate
    freeze = source.freeze
    values = dict(resolution.subject_key)
    expected = {
        "run_id": source.execution.ledger_run_id,
        "research_brief_id": gate.object_id,
        "contract_id": source.contract.contract_id,
        "contract_artifact_sha256": source.contract_record.sha256,
        "contract_record_hash": source.contract_record.record_hash,
        "contract_sha256": source.contract.sha256,
        "contract_freeze_artifact_sha256": source.freeze_record.sha256,
        "contract_freeze_record_hash": source.freeze_record.record_hash,
        "frozen_run_spec_artifact_sha256": source.protocol.frozen_run_spec_artifact_sha256,
        "frozen_run_spec_record_hash": source.protocol.frozen_run_spec_record_hash,
        "frozen_run_spec_sha256": source.protocol.frozen_run_spec_sha256,
        "design_freeze_event_id": freeze.design_freeze_event_id,
        "design_freeze_event_hash": freeze.design_freeze_event_hash,
        "design_freeze_event_index": str(freeze.design_freeze_event_index),
        "selected_direction_id": gate.selected_direction_id,
        "criteria_projection_sha256": gate.criteria_projection_sha256,
        "research_question_assessment_outcome": gate.outcome.value,
    }
    expected.update((name, getattr(gate, name)) for name in (
        "goal_artifact_sha256", "goal_record_hash", "goal_sha256",
        "investigation_state_artifact_sha256", "investigation_state_record_hash", "investigation_state_sha256",
        "research_brief_artifact_sha256", "research_brief_record_hash", "research_brief_sha256",
    ))
    if any(values.get(name) != value for name, value in expected.items()):
        return False
    admissions = {item.artifact_sha256: item for item in resolution.source_admissions}
    assessment = admissions.get(values.get("research_question_assessment_artifact_sha256"))
    freeze_admission = admissions.get(source.freeze_record.sha256)
    return bool(
        assessment is not None and freeze_admission is not None
        and assessment.artifact_record_hash == values.get("research_question_assessment_record_hash")
        and assessment.ledger_event_id == values.get("research_question_assessment_event_id")
        and assessment.ledger_event_hash == values.get("research_question_assessment_event_hash")
        and str(assessment.ledger_event_index) == values.get("research_question_assessment_event_index")
        and assessment.ledger_event_index < freeze.design_freeze_event_index
        and gate.gate_event_index < freeze.design_freeze_event_index
        and freeze_admission.artifact_record_hash == source.freeze_record.record_hash
        and freeze_admission.ledger_event_id == freeze.design_freeze_event_id
        and freeze_admission.ledger_event_hash == freeze.design_freeze_event_hash
        and freeze_admission.ledger_event_index == freeze.design_freeze_event_index
    )


def _cohort_execution_subject(source: _ScientificCohortDesignSource) -> dict[str, str]:
    """Common execution identities, not a requirement that all runs be equal."""

    return {
        "run_id": source.execution.ledger_run_id,
        "execution_run_id": source.execution.execution_run_id,
        "contract_artifact_sha256": source.contract_record.sha256,
        "contract_record_hash": str(source.contract_record.record_hash),
        "contract_sha256": source.contract.sha256,
        "frozen_run_spec_artifact_sha256": source.protocol.frozen_run_spec_artifact_sha256,
        "frozen_run_spec_record_hash": source.protocol.frozen_run_spec_record_hash,
        "frozen_run_spec_sha256": source.protocol.frozen_run_spec_sha256,
        "scientific_execution_authority_artifact_sha256": source.execution_record.sha256,
        "scientific_execution_authority_record_hash": str(source.execution_record.record_hash),
        "dataset_id": source.protocol.dataset_id,
        "dataset_artifact_sha256": source.protocol.dataset_authority_artifact_sha256,
        "dataset_record_hash": source.protocol.dataset_authority_record_hash,
    }


def _cohort_result_leaf_matches_member(
    resolution: ScientificRCheckResolution,
    member: _ScientificCohortResult,
    design: _ScientificCohortDesignObligation,
) -> bool:
    """Exact R2/R4 coverage of one Result/Test; category audit joins are separate."""

    if (
        type(resolution) is not ScientificRCheckResolution
        or resolution.r_check not in {RCheck.R2, RCheck.R4}
        or resolution.evaluator_class not in {EvaluatorClass.E0, EvaluatorClass.E2}
        or type(member) is not _ScientificCohortResult
        or type(design) is not _ScientificCohortDesignObligation
        or design.source is None or design.execution != member.execution
    ):
        return False
    expected = _cohort_execution_subject(design.source)
    canonical = {
        "result": member.result,
        "statistical_test": member.statistical_test,
        "run": member.execution.run,
        "implementation": member.execution.implementation,
        "method": member.execution.method,
        "dataset": member.execution.dataset,
    }
    for name, binding in canonical.items():
        expected[f"canonical_{name}_artifact_sha256"] = binding.artifact_sha256
        expected[f"canonical_{name}_record_hash"] = binding.artifact_record_hash
    values = dict(resolution.subject_key)
    if any(values.get(name) != value for name, value in expected.items()):
        return False
    admissions = {item.artifact_sha256: item for item in resolution.source_admissions}
    required = (member.result, member.statistical_test)
    if resolution.r_check is RCheck.R2:
        required = (*required, member.execution.run, member.execution.implementation, member.execution.method)
    for binding in required:
        admission = admissions.get(binding.artifact_sha256)
        if admission != _ScientificSourceAdmission(
            binding.artifact_sha256, binding.artifact_record_hash,
            binding.materialization_event_id, binding.materialization_event_hash,
            binding.materialization_event_index,
        ):
            return False
    if resolution.r_check is RCheck.R2:
        source = design.source
        if admissions.get(source.protocol.frozen_run_spec_artifact_sha256) != _ScientificSourceAdmission(
            source.protocol.frozen_run_spec_artifact_sha256, source.protocol.frozen_run_spec_record_hash,
            source.freeze.design_freeze_event_id, source.freeze.design_freeze_event_hash,
            source.freeze.design_freeze_event_index,
        ):
            return False
    return True


def _cohort_r3_leaf_matches_execution(
    resolution: ScientificRCheckResolution,
    design: _ScientificCohortDesignObligation,
) -> bool:
    """Exact domain/timeline coverage even when this Run has no Result."""

    if (
        type(resolution) is not ScientificRCheckResolution
        or resolution.r_check is not RCheck.R3
        or resolution.evaluator_class not in {EvaluatorClass.E0, EvaluatorClass.E3}
        or type(design) is not _ScientificCohortDesignObligation
        or design.source is None
    ):
        return False
    source = design.source
    expected = _cohort_execution_subject(source)
    if resolution.evaluator_class is EvaluatorClass.E0:
        expected.update(
            canonical_run_artifact_sha256=design.execution.run.artifact_sha256,
            canonical_run_record_hash=design.execution.run.artifact_record_hash,
        )
        own_prefix = "domain_validity"
    else:
        expected.update(
            protocol_binding_artifact_sha256=source.protocol_record.sha256,
            protocol_binding_record_hash=str(source.protocol_record.record_hash),
        )
        own_prefix = "scientific_confirmatory_timeline"
    values = dict(resolution.subject_key)
    if any(values.get(name) != value for name, value in expected.items()):
        return False
    # The full leaf owner supplies the actual domain/timeline publication,
    # not an arbitrary later artifact reference selected by the composer.
    return bool(len(resolution.source_admissions) == 1 and (
        resolution.source_admissions[0].artifact_sha256 == values.get(f"{own_prefix}_artifact_sha256")
        and resolution.source_admissions[0].artifact_record_hash == values.get(f"{own_prefix}_record_hash")
    ))


@dataclass(frozen=True, slots=True)
class _ScientificSourceAdmission:
    """An artifact's source-owned admission or authoritative input checkpoint.

    A later event mentioning the same artifact is not another admission. This
    private value only transports a replay result; constructing it grants no
    authority and it is never serialized as a separate provenance record.
    Design/question receipts are derived after their owned input checkpoint;
    that checkpoint need not contain the later receipt artifact itself.
    """

    artifact_sha256: str
    artifact_record_hash: str
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int

    def __post_init__(self) -> None:
        for digest in (self.artifact_sha256, self.artifact_record_hash, self.ledger_event_hash):
            if type(digest) is not str or _SHA256.fullmatch(digest) is None:
                raise ValueError("scientific source admission digest is invalid")
        if (
            type(self.ledger_event_id) is not str
            or _IDENTIFIER.fullmatch(self.ledger_event_id) is None
            or type(self.ledger_event_index) is not int
            or self.ledger_event_index < 0
        ):
            raise ValueError("scientific source admission event is invalid")


@dataclass(frozen=True, slots=True)
class ScientificRCheckResolution:
    """Ephemeral result of one exact, freshly replayed scientific join."""

    r_check: RCheck
    evaluator_class: EvaluatorClass
    status: AuthorityStatus
    scope: AuthorityScope
    reason_code: str
    checks: tuple[tuple[str, str], ...]
    subject_key: tuple[tuple[str, str], ...]
    source_admissions: tuple[_ScientificSourceAdmission, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.r_check, RCheck):
            raise ValueError("scientific R-check resolution requires a typed check")
        if not isinstance(self.evaluator_class, EvaluatorClass):
            raise ValueError("scientific R-check resolution requires a typed evaluator")
        if not isinstance(self.status, AuthorityStatus):
            raise ValueError("scientific R-check resolution requires a typed status")
        if not isinstance(self.scope, AuthorityScope):
            raise ValueError("scientific R-check resolution requires a typed scope")
        if (
            not isinstance(self.reason_code, str)
            or _IDENTIFIER.fullmatch(self.reason_code) is None
        ):
            raise ValueError("scientific R-check resolution reason is invalid")
        for name, values in (
            ("checks", self.checks),
            ("subject_key", self.subject_key),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not all(isinstance(value, str) and value for value in item)
                for item in values
            ):
                raise ValueError(f"scientific R-check {name} are invalid")
        subject = dict(self.subject_key)
        if len(subject) != len(self.subject_key) or subject.get("run_id") is None:
            raise ValueError("scientific R-check subject key is incomplete")
        for key, value in self.subject_key:
            if key.endswith("_sha256") or key.endswith("_record_hash"):
                if _SHA256.fullmatch(value) is None:
                    raise ValueError("scientific R-check subject digest is invalid")
        if (
            type(self.source_admissions) is not tuple
            or len(self.source_admissions) > _MAX_SOURCES
            or any(type(item) is not _ScientificSourceAdmission for item in self.source_admissions)
            or len({item.artifact_sha256 for item in self.source_admissions})
            != len(self.source_admissions)
        ):
            raise ValueError("scientific R-check source admissions are malformed")


def _resolution(
    *,
    r_check: RCheck = RCheck.R1,
    evaluator_class: EvaluatorClass,
    status: AuthorityStatus,
    scope: AuthorityScope,
    reason_code: str,
    checks: Iterable[tuple[str, str]],
    subject_key: Iterable[tuple[str, str]],
    source_admissions: tuple[_ScientificSourceAdmission, ...] = (),
) -> ScientificRCheckResolution:
    return ScientificRCheckResolution(
        r_check=r_check,
        evaluator_class=evaluator_class,
        status=status,
        scope=scope,
        reason_code=reason_code,
        checks=tuple(checks),
        subject_key=tuple(subject_key),
        source_admissions=source_admissions,
    )


def _record_subject(
    run_id: str,
    assessment: Any,
    assessment_record: ArtifactRecord,
    freeze: Any,
    freeze_record: ArtifactRecord,
    contract: Any,
    contract_record: ArtifactRecord,
    audit_record: ArtifactRecord | None,
) -> tuple[tuple[str, str], ...]:
    values = [
        ("run_id", run_id),
        ("research_brief_id", assessment.object_id),
        ("contract_id", freeze.object_id),
        ("research_question_assessment_artifact_sha256", assessment_record.sha256),
        (
            "research_question_assessment_record_hash",
            str(assessment_record.record_hash),
        ),
        ("contract_freeze_artifact_sha256", freeze_record.sha256),
        ("contract_freeze_record_hash", str(freeze_record.record_hash)),
        ("contract_artifact_sha256", contract_record.sha256),
        ("contract_record_hash", str(contract_record.record_hash)),
        ("contract_sha256", contract.sha256),
    ]
    dataset = getattr(contract, "dataset", None)
    dataset_id = getattr(dataset, "dataset_id", None)
    if isinstance(dataset_id, str) and dataset_id:
        values.append(("dataset_id", dataset_id))
    if audit_record is not None:
        values.extend(
            (
                ("semantic_audit_artifact_sha256", audit_record.sha256),
                ("semantic_audit_record_hash", str(audit_record.record_hash)),
            )
        )
    return tuple(values)


def _audit_binds(
    provenance_bindings: Mapping[str, str],
    artifact_sha256: str,
    record_hash: str | None,
) -> bool:
    if record_hash is None:
        return False
    return provenance_bindings.get(artifact_sha256) == record_hash


def _assessment_subject(
    run_id: str,
    assessment: Any,
    assessment_record: ArtifactRecord,
) -> tuple[tuple[str, str], ...]:
    return (
        ("run_id", run_id),
        ("research_brief_id", assessment.object_id),
        ("research_question_assessment_artifact_sha256", assessment_record.sha256),
        (
            "research_question_assessment_record_hash",
            str(assessment_record.record_hash),
        ),
        ("research_brief_artifact_sha256", assessment.research_brief_artifact_sha256),
        ("research_brief_record_hash", assessment.research_brief_record_hash),
    )


def _with_owned_r1_sources(
    resolution: ScientificRCheckResolution,
    *,
    assessment: Any,
    assessment_record: ArtifactRecord,
    freeze: Any | None = None,
    freeze_record: ArtifactRecord | None = None,
    audit_source: Any | None = None,
) -> ScientificRCheckResolution:
    """Carry fresh R1 root identities, not a guessed canonical Question ID.

    Called only after the corresponding complete source owners. A positive
    Question gate and an outcome-neutral assessment have DIFFERENT event and
    semantic-judgment identities. Cohort matching uses their common owned
    goal/state/brief roots and separately checks each checkpoint's chronology.
    """

    from .scientific_design import ResearchQuestionGateAssessment, EvaluationContractFreezeGateReceipt
    from .gates import _SemanticChallengeAuditReplay

    if type(assessment) is not ResearchQuestionGateAssessment or type(assessment_record) is not ArtifactRecord:
        raise ValueError("R1 source companion requires its owned assessment")
    values = dict(resolution.subject_key)
    values.update(
        research_brief_id=assessment.object_id,
        research_question_assessment_id=assessment.assessment_id,
        research_question_assessment_event_id=assessment.gate_event_id,
        research_question_assessment_event_hash=assessment.gate_event_hash,
        research_question_assessment_event_index=str(assessment.gate_event_index),
        research_question_assessment_outcome=assessment.outcome.value,
        selected_direction_id=assessment.selected_direction_id,
        criteria_projection_sha256=assessment.criteria_projection_sha256,
    )
    for name in (
        "goal_artifact_sha256", "goal_record_hash", "goal_sha256",
        "investigation_state_artifact_sha256", "investigation_state_record_hash", "investigation_state_sha256",
        "research_brief_artifact_sha256", "research_brief_record_hash", "research_brief_sha256",
    ):
        values[name] = getattr(assessment, name)
    admissions = (_ScientificSourceAdmission(
        artifact_sha256=assessment_record.sha256,
        artifact_record_hash=str(assessment_record.record_hash),
        ledger_event_id=assessment.gate_event_id,
        ledger_event_hash=assessment.gate_event_hash,
        ledger_event_index=assessment.gate_event_index,
    ),)
    if freeze is not None or freeze_record is not None:
        if type(freeze) is not EvaluationContractFreezeGateReceipt or type(freeze_record) is not ArtifactRecord:
            raise ValueError("R1 source companion lacks its complete design freeze")
        values.update(
            frozen_run_spec_artifact_sha256=freeze.frozen_run_spec_artifact_sha256,
            frozen_run_spec_record_hash=freeze.frozen_run_spec_record_hash,
            frozen_run_spec_sha256=freeze.frozen_run_spec_sha256,
            design_freeze_event_id=freeze.design_freeze_event_id,
            design_freeze_event_hash=freeze.design_freeze_event_hash,
            design_freeze_event_index=str(freeze.design_freeze_event_index),
        )
        admissions = (*admissions, _ScientificSourceAdmission(
            artifact_sha256=freeze_record.sha256,
            artifact_record_hash=str(freeze_record.record_hash),
            ledger_event_id=freeze.design_freeze_event_id,
            ledger_event_hash=freeze.design_freeze_event_hash,
            ledger_event_index=freeze.design_freeze_event_index,
        ))
    if audit_source is not None:
        if type(audit_source) is not _SemanticChallengeAuditReplay:
            raise ValueError("R1 source companion requires its full audit replay")
        admissions = (*admissions, _ScientificSourceAdmission(
            artifact_sha256=audit_source.record.sha256,
            artifact_record_hash=str(audit_source.record.record_hash),
            ledger_event_id=audit_source.publication_event_id,
            ledger_event_hash=audit_source.publication_event_hash,
            ledger_event_index=audit_source.publication_event_index,
        ))
    return replace(resolution, subject_key=tuple(values.items()), source_admissions=admissions)


def _derive_r1_assessment_only(
    *,
    run_id: str,
    evaluator_class: EvaluatorClass,
    assessment: Any,
    assessment_record: ArtifactRecord,
) -> ScientificRCheckResolution:
    """Retain a precise adverse question result without inventing a freeze."""

    from .scientific_design import (
        ResearchGateOutcome,
        ScientificGateVerificationStatus,
    )

    subject_key = _assessment_subject(run_id, assessment, assessment_record)
    checks = [
        ("research_question_gate_owner_replay", "PASS"),
        ("evaluation_contract_freeze_owner_replay", "UNAVAILABLE"),
        ("research_question_gate_outcome", assessment.outcome.value),
    ]
    scientific = (
        assessment.run_id == run_id
        and assessment.verification_status
        is ScientificGateVerificationStatus.SCIENTIFIC_EVIDENCE
        and assessment.scientific_evidence_eligible is True
    )
    if scientific and assessment.outcome is ResearchGateOutcome.INSUFFICIENT_NOVELTY:
        return _resolution(
            evaluator_class=evaluator_class,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="SCIENTIFIC_RESEARCH_QUESTION_INSUFFICIENT_NOVELTY",
            checks=checks,
            subject_key=subject_key,
        )
    blocker = (
        "NON_EVIDENTIARY_MECHANICAL"
        if assessment.verification_status
        is ScientificGateVerificationStatus.NON_EVIDENTIARY
        else "R1_CONTRACT_FREEZE_AUTHORITY_UNAVAILABLE"
    )
    checks.append(("research_question_authority_blocker", blocker))
    return _resolution(
        evaluator_class=evaluator_class,
        status=AuthorityStatus.UNTESTED,
        scope=(
            AuthorityScope.SCIENTIFIC if scientific else AuthorityScope.SYSTEM_FIXTURE
        ),
        reason_code=blocker,
        checks=checks,
        subject_key=subject_key,
    )


def _derive_r1_join(
    *,
    run_id: str,
    evaluator_class: EvaluatorClass,
    assessment: Any,
    assessment_record: ArtifactRecord,
    freeze: Any,
    freeze_record: ArtifactRecord,
    contract: Any,
    contract_record: ArtifactRecord,
    audit: Any | None,
    audit_record: ArtifactRecord | None,
    audit_provenance_bindings: Mapping[str, str] | None = None,
) -> ScientificRCheckResolution:
    """Apply the closed R1 rule to values already returned by their owners."""

    from .gates import SemanticChallengeAuditStatus
    from .scientific_design import (
        ResearchGateOutcome,
        ScientificGateVerificationStatus,
    )

    subject_key = _record_subject(
        run_id,
        assessment,
        assessment_record,
        freeze,
        freeze_record,
        contract,
        contract_record,
        audit_record,
    )
    checks: list[tuple[str, str]] = [
        ("research_question_gate_owner_replay", "PASS"),
        ("evaluation_contract_freeze_owner_replay", "PASS"),
    ]
    joined = (
        assessment.run_id == run_id
        and freeze.run_id == run_id
        and assessment.ledger_path == freeze.ledger_path
        and assessment.gate_event_index < freeze.design_freeze_event_index
        and assessment.research_brief_sha256 == contract.research_brief_sha256
        and freeze.contract_artifact_sha256 == contract_record.sha256
        and freeze.contract_record_hash == contract_record.record_hash
        and freeze.contract_sha256 == contract.sha256
    )
    checks.append(("research_question_contract_join", "PASS" if joined else "FAIL"))
    if not joined:
        return _resolution(
            evaluator_class=evaluator_class,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="SCIENTIFIC_R1_SUBJECT_MISMATCH",
            checks=checks,
            subject_key=subject_key,
        )

    if evaluator_class is EvaluatorClass.E2:
        audit_joined = (
            audit is not None
            and audit_record is not None
            and audit_provenance_bindings is not None
            and audit.run_id == run_id
            and audit.verification_event_index > freeze.design_freeze_event_index
            and _audit_binds(
                audit_provenance_bindings,
                contract_record.sha256,
                contract_record.record_hash,
            )
            and _audit_binds(
                audit_provenance_bindings,
                assessment.research_brief_artifact_sha256,
                assessment.research_brief_record_hash,
            )
        )
        checks.append(
            (
                "experimental_design_audit_subject_join",
                "PASS" if audit_joined else "FAIL",
            )
        )
        if not audit_joined:
            return _resolution(
                evaluator_class=evaluator_class,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_R1_AUDIT_SUBJECT_MISMATCH",
                checks=checks,
                subject_key=subject_key,
            )

    scientific_question = (
        assessment.verification_status
        is ScientificGateVerificationStatus.SCIENTIFIC_EVIDENCE
        and assessment.scientific_evidence_eligible is True
    )
    checks.append(
        (
            "research_question_scientific_scope",
            "PASS" if scientific_question else assessment.verification_status.value,
        )
    )
    checks.append(("research_question_gate_outcome", assessment.outcome.value))
    if (
        scientific_question
        and assessment.outcome is ResearchGateOutcome.INSUFFICIENT_NOVELTY
    ):
        return _resolution(
            evaluator_class=evaluator_class,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="SCIENTIFIC_RESEARCH_QUESTION_INSUFFICIENT_NOVELTY",
            checks=checks,
            subject_key=subject_key,
        )
    if not scientific_question:
        blocker = (
            "NON_EVIDENTIARY_MECHANICAL"
            if assessment.verification_status
            is ScientificGateVerificationStatus.NON_EVIDENTIARY
            else "SCIENTIFIC_GATE_AUTHORITY_UNAVAILABLE"
        )
        checks.append(("research_question_authority_blocker", blocker))
        return _resolution(
            evaluator_class=evaluator_class,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code=blocker,
            checks=checks,
            subject_key=subject_key,
        )

    if evaluator_class is EvaluatorClass.E2:
        assert audit is not None
        checks.append(("experimental_design_audit", audit.status.value))
        if audit.scientific_source_qualified is not True:
            return _resolution(
                evaluator_class=evaluator_class,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="EXPERIMENTAL_DESIGN_AUDIT_AUTHORITY_UNAVAILABLE",
                checks=checks,
                subject_key=subject_key,
            )
        if audit.status is SemanticChallengeAuditStatus.FAIL:
            return _resolution(
                evaluator_class=evaluator_class,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code="EXPERIMENTAL_DESIGN_AUDIT_FAILED",
                checks=checks,
                subject_key=subject_key,
            )
        if audit.status is not SemanticChallengeAuditStatus.PASS:
            return _resolution(
                evaluator_class=evaluator_class,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code="EXPERIMENTAL_DESIGN_AUDIT_INCOMPLETE",
                checks=checks,
                subject_key=subject_key,
            )

    if assessment.outcome is not ResearchGateOutcome.PROCEED:
        checks.append(("research_question_outcome_scope", "INCOMPLETE_NOT_INVALID"))
        return _resolution(
            evaluator_class=evaluator_class,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="RESEARCH_QUESTION_REQUIRES_FURTHER_WORK",
            checks=checks,
            subject_key=subject_key,
        )

    return _resolution(
        evaluator_class=evaluator_class,
        status=AuthorityStatus.PASS,
        scope=AuthorityScope.SCIENTIFIC,
        reason_code=(
            "SCIENTIFIC_RESEARCH_QUESTION_AND_DESIGN_AUDIT_REPLAYED"
            if evaluator_class is EvaluatorClass.E2
            else "SCIENTIFIC_RESEARCH_QUESTION_AND_CONTRACT_REPLAYED"
        ),
        checks=checks,
        subject_key=subject_key,
    )


def _domain_subject(
    run_id: str,
    record: ArtifactRecord,
    resolved: Any,
    registry: ArtifactRegistry,
    ledger: EventLedger,
) -> tuple[tuple[str, str], ...]:
    manifest_record = registry.get_metadata(resolved.manifest_artifact_sha256)
    values = [
        ("run_id", run_id),
        ("domain_object_id", resolved.object_id),
        ("domain_task_id", resolved.task_id),
        ("domain_validity_artifact_sha256", record.sha256),
        ("domain_validity_record_hash", str(record.record_hash)),
        ("domain_manifest_artifact_sha256", manifest_record.sha256),
        ("domain_manifest_record_hash", str(manifest_record.record_hash)),
    ]
    if resolved.projection_artifact_sha256 is not None:
        projection_record = registry.get_metadata(resolved.projection_artifact_sha256)
        from .generic_ml_projection import (
            require_generic_ml_paired_metric_projection_authority,
        )
        from .security import safe_json_loads

        projection_payload = safe_json_loads(
            registry.get_bytes(projection_record.sha256)
        )
        if not isinstance(projection_payload, Mapping):
            raise ValueError("domain projection payload is not an object")
        selector_fields = {
            "scientific_domain_evidence_source_artifact_sha256",
            "execution_run_id",
            "evaluation_contract_artifact_sha256",
            "output_manifest_artifact_sha256",
        }
        if selector_fields.issubset(projection_payload):
            source_artifact_sha256 = str(
                projection_payload["scientific_domain_evidence_source_artifact_sha256"]
            )
            projection = require_generic_ml_paired_metric_projection_authority(
                registry,
                ledger,
                projection_artifact_sha256=projection_record.sha256,
                expected_ledger_run_id=run_id,
                expected_execution_run_id=str(projection_payload["execution_run_id"]),
                expected_domain_evidence_source_artifact_sha256=(
                    source_artifact_sha256
                ),
                expected_contract_artifact_sha256=str(
                    projection_payload["evaluation_contract_artifact_sha256"]
                ),
                expected_output_manifest_artifact_sha256=str(
                    projection_payload["output_manifest_artifact_sha256"]
                ),
            )
            from .experiments import require_scientific_execution_run_spec
            from .scientific_design import require_frozen_evaluation_contract

            contract = require_frozen_evaluation_contract(
                registry,
                contract_artifact_sha256=(
                    projection.evaluation_contract_artifact_sha256
                ),
            )
            spec = require_scientific_execution_run_spec(
                registry,
                frozen_run_spec_artifact_sha256=(
                    projection.frozen_run_spec_artifact_sha256
                ),
            )
            values.extend(
                (
                    ("execution_run_id", projection.execution_run_id),
                    ("dataset_id", contract.dataset.dataset_id),
                    (
                        "contract_artifact_sha256",
                        projection.evaluation_contract_artifact_sha256,
                    ),
                    (
                        "contract_record_hash",
                        projection.evaluation_contract_record_hash,
                    ),
                    ("contract_sha256", contract.sha256),
                    (
                        "frozen_run_spec_artifact_sha256",
                        projection.frozen_run_spec_artifact_sha256,
                    ),
                    (
                        "frozen_run_spec_record_hash",
                        projection.frozen_run_spec_record_hash,
                    ),
                    ("frozen_run_spec_sha256", spec.sha256),
                    (
                        "scientific_execution_authority_artifact_sha256",
                        projection.scientific_execution_authority_artifact_sha256,
                    ),
                    (
                        "scientific_execution_authority_record_hash",
                        projection.scientific_execution_authority_record_hash,
                    ),
                    (
                        "dataset_artifact_sha256",
                        projection.dataset_authority_artifact_sha256,
                    ),
                    (
                        "dataset_record_hash",
                        projection.dataset_authority_record_hash,
                    ),
                    (
                        "dataset_raw_artifact_sha256",
                        projection.dataset_raw_artifact_sha256,
                    ),
                    (
                        "dataset_raw_record_hash",
                        projection.dataset_raw_record_hash,
                    ),
                    (
                        "canonical_run_artifact_sha256",
                        projection.canonical_run_artifact_sha256,
                    ),
                    (
                        "canonical_run_record_hash",
                        projection.canonical_run_record_hash,
                    ),
                    (
                        "canonical_run_content_hash",
                        projection.canonical_run_content_hash,
                    ),
                )
            )
        values.extend(
            (
                ("domain_projection_artifact_sha256", projection_record.sha256),
                ("domain_projection_record_hash", str(projection_record.record_hash)),
            )
        )
    return tuple(values)


def _domain_admission_after_full_replay(
    *,
    record: ArtifactRecord,
    events: tuple[Any, ...],
) -> _ScientificSourceAdmission:
    """Retain the exact publication already validated by the full v3 owner.

    The domain owner binds one deterministic receipt-specific event ID and
    compares the entire expected event and its correction history. This is
    only a projection of that completed replay under the enclosing paired
    snapshot; it cannot authenticate a caller-constructed receipt or event.
    """

    from .domains import _scientific_domain_validity_event_id

    event_id = _scientific_domain_validity_event_id(record.sha256)
    matches = tuple((index, event) for index, event in enumerate(events) if event.event_id == event_id)
    if len(matches) != 1:
        raise ValueError("domain source lacks its unique owner-validated publication")
    index, event = matches[0]
    return _ScientificSourceAdmission(
        artifact_sha256=record.sha256,
        artifact_record_hash=str(record.record_hash),
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=index,
    )


def _resolve_r3_e0_domain(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    record: ArtifactRecord,
    payload: Mapping[str, Any],
) -> ScientificRCheckResolution:
    from .domains import (
        DomainEvidenceScope,
        DomainKind,
        DomainValidityStatus,
        require_projection_backed_scientific_domain_validity,
        resolve_domain_validity,
    )

    domain = DomainKind(str(payload["domain"]))
    object_id = str(payload["object_id"])
    task_id = str(payload["task_id"])
    resolved = resolve_domain_validity(
        registry,
        record.sha256,
        expected_run_id=run_id,
        expected_domain=domain,
        expected_object_id=object_id,
        expected_task_id=task_id,
        ledger=ledger,
    )
    subject_key = _domain_subject(run_id, record, resolved, registry, ledger)
    checks: list[tuple[str, str]] = [
        ("domain_validity_owner_replay", "PASS"),
        ("domain_scope", resolved.scope.value),
        (
            "domain_projection",
            "PASS" if resolved.projection_artifact_sha256 else "UNAVAILABLE",
        ),
    ]
    checks.extend(
        (f"domain_check:{item.machine_code}", item.status.value)
        for item in resolved.outcome.checks
    )
    if resolved.scope is not DomainEvidenceScope.SCIENTIFIC_EVIDENCE:
        return ScientificRCheckResolution(
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="NON_EVIDENTIARY_DOMAIN_FIXTURE",
            checks=tuple(checks),
            subject_key=subject_key,
        )
    if resolved.projection_artifact_sha256 is None:
        return ScientificRCheckResolution(
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="PROJECTION_BACKED_DOMAIN_VALIDITY_UNAVAILABLE",
            checks=tuple(checks),
            subject_key=subject_key,
        )
    if resolved.outcome.status is DomainValidityStatus.FAIL:
        return ScientificRCheckResolution(
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="PROJECTION_BACKED_DOMAIN_VALIDITY_FAILED",
            checks=tuple(checks),
            subject_key=subject_key,
        )
    if resolved.outcome.status is DomainValidityStatus.BLOCKED:
        return ScientificRCheckResolution(
            r_check=RCheck.R3,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SCIENTIFIC,
            reason_code="PROJECTION_BACKED_DOMAIN_VALIDITY_BLOCKED",
            checks=tuple(checks),
            subject_key=subject_key,
        )
    required = require_projection_backed_scientific_domain_validity(
        registry,
        record.sha256,
        expected_run_id=run_id,
        expected_domain=domain,
        expected_object_id=object_id,
        expected_task_id=task_id,
        ledger=ledger,
    )
    if required != resolved:
        raise ValueError("projection-backed domain owner changed during composition")
    return ScientificRCheckResolution(
        r_check=RCheck.R3,
        evaluator_class=EvaluatorClass.E0,
        status=AuthorityStatus.PASS,
        scope=AuthorityScope.SCIENTIFIC,
        reason_code="PROJECTION_BACKED_DOMAIN_VALIDITY_REPLAYED",
        checks=tuple(checks),
        subject_key=subject_key,
    )


@dataclass(frozen=True, slots=True)
class _CanonicalScientificSubject:
    scoped: Any
    result: Any
    result_record: ArtifactRecord
    result_binding: Any
    statistical_test: Any
    statistical_test_record: ArtifactRecord
    statistical_test_binding: Any
    run: Any
    run_record: ArtifactRecord
    implementation: Any
    implementation_record: ArtifactRecord
    method: Any
    method_record: ArtifactRecord
    dataset: Any
    dataset_record: ArtifactRecord
    promotion_record: ArtifactRecord
    projection: Any
    spec: Any
    spec_record: ArtifactRecord
    method_binding: Any | None


def _canonical_state_value(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
) -> Any:
    from .research_state import CanonicalResearchObject
    from .security import safe_json_loads

    if not record.logical_type.startswith("research_state."):
        raise ValueError("selected artifact is not canonical research state")
    raw = registry.get_bytes(record.sha256)
    value = safe_json_loads(raw)
    if not isinstance(value, Mapping):
        raise ValueError("canonical research-state payload is not an object")
    result = CanonicalResearchObject.from_dict(value)
    if result.logical_type != record.logical_type or result.canonical_bytes() != raw:
        raise ValueError("canonical research-state bytes or type are substituted")
    return result


def _canonical_v3_selected(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
) -> bool:
    """Select exact canonical v3/v4 views of the method-neutral v3 owner.

    The logical types predate the outcome-neutral v3 projection, so version
    dispatch belongs to the canonical metadata owned by that projection.  Old
    pairs retain the historical evaluator path instead of being reinterpreted.
    """

    from .models import thaw_json
    from .scientific_design import (
        SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3,
        SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4,
        SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3,
        SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4,
    )

    by_type = {record.logical_type: record for record in records}
    result = _canonical_state_value(registry, by_type[_CANONICAL_RESULT])
    statistical_test = _canonical_state_value(
        registry,
        by_type[_CANONICAL_STATISTICAL_TEST],
    )
    result_schema = thaw_json(result.metadata).get("schema_version")
    statistical_schema = thaw_json(statistical_test.metadata).get("schema_version")
    exact_pairs = (
        (SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3, SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3),
        (SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V4, SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V4),
    )
    if (result_schema, statistical_schema) in exact_pairs:
        return True
    if (
        isinstance(result_schema, str)
        and result_schema.startswith("scientific-result-canonical-state/")
    ) or (
        isinstance(statistical_schema, str)
        and statistical_schema.startswith("scientific-statistical-canonical-state/")
    ):
        raise ValueError("canonical Result/Test schema profiles disagree")
    return False


def _canonical_record_for_reference(
    registry: ArtifactRegistry,
    reference: Any,
) -> tuple[Any, ArtifactRecord]:
    matches: list[tuple[Any, ArtifactRecord]] = []
    snake_type = re.sub(r"(?<!^)(?=[A-Z])", "_", reference.object_type).lower()
    expected_type = f"research_state.{snake_type}"
    for record in registry.list_records():
        if record.logical_type != expected_type:
            continue
        value = _canonical_state_value(registry, record)
        if (
            value.object_id == reference.object_id
            and value.content_hash == reference.content_hash
        ):
            matches.append((value, record))
    if len(matches) != 1:
        raise ValueError("canonical parent reference is absent or ambiguous")
    return matches[0]


def _one_parent(record: Any, object_type: str, relation: str) -> Any:
    matches = tuple(
        value
        for value in record.parents
        if value.object_type == object_type and value.relation == relation
    )
    if len(matches) != 1 or matches[0].evaluated is not True:
        raise ValueError("canonical scientific parent is absent or ambiguous")
    return matches[0]


def _canonical_subject(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    records: tuple[ArtifactRecord, ...],
    require_explicit_structure: bool,
) -> _CanonicalScientificSubject:
    from .experiments import (
        require_scientific_execution_run_spec,
        resolve_scientific_method_definition_binding,
    )
    from .models import thaw_json
    from .research_state import (
        Implementation,
        Method,
        Result,
        Run,
        StatisticalTest,
        _resolve_current_research_state_bindings,
        resolve_current_research_state_bindings,
    )
    from .scientific_design import (
        SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3,
        require_scientific_result_canonical_projection_v3,
    )

    by_type = {record.logical_type: record for record in records}
    selected_state = (
        by_type[_CANONICAL_RESULT],
        by_type[_CANONICAL_STATISTICAL_TEST],
    )
    if require_explicit_structure:
        selected_state = (
            by_type[_CANONICAL_RESULT],
            by_type[_CANONICAL_STATISTICAL_TEST],
            by_type[_CANONICAL_RUN],
            by_type[_CANONICAL_IMPLEMENTATION],
            by_type[_CANONICAL_METHOD],
        )
        scoped = _resolve_current_research_state_bindings(
            registry,
            ledger,
            run_id=run_id,
            state_artifact_hashes=tuple(item.sha256 for item in selected_state),
            allowed_object_types=frozenset(
                {"Result", "StatisticalTest", "Run", "Implementation", "Method"}
            ),
        )
    else:
        scoped = resolve_current_research_state_bindings(
            registry,
            ledger,
            run_id=run_id,
            state_artifact_hashes=tuple(item.sha256 for item in selected_state),
        )
    binding_by_artifact = {item.artifact_sha256: item for item in scoped.entries}
    if set(binding_by_artifact) != {item.sha256 for item in selected_state}:
        raise ValueError("canonical owner returned another selected source set")
    result_binding = binding_by_artifact[by_type[_CANONICAL_RESULT].sha256]
    statistical_binding = binding_by_artifact[
        by_type[_CANONICAL_STATISTICAL_TEST].sha256
    ]
    result = result_binding.research_object
    statistical_test = statistical_binding.research_object
    if not isinstance(result, Result) or not isinstance(
        statistical_test,
        StatisticalTest,
    ):
        raise ValueError("canonical Result/Test selection is malformed")

    run_reference = _one_parent(result, "Run", "aggregates")
    run, run_record = _canonical_record_for_reference(registry, run_reference)
    experiment_reference = _one_parent(run, "Experiment", "executes")
    experiment, _experiment_record = _canonical_record_for_reference(
        registry,
        experiment_reference,
    )
    implementation_reference = _one_parent(experiment, "Implementation", "uses")
    implementation, implementation_record = _canonical_record_for_reference(
        registry,
        implementation_reference,
    )
    method_reference = _one_parent(implementation, "Method", "implements")
    method, method_record = _canonical_record_for_reference(
        registry,
        method_reference,
    )
    dataset_references = tuple(
        value
        for value in experiment.parents
        if value.object_type == "Dataset" and value.relation == "uses"
    )
    if len(dataset_references) != 1 or dataset_references[0].evaluated is not True:
        raise ValueError("canonical scientific Dataset parent is ambiguous")
    dataset, dataset_record = _canonical_record_for_reference(
        registry,
        dataset_references[0],
    )
    if (
        not isinstance(run, Run)
        or not isinstance(implementation, Implementation)
        or not isinstance(method, Method)
    ):
        raise ValueError("canonical Method/Implementation/Run ancestry is malformed")
    if require_explicit_structure and (
        run_record != by_type[_CANONICAL_RUN]
        or implementation_record != by_type[_CANONICAL_IMPLEMENTATION]
        or method_record != by_type[_CANONICAL_METHOD]
    ):
        raise ValueError("selected canonical structure is not the Result ancestry")

    promotion_hashes = tuple(
        digest
        for digest, logical_type in zip(
            result_binding.authority_artifact_hashes,
            result_binding.authority_logical_types,
            strict=True,
        )
        if logical_type == SCIENTIFIC_RESULT_PROMOTION_RECEIPT_LOGICAL_TYPE_V3
    )
    if len(promotion_hashes) != 1 or promotion_hashes[0] not in (
        statistical_binding.authority_artifact_hashes
    ):
        raise ValueError("canonical Result/Test do not share one v3 promotion")
    promotion_record = registry.get_metadata(promotion_hashes[0])
    projection = require_scientific_result_canonical_projection_v3(
        registry,
        ledger,
        promotion_receipt_artifact_sha256=promotion_record.sha256,
        expected_ledger_run_id=run_id,
        expected_execution_run_id=run.object_id,
        expected_result_id=result.object_id,
        canonical_state_code_version=scoped.code_version,
    )
    spec_record = registry.get_metadata(projection.frozen_run_spec_artifact_sha256)
    if require_explicit_structure and spec_record != by_type[_FROZEN_RUN_SPEC]:
        raise ValueError("selected frozen run spec is not the Result projection spec")
    spec = require_scientific_execution_run_spec(
        registry,
        frozen_run_spec_artifact_sha256=spec_record.sha256,
    )
    method_binding = resolve_scientific_method_definition_binding(
        registry,
        spec=spec,
    )
    joined = (
        result.run_ids == (run.object_id,)
        and statistical_test.result_ids == (result.object_id,)
        and statistical_test.parents
        == (_one_parent(statistical_test, "Result", "tests"),)
        and statistical_test.parents[0].content_hash == result.content_hash
        and run.parents == (experiment_reference,)
        and run.experiment_id == experiment.object_id
        and implementation.parents == (method_reference,)
        and experiment.implementation_id == implementation.object_id
        and experiment.dataset_ids == (dataset.object_id,)
        and run.dataset_ids == experiment.dataset_ids
        and run.object_id == projection.execution_run_id
        and spec.run_id == run.object_id
        and spec.experiment_id == experiment.object_id
        and run.code_revision == projection.execution_code_revision
        and run.configuration_artifact_hash == spec.configuration_sha256
        and implementation.method_id == method.object_id
        and implementation.code_artifact_hashes == (spec.code_sha256,)
        and implementation.configuration_artifact_hashes == (spec.configuration_sha256,)
        and thaw_json(result.metadata) == projection.state_metadata
        and thaw_json(statistical_test.metadata)
        == projection.statistical_state_metadata
    )
    if not joined:
        raise ValueError("canonical scientific Result subject is internally spliced")
    if method_binding is not None and (
        method.authority_artifact_hashes
        != (method_binding.method_definition_artifact_sha256,)
        or method_binding.method_definition_record_hash
        != str(
            registry.get_metadata(
                method_binding.method_definition_artifact_sha256
            ).record_hash
        )
        or method.object_id != method_binding.method_id
        or method.name != method_binding.name
        or method.description != method_binding.description
        or method.assumptions != method_binding.assumptions
        or method.component_ids != method_binding.component_ids
    ):
        raise ValueError("canonical Method differs from prospective definition")
    return _CanonicalScientificSubject(
        scoped=scoped,
        result=result,
        result_record=by_type[_CANONICAL_RESULT],
        result_binding=result_binding,
        statistical_test=statistical_test,
        statistical_test_record=by_type[_CANONICAL_STATISTICAL_TEST],
        statistical_test_binding=statistical_binding,
        run=run,
        run_record=run_record,
        implementation=implementation,
        implementation_record=implementation_record,
        method=method,
        method_record=method_record,
        dataset=dataset,
        dataset_record=dataset_record,
        promotion_record=promotion_record,
        projection=projection,
        spec=spec,
        spec_record=spec_record,
        method_binding=method_binding,
    )


def _canonical_subject_key(
    run_id: str,
    subject: _CanonicalScientificSubject,
    registry: ArtifactRegistry,
    *,
    audit: Any | None = None,
    audit_record: ArtifactRecord | None = None,
) -> tuple[tuple[str, str], ...]:
    projection = subject.projection
    contract_record = registry.get_metadata(projection.contract_artifact_sha256)
    from .scientific_design import require_frozen_evaluation_contract

    contract = require_frozen_evaluation_contract(
        registry,
        contract_artifact_sha256=contract_record.sha256,
    )
    execution_record = registry.get_metadata(
        projection.scientific_execution_authority_artifact_sha256
    )
    code_record = registry.get_metadata(subject.spec.code_sha256)
    configuration_record = registry.get_metadata(subject.spec.configuration_sha256)
    assessment_record = registry.get_metadata(
        projection.checked_result_assessment_artifact_sha256
    )
    dataset_authority_hashes = tuple(subject.dataset.authority_artifact_hashes)
    dataset_artifact_sha256 = (
        dataset_authority_hashes[0]
        if len(dataset_authority_hashes) == 1
        and registry.get_metadata(dataset_authority_hashes[0]).logical_type
        == "scientific_dataset_authority"
        else projection.data_artifact_sha256
    )
    dataset_source_record = registry.get_metadata(dataset_artifact_sha256)
    projected_dataset_record = registry.get_metadata(projection.data_artifact_sha256)
    values = [
        ("run_id", run_id),
        ("execution_run_id", projection.execution_run_id),
        ("contract_artifact_sha256", contract_record.sha256),
        ("contract_record_hash", str(contract_record.record_hash)),
        ("contract_sha256", contract.sha256),
        ("frozen_run_spec_artifact_sha256", subject.spec_record.sha256),
        ("frozen_run_spec_record_hash", str(subject.spec_record.record_hash)),
        ("frozen_run_spec_sha256", subject.spec.sha256),
        ("code_artifact_sha256", code_record.sha256),
        ("code_artifact_record_hash", str(code_record.record_hash)),
        ("configuration_artifact_sha256", configuration_record.sha256),
        ("configuration_artifact_record_hash", str(configuration_record.record_hash)),
        ("scientific_execution_authority_artifact_sha256", execution_record.sha256),
        (
            "scientific_execution_authority_record_hash",
            str(execution_record.record_hash),
        ),
        ("checked_result_assessment_artifact_sha256", assessment_record.sha256),
        ("checked_result_assessment_record_hash", str(assessment_record.record_hash)),
        (
            "scientific_result_promotion_artifact_sha256",
            subject.promotion_record.sha256,
        ),
        (
            "scientific_result_promotion_record_hash",
            str(subject.promotion_record.record_hash),
        ),
        ("method_id", subject.method.object_id),
        ("method_content_hash", subject.method.content_hash),
        ("canonical_method_artifact_sha256", subject.method_record.sha256),
        ("canonical_method_record_hash", str(subject.method_record.record_hash)),
        ("implementation_id", subject.implementation.object_id),
        ("implementation_content_hash", subject.implementation.content_hash),
        (
            "canonical_implementation_artifact_sha256",
            subject.implementation_record.sha256,
        ),
        (
            "canonical_implementation_record_hash",
            str(subject.implementation_record.record_hash),
        ),
        ("canonical_run_artifact_sha256", subject.run_record.sha256),
        ("canonical_run_record_hash", str(subject.run_record.record_hash)),
        ("canonical_run_content_hash", subject.run.content_hash),
        ("result_id", subject.result.object_id),
        ("result_content_hash", subject.result.content_hash),
        ("canonical_result_artifact_sha256", subject.result_record.sha256),
        ("canonical_result_record_hash", str(subject.result_record.record_hash)),
        ("statistical_test_id", subject.statistical_test.object_id),
        ("statistical_test_content_hash", subject.statistical_test.content_hash),
        (
            "canonical_statistical_test_artifact_sha256",
            subject.statistical_test_record.sha256,
        ),
        (
            "canonical_statistical_test_record_hash",
            str(subject.statistical_test_record.record_hash),
        ),
        ("dataset_id", subject.dataset.object_id),
        ("dataset_artifact_sha256", dataset_source_record.sha256),
        ("dataset_record_hash", str(dataset_source_record.record_hash)),
        ("dataset_projection_artifact_sha256", projected_dataset_record.sha256),
        ("dataset_projection_record_hash", str(projected_dataset_record.record_hash)),
        ("canonical_dataset_artifact_sha256", subject.dataset_record.sha256),
        ("canonical_dataset_record_hash", str(subject.dataset_record.record_hash)),
        ("canonical_dataset_content_hash", subject.dataset.content_hash),
        ("scientific_result_outcome", subject.projection.outcome.value),
    ]
    if subject.method_binding is not None:
        values.extend(
            (
                (
                    "method_definition_artifact_sha256",
                    subject.method_binding.method_definition_artifact_sha256,
                ),
                (
                    "method_definition_record_hash",
                    subject.method_binding.method_definition_record_hash,
                ),
            )
        )
    if audit is not None and audit_record is not None:
        values.extend(
            (
                ("semantic_audit_artifact_sha256", audit_record.sha256),
                ("semantic_audit_record_hash", str(audit_record.record_hash)),
                (
                    "canonical_snapshot_artifact_sha256",
                    audit.research_state_snapshot_artifact_hash,
                ),
                (
                    "canonical_snapshot_record_hash",
                    audit.research_state_snapshot_artifact_record_hash,
                ),
            )
        )
    return tuple(values)


def _canonical_source_admissions(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    subject: _CanonicalScientificSubject,
    include_frozen_spec: bool,
) -> tuple[_ScientificSourceAdmission, ...]:
    """Retain named canonical admissions and the exact spec's design freeze.

    `subject` is the result of the complete canonical source replay above.
    The additional spec source is followed through that same promotion's
    owned timeline/protocol, never chosen from generic artifact references.
    """

    admissions = tuple(_ScientificSourceAdmission(
        artifact_sha256=item.artifact_sha256,
        artifact_record_hash=item.artifact_record_hash,
        ledger_event_id=item.materialization_event_id,
        ledger_event_hash=item.materialization_event_hash,
        ledger_event_index=item.materialization_event_index,
    ) for item in subject.scoped.entries)
    if not include_frozen_spec:
        return admissions
    from .evaluators import _canonical_json_artifact
    from .scientific_design import (
        ScientificResultPromotionReceiptV3,
        ScientificConfirmatoryTimelineReceiptV2,
        _require_scientific_confirmatory_timeline_source_v2,
        require_evaluation_contract_freeze_gate_receipt,
        require_frozen_evaluation_contract,
    )

    promotion = ScientificResultPromotionReceiptV3.from_dict(
        _canonical_json_artifact(registry, subject.promotion_record),
    )
    timeline_record = registry.get_metadata(promotion.scientific_timeline_receipt_artifact_sha256)
    stated = ScientificConfirmatoryTimelineReceiptV2.from_dict(
        _canonical_json_artifact(registry, timeline_record),
    )
    timeline = _require_scientific_confirmatory_timeline_source_v2(
        registry, ledger,
        receipt_artifact_sha256=timeline_record.sha256,
        expected_ledger_run_id=run_id,
        expected_execution_run_id=subject.run.object_id,
        expected_contract_artifact_sha256=subject.projection.contract_artifact_sha256,
        expected_preparation_artifact_sha256=stated.scientific_execution_preparation_artifact_sha256,
        expected_execution_authority_artifact_sha256=subject.projection.scientific_execution_authority_artifact_sha256,
        expected_output_manifest_artifact_sha256=stated.output_manifest_artifact_sha256,
        expected_generic_ml_projection_artifact_sha256=stated.generic_ml_projection_artifact_sha256,
    )
    protocol = timeline.protocol_binding
    contract = require_frozen_evaluation_contract(
        registry, contract_artifact_sha256=subject.projection.contract_artifact_sha256,
    )
    freeze = require_evaluation_contract_freeze_gate_receipt(
        registry, ledger,
        receipt_artifact_sha256=protocol.evaluation_contract_freeze_receipt_artifact_sha256,
        expected_run_id=run_id,
        expected_contract_id=contract.contract_id,
    )
    if (
        timeline.receipt != stated
        or timeline.record != timeline_record
        or promotion.ledger_run_id != run_id
        or promotion.execution_run_id != subject.run.object_id
        or promotion.result_id != subject.result.object_id
        or freeze.contract_artifact_sha256 != subject.projection.contract_artifact_sha256
        or freeze.contract_sha256 != contract.sha256
        or freeze.frozen_run_spec_artifact_sha256 != subject.spec_record.sha256
        or freeze.frozen_run_spec_record_hash != str(subject.spec_record.record_hash)
        or freeze.frozen_run_spec_sha256 != subject.spec.sha256
        or protocol.frozen_run_spec_artifact_sha256 != subject.spec_record.sha256
        or protocol.frozen_run_spec_record_hash != str(subject.spec_record.record_hash)
        or protocol.frozen_run_spec_sha256 != subject.spec.sha256
        or freeze.design_freeze_event_index >= timeline.publication_event_index
    ):
        raise ValueError("canonical spec admission is not its owned design freeze")
    return (*admissions, _ScientificSourceAdmission(
        artifact_sha256=subject.spec_record.sha256,
        artifact_record_hash=str(subject.spec_record.record_hash),
        ledger_event_id=freeze.design_freeze_event_id,
        ledger_event_hash=freeze.design_freeze_event_hash,
        ledger_event_index=freeze.design_freeze_event_index,
    ))


def _replay_semantic_audit(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    record: ArtifactRecord,
    payload: Mapping[str, Any],
    category: Any,
) -> tuple[Any, Mapping[str, str], Any]:
    from .gates import (
        SemanticChallengeAuditAuthority,
        _semantic_challenger_audit_content_projection,
        _require_semantic_challenge_audit_source,
    )

    stated = SemanticChallengeAuditAuthority.from_dict(payload)
    source = _require_semantic_challenge_audit_source(
        registry,
        ledger,
        authority_artifact_hash=record.sha256,
        expected_run_id=run_id,
        expected_assessment_id=stated.assessment_id,
        expected_category=category,
        expected_research_state_snapshot_artifact_hash=(
            stated.research_state_snapshot_artifact_hash
        ),
        expected_claim_graph_artifact_hash=stated.claim_graph_artifact_hash,
        expected_central_claim_ids=stated.central_claim_ids,
        expected_reproducibility_package_artifact_hash=(
            stated.reproducibility_package_artifact_hash
        ),
    )
    audit = source.authority
    if audit != stated or source.record != record:
        raise ValueError("semantic audit owner returned another authority")
    projection = _semantic_challenger_audit_content_projection(
        registry,
        (
            audit.claim_graph_artifact_hash,
            *audit.evidence_artifact_hashes,
            *audit.result_artifact_hashes,
        ),
    )
    bindings = {
        str(item["artifact_sha256"]): str(item["artifact_record_hash"])
        for item in projection
    }
    return audit, bindings, source


def _derive_canonical_check(
    *,
    r_check: RCheck,
    evaluator_class: EvaluatorClass,
    subject: _CanonicalScientificSubject,
    registry: ArtifactRegistry,
    run_id: str,
    audit: Any | None = None,
    audit_record: ArtifactRecord | None = None,
    audit_bindings: Mapping[str, str] | None = None,
) -> ScientificRCheckResolution:
    from .gates import SemanticChallengeAuditStatus

    checks: list[tuple[str, str]] = [
        ("canonical_scoped_owner_replay", "PASS"),
        ("outcome_neutral_result_test_join", "PASS"),
    ]
    if not (
        subject.result_binding.scientific_evidence_eligible
        and subject.statistical_test_binding.scientific_evidence_eligible
    ):
        checks.append(("canonical_scientific_evidence_eligibility", "UNAVAILABLE"))
        return _resolution(
            r_check=r_check,
            evaluator_class=evaluator_class,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="CANONICAL_SCIENTIFIC_AUTHORITY_UNAVAILABLE",
            checks=checks,
            subject_key=_canonical_subject_key(run_id, subject, registry),
        )
    checks.append(("canonical_scientific_evidence_eligibility", "PASS"))
    if r_check is RCheck.R2:
        checks.extend(
            (
                ("method_implementation_run_spec_structural_join", "PASS"),
                (
                    "structural_claim_scope",
                    "INTENTION_PROVENANCE_NOT_CODE_SEMANTICS",
                ),
            )
        )
        if subject.method_binding is None:
            checks.append(("prospective_method_definition", "UNAVAILABLE"))
            return _resolution(
                r_check=r_check,
                evaluator_class=evaluator_class,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code="PROSPECTIVE_METHOD_DEFINITION_UNAVAILABLE",
                checks=checks,
                subject_key=_canonical_subject_key(run_id, subject, registry),
            )
        checks.append(("prospective_method_definition", "PASS"))

    if evaluator_class is EvaluatorClass.E2:
        if audit is None or audit_record is None or audit_bindings is None:
            raise ValueError("semantic R-check requires its exact audit")
        selected = (
            subject.result_record,
            subject.statistical_test_record,
        )
        direct = dict(
            zip(
                audit.result_artifact_hashes,
                audit.result_artifact_record_hashes,
                strict=True,
            )
        )
        required_records = (
            subject.result_record,
            subject.statistical_test_record,
            subject.run_record,
            subject.implementation_record,
            subject.method_record,
            subject.spec_record,
            registry.get_metadata(subject.spec.code_sha256),
            registry.get_metadata(subject.spec.configuration_sha256),
            *(
                (
                    registry.get_metadata(
                        subject.method_binding.method_definition_artifact_sha256
                    ),
                )
                if subject.method_binding is not None
                else ()
            ),
        )
        audit_joined = all(
            direct.get(item.sha256) == str(item.record_hash) for item in selected
        ) and all(
            audit_bindings.get(item.sha256) == str(item.record_hash)
            for item in required_records
        )
        checks.append(
            (
                "semantic_audit_same_canonical_subject",
                "PASS" if audit_joined else "FAIL",
            )
        )
        if not audit_joined:
            return _resolution(
                r_check=r_check,
                evaluator_class=evaluator_class,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code="SCIENTIFIC_R_CHECK_AUDIT_SUBJECT_MISMATCH",
                checks=checks,
                subject_key=_canonical_subject_key(
                    run_id,
                    subject,
                    registry,
                    audit=audit,
                    audit_record=audit_record,
                ),
            )
        checks.append(("semantic_audit", audit.status.value))
        if audit.scientific_source_qualified is not True:
            return _resolution(
                r_check=r_check,
                evaluator_class=evaluator_class,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SEMANTIC_AUDIT_SCIENTIFIC_AUTHORITY_UNAVAILABLE",
                checks=checks,
                subject_key=_canonical_subject_key(
                    run_id, subject, registry, audit=audit, audit_record=audit_record
                ),
            )
        if audit.status is SemanticChallengeAuditStatus.FAIL:
            return _resolution(
                r_check=r_check,
                evaluator_class=evaluator_class,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code=(
                    "IMPLEMENTATION_AUDIT_FAILED"
                    if r_check is RCheck.R2
                    else "STATISTICS_AUDIT_FAILED"
                ),
                checks=checks,
                subject_key=_canonical_subject_key(
                    run_id, subject, registry, audit=audit, audit_record=audit_record
                ),
            )
        if audit.status is not SemanticChallengeAuditStatus.PASS:
            return _resolution(
                r_check=r_check,
                evaluator_class=evaluator_class,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code="SEMANTIC_AUDIT_INCOMPLETE",
                checks=checks,
                subject_key=_canonical_subject_key(
                    run_id, subject, registry, audit=audit, audit_record=audit_record
                ),
            )
    return _resolution(
        r_check=r_check,
        evaluator_class=evaluator_class,
        status=AuthorityStatus.PASS,
        scope=AuthorityScope.SCIENTIFIC,
        reason_code=(
            "SCIENTIFIC_METHOD_IMPLEMENTATION_STRUCTURE_REPLAYED"
            if r_check is RCheck.R2 and evaluator_class is EvaluatorClass.E0
            else "SCIENTIFIC_IMPLEMENTATION_AUDIT_REPLAYED"
            if r_check is RCheck.R2
            else "SCIENTIFIC_RESULT_STATISTICS_REPLAYED"
            if evaluator_class is EvaluatorClass.E0
            else "SCIENTIFIC_STATISTICS_AUDIT_REPLAYED"
        ),
        checks=checks,
        subject_key=_canonical_subject_key(
            run_id,
            subject,
            registry,
            audit=audit,
            audit_record=audit_record,
        ),
    )


def _resolve_r3_e3_timeline(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    record: ArtifactRecord,
    payload: Mapping[str, Any],
) -> ScientificRCheckResolution:
    from .scientific_design import (
        ScientificConfirmatoryTimelineReceiptV2,
        _require_scientific_confirmatory_timeline_source_v2,
    )

    stated = ScientificConfirmatoryTimelineReceiptV2.from_dict(payload)
    source = _require_scientific_confirmatory_timeline_source_v2(
        registry,
        ledger,
        receipt_artifact_sha256=record.sha256,
        expected_ledger_run_id=run_id,
        expected_execution_run_id=stated.execution_run_id,
        expected_contract_artifact_sha256=stated.contract_artifact_sha256,
        expected_preparation_artifact_sha256=(
            stated.scientific_execution_preparation_artifact_sha256
        ),
        expected_execution_authority_artifact_sha256=(
            stated.scientific_execution_authority_artifact_sha256
        ),
        expected_output_manifest_artifact_sha256=(
            stated.output_manifest_artifact_sha256
        ),
        expected_generic_ml_projection_artifact_sha256=(
            stated.generic_ml_projection_artifact_sha256
        ),
    )
    receipt = source.receipt
    if receipt != stated or source.record != record or receipt.scientific_gate_passed is not True:
        raise ValueError("scientific confirmatory owner returned another receipt")
    # The complete timeline replay already resolved this exact prospective
    # protocol. Carry it with the actual validated publication, not the earlier
    # projection checkpoint stored inside the receipt.
    binding = source.protocol_binding
    source_records = {
        digest: registry.get_metadata(digest)
        for digest in (
            receipt.contract_artifact_sha256,
            receipt.scientific_execution_preparation_artifact_sha256,
            receipt.scientific_execution_authority_artifact_sha256,
            receipt.output_manifest_artifact_sha256,
            receipt.generic_ml_projection_artifact_sha256,
            receipt.confirmatory_timeline_receipt_artifact_sha256,
            receipt.confirmation_reveal_gate_receipt_artifact_sha256,
            binding.frozen_run_spec_artifact_sha256,
            binding.dataset_authority_artifact_sha256,
        )
    }
    subject_key = (
        ("run_id", run_id),
        ("execution_run_id", receipt.execution_run_id),
        ("protocol_binding_artifact_sha256", receipt.protocol_binding_artifact_sha256),
        ("protocol_binding_record_hash", receipt.protocol_binding_record_hash),
        ("contract_artifact_sha256", receipt.contract_artifact_sha256),
        (
            "contract_record_hash",
            str(source_records[receipt.contract_artifact_sha256].record_hash),
        ),
        ("contract_sha256", binding.contract_sha256),
        ("frozen_run_spec_artifact_sha256", binding.frozen_run_spec_artifact_sha256),
        ("frozen_run_spec_record_hash", binding.frozen_run_spec_record_hash),
        ("frozen_run_spec_sha256", binding.frozen_run_spec_sha256),
        (
            "scientific_execution_authority_artifact_sha256",
            receipt.scientific_execution_authority_artifact_sha256,
        ),
        (
            "scientific_execution_authority_record_hash",
            receipt.scientific_execution_authority_record_hash,
        ),
        ("dataset_artifact_sha256", binding.dataset_authority_artifact_sha256),
        ("dataset_record_hash", binding.dataset_authority_record_hash),
        ("dataset_id", binding.dataset_id),
        (
            "domain_projection_artifact_sha256",
            receipt.generic_ml_projection_artifact_sha256,
        ),
        ("domain_projection_record_hash", receipt.generic_ml_projection_record_hash),
        ("scientific_confirmatory_timeline_artifact_sha256", record.sha256),
        ("scientific_confirmatory_timeline_record_hash", str(record.record_hash)),
        (
            "legacy_confirmatory_timeline_artifact_sha256",
            receipt.confirmatory_timeline_receipt_artifact_sha256,
        ),
        (
            "legacy_confirmatory_timeline_record_hash",
            receipt.confirmatory_timeline_receipt_record_hash,
        ),
        (
            "confirmation_reveal_artifact_sha256",
            receipt.confirmation_reveal_gate_receipt_artifact_sha256,
        ),
        (
            "confirmation_reveal_record_hash",
            receipt.confirmation_reveal_gate_receipt_record_hash,
        ),
        ("confirmatory_projection_event_id", receipt.projection_event_id),
        ("confirmatory_projection_event_hash", receipt.projection_event_hash),
        ("ledger_prefix_head_hash", receipt.ledger_prefix_head_hash),
    )
    return _resolution(
        r_check=RCheck.R3,
        evaluator_class=EvaluatorClass.E3,
        status=AuthorityStatus.PASS,
        scope=AuthorityScope.SCIENTIFIC,
        reason_code="SCIENTIFIC_INDEPENDENT_CUSTODY_TIMELINE_REPLAYED",
        checks=(
            ("scientific_confirmatory_timeline_v2_owner_replay", "PASS"),
            ("independent_custody_scientific_gate", "PASS"),
            ("confirmatory_chronology", "PASS"),
        ),
        subject_key=subject_key,
        source_admissions=(_ScientificSourceAdmission(
            artifact_sha256=record.sha256,
            artifact_record_hash=str(record.record_hash),
            ledger_event_id=source.publication_event_id,
            ledger_event_hash=source.publication_event_hash,
            ledger_event_index=source.publication_event_index,
        ),),
    )


def _source_records(
    registry: ArtifactRegistry,
    source_artifact_sha256s: tuple[str, ...],
) -> tuple[ArtifactRecord, ...]:
    if (
        not source_artifact_sha256s
        or len(source_artifact_sha256s) > _MAX_SOURCES
        or len(set(source_artifact_sha256s)) != len(source_artifact_sha256s)
        or any(_SHA256.fullmatch(value) is None for value in source_artifact_sha256s)
    ):
        raise ValueError("scientific R-check source selection is invalid")
    return tuple(registry.get_metadata(value) for value in source_artifact_sha256s)


def _exact_route(
    r_check: RCheck,
    evaluator_class: EvaluatorClass,
    records: tuple[ArtifactRecord, ...],
) -> str | None:
    counts = Counter(record.logical_type for record in records)
    routes = {
        (
            RCheck.R1,
            EvaluatorClass.E0,
            ((_QUESTION_ASSESSMENT, 1),),
        ): "R1_ASSESSMENT_E0",
        (
            RCheck.R1,
            EvaluatorClass.E2,
            ((_QUESTION_ASSESSMENT, 1),),
        ): "R1_ASSESSMENT_E2",
        (
            RCheck.R1,
            EvaluatorClass.E0,
            ((_CONTRACT_FREEZE, 1), (_QUESTION_ASSESSMENT, 1)),
        ): "R1_E0",
        (
            RCheck.R1,
            EvaluatorClass.E2,
            (
                (_CONTRACT_FREEZE, 1),
                (_QUESTION_ASSESSMENT, 1),
                (_SEMANTIC_AUDIT, 1),
            ),
        ): "R1_E2",
        (
            RCheck.R3,
            EvaluatorClass.E0,
            ((_GENERIC_ML_DOMAIN_VALIDITY, 1),),
        ): "R3_E0_DOMAIN",
        (
            RCheck.R3,
            EvaluatorClass.E3,
            ((_SCIENTIFIC_CONFIRMATORY_TIMELINE_V2, 1),),
        ): "R3_E3_TIMELINE_V2",
        (
            RCheck.R4,
            EvaluatorClass.E0,
            ((_CANONICAL_RESULT, 1), (_CANONICAL_STATISTICAL_TEST, 1)),
        ): "R4_E0_CANONICAL_V3",
        (
            RCheck.R4,
            EvaluatorClass.E2,
            (
                (_CANONICAL_RESULT, 1),
                (_CANONICAL_STATISTICAL_TEST, 1),
                (_SEMANTIC_AUDIT, 1),
            ),
        ): "R4_E2_CANONICAL_V3",
        (
            RCheck.R2,
            EvaluatorClass.E0,
            (
                (_FROZEN_RUN_SPEC, 1),
                (_CANONICAL_IMPLEMENTATION, 1),
                (_CANONICAL_METHOD, 1),
                (_CANONICAL_RESULT, 1),
                (_CANONICAL_RUN, 1),
                (_CANONICAL_STATISTICAL_TEST, 1),
            ),
        ): "R2_E0_CANONICAL_V3",
        (
            RCheck.R2,
            EvaluatorClass.E2,
            (
                (_FROZEN_RUN_SPEC, 1),
                (_CANONICAL_IMPLEMENTATION, 1),
                (_CANONICAL_METHOD, 1),
                (_CANONICAL_RESULT, 1),
                (_CANONICAL_RUN, 1),
                (_CANONICAL_STATISTICAL_TEST, 1),
                (_SEMANTIC_AUDIT, 1),
            ),
        ): "R2_E2_CANONICAL_V3",
    }
    return routes.get((r_check, evaluator_class, tuple(sorted(counts.items()))))


def resolve_scientific_r_check_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    r_check: str | RCheck,
    evaluator_class: str | EvaluatorClass,
    source_artifact_sha256s: tuple[str, ...],
) -> ScientificRCheckResolution | None:
    """Freshly compose a recognized exact scientific R-check source set.

    A recognized set whose selected source is malformed, stale, substituted,
    or mismatched returns ``FAIL``.  An unrecognized exact multiset returns
    ``None`` and grants nothing.
    """

    from .evaluators import (
        _canonical_json_artifact,
        _r_check_read_snapshot,
        _validate_runtime,
    )
    from .gates import (
        ChallengeCategory,
    )
    from .scientific_design import (
        EvaluationContractFreezeGateReceipt,
        ResearchQuestionGateAssessment,
        require_evaluation_contract_freeze_gate_receipt,
        require_frozen_evaluation_contract,
        require_research_question_gate_assessment,
    )

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ValueError("scientific R-check join requires exact registry and ledger")
    if registry.policy.root != ledger.policy.root:
        raise ValueError("scientific R-check registry and ledger roots differ")
    if not isinstance(run_id, str) or _IDENTIFIER.fullmatch(run_id) is None:
        raise ValueError("scientific R-check run ID is invalid")
    try:
        check = r_check if isinstance(r_check, RCheck) else RCheck(r_check)
        evaluator = (
            evaluator_class
            if isinstance(evaluator_class, EvaluatorClass)
            else EvaluatorClass(evaluator_class)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("scientific R-check selector is invalid") from exc

    _validate_runtime(registry, ledger, run_id)
    entry = _r_check_read_snapshot(registry, ledger)
    records = _source_records(registry, source_artifact_sha256s)
    route = _exact_route(check, evaluator, records)
    if route is None:
        if _r_check_read_snapshot(registry, ledger) != entry:
            raise ValueError("scientific R-check source changed during selector replay")
        return None
    by_type = {record.logical_type: record for record in records}
    failure_subject = (("run_id", run_id),)
    if route in {
        "R2_E0_CANONICAL_V3",
        "R2_E2_CANONICAL_V3",
        "R4_E0_CANONICAL_V3",
        "R4_E2_CANONICAL_V3",
    }:
        try:
            is_v3 = _canonical_v3_selected(registry, records)
        except Exception:
            is_v3 = None
        if is_v3 is False:
            if _r_check_read_snapshot(registry, ledger) != entry:
                raise ValueError(
                    "scientific R-check source changed during selector replay"
                )
            return None
        if is_v3 is None:
            result = ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="CANONICAL_V3_SELECTOR_REPLAY_FAILED",
                checks=(("canonical_v3_selector_replay", "FAIL"),),
                subject_key=failure_subject,
            )
        else:
            try:
                subject = _canonical_subject(
                    registry,
                    ledger,
                    run_id=run_id,
                    records=records,
                    require_explicit_structure=check is RCheck.R2,
                )
                audit = None
                audit_record = None
                audit_bindings = None
                admissions = _canonical_source_admissions(
                    registry, ledger, run_id=run_id, subject=subject,
                    include_frozen_spec=check is RCheck.R2,
                )
                if evaluator is EvaluatorClass.E2:
                    audit_record = by_type[_SEMANTIC_AUDIT]
                    audit_payload = _canonical_json_artifact(
                        registry,
                        audit_record,
                    )
                    audit, audit_bindings, audit_source = _replay_semantic_audit(
                        registry,
                        ledger,
                        run_id=run_id,
                        record=audit_record,
                        payload=audit_payload,
                        category=(
                            ChallengeCategory.IMPLEMENTATION
                            if check is RCheck.R2
                            else ChallengeCategory.STATISTICS
                        ),
                    )
                    admissions = (*admissions, _ScientificSourceAdmission(
                        artifact_sha256=audit_record.sha256,
                        artifact_record_hash=str(audit_record.record_hash),
                        ledger_event_id=audit_source.publication_event_id,
                        ledger_event_hash=audit_source.publication_event_hash,
                        ledger_event_index=audit_source.publication_event_index,
                    ))
                result = _derive_canonical_check(
                    r_check=check,
                    evaluator_class=evaluator,
                    subject=subject,
                    registry=registry,
                    run_id=run_id,
                    audit=audit,
                    audit_record=audit_record,
                    audit_bindings=audit_bindings,
                )
                if {item.artifact_sha256 for item in admissions} != {item.sha256 for item in records}:
                    raise ValueError("scientific canonical admissions omit or add a named source")
                result = replace(result, source_admissions=admissions)
            except Exception:
                result = ScientificRCheckResolution(
                    r_check=check,
                    evaluator_class=evaluator,
                    status=AuthorityStatus.FAIL,
                    scope=AuthorityScope.SYSTEM_FIXTURE,
                    reason_code=(
                        "SCIENTIFIC_R2_OWNER_REPLAY_FAILED"
                        if check is RCheck.R2
                        else "SCIENTIFIC_R4_OWNER_REPLAY_FAILED"
                    ),
                    checks=(("canonical_scientific_owner_replay", "FAIL"),),
                    subject_key=failure_subject,
                )
        if _r_check_read_snapshot(registry, ledger) != entry:
            return ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
                checks=(("complete_source_snapshot", "DRIFT"),),
                subject_key=failure_subject,
            )
        return result
    if route == "R3_E3_TIMELINE_V2":
        from .scientific_design import ScientificConfirmatoryTimelineUnavailable

        record = by_type[_SCIENTIFIC_CONFIRMATORY_TIMELINE_V2]
        if record.schema_version != "2.0":
            result = ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_CONFIRMATORY_TIMELINE_V2_REPLAY_FAILED",
                checks=(("scientific_confirmatory_timeline_v2_owner_replay", "FAIL"),),
                subject_key=failure_subject,
            )
            if _r_check_read_snapshot(registry, ledger) != entry:
                return ScientificRCheckResolution(
                    r_check=check,
                    evaluator_class=evaluator,
                    status=AuthorityStatus.FAIL,
                    scope=AuthorityScope.SYSTEM_FIXTURE,
                    reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
                    checks=(("complete_source_snapshot", "DRIFT"),),
                    subject_key=failure_subject,
                )
            return result
        try:
            payload = _canonical_json_artifact(registry, record)
            result = _resolve_r3_e3_timeline(
                registry,
                ledger,
                run_id=run_id,
                record=record,
                payload=payload,
            )
        except ScientificConfirmatoryTimelineUnavailable as exc:
            result = ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.UNTESTED,
                scope=AuthorityScope.SCIENTIFIC,
                reason_code=exc.reason_code,
                checks=(
                    (
                        "scientific_confirmatory_timeline_v2_owner_replay",
                        exc.resolution_status.value,
                    ),
                    ("independent_custody_scientific_gate", "UNAVAILABLE"),
                ),
                subject_key=(
                    ("run_id", run_id),
                    ("scientific_confirmatory_timeline_artifact_sha256", record.sha256),
                    (
                        "scientific_confirmatory_timeline_record_hash",
                        str(record.record_hash),
                    ),
                ),
            )
        except Exception:
            result = ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_CONFIRMATORY_TIMELINE_V2_REPLAY_FAILED",
                checks=(("scientific_confirmatory_timeline_v2_owner_replay", "FAIL"),),
                subject_key=failure_subject,
            )
        if _r_check_read_snapshot(registry, ledger) != entry:
            return ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
                checks=(("complete_source_snapshot", "DRIFT"),),
                subject_key=failure_subject,
            )
        return result
    if route == "R3_E0_DOMAIN":
        from .domains import SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3

        record = by_type[_GENERIC_ML_DOMAIN_VALIDITY]
        if (
            record.schema_version
            != SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3
        ):
            if _r_check_read_snapshot(registry, ledger) != entry:
                raise ValueError(
                    "scientific R-check source changed during selector replay"
                )
            # v1/v2 receipts retain the historical evaluator path.  Sharing a
            # logical type with v3 is not permission to reinterpret old bytes.
            return None
        try:
            payload = _canonical_json_artifact(registry, record)
            result = _resolve_r3_e0_domain(
                registry,
                ledger,
                run_id=run_id,
                record=record,
                payload=payload,
            )
            result = replace(result, source_admissions=(
                _domain_admission_after_full_replay(record=record, events=entry[1].events),
            ))
        except Exception:
            result = ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="PROJECTION_BACKED_DOMAIN_OWNER_REPLAY_FAILED",
                checks=(("projection_backed_domain_owner_replay", "FAIL"),),
                subject_key=failure_subject,
            )
        if _r_check_read_snapshot(registry, ledger) != entry:
            return ScientificRCheckResolution(
                r_check=check,
                evaluator_class=evaluator,
                status=AuthorityStatus.FAIL,
                scope=AuthorityScope.SYSTEM_FIXTURE,
                reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
                checks=(("complete_source_snapshot", "DRIFT"),),
                subject_key=failure_subject,
            )
        return result
    try:
        assessment_record = by_type[_QUESTION_ASSESSMENT]
        assessment_stated = ResearchQuestionGateAssessment.from_dict(
            _canonical_json_artifact(registry, assessment_record)
        )
        assessment = require_research_question_gate_assessment(
            registry,
            ledger,
            assessment_artifact_sha256=assessment_record.sha256,
            expected_run_id=run_id,
            expected_object_id=assessment_stated.object_id,
        )
        if route in {"R1_ASSESSMENT_E0", "R1_ASSESSMENT_E2"}:
            result = _derive_r1_assessment_only(
                run_id=run_id,
                evaluator_class=evaluator,
                assessment=assessment,
                assessment_record=assessment_record,
            )
            result = _with_owned_r1_sources(
                result, assessment=assessment, assessment_record=assessment_record,
            )
            if _r_check_read_snapshot(registry, ledger) != entry:
                return ScientificRCheckResolution(
                    r_check=check,
                    evaluator_class=evaluator,
                    status=AuthorityStatus.FAIL,
                    scope=AuthorityScope.SYSTEM_FIXTURE,
                    reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
                    checks=(("complete_source_snapshot", "DRIFT"),),
                    subject_key=failure_subject,
                )
            return result
        freeze_record = by_type[_CONTRACT_FREEZE]
        freeze_stated = EvaluationContractFreezeGateReceipt.from_dict(
            _canonical_json_artifact(registry, freeze_record)
        )
        contract = require_frozen_evaluation_contract(
            registry,
            contract_artifact_sha256=freeze_stated.contract_artifact_sha256,
        )
        freeze = require_evaluation_contract_freeze_gate_receipt(
            registry,
            ledger,
            receipt_artifact_sha256=freeze_record.sha256,
            expected_run_id=run_id,
            expected_contract_id=freeze_stated.object_id,
            contract=contract,
        )
        contract_record = registry.get_metadata(freeze.contract_artifact_sha256)
        audit = None
        audit_record = None
        audit_provenance_bindings = None
        audit_source = None
        if route == "R1_E2":
            audit_record = by_type[_SEMANTIC_AUDIT]
            audit, audit_provenance_bindings, audit_source = _replay_semantic_audit(
                registry, ledger, run_id=run_id, record=audit_record,
                payload=_canonical_json_artifact(registry, audit_record),
                category=ChallengeCategory.EXPERIMENTAL_DESIGN,
            )
        result = _derive_r1_join(
            run_id=run_id,
            evaluator_class=evaluator,
            assessment=assessment,
            assessment_record=assessment_record,
            freeze=freeze,
            freeze_record=freeze_record,
            contract=contract,
            contract_record=contract_record,
            audit=audit,
            audit_record=audit_record,
            audit_provenance_bindings=audit_provenance_bindings,
        )
        result = _with_owned_r1_sources(
            result, assessment=assessment, assessment_record=assessment_record,
            freeze=freeze, freeze_record=freeze_record, audit_source=audit_source,
        )
    except Exception:
        result = ScientificRCheckResolution(
            r_check=check,
            evaluator_class=evaluator,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="SCIENTIFIC_R1_OWNER_REPLAY_FAILED",
            checks=(("scientific_r1_owner_replay", "FAIL"),),
            subject_key=failure_subject,
        )
    if _r_check_read_snapshot(registry, ledger) != entry:
        return ScientificRCheckResolution(
            r_check=check,
            evaluator_class=evaluator,
            status=AuthorityStatus.FAIL,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            reason_code="SCIENTIFIC_R_CHECK_SOURCE_DRIFT",
            checks=(("complete_source_snapshot", "DRIFT"),),
            subject_key=failure_subject,
        )
    return result


__all__ = [
    "ScientificRCheckResolution",
    "resolve_scientific_r_check_sources",
]
