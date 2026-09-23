from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry, MAX_ARTIFACT_PARENTS
from scientist_one.experiments import (
    AblationResult as ManifestAblationResult,
    ExperimentPhase,
    FrozenRunSpec,
    OutputArtifact,
    OutputManifest,
    SeedRunResult,
    SeedRunStatus,
)
from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    EvaluatorClass,
    RCheck,
    register_r_check_authority,
    resolve_r_check_authority,
)
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.scientific_design import (
    MAX_SOURCES,
    AblationResult,
    AblationSpec,
    BaselineExclusion,
    BaselineRecord,
    BaselineRegistry,
    BaselineStatus,
    ComparisonConditions,
    ComputeBudget,
    ConfirmatoryTimelineReceipt,
    DatasetContract,
    EvaluationContract,
    EvaluationContractAmendment,
    EvaluationContractFreezeGateReceipt,
    EvaluatorAssessment,
    EvaluatorExploitationSignal,
    ExecutionSeparation,
    ExperimentPlan,
    ExperimentStage,
    ExploitationSignalKind,
    Hypothesis,
    HypothesisRegister,
    HypothesisRole,
    HypothesisTiming,
    InvestigationRound,
    InvestigationRoundKind,
    InvestigationSourceBinding,
    LiteratureRecord,
    MetricDirection,
    MetricObservation,
    MetricScope,
    MetricSpec,
    MetricUnit,
    NoveltyEntry,
    NoveltyEvidenceBinding,
    NoveltyDimension,
    NoveltyRegister,
    NoveltyStatus,
    PriorWorkComparison,
    ProblemInvestigator,
    ProblemInvestigationState,
    ProblemInvestigationStatus,
    ProxyInferenceContract,
    ReportingRegime,
    ResearchBrief,
    ResearchDirection,
    ResearchGateOutcome,
    ResearchGoal,
    ResearchQuestionAssessment,
    ResearchQuestionCriteria,
    RunDisposition,
    ScientificDesignError,
    ScientificPromotionError,
    ScientificTimelineReceipt,
    SeedReportingPlan,
    SeedRunRecord,
    StatisticalEvidence,
    StatisticalPlan,
    admit_experiment,
    build_elite_pool,
    build_checked_novelty_register,
    metric_improvement,
    promote_hypothesis,
    record_scientific_design_freeze,
    record_scientific_result_observed,
    record_evaluation_contract_amendment,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
    register_evaluation_contract_freeze_gate_receipt,
    register_confirmatory_timeline_receipt,
    register_scientific_timeline_receipt,
    require_scientific_timeline_receipt,
    require_evaluation_contract_freeze_gate_receipt,
    require_confirmatory_timeline_receipt,
    require_evaluator_integrity,
    require_checked_novelty_clearance,
    require_research_gate,
    validate_ablation_results,
    validate_amended_evaluation_contract,
    validate_baseline_registry,
    validate_metric_claim_scope,
    validate_seed_report,
    validate_statistical_evidence,
    validate_superiority_claim,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def make_goal() -> ResearchGoal:
    return ResearchGoal(
        goal_id="goal-1",
        question="Does the candidate improve subject-level accuracy?",
        scope="Frozen synthetic population and protocol.",
        constraints=("offline", "bounded local compute"),
        seed_source_ids=("paper-0",),
    )


def make_literature(index: int, **changes: object) -> LiteratureRecord:
    values: dict[str, object] = {
        "source_id": f"paper-{index}",
        "title": f"Prior method {index}",
        "stable_locator": f"doi:10.0000/example.{index}",
        "full_text_sha256": digest(f"paper-{index}"),
        "methodology_relevance": 4,
        "problem_alignment": 4,
        "structured_notes": ("Methods and evaluation were read from full text.",),
        "full_text_reviewed": True,
        "destroys_gap": False,
    }
    values.update(changes)
    return LiteratureRecord(**values)  # type: ignore[arg-type]


def make_investigation_state(
    records: tuple[LiteratureRecord, ...] | None = None,
    *,
    disconfirming_source_ids: tuple[str, ...] = ("paper-2",),
    goal: ResearchGoal | None = None,
) -> ProblemInvestigationState:
    records = records or tuple(make_literature(index) for index in range(5))
    goal = goal or make_goal()
    bindings = tuple(
        InvestigationSourceBinding(
            source_id=record.source_id,
            literature_record_sha256=record.sha256,
            record_artifact_hash=digest(f"record-artifact:{record.source_id}"),
            citation_node_id="citation-node:" + digest(record.source_id),
            canonical_work_key="citation-work:" + digest(record.stable_locator),
        )
        for record in records
    )
    by_id = {binding.source_id: binding for binding in bindings}
    seed = InvestigationRound(
        round_id="investigation-seed",
        round_number=1,
        kind=InvestigationRoundKind.SEED_SEARCH,
        query="Frozen seed query and synonyms.",
        source_bindings=bindings,
        retained_source_ids=tuple(binding.source_id for binding in bindings),
        evidence_artifact_hashes=tuple(
            binding.record_artifact_hash for binding in bindings
        )
        + (digest("seed-search-receipt"),),
        findings=("Seed scholarly records were captured through the gateway.",),
        previous_round_sha256=None,
    )
    expansion = InvestigationRound(
        round_id="investigation-citation-expansion",
        round_number=2,
        kind=InvestigationRoundKind.CITATION_EXPANSION,
        query="Expand references and cited-by records under the frozen plan.",
        source_bindings=bindings,
        retained_source_ids=tuple(binding.source_id for binding in bindings),
        evidence_artifact_hashes=tuple(
            binding.record_artifact_hash for binding in bindings
        )
        + (digest("citation-expansion-receipt"),),
        findings=("Bounded citation expansion completed.",),
        previous_round_sha256=seed.sha256,
    )
    filtering = InvestigationRound(
        round_id="investigation-relevance-filtering",
        round_number=3,
        kind=InvestigationRoundKind.RELEVANCE_FILTERING,
        query="Apply the frozen methodology/problem relevance rubric.",
        source_bindings=bindings,
        retained_source_ids=tuple(binding.source_id for binding in bindings),
        evidence_artifact_hashes=tuple(
            binding.record_artifact_hash for binding in bindings
        )
        + (digest("relevance-filtering-receipt"),),
        findings=("Relevant records were retained deterministically.",),
        previous_round_sha256=expansion.sha256,
    )
    full_text = InvestigationRound(
        round_id="investigation-full-text",
        round_number=4,
        kind=InvestigationRoundKind.FULL_TEXT_REVIEW,
        query="Read retained records using the frozen relevance rubric.",
        source_bindings=bindings,
        retained_source_ids=tuple(binding.source_id for binding in bindings),
        evidence_artifact_hashes=tuple(
            binding.record_artifact_hash for binding in bindings
        )
        + (digest("full-text-review-receipt"),),
        findings=("All elite candidates received structured full-text review.",),
        previous_round_sha256=filtering.sha256,
    )
    disconfirming_bindings = tuple(by_id[value] for value in disconfirming_source_ids)
    disconfirming = InvestigationRound(
        round_id="investigation-disconfirming",
        round_number=5,
        kind=InvestigationRoundKind.DISCONFIRMING_SEARCH,
        query="Search for work that already resolves or destroys the proposed gap.",
        source_bindings=disconfirming_bindings,
        retained_source_ids=tuple(binding.source_id for binding in disconfirming_bindings),
        evidence_artifact_hashes=tuple(
            binding.record_artifact_hash for binding in disconfirming_bindings
        )
        + (digest("disconfirming-search-receipt"),),
        findings=("The explicit gap-destroying search completed.",),
        previous_round_sha256=full_text.sha256,
    )
    return ProblemInvestigationState(
        goal_id=goal.goal_id,
        goal_sha256=goal.sha256,
        goal_artifact_hash=digest("research-goal-artifact"),
        status=ProblemInvestigationStatus.READY_FOR_BRIEF,
        rounds=(seed, expansion, filtering, full_text, disconfirming),
        citation_graph_sha256=digest("citation-graph"),
        citation_graph_artifact_hash=digest("citation-graph-artifact"),
        citation_expansion_plan_sha256=digest("citation-expansion-plan"),
        citation_expansion_plan_artifact_hash=digest("citation-expansion-artifact"),
        citation_expansion_execution_sha256=digest("citation-expansion-execution"),
        citation_expansion_execution_artifact_hash=digest(
            "citation-expansion-execution-artifact"
        ),
        evidence_ranking_sha256=digest("evidence-ranking"),
        evidence_ranking_artifact_hash=digest("evidence-ranking-artifact"),
    )


def make_brief(**assessment_changes: bool) -> ResearchBrief:
    goal = make_goal()
    records = tuple(make_literature(index) for index in range(5))
    pool = build_elite_pool(goal, records)
    assessment_values = {
        "precision": True,
        "falsifiability": True,
        "importance": True,
        "gap_reality": True,
        "tractability": True,
        "resource_availability": True,
        "identifiable_contribution": True,
        "literature_sufficient": True,
    }
    assessment_values.update(assessment_changes)
    investigation_state = make_investigation_state(records)
    return ResearchBrief(
        brief_id="brief-1",
        goal=goal,
        elite_pool=pool,
        directions=(
            ResearchDirection(
                direction_id="direction-1",
                question="Can the frozen candidate improve accuracy?",
                unresolved_weakness="Existing approaches are unstable under the control.",
                candidate_gap="No method addresses the frozen failure mode.",
                source_ids=("paper-0", "paper-1"),
                disconfirming_source_ids=("paper-2",),
                experimentally_distinguishable=True,
                feasible_with_resources=True,
            ),
        ),
        selected_direction_id="direction-1",
        existing_approaches=("Strong published baseline",),
        evaluation_conventions=("Subject-level held-out accuracy",),
        assessment=ResearchQuestionAssessment(**assessment_values),
        investigation_state_sha256=investigation_state.sha256,
        investigation_state_artifact_hash=digest("investigation-state-artifact"),
    )


def make_prior_work(**changes: object) -> PriorWorkComparison:
    values: dict[str, object] = {
        "work_id": "paper-0",
        "citation_id": "citation-1",
        "evidence_sha256": digest("paper-0"),
        "mechanism": "Uses a distinct frozen mechanism.",
        "objective": "Optimizes the same scientific objective.",
        "training": "Uses the same training population.",
        "inference": "Uses a different inference procedure.",
        "data": "Uses the same dataset version.",
        "evaluation": "Uses the same subject-level evaluation.",
        "claimed_benefit": "Claims improved accuracy.",
        "is_closest": True,
        "conflicts_with_contribution": False,
        "collision_dimensions": (),
        "conflict_reason": None,
    }
    values.update(changes)
    return PriorWorkComparison(**values)  # type: ignore[arg-type]


def make_novelty(**changes: object) -> NoveltyRegister:
    values: dict[str, object] = {
        "contribution_id": "contribution-1",
        "statement": "A bounded mechanism for the frozen gap.",
        "comparisons": (make_prior_work(),),
        "known_combination_search": "Searched the component combination and synonyms.",
        "disconfirming_search": "Searched for work that already resolves the gap.",
        "status": NoveltyStatus.MODERATE_NOVELTY,
    }
    values.update(changes)
    entry = NoveltyEntry(**values)  # type: ignore[arg-type]
    records = tuple(make_literature(index) for index in range(5))
    state = make_investigation_state(records)
    state_bindings = {value.source_id: value for value in state.source_bindings}
    records_by_id = {value.source_id: value for value in records}
    bindings = tuple(
        NoveltyEvidenceBinding(
            work_id=comparison.work_id,
            citation_id=comparison.citation_id,
            literature_record_sha256=records_by_id[comparison.work_id].sha256,
            record_artifact_hash=state_bindings[
                comparison.work_id
            ].record_artifact_hash,
            citation_node_id=state_bindings[comparison.work_id].citation_node_id,
            canonical_work_key=state_bindings[
                comparison.work_id
            ].canonical_work_key,
            full_text_sha256=records_by_id[comparison.work_id].full_text_sha256,
            full_text_artifact_hash=records_by_id[
                comparison.work_id
            ].full_text_sha256,
            reference_verification_artifact_hash=digest(
                f"reference-verification:{comparison.work_id}"
            ),
            reference_verification_level=5,
        )
        for comparison in entry.comparisons
    )
    resolved = tuple(
        sorted(
            {
                digest("investigation-state-artifact"),
                *state.parent_artifact_hashes,
                *(
                    artifact_hash
                    for binding in bindings
                    for artifact_hash in binding.parent_artifact_hashes
                ),
            }
        )
    )
    return build_checked_novelty_register(
        entries=(entry,),
        investigation_state=state,
        investigation_state_artifact_hash=digest("investigation-state-artifact"),
        literature_records=records,
        evidence_bindings=bindings,
        resolved_artifact_hashes=resolved,
    )


def make_hypothesis(
    hypothesis_id: str,
    role: HypothesisRole,
    **changes: object,
) -> Hypothesis:
    values: dict[str, object] = {
        "hypothesis_id": hypothesis_id,
        "role": role,
        "statement": f"{hypothesis_id} improves the frozen primary metric.",
        "motivation": "Prior evidence identifies a testable mechanism.",
        "prior_evidence_ids": ("evidence-1",),
        "prediction": "Directed improvement exceeds the meaningful threshold.",
        "falsification_condition": "The adjusted interval includes no improvement.",
        "planned_experiment": (
            "experiment-" + hypothesis_id.removeprefix("hypothesis-")
        ),
    }
    values.update(changes)
    return Hypothesis(**values)  # type: ignore[arg-type]


def make_hypotheses() -> HypothesisRegister:
    return HypothesisRegister(
        (
            make_hypothesis("hypothesis-primary", HypothesisRole.PRIMARY),
            make_hypothesis("hypothesis-secondary", HypothesisRole.SECONDARY),
        )
    )


def make_metric(**changes: object) -> MetricSpec:
    values: dict[str, object] = {
        "metric_id": "accuracy",
        "name": "Subject accuracy",
        "definition": "Correct subjects divided by evaluated subjects.",
        "direction": MetricDirection.HIGHER_IS_BETTER,
        "unit": MetricUnit.FRACTION,
        "scope": MetricScope.END_TO_END,
        "aggregation": "Mean across the frozen seed distribution.",
    }
    values.update(changes)
    return MetricSpec(**values)  # type: ignore[arg-type]


def make_conditions(**changes: object) -> ComparisonConditions:
    values: dict[str, object] = {
        "data_identity": "dataset-v1",
        "split_identity": "split-v1",
        "supervision": "labels-v1",
        "pretrained_resources": "none",
        "hyperparameter_search": "grid-v1",
        "preprocessing": "preprocess-v1",
        "evaluator": "evaluator-v1",
        "hardware_class": "local-cpu",
        "latency_method": "not-applicable",
        "failure_policy": "retain every failed and invalid run",
        "metric_id": "accuracy",
        "metric_unit": MetricUnit.FRACTION,
        "tuning_trials": 8,
        "compute_budget": 100.0,
    }
    values.update(changes)
    return ComparisonConditions(**values)  # type: ignore[arg-type]


def make_baseline(**changes: object) -> BaselineRecord:
    values: dict[str, object] = {
        "baseline_id": "baseline-strong",
        "name": "Strong baseline",
        "paper_locator": "doi:10.0000/strong",
        "implementation": "registry:baseline-code",
        "implementation_version": "v1",
        "conditions": make_conditions(),
        "status": BaselineStatus.MUST_RUN,
        "expected_metric": 0.70,
        "reported_metric": 0.71,
        "observed_metric": 0.70,
        "evaluation_compatible": True,
        "implementation_confidence": 0.95,
        "fairness_assessment": "All comparison dimensions are frozen and equivalent.",
        "exclusion": None,
    }
    values.update(changes)
    return BaselineRecord(**values)  # type: ignore[arg-type]


def make_statistical_plan(**changes: object) -> StatisticalPlan:
    values: dict[str, object] = {
        "primary_test": "paired subject permutation",
        "alpha": 0.05,
        "effect_size": "directed accuracy difference",
        "confidence_interval": "subject bootstrap 95 percent",
        "resampling_unit": "subject",
        "comparison_family_size": 2,
        "multiplicity_correction": "Holm",
        "minimum_effect": 0.02,
        "minimum_sample_size": 20,
        "power_or_sensitivity": "Sensitivity at effects 0.01 through 0.05.",
    }
    values.update(changes)
    return StatisticalPlan(**values)  # type: ignore[arg-type]


def make_contract(**changes: object) -> EvaluationContract:
    values: dict[str, object] = {
        "contract_id": "contract-1",
        "version": 1,
        "research_brief_sha256": make_brief().sha256,
        "novelty_register": make_novelty(),
        "hypothesis_register": make_hypotheses(),
        "dataset": DatasetContract(
            dataset_id="dataset-v1",
            train_split_id="train-v1",
            development_split_id="development-v1",
            validation_split_id="validation-v1",
            confirmatory_split_id="confirmatory-v1",
            exclusions=("Exclude malformed records before any split is opened.",),
        ),
        "primary_metric": make_metric(),
        "secondary_metrics": (
            make_metric(
                metric_id="proxy-score",
                name="Development proxy score",
                definition="A development-only intermediate score.",
                scope=MetricScope.PROXY,
            ),
        ),
        "baseline_registry": BaselineRegistry((make_baseline(),)),
        "candidate_conditions": make_conditions(),
        "seed_reporting": SeedReportingPlan(
            seeds=(7, 11, 19),
            regime=ReportingRegime.ALL_SEEDS,
            selection_policy="Report the complete distribution; select no representative seed.",
            selection_defined_before_results=True,
            preserve_all_runs=True,
            technical_retry_rule="Retry only a recorded infrastructure crash.",
        ),
        "compute_budget": ComputeBudget(12, 3600.0, 4, 1, 8),
        "statistical_plan": make_statistical_plan(),
        "robustness_tests": ("Frozen shift robustness test",),
        "ablations": (
            AblationSpec(
                ablation_id="ablation-core",
                hypothesis_id="hypothesis-primary",
                component_changed="core component",
                intervention="Remove only the core component.",
                expected_observation="The directed improvement should diminish.",
            ),
        ),
        "stopping_criteria": ("Stop after the frozen seed set and required ablation.",),
        "success_criteria": ("Adjusted interval establishes meaningful improvement.",),
        "failure_criteria": ("No improvement, invalidity, or evaluator exploitation.",),
        "separation": ExecutionSeparation(6, 3, "protected-holdout"),
        "proxy_inferences": (),
        "frozen_at": "2026-08-29T00:00:00Z",
        "frozen_by": "protocol-designer",
    }
    values.update(changes)
    return EvaluationContract(**values)  # type: ignore[arg-type]


def successful_run(seed: int, value: float, *, selected: bool = False) -> SeedRunRecord:
    return SeedRunRecord(
        run_id=f"run-{seed}",
        seed=seed,
        disposition=RunDisposition.SUCCESS,
        metric_value=value,
        artifact_sha256=digest(f"run-{seed}"),
        selected=selected,
    )


def passing_statistics(**changes: object) -> StatisticalEvidence:
    values: dict[str, object] = {
        "improvement_effect": 0.06,
        "confidence_low": 0.03,
        "confidence_high": 0.09,
        "adjusted_p_value": 0.02,
        "sample_size": 50,
        "multiplicity_correction": "Holm",
        "artifact_sha256": digest("statistical-evidence"),
    }
    values.update(changes)
    return StatisticalEvidence(**values)  # type: ignore[arg-type]


def _timeline_artifact(
    registry: ArtifactRegistry,
    payload: bytes,
    logical_type: str,
    role: Role,
    parents: tuple[str, ...] = (),
):
    return registry.put_bytes(
        payload,
        logical_type=logical_type,
        origin="scientific timeline focused fixture",
        creator_role=role,
        creation_command=("scientist-one", "timeline-focused-test"),
        parent_artifacts=parents,
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _prepared_timeline(root: str) -> dict[str, object]:
    registry = ArtifactRegistry(root)
    ledger = EventLedger(root, "runs/timeline/events.jsonl")
    evidence = _timeline_artifact(
        registry,
        b'{"evidence":"frozen"}\n',
        "timeline_contract_evidence",
        Role.EVIDENCE_CURATOR,
    )
    contract = make_contract()
    contract_record = register_frozen_evaluation_contract(
        registry,
        contract=contract,
        parent_artifact_sha256s=(evidence.sha256,),
    )
    code = _timeline_artifact(
        registry, b"print('timeline')\n", "experiment_code", Role.IMPLEMENTER
    )
    data = _timeline_artifact(
        registry, b'{"dataset":"v1"}\n', "experiment_dataset", Role.EVIDENCE_CURATOR
    )
    configuration = _timeline_artifact(
        registry,
        b'{"configuration":"v1"}\n',
        "experiment_configuration",
        Role.PROTOCOL_DESIGNER,
    )
    evaluator = _timeline_artifact(
        registry,
        b'{"evaluator":"v1"}\n',
        "evaluator_implementation",
        Role.PROTOCOL_DESIGNER,
    )
    plans = tuple(
        ExperimentPlan(
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            stage=ExperimentStage.EXPLORATORY,
            contract_sha256=contract.sha256,
            dataset_split_id="development-v1",
            seed=seed,
            evaluator_id="evaluator-v1",
            uses_protected_resource=False,
            results_seen_before_plan=False,
        )
        for seed in contract.seed_reporting.seeds
    )
    plan_records = tuple(
        register_frozen_experiment_plan(
            registry,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            plan=plan,
        )
        for plan in plans
    )
    spec = FrozenRunSpec(
        run_id="timeline-execution",
        experiment_id="experiment-primary",
        hypothesis_id="hypothesis-primary",
        phase=ExperimentPhase.EXPLORATORY,
        argv=("/usr/bin/python3", "-I", "fixture.py"),
        working_directory=".",
        code_sha256=code.sha256,
        data_sha256=data.sha256,
        configuration_sha256=configuration.sha256,
        evaluator_sha256=evaluator.sha256,
        seeds=contract.seed_reporting.seeds,
        required_ablations=("ablation-core",),
        metadata={"evaluation_split": "development-v1"},
    )
    spec_record = register_frozen_run_spec(
        registry,
        contract=contract,
        contract_artifact_sha256=contract_record.sha256,
        experiment_plan_artifact_sha256s=tuple(item.sha256 for item in plan_records),
        spec=spec,
    )
    return locals()


def _register_timeline_outputs(
    values: dict[str, object],
    *,
    created_at: str | None = None,
    namespace_outputs: bool = True,
):
    registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
    spec: FrozenRunSpec = values["spec"]  # type: ignore[assignment]
    spec_record = values["spec_record"]
    payloads = tuple(
        canonical_json_bytes(
            {
                "run_id": spec.run_id,
                "spec_sha256": spec.sha256,
                "seed": seed,
                "value": 0.5 + index / 100,
            }
        )
        + b"\n"
        for index, seed in enumerate(spec.seeds)
    ) + (
        canonical_json_bytes(
            {
                "run_id": spec.run_id,
                "spec_sha256": spec.sha256,
                "ablation": "ablation-core",
                "status": "PASS",
            }
        )
        + b"\n",
    )
    descriptors = tuple(
        OutputArtifact(
            path=f"result-{index}.json",
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            logical_type=("seed_output" if index < len(spec.seeds) else "ablation_output"),
        )
        for index, payload in enumerate(payloads)
    )
    manifest = OutputManifest(
        run_id=spec.run_id,
        spec_sha256=spec.sha256,
        code_sha256=spec.code_sha256,
        data_sha256=spec.data_sha256,
        configuration_sha256=spec.configuration_sha256,
        evaluator_sha256=spec.evaluator_sha256,
        planned_seeds=spec.seeds,
        seed_results=tuple(
            SeedRunResult(
                seed=seed,
                status=SeedRunStatus.SUCCESS,
                metric=0.5 + index / 100,
                artifact_sha256=descriptors[index].sha256,
            )
            for index, seed in enumerate(spec.seeds)
        ),
        artifacts=descriptors,
        ablations=(
            ManifestAblationResult(
                "ablation-core",
                descriptors[-1].sha256,
                "PASS",
            ),
        ),
    )
    manifest_record = registry.put_json(
        manifest.to_dict(),
        logical_type="experiment_output_manifest",
        origin="scientific timeline focused fixture",
        creator_role=Role.EXPERIMENT_RUNNER,
        creation_command=("scientist-one", "timeline-focused-test"),
        parent_artifacts=(spec_record.sha256,),  # type: ignore[union-attr]
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=created_at,
    )
    output_records = tuple(
        _timeline_artifact(
            registry,
            payload,
            (
                f"experiment_output.{descriptor.logical_type}"
                if namespace_outputs
                else descriptor.logical_type
            ),
            Role.EXPERIMENT_RUNNER,
            (manifest_record.sha256, spec_record.sha256),  # type: ignore[union-attr]
        )
        for payload, descriptor in zip(payloads, descriptors)
    )
    values.update(
        manifest=manifest,
        manifest_record=manifest_record,
        output_records=output_records,
    )
    return manifest_record


def _prepared_confirmatory_timeline(root: str) -> dict[str, object]:
    registry = ArtifactRegistry(root)
    ledger = EventLedger(root, "runs/confirmatory-timeline/events.jsonl")
    study_id = "timeline-study"
    study_version = 1
    protocol = {"study_id": study_id, "study_version": study_version}
    protocol_sha256 = hashlib.sha256(canonical_json_bytes(protocol)).hexdigest()
    protocol_record = _timeline_artifact(
        registry,
        canonical_json_bytes(
            {"protocol": protocol, "protocol_sha256": protocol_sha256}
        )
        + b"\n",
        "frozen_protocol",
        Role.PROTOCOL_DESIGNER,
    )

    def support(name: str, role: Role = Role.EVIDENCE_CURATOR):
        return _timeline_artifact(
            registry,
            canonical_json_bytes({"authority": name}) + b"\n",
            name,
            role,
        )

    blind = support("blind_interpretation", Role.PROTOCOL_DESIGNER)
    source = support("frozen_source_inventory")
    configuration = support("frozen_configuration_inventory", Role.PROTOCOL_DESIGNER)
    split = support("frozen_confirmatory_split", Role.HOLDOUT_CUSTODIAN)
    review = support("midrun_review", Role.SCIENTIFIC_REVIEWER)
    charge = support("resource_runtime_confirmatory_charge", Role.ORCHESTRATOR)
    fresh_parents = (
        protocol_record.sha256,
        blind.sha256,
        source.sha256,
        configuration.sha256,
        split.sha256,
        review.sha256,
    )
    fresh_record = _timeline_artifact(
        registry,
        canonical_json_bytes(
            {
                "kind": "SEALED_CUSTODY",
                "study_id": study_id,
                "study_version": study_version,
            }
        )
        + b"\n",
        "fresh_custody_receipt",
        Role.HOLDOUT_CUSTODIAN,
        fresh_parents,
    )
    custody_record = _timeline_artifact(
        registry,
        canonical_json_bytes(
            {
                "kind": "REVEALED_CUSTODY",
                "study_id": study_id,
                "study_version": study_version,
            }
        )
        + b"\n",
        "custody_record",
        Role.HOLDOUT_CUSTODIAN,
        (
            protocol_record.sha256,
            source.sha256,
            configuration.sha256,
            split.sha256,
            blind.sha256,
            review.sha256,
            charge.sha256,
            fresh_record.sha256,
        ),
    )
    result_record = _timeline_artifact(
        registry,
        canonical_json_bytes(
            {
                "input_hashes": {
                    "frozen_protocol": protocol_record.sha256,
                    "custody_record": custody_record.sha256,
                },
                "scientific_protocol_sha256": protocol_sha256,
            }
        )
        + b"\n",
        "machine_results",
        Role.EXPERIMENT_RUNNER,
        (
            protocol_record.sha256,
            blind.sha256,
            custody_record.sha256,
            source.sha256,
            configuration.sha256,
        ),
    )
    return locals()


def _append_confirmatory_timeline_event(
    values: dict[str, object],
    kind: str,
    *,
    timestamp: str,
):
    ledger: EventLedger = values["ledger"]  # type: ignore[assignment]
    protocol_record = values["protocol_record"]
    fresh_record = values["fresh_record"]
    custody_record = values["custody_record"]
    result_record = values["result_record"]
    if kind == "freeze":
        records = (fresh_record,)
        actor = Role.HOLDOUT_CUSTODIAN
        event_type = "CHECKPOINT"
    elif kind == "start":
        records = (protocol_record, fresh_record)
        actor = Role.ORCHESTRATOR
        event_type = "CONFIRMATORY_STARTED"
    elif kind == "result":
        records = (custody_record, result_record)
        actor = Role.ORCHESTRATOR
        event_type = "CONFIRMATORY_COMPLETED"
    else:  # pragma: no cover - test helper misuse.
        raise AssertionError(kind)
    metadata: dict[str, object] = {
        "artifact_types": [item.logical_type for item in records],
        "artifact_record_hashes": [str(item.record_hash) for item in records],
    }
    if kind in {"freeze", "start"}:
        metadata["fresh_custody"] = {
            "artifact_sha256": fresh_record.sha256,
            "artifact_record_hash": str(fresh_record.record_hash),
            "protocol_hash": values["protocol_sha256"],
            "study_version": values["study_version"],
        }
    return ledger.record(
        run_id="confirmatory-timeline-run",
        actor_role=actor,
        state_before="CONFIRM",
        requested_state_after="CONFIRM",
        artifact_hashes=tuple(item.sha256 for item in records),
        code_version="confirmatory-timeline-fixture-v1",
        configuration_hash=digest("confirmatory-timeline-configuration"),
        reason=f"record exact confirmatory {kind} authority",
        event_type=event_type,
        timestamp=timestamp,
        metadata=metadata,
    )


class ProblemInvestigatorTests(unittest.TestCase):
    def test_checked_investigator_derives_honest_proceed(self) -> None:
        goal = make_goal()
        records = tuple(make_literature(index) for index in range(5))
        investigation_state = make_investigation_state(records)
        direction = ResearchDirection(
            direction_id="direction-checked",
            question="Can the frozen candidate improve accuracy?",
            unresolved_weakness="Existing approaches fail the frozen control.",
            candidate_gap="No reviewed work resolves the selected mechanism.",
            source_ids=("paper-0", "paper-1"),
            disconfirming_source_ids=("paper-2",),
            experimentally_distinguishable=True,
            feasible_with_resources=True,
        )
        brief = ProblemInvestigator().build_checked_brief(
            brief_id="brief-checked",
            goal=goal,
            literature_records=records,
            directions=(direction,),
            selected_direction_id=direction.direction_id,
            existing_approaches=("Strong published baseline",),
            evaluation_conventions=("Subject-level held-out accuracy",),
            criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
            investigation_state=investigation_state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        self.assertIs(brief.gate_outcome, ResearchGateOutcome.PROCEED)
        self.assertEqual(brief.gap_destroying_source_ids, ())
        require_research_gate(
            brief,
            investigation_state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )

    def test_checked_investigator_derives_destroyed_gap_from_bound_evidence(self) -> None:
        goal = make_goal()
        direction = ResearchDirection(
            direction_id="direction-destroyed",
            question="Can the frozen candidate improve accuracy?",
            unresolved_weakness="A suspected weakness requires disconfirming review.",
            candidate_gap="The proposed gap may already be resolved.",
            source_ids=("paper-0", "paper-1"),
            disconfirming_source_ids=("paper-2",),
            experimentally_distinguishable=True,
            feasible_with_resources=True,
        )
        records = tuple(
            make_literature(index, destroys_gap=(index == 2))
            for index in range(5)
        )
        investigation_state = make_investigation_state(records)
        brief = ProblemInvestigator().build_checked_brief(
            brief_id="brief-destroyed",
            goal=goal,
            literature_records=records,
            directions=(direction,),
            selected_direction_id=direction.direction_id,
            existing_approaches=("Prior work that resolves the proposed gap",),
            evaluation_conventions=("Subject-level held-out accuracy",),
            criteria=ResearchQuestionCriteria(True, True, True, True, True, True),
            investigation_state=investigation_state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        self.assertIs(
            brief.gate_outcome,
            ResearchGateOutcome.INSUFFICIENT_NOVELTY,
        )
        self.assertEqual(brief.gap_destroying_source_ids, ("paper-2",))
        with self.assertRaisesRegex(ScientificPromotionError, "INSUFFICIENT_NOVELTY"):
            require_research_gate(
                brief,
                investigation_state,
                investigation_state_artifact_hash=digest("investigation-state-artifact"),
            )

    def test_brief_ready_state_requires_explicit_disconfirming_round(self) -> None:
        state = make_investigation_state()
        with self.assertRaisesRegex(ScientificDesignError, "multi-round|disconfirming"):
            replace(state, rounds=state.rounds[:-1])

    def test_elite_pool_filters_by_frozen_threshold_and_retains_disconfirmers(self) -> None:
        goal = make_goal()
        records = tuple(make_literature(index) for index in range(5)) + (
            make_literature(5, methodology_relevance=3, problem_alignment=3),
            make_literature(6, destroys_gap=True),
        )
        pool = build_elite_pool(goal, records)
        self.assertEqual(len(pool.records), 6)
        self.assertIn("paper-6", pool.source_ids)
        self.assertNotIn("paper-5", pool.source_ids)

    def test_elite_pool_fails_when_grounding_is_insufficient_or_unbounded(self) -> None:
        with self.assertRaisesRegex(ScientificDesignError, "at least 5"):
            build_elite_pool(make_goal(), tuple(make_literature(i) for i in range(4)))
        with self.assertRaisesRegex(ScientificDesignError, "exceeds"):
            build_elite_pool(
                make_goal(),
                (make_literature(i) for i in range(MAX_SOURCES + 1)),
            )

    def test_research_brief_gate_is_derived_and_hash_stable(self) -> None:
        brief = make_brief()
        self.assertIs(brief.gate_outcome, ResearchGateOutcome.PROCEED)
        self.assertEqual(brief.sha256, make_brief().sha256)
        require_research_gate(
            brief,
            make_investigation_state(),
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        with self.assertRaises(FrozenInstanceError):
            brief.selected_direction_id = "direction-2"  # type: ignore[misc]

    def test_every_research_gate_failure_has_typed_nonproceed_outcome(self) -> None:
        cases = {
            "literature_sufficient": ResearchGateOutcome.MORE_LITERATURE_REQUIRED,
            "importance": ResearchGateOutcome.TERMINATE,
            "gap_reality": ResearchGateOutcome.INSUFFICIENT_NOVELTY,
            "tractability": ResearchGateOutcome.INFEASIBLE_WITH_CURRENT_RESOURCES,
            "resource_availability": ResearchGateOutcome.INFEASIBLE_WITH_CURRENT_RESOURCES,
            "precision": ResearchGateOutcome.REFORMULATE,
            "falsifiability": ResearchGateOutcome.REFORMULATE,
            "identifiable_contribution": ResearchGateOutcome.REFORMULATE,
        }
        for field, expected in cases.items():
            with self.subTest(field=field):
                brief = make_brief(**{field: False})
                self.assertIs(brief.gate_outcome, expected)
                with self.assertRaises(ScientificPromotionError):
                    require_research_gate(
                        brief,
                        make_investigation_state(),
                        investigation_state_artifact_hash=digest(
                            "investigation-state-artifact"
                        ),
                    )

    def test_proceed_requires_persisted_state_and_confined_sources(self) -> None:
        brief = make_brief()
        direction = replace(brief.directions[0], disconfirming_source_ids=())
        zero_state = make_investigation_state(disconfirming_source_ids=())
        zero_result_brief = replace(
            brief,
            directions=(direction,),
            investigation_state_sha256=zero_state.sha256,
        )
        require_research_gate(
            zero_result_brief,
            zero_state,
            investigation_state_artifact_hash=digest("investigation-state-artifact"),
        )
        direction = replace(brief.directions[0], source_ids=("unknown-paper",))
        with self.assertRaisesRegex(ScientificDesignError, "outside the elite pool"):
            replace(brief, directions=(direction,))


class NoveltyAndHypothesisTests(unittest.TestCase):
    def test_novelty_reserves_registry_parent_slot_for_brief(self) -> None:
        comparisons = tuple(
            make_prior_work(
                work_id=f"paper-{index}",
                citation_id=f"citation-{index}",
                evidence_sha256=digest(f"full:{index}"),
                is_closest=index == 0,
            )
            for index in range(85)
        )
        entry = NoveltyEntry(
            contribution_id="boundary-contribution",
            statement="Boundary-sized checked novelty authority.",
            comparisons=comparisons,
            known_combination_search="A bounded known-combination search.",
            disconfirming_search="A bounded disconfirming search.",
            status=NoveltyStatus.MODERATE_NOVELTY,
        )
        bindings = tuple(
            NoveltyEvidenceBinding(
                work_id=comparison.work_id,
                citation_id=comparison.citation_id,
                literature_record_sha256=digest(f"literature:{index}"),
                record_artifact_hash=digest(f"record:{index}"),
                citation_node_id=f"citation-node:{digest(f'node:{index}')}",
                canonical_work_key=f"citation-work:{digest(f'work:{index}')}",
                full_text_sha256=digest(f"full:{index}"),
                full_text_artifact_hash=digest(f"full:{index}"),
                reference_verification_artifact_hash=(
                    digest(f"full:{index}")
                    if index == len(comparisons) - 1
                    else digest(f"reference:{index}")
                ),
                reference_verification_level=5,
            )
            for index, comparison in enumerate(comparisons)
        )
        allowed = NoveltyRegister(
            entries=(entry,),
            investigation_state_sha256=digest("boundary-state-content"),
            investigation_state_artifact_hash=digest("state-parent"),
            evidence_bindings=bindings,
        )
        self.assertEqual(
            len(allowed.parent_artifact_hashes),
            MAX_ARTIFACT_PARENTS - 1,
        )
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            labels = {
                "state-parent",
                "brief-parent",
                *(f"record:{index}" for index in range(85)),
                *(f"full:{index}" for index in range(85)),
                *(f"reference:{index}" for index in range(84)),
            }
            records = {
                label: registry.put_bytes(
                    label.encode("utf-8"),
                    logical_type="boundary_parent",
                    origin="novelty registry-boundary fixture",
                    creator_role=Role.PROBLEM_INVESTIGATOR,
                    creation_command=("scientist-one", "boundary-test"),
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    validation_result="PASS",
                    frozen=True,
                )
                for label in labels
            }
            persisted = registry.put_json(
                {"novelty_sha256": allowed.sha256},
                logical_type="novelty_register_boundary",
                origin="novelty registry-boundary fixture",
                creator_role=Role.PROBLEM_INVESTIGATOR,
                creation_command=("scientist-one", "boundary-test"),
                parent_artifacts=(
                    records["brief-parent"].sha256,
                    *allowed.parent_artifact_hashes,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            self.assertEqual(
                len(persisted.parent_artifacts),
                MAX_ARTIFACT_PARENTS,
            )
        with self.assertRaisesRegex(ScientificDesignError, "brief"):
            NoveltyRegister(
                entries=(entry,),
                investigation_state_sha256=digest("boundary-state-content"),
                investigation_state_artifact_hash=digest("state-parent"),
                evidence_bindings=(
                    *bindings[:-1],
                    replace(
                        bindings[-1],
                        reference_verification_artifact_hash=digest(
                            "reference:84"
                        ),
                    ),
                ),
            )

    def test_checked_novelty_resolves_exact_prior_work_and_registry_artifacts(self) -> None:
        records = tuple(make_literature(index) for index in range(5))
        state = make_investigation_state(records)
        register = make_novelty()
        resolved = tuple(
            sorted(
                {
                    digest("investigation-state-artifact"),
                    *state.parent_artifact_hashes,
                    *(
                        artifact_hash
                        for binding in register.evidence_bindings
                        for artifact_hash in binding.parent_artifact_hashes
                    ),
                }
            )
        )
        require_checked_novelty_clearance(
            register,
            "contribution-1",
            investigation_state=state,
            investigation_state_artifact_hash=digest(
                "investigation-state-artifact"
            ),
            literature_records=records,
            resolved_artifact_hashes=resolved,
        )
        self.assertIn(
            register.evidence_bindings[0].reference_verification_artifact_hash,
            register.parent_artifact_hashes,
        )

    def test_forged_or_nonexistent_novelty_evidence_cannot_clear(self) -> None:
        records = tuple(make_literature(index) for index in range(5))
        state = make_investigation_state(records)
        register = make_novelty()
        resolved = tuple(
            sorted(
                {
                    digest("investigation-state-artifact"),
                    *state.parent_artifact_hashes,
                    *(
                        artifact_hash
                        for binding in register.evidence_bindings
                        for artifact_hash in binding.parent_artifact_hashes
                    ),
                }
            )
        )
        unbound = NoveltyRegister(register.entries)
        with self.assertRaisesRegex(ScientificPromotionError, "evidence authority"):
            unbound.require_clearance("contribution-1")

        comparison = register.entries[0].comparisons[0]
        forged_entry = replace(
            register.entries[0],
            comparisons=(
                replace(comparison, evidence_sha256=digest("forged-full-text")),
            ),
        )
        with self.assertRaisesRegex(ScientificDesignError, "exact reviewed full-text"):
            build_checked_novelty_register(
                entries=(forged_entry,),
                investigation_state=state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
                literature_records=records,
                evidence_bindings=register.evidence_bindings,
                resolved_artifact_hashes=resolved,
            )

        nonexistent_binding = replace(
            register.evidence_bindings[0],
            reference_verification_artifact_hash=digest(
                "nonexistent-reference-verification"
            ),
        )
        with self.assertRaisesRegex(ScientificDesignError, "not resolved"):
            build_checked_novelty_register(
                entries=register.entries,
                investigation_state=state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
                literature_records=records,
                evidence_bindings=(nonexistent_binding,),
                resolved_artifact_hashes=resolved,
            )

        low_verification = replace(
            register.evidence_bindings[0],
            reference_verification_level=2,
        )
        with self.assertRaisesRegex(ScientificDesignError, "semantic LEVEL_4"):
            build_checked_novelty_register(
                entries=register.entries,
                investigation_state=state,
                investigation_state_artifact_hash=digest(
                    "investigation-state-artifact"
                ),
                literature_records=records,
                evidence_bindings=(low_verification,),
                resolved_artifact_hashes=resolved,
            )

    def test_closest_prior_work_collision_cannot_be_labeled_novel(self) -> None:
        collision = make_prior_work(
            conflicts_with_contribution=True,
            collision_dimensions=(NoveltyDimension.MECHANISM,),
            conflict_reason="The closest work already implements the claimed mechanism.",
        )
        with self.assertRaisesRegex(ScientificDesignError, "conflict exists"):
            make_novelty(comparisons=(collision,))
        blocked = make_novelty(
            comparisons=(collision,),
            status=NoveltyStatus.NOT_NOVEL,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "NOT_NOVEL"):
            blocked.require_clearance("contribution-1")

    def test_novelty_requires_exactly_one_closest_external_comparison(self) -> None:
        with self.assertRaisesRegex(ScientificDesignError, "exactly one closest"):
            make_novelty(comparisons=(make_prior_work(is_closest=False),))
        with self.assertRaisesRegex(ScientificDesignError, "SHA-256"):
            make_prior_work(evidence_sha256="not-evidence")

    def test_uncertain_novelty_fails_closed(self) -> None:
        register = make_novelty(status=NoveltyStatus.UNCERTAIN)
        with self.assertRaises(ScientificPromotionError):
            register.require_clearance("contribution-1")

    def test_result_observed_hypothesis_must_be_post_hoc(self) -> None:
        with self.assertRaisesRegex(ScientificDesignError, "POST_HOC"):
            make_hypothesis(
                "hypothesis-new",
                HypothesisRole.SECONDARY,
                formed_after_observation=True,
                timing=HypothesisTiming.PRE_SPECIFIED,
            )
        post_hoc = make_hypothesis(
            "hypothesis-new",
            HypothesisRole.SECONDARY,
            formed_after_observation=True,
            timing=HypothesisTiming.POST_HOC,
        )
        self.assertIs(post_hoc.timing, HypothesisTiming.POST_HOC)

    def test_register_requires_exactly_one_falsifiable_primary(self) -> None:
        with self.assertRaisesRegex(ScientificDesignError, "exactly one primary"):
            HypothesisRegister(
                (
                    make_hypothesis("h1", HypothesisRole.SECONDARY),
                    make_hypothesis("h2", HypothesisRole.SECONDARY),
                )
            )
        with self.assertRaisesRegex(ScientificDesignError, "falsification_condition"):
            make_hypothesis("h1", HypothesisRole.PRIMARY, falsification_condition=" ")

    def test_promotion_is_append_only_and_cannot_follow_results(self) -> None:
        original = make_hypotheses()
        promoted = promote_hypothesis(
            original,
            "hypothesis-secondary",
            promotion_id="promotion-1",
            occurred_at="2026-08-29T00:00:00Z",
            actor_id="hypothesis-designer",
            reason="Promoted before confirmation because it discriminates the mechanism.",
            results_observed=False,
        )
        self.assertEqual(original.primary.hypothesis_id, "hypothesis-primary")
        self.assertEqual(promoted.primary.hypothesis_id, "hypothesis-secondary")
        self.assertEqual(len(promoted.promotion_history), 1)
        with self.assertRaisesRegex(ScientificDesignError, "after results"):
            promote_hypothesis(
                original,
                "hypothesis-secondary",
                promotion_id="promotion-2",
                occurred_at="2026-08-29T01:00:00Z",
                actor_id="hypothesis-designer",
                reason="Observed result looked promising.",
                results_observed=True,
            )


class EvaluationContractTests(unittest.TestCase):
    def test_contract_is_deeply_frozen_hash_stable_and_pre_result(self) -> None:
        contract = make_contract()
        self.assertEqual(contract.sha256, make_contract().sha256)
        with self.assertRaises(FrozenInstanceError):
            contract.version = 2  # type: ignore[misc]
        with self.assertRaisesRegex(ScientificDesignError, "before results"):
            make_contract(results_seen_at_freeze=True)

    def test_metric_direction_is_authoritative_not_writer_selected(self) -> None:
        metric = make_metric(direction=MetricDirection.LOWER_IS_BETTER)
        candidate = MetricObservation("accuracy", 0.20, MetricUnit.FRACTION)
        baseline = MetricObservation("accuracy", 0.30, MetricUnit.FRACTION)
        self.assertAlmostEqual(metric_improvement(metric, candidate, baseline), 0.10)
        self.assertLess(
            metric_improvement(
                metric,
                MetricObservation("accuracy", 0.40, MetricUnit.FRACTION),
                baseline,
            ),
            0,
        )

    def test_percent_fraction_and_seconds_milliseconds_never_implicitly_convert(self) -> None:
        with self.assertRaisesRegex(ScientificPromotionError, "unit mismatch"):
            metric_improvement(
                make_metric(unit=MetricUnit.FRACTION),
                MetricObservation("accuracy", 60.0, MetricUnit.PERCENT),
                MetricObservation("accuracy", 0.55, MetricUnit.FRACTION),
            )
        latency = make_metric(
            metric_id="latency",
            direction=MetricDirection.LOWER_IS_BETTER,
            unit=MetricUnit.SECONDS,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "unit mismatch"):
            metric_improvement(
                latency,
                MetricObservation("latency", 50.0, MetricUnit.MILLISECONDS),
                MetricObservation("latency", 0.06, MetricUnit.SECONDS),
            )

    def test_omitted_must_run_baseline_blocks_superiority(self) -> None:
        contract = make_contract()
        with self.assertRaisesRegex(ScientificPromotionError, "MUST_RUN"):
            validate_baseline_registry(
                contract.baseline_registry,
                executed_baseline_ids=(),
                candidate_conditions=contract.candidate_conditions,
                central_superiority_claim=True,
            )

    def test_executed_baseline_requires_an_observed_metric(self) -> None:
        registry = BaselineRegistry((make_baseline(observed_metric=None),))
        with self.assertRaisesRegex(ScientificPromotionError, "observed metric"):
            validate_baseline_registry(
                registry,
                executed_baseline_ids=("baseline-strong",),
                candidate_conditions=make_conditions(),
                central_superiority_claim=True,
            )

    def test_must_run_exclusion_booleans_never_authorize_omission(self) -> None:
        weak = BaselineExclusion(
            reason="The baseline was inconvenient to execute.",
            evidence_ids=("resource-record",),
            scientifically_unavoidable=False,
            preserves_claim_validity=False,
        )
        registry = BaselineRegistry((make_baseline(exclusion=weak),))
        with self.assertRaises(ScientificPromotionError):
            validate_baseline_registry(
                registry,
                executed_baseline_ids=(),
                candidate_conditions=make_conditions(),
                central_superiority_claim=False,
            )
        strong = replace(
            weak,
            reason="The authoritative implementation cannot evaluate this frozen outcome.",
            scientifically_unavoidable=True,
            preserves_claim_validity=True,
        )
        self.assertTrue(strong.strong)
        with self.assertRaisesRegex(ScientificPromotionError, "MUST_RUN"):
            validate_baseline_registry(
                BaselineRegistry((make_baseline(exclusion=strong),)),
                executed_baseline_ids=(),
                candidate_conditions=make_conditions(),
                central_superiority_claim=False,
            )

    def test_unfair_compute_or_tuning_budget_blocks_comparison(self) -> None:
        for field, value in (("tuning_trials", 40), ("compute_budget", 500.0)):
            with self.subTest(field=field):
                baseline = make_baseline(conditions=make_conditions(**{field: value}))
                with self.assertRaisesRegex(ScientificPromotionError, field):
                    validate_baseline_registry(
                        BaselineRegistry((baseline,)),
                        executed_baseline_ids=("baseline-strong",),
                        candidate_conditions=make_conditions(),
                        central_superiority_claim=True,
                    )

    def test_every_fairness_dimension_is_checked(self) -> None:
        fields = {
            "data_identity": "other-data",
            "split_identity": "other-split",
            "supervision": "extra-labels",
            "pretrained_resources": "foundation-model",
            "hyperparameter_search": "larger-search",
            "preprocessing": "other-preprocess",
            "evaluator": "other-evaluator",
            "hardware_class": "gpu",
            "latency_method": "warm-cache-only",
            "failure_policy": "exclude failures",
            "metric_id": "proxy-score",
            "metric_unit": MetricUnit.PERCENT,
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                registry = BaselineRegistry(
                    (make_baseline(conditions=make_conditions(**{field: value})),)
                )
                with self.assertRaisesRegex(ScientificPromotionError, field):
                    validate_baseline_registry(
                        registry,
                        executed_baseline_ids=("baseline-strong",),
                        candidate_conditions=make_conditions(),
                        central_superiority_claim=True,
                    )

    def test_contract_rejects_uncleared_novelty_posthoc_primary_and_bad_statistics(self) -> None:
        with self.assertRaises(ScientificPromotionError):
            make_contract(novelty_register=make_novelty(status=NoveltyStatus.UNCERTAIN))
        post_hoc_primary = make_hypothesis(
            "posthoc-primary",
            HypothesisRole.PRIMARY,
            timing=HypothesisTiming.POST_HOC,
            formed_after_observation=True,
        )
        with self.assertRaisesRegex(ScientificDesignError, "pre-specified"):
            make_contract(
                hypothesis_register=HypothesisRegister((post_hoc_primary,)),
                ablations=(),
            )
        with self.assertRaisesRegex(ScientificDesignError, "multiple comparisons"):
            make_statistical_plan(multiplicity_correction="none")

    def test_contract_amendments_are_exact_append_only_lineage(self) -> None:
        parent = make_contract()
        child = replace(
            parent,
            version=2,
            success_criteria=("A stricter independently justified success criterion.",),
            separation=ExecutionSeparation(6, 3, "fresh-protected-holdout"),
            frozen_at="2026-08-30T00:00:00Z",
        )
        amendment = record_evaluation_contract_amendment(
            parent,
            amendment_id="amendment-1",
            recorded_at="2026-08-30T00:00:00Z",
            author_id="protocol-designer",
            reason="Results were visible; start a new version with a fresh reserve.",
            affected_experiment_ids=("experiment-confirm",),
            changed_fields=("separation", "success_criteria"),
            results_already_seen=True,
            requires_new_confirmatory_reserve=True,
        )
        validate_amended_evaluation_contract(parent, child, amendment)
        self.assertEqual(parent.version, 1)
        with self.assertRaisesRegex(ScientificPromotionError, "exactly describe"):
            validate_amended_evaluation_contract(
                parent,
                child,
                replace(amendment, changed_fields=("success_criteria",)),
            )

    def test_postresult_amendment_cannot_reuse_protected_reserve(self) -> None:
        parent = make_contract()
        with self.assertRaisesRegex(ScientificDesignError, "fresh confirmatory reserve"):
            EvaluationContractAmendment(
                amendment_id="amendment-bad",
                parent_contract_sha256=parent.sha256,
                contract_id=parent.contract_id,
                from_version=1,
                to_version=2,
                recorded_at="2026-08-30T00:00:00Z",
                author_id="protocol-designer",
                reason="Attempt to revise after results.",
                affected_experiment_ids=("experiment-confirm",),
                changed_fields=("success_criteria",),
                results_already_seen=True,
                requires_new_confirmatory_reserve=False,
            )


class SelectionStatisticsAndPromotionTests(unittest.TestCase):
    def test_all_seed_reporting_rejects_selective_omission(self) -> None:
        plan = make_contract().seed_reporting
        with self.assertRaisesRegex(ScientificPromotionError, "selective"):
            validate_seed_report(
                plan,
                (successful_run(7, 0.72), successful_run(19, 0.75)),
                make_metric(),
            )

    def test_all_seed_reporting_preserves_failed_and_invalid_outcomes(self) -> None:
        plan = make_contract().seed_reporting
        records = (
            successful_run(7, 0.72),
            SeedRunRecord(
                "run-11",
                11,
                RunDisposition.FAILED,
                None,
                digest("failed-log"),
                failure_reason="process crash",
            ),
            SeedRunRecord(
                "run-19",
                19,
                RunDisposition.INVALID,
                None,
                digest("invalid-log"),
                failure_reason="leakage detected",
            ),
        )
        report = validate_seed_report(plan, records, make_metric())
        self.assertEqual((report.successful_runs, report.failed_runs, report.invalid_runs), (1, 1, 1))

    def test_best_of_n_requires_predeclared_policy_full_distribution_and_true_best(self) -> None:
        with self.assertRaisesRegex(ScientificDesignError, "frozen before results"):
            SeedReportingPlan(
                seeds=(7, 11, 19),
                regime=ReportingRegime.BEST_OF_N,
                selection_policy="Select maximum accuracy.",
                selection_defined_before_results=False,
                preserve_all_runs=True,
                technical_retry_rule="Recorded infrastructure crashes only.",
                best_of_n=3,
            )
        with self.assertRaisesRegex(ScientificDesignError, "must be preserved"):
            SeedReportingPlan(
                seeds=(7, 11, 19),
                regime=ReportingRegime.ALL_SEEDS,
                selection_policy="Claim all seeds while discarding failures.",
                selection_defined_before_results=True,
                preserve_all_runs=False,
                technical_retry_rule="Recorded infrastructure crashes only.",
            )
        plan = SeedReportingPlan(
            seeds=(7, 11, 19),
            regime=ReportingRegime.BEST_OF_N,
            selection_policy="Select maximum frozen primary accuracy.",
            selection_defined_before_results=True,
            preserve_all_runs=True,
            technical_retry_rule="Recorded infrastructure crashes only.",
            best_of_n=3,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "metric direction"):
            validate_seed_report(
                plan,
                (
                    successful_run(7, 0.72, selected=True),
                    successful_run(11, 0.80),
                    successful_run(19, 0.75),
                ),
                make_metric(),
            )
        report = validate_seed_report(
            plan,
            (
                successful_run(7, 0.72),
                successful_run(11, 0.80, selected=True),
                successful_run(19, 0.75),
            ),
            make_metric(),
        )
        self.assertEqual(report.selected_run_id, "run-11")
        self.assertEqual(report.successful_distribution, (0.72, 0.80, 0.75))

    def test_statistically_weak_result_cannot_be_framed_as_superiority(self) -> None:
        plan = make_statistical_plan()
        weak_cases = (
            passing_statistics(improvement_effect=0.01),
            passing_statistics(confidence_low=-0.01),
            passing_statistics(adjusted_p_value=0.20),
            passing_statistics(sample_size=10),
            passing_statistics(multiplicity_correction="uncorrected"),
        )
        for evidence in weak_cases:
            with self.subTest(evidence=evidence):
                with self.assertRaises(ScientificPromotionError):
                    validate_statistical_evidence(plan, evidence)
        validate_statistical_evidence(plan, passing_statistics())

    def test_proxy_metric_cannot_be_promoted_to_end_to_end_without_verified_inference(self) -> None:
        contract = make_contract()
        with self.assertRaisesRegex(ScientificPromotionError, "proxy metric"):
            validate_metric_claim_scope(
                contract,
                evidence_metric_id="proxy-score",
                claimed_scope=MetricScope.END_TO_END,
            )
        unverified = ProxyInferenceContract(
            proxy_metric_id="proxy-score",
            end_to_end_metric_id="accuracy",
            justification="The proxy might correlate with system accuracy.",
            validation_method="Frozen correlation analysis.",
            evidence_ids=("proxy-study",),
            independently_verified=False,
        )
        with self.assertRaises(ScientificPromotionError):
            validate_metric_claim_scope(
                make_contract(proxy_inferences=(unverified,)),
                evidence_metric_id="proxy-score",
                claimed_scope=MetricScope.END_TO_END,
            )
        verified = replace(unverified, independently_verified=True)
        with self.assertRaisesRegex(ScientificPromotionError, "registry-resolved"):
            validate_metric_claim_scope(
                make_contract(proxy_inferences=(verified,)),
                evidence_metric_id="proxy-score",
                claimed_scope=MetricScope.END_TO_END,
            )

    def test_exploration_and_confirmation_use_disjoint_validity_resources(self) -> None:
        contract = make_contract()
        exploratory = ExperimentPlan(
            experiment_id="experiment-secondary",
            hypothesis_id="hypothesis-secondary",
            stage=ExperimentStage.EXPLORATORY,
            contract_sha256=contract.sha256,
            dataset_split_id="development-v1",
            seed=7,
            evaluator_id="evaluator-v1",
            uses_protected_resource=False,
            results_seen_before_plan=False,
        )
        admit_experiment(contract, exploratory)
        for split_id in ("train-v1", "validation-v1"):
            with self.subTest(split_id=split_id):
                admit_experiment(
                    contract,
                    replace(exploratory, dataset_split_id=split_id),
                )
        for split_id in ("unknown-v1", "confirmatory-v1:alias"):
            with self.subTest(split_id=split_id):
                with self.assertRaisesRegex(
                    ScientificPromotionError, "exact frozen exploratory split"
                ):
                    admit_experiment(
                        contract,
                        replace(exploratory, dataset_split_id=split_id),
                    )
        with self.assertRaisesRegex(ScientificPromotionError, "planned experiment"):
            admit_experiment(
                contract,
                replace(exploratory, experiment_id="experiment-primary"),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "protected"):
            admit_experiment(
                contract,
                replace(exploratory, uses_protected_resource=True),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "protected"):
            admit_experiment(
                contract,
                replace(
                    exploratory,
                    dataset_split_id="confirmatory-v1",
                    uses_protected_resource=True,
                ),
            )
        confirmatory = ExperimentPlan(
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            stage=ExperimentStage.CONFIRMATORY,
            contract_sha256=contract.sha256,
            dataset_split_id="confirmatory-v1",
            seed=11,
            evaluator_id="evaluator-v1",
        uses_protected_resource=True,
            results_seen_before_plan=False,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "registry/ledger"):
            admit_experiment(contract, confirmatory)
        with self.assertRaisesRegex(ScientificPromotionError, "planned experiment"):
            admit_experiment(
                contract,
                replace(confirmatory, experiment_id="experiment-secondary"),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "protected-resource"):
            admit_experiment(
                contract,
                replace(confirmatory, uses_protected_resource=False),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "confirmatory split"):
            admit_experiment(
                contract,
                replace(confirmatory, dataset_split_id="validation-v1"),
            )
        with self.assertRaisesRegex(ScientificPromotionError, "registry/ledger"):
            admit_experiment(contract, replace(confirmatory, results_seen_before_plan=True))

    def test_ablation_and_hypothesis_purpose_bindings_are_exact(self) -> None:
        contract = make_contract()
        secondary = ExperimentPlan(
            experiment_id="experiment-secondary",
            hypothesis_id="hypothesis-secondary",
            stage=ExperimentStage.EXPLORATORY,
            contract_sha256=contract.sha256,
            dataset_split_id="development-v1",
            seed=7,
            evaluator_id="evaluator-v1",
            uses_protected_resource=False,
            results_seen_before_plan=False,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "different hypothesis"):
            admit_experiment(
                contract,
                replace(secondary, ablation_id="ablation-core"),
            )
        with self.assertRaisesRegex(ScientificDesignError, "planned experiment IDs"):
            HypothesisRegister(
                (
                    make_hypothesis(
                        "hypothesis-primary",
                        HypothesisRole.PRIMARY,
                        planned_experiment="experiment-shared",
                    ),
                    make_hypothesis(
                        "hypothesis-secondary",
                        HypothesisRole.SECONDARY,
                        planned_experiment="experiment-shared",
                    ),
                )
            )

    def test_evaluator_exploitation_signal_is_independently_blocking(self) -> None:
        signal = EvaluatorExploitationSignal(
            ExploitationSignalKind.METRIC_PARSER_MANIPULATION,
            "Candidate writes an output parsed as a score without doing the task.",
            "exploit-evidence",
        )
        with self.assertRaisesRegex(ScientificDesignError, "blocking"):
            EvaluatorAssessment("evaluator-v1", "v1", (signal,), True)
        assessment = EvaluatorAssessment("evaluator-v1", "v1", (signal,), False)
        with self.assertRaisesRegex(ScientificPromotionError, "METRIC_PARSER"):
            require_evaluator_integrity(assessment)

    def test_fabricated_and_missing_ablation_results_fail_closed(self) -> None:
        contract = make_contract()
        fabricated = AblationResult(
            "ablation-invented",
            True,
            digest("fabricated-ablation"),
            "Claims a favorable result for an unregistered ablation.",
        )
        with self.assertRaisesRegex(ScientificPromotionError, "fabricated"):
            validate_ablation_results(contract, (fabricated,))
        with self.assertRaisesRegex(ScientificPromotionError, "required ablations"):
            validate_ablation_results(contract, ())
        validate_ablation_results(
            contract,
            (
                AblationResult(
                    "ablation-core",
                    True,
                    digest("real-ablation"),
                    "Removing the component eliminated the directed effect.",
                ),
            ),
        )

    def test_aggregate_superiority_gate_requires_direction_stats_evaluator_and_scope(self) -> None:
        contract = make_contract()
        clean = EvaluatorAssessment("evaluator-v1", "v1", (), True)
        validate_superiority_claim(
            contract,
            executed_baseline_ids=("baseline-strong",),
            candidate_observation=MetricObservation("accuracy", 0.76, MetricUnit.FRACTION),
            baseline_observation=MetricObservation("accuracy", 0.70, MetricUnit.FRACTION),
            statistical_evidence=passing_statistics(),
            evaluator_assessment=clean,
            evidence_metric_id="accuracy",
            claimed_scope=MetricScope.END_TO_END,
        )
        with self.assertRaisesRegex(ScientificPromotionError, "metric direction"):
            validate_superiority_claim(
                contract,
                executed_baseline_ids=("baseline-strong",),
                candidate_observation=MetricObservation("accuracy", 0.65, MetricUnit.FRACTION),
                baseline_observation=MetricObservation("accuracy", 0.70, MetricUnit.FRACTION),
                statistical_evidence=passing_statistics(),
                evaluator_assessment=clean,
                evidence_metric_id="accuracy",
                claimed_scope=MetricScope.END_TO_END,
            )


class ScientificTimelineAuthorityTests(unittest.TestCase):
    @staticmethod
    def _reproduction_values(
        values: dict[str, object],
    ) -> dict[str, object]:
        reproduction = dict(values)
        spec = replace(
            values["spec"],  # type: ignore[arg-type]
            run_id="timeline-reproduction",
        )
        spec_record = register_frozen_run_spec(
            values["registry"],  # type: ignore[arg-type]
            contract=values["contract"],  # type: ignore[arg-type]
            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
            ),
            spec=spec,
        )
        reproduction.update(spec=spec, spec_record=spec_record)
        return reproduction

    def _freeze(self, values: dict[str, object]):
        return record_scientific_design_freeze(
            values["registry"],  # type: ignore[arg-type]
            values["ledger"],  # type: ignore[arg-type]
            run_id="timeline-run",
            contract=values["contract"],  # type: ignore[arg-type]
            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
        )

    def _record_result(self, values: dict[str, object]):
        return record_scientific_result_observed(
            values["registry"],  # type: ignore[arg-type]
            values["ledger"],  # type: ignore[arg-type]
            run_id="timeline-run",
            contract=values["contract"],  # type: ignore[arg-type]
            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
            output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
        )

    def _register_receipt(self, values: dict[str, object]):
        return register_scientific_timeline_receipt(
            values["registry"],  # type: ignore[arg-type]
            values["ledger"],  # type: ignore[arg-type]
            receipt_id="timeline-receipt",
            run_id="timeline-run",
            contract=values["contract"],  # type: ignore[arg-type]
            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
            output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
        )

    def _register_contract_freeze_receipt(self, values: dict[str, object]):
        return register_evaluation_contract_freeze_gate_receipt(
            values["registry"],  # type: ignore[arg-type]
            values["ledger"],  # type: ignore[arg-type]
            receipt_id="evaluation-contract-freeze-gate-receipt",
            run_id="timeline-run",
            contract=values["contract"],  # type: ignore[arg-type]
            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
            ),
            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
        )

    def test_evaluation_contract_freeze_gate_is_exact_and_prospective_only(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            self._freeze(values)
            record = self._register_contract_freeze_receipt(values)
            receipt = require_evaluation_contract_freeze_gate_receipt(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                receipt_artifact_sha256=record.sha256,
                expected_run_id="timeline-run",
                expected_contract_id=values["contract"].contract_id,  # type: ignore[union-attr]
                contract=None,
            )
            self.assertIsInstance(receipt, EvaluationContractFreezeGateReceipt)
            self.assertTrue(receipt.scientific_gate_passed)
            self.assertEqual(receipt.freeze_scope, "DESIGN_FREEZE_VALIDITY_ONLY")
            self.assertFalse(receipt.result_validity_authorized)
            self.assertEqual(
                values["registry"].get_metadata(record.sha256).parent_artifacts,  # type: ignore[union-attr]
                (
                    values["contract_record"].sha256,  # type: ignore[union-attr]
                    *(item.sha256 for item in values["plan_records"]),  # type: ignore[union-attr]
                    values["spec_record"].sha256,  # type: ignore[union-attr]
                ),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "another run"):
                require_evaluation_contract_freeze_gate_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=record.sha256,
                    expected_run_id="wrong-run",
                    expected_contract_id=receipt.object_id,
                )

    def test_evaluation_contract_freeze_rejects_unlogged_results_correction_and_parent_order(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            freeze_event = self._freeze(values)
            record = self._register_contract_freeze_receipt(values)
            original = safe_json_loads(
                values["registry"].get_bytes(record.sha256)  # type: ignore[union-attr]
            )
            original["receipt_id"] = "reordered-contract-freeze-receipt"
            parents = values["registry"].get_metadata(record.sha256).parent_artifacts  # type: ignore[union-attr]
            reordered = values["registry"].put_json(  # type: ignore[union-attr]
                original,
                logical_type="evaluation_contract_freeze_gate_receipt",
                origin=(
                    "registry-ledger prospective evaluation-contract freeze "
                    "verification"
                ),
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=(
                    "scientist-one",
                    "verify-evaluation-contract-freeze",
                ),
                parent_artifacts=tuple(reversed(parents)),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(ScientificPromotionError, "reordered parents"):
                require_evaluation_contract_freeze_gate_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=reordered.sha256,
                    expected_run_id="timeline-run",
                    expected_contract_id=values["contract"].contract_id,  # type: ignore[union-attr]
                )

            substituted_metadata = dict(original)
            substituted_metadata["receipt_id"] = (
                "substituted-metadata-contract-freeze-receipt"
            )
            metadata_record = values["registry"].put_json(  # type: ignore[union-attr]
                substituted_metadata,
                logical_type="evaluation_contract_freeze_gate_receipt",
                origin="adversarial contract-freeze metadata",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "adversarial-test"),
                parent_artifacts=parents,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "metadata is not source-owned",
            ):
                require_evaluation_contract_freeze_gate_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=metadata_record.sha256,
                    expected_run_id="timeline-run",
                    expected_contract_id=values["contract"].contract_id,  # type: ignore[union-attr]
                )

            _register_timeline_outputs(values)
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "matching result manifest requires exactly one",
            ):
                require_evaluation_contract_freeze_gate_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=record.sha256,
                    expected_run_id="timeline-run",
                    expected_contract_id=values["contract"].contract_id,  # type: ignore[union-attr]
                )
            values["ledger"].append_correction(  # type: ignore[union-attr]
                freeze_event.event_id,
                actor_role=Role.SCIENTIFIC_REVIEWER,
                reason="The prospective design-freeze checkpoint is withdrawn.",
                corrected_fields={"authority": "WITHDRAWN"},
            )
            with self.assertRaisesRegex(ScientificPromotionError, "superseded"):
                require_evaluation_contract_freeze_gate_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=record.sha256,
                    expected_run_id="timeline-run",
                    expected_contract_id=values["contract"].contract_id,  # type: ignore[union-attr]
                )

    def test_honest_exploratory_timeline_rehydrates_without_in_memory_contract(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            self._freeze(values)
            _register_timeline_outputs(values)
            self._record_result(values)
            record = self._register_receipt(values)
            receipt = require_scientific_timeline_receipt(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                receipt_artifact_sha256=record.sha256,
                run_id="timeline-run",
                contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
                experiment_plan_artifact_sha256s=tuple(
                    item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
                ),
                frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
                output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
                contract=None,
            )
            self.assertIsInstance(receipt, ScientificTimelineReceipt)
            self.assertLess(
                receipt.design_freeze_event_index,
                receipt.result_event_index,
            )
            self.assertTrue(receipt.frozen_before_result_visibility)

    def test_missing_result_event_cannot_mint_timeline_authority(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            self._freeze(values)
            _register_timeline_outputs(values)
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "exactly one result-visibility",
            ):
                self._register_receipt(values)

    def test_backdated_registry_time_and_false_boolean_cannot_hide_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            self.assertFalse(values["plans"][0].results_seen_before_plan)  # type: ignore[index,union-attr]
            _register_timeline_outputs(
                values,
                created_at="2020-01-01T00:00:00Z",
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "after matching results",
            ):
                self._freeze(values)

    def test_namespaced_autonomous_manifest_coexists_with_temporal_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
            sidecar_spec = _timeline_artifact(
                registry,
                b'{"authority":"autonomous-sidecar"}\n',
                "autonomous_implementation.frozen_run_spec",
                Role.IMPLEMENTER,
            )
            _timeline_artifact(
                registry,
                b'{"manifest":"autonomous-sidecar"}\n',
                "experiment_output_manifest",
                Role.EXPERIMENT_RUNNER,
                (sidecar_spec.sha256,),
            )

            event = self._freeze(values)

            self.assertEqual(event.actor_role, Role.PROTOCOL_DESIGNER)

    def test_later_exact_reproduction_remains_live_registry_revalidatable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            reproduction = self._reproduction_values(values)
            self._freeze(values)
            self._freeze(reproduction)
            _register_timeline_outputs(values)
            self._record_result(values)
            primary_record = self._register_receipt(values)
            _register_timeline_outputs(reproduction)
            self._record_result(reproduction)
            reproduction_record = self._register_receipt(reproduction)
            for selected, record in (
                (values, primary_record),
                (reproduction, reproduction_record),
            ):
                receipt = require_scientific_timeline_receipt(
                    selected["registry"],  # type: ignore[arg-type]
                    selected["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=record.sha256,
                    run_id="timeline-run",
                    contract_artifact_sha256=selected["contract_record"].sha256,  # type: ignore[union-attr]
                    experiment_plan_artifact_sha256s=tuple(
                        item.sha256 for item in selected["plan_records"]  # type: ignore[union-attr]
                    ),
                    frozen_run_spec_artifact_sha256=selected["spec_record"].sha256,  # type: ignore[union-attr]
                    output_manifest_artifact_sha256=selected["manifest_record"].sha256,  # type: ignore[union-attr]
                    contract=None,
                )
                self.assertTrue(receipt.frozen_before_result_visibility)

    def test_unledgered_later_manifest_invalidates_live_receipt_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            reproduction = self._reproduction_values(values)
            self._freeze(values)
            self._freeze(reproduction)
            _register_timeline_outputs(values)
            self._record_result(values)
            primary_record = self._register_receipt(values)
            _register_timeline_outputs(reproduction)
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "matching result manifest requires exactly one",
            ):
                require_scientific_timeline_receipt(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    receipt_artifact_sha256=primary_record.sha256,
                    run_id="timeline-run",
                    contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
                    experiment_plan_artifact_sha256s=tuple(
                        item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
                    ),
                    frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
                    output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
                )

    def test_wrong_output_namespace_and_pre_event_visibility_reject(self) -> None:
        for mode, message in (
            ("wrong-namespace", "exact frozen experiment-runner custody"),
            ("pre-event-visibility", "first visibility"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                values = _prepared_timeline(root)
                freeze_event = self._freeze(values)
                _register_timeline_outputs(
                    values,
                    namespace_outputs=mode != "wrong-namespace",
                )
                if mode == "wrong-namespace":
                    with self.assertRaisesRegex(ScientificPromotionError, message):
                        self._record_result(values)
                    continue
                manifest_record = values["manifest_record"]
                values["ledger"].record(  # type: ignore[union-attr]
                    run_id="timeline-run",
                    actor_role=Role.ORCHESTRATOR,
                    state_before=freeze_event.requested_state_after,
                    requested_state_after=freeze_event.requested_state_after,
                    artifact_hashes=(manifest_record.sha256,),
                    code_version="pre-result-label-only-event",
                    configuration_hash=values["spec"].configuration_sha256,  # type: ignore[union-attr]
                    reason="untyped early manifest visibility",
                    event_type="CHECKPOINT",
                    metadata={"label_only": True},
                )
                self._record_result(values)
                with self.assertRaisesRegex(ScientificPromotionError, message):
                    self._register_receipt(values)

    def test_duplicate_result_events_and_corrections_invalidate_timeline(self) -> None:
        for mode in ("duplicate", "correction"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                values = _prepared_timeline(root)
                self._freeze(values)
                _register_timeline_outputs(values)
                result_event = self._record_result(values)
                if mode == "duplicate":
                    self._record_result(values)
                    with self.assertRaisesRegex(
                        ScientificPromotionError,
                        "exactly one result-visibility",
                    ):
                        self._register_receipt(values)
                else:
                    record = self._register_receipt(values)
                    values["ledger"].append_correction(  # type: ignore[union-attr]
                        result_event.event_id,
                        actor_role=Role.SCIENTIFIC_REVIEWER,
                        reason="The selected result timeline event is withdrawn.",
                        corrected_fields={"authority": "WITHDRAWN"},
                    )
                    with self.assertRaisesRegex(
                        ScientificPromotionError,
                        "superseded",
                    ):
                        require_scientific_timeline_receipt(
                            values["registry"],  # type: ignore[arg-type]
                            values["ledger"],  # type: ignore[arg-type]
                            receipt_artifact_sha256=record.sha256,
                            run_id="timeline-run",
                            contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
                            experiment_plan_artifact_sha256s=tuple(
                                item.sha256 for item in values["plan_records"]  # type: ignore[union-attr]
                            ),
                            frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
                            output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
                        )


class ConfirmatoryTimelineAuthorityTests(unittest.TestCase):
    @staticmethod
    def _receipt_arguments(values: dict[str, object]) -> dict[str, object]:
        return {
            "receipt_id": "confirmatory-timeline-receipt",
            "run_id": "confirmatory-timeline-run",
            "study_id": values["study_id"],
            "study_version": values["study_version"],
            "protocol_artifact_sha256": values["protocol_record"].sha256,
            "fresh_custody_receipt_sha256": values["fresh_record"].sha256,
            "custody_record_sha256": values["custody_record"].sha256,
            "result_artifact_sha256": values["result_record"].sha256,
        }

    def test_confirmatory_sequence_ignores_backdated_timestamps_and_rehydrates(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_confirmatory_timeline(root)
            _append_confirmatory_timeline_event(
                values, "freeze", timestamp="2030-01-01T00:00:00Z"
            )
            _append_confirmatory_timeline_event(
                values, "start", timestamp="2029-01-01T00:00:00Z"
            )
            _append_confirmatory_timeline_event(
                values, "result", timestamp="2020-01-01T00:00:00Z"
            )
            arguments = self._receipt_arguments(values)
            record = register_confirmatory_timeline_receipt(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                **arguments,  # type: ignore[arg-type]
            )
            receipt = require_confirmatory_timeline_receipt(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                receipt_artifact_sha256=record.sha256,
                **{
                    key: value
                    for key, value in arguments.items()
                    if key != "receipt_id"
                },  # type: ignore[arg-type]
            )
            self.assertIsInstance(receipt, ConfirmatoryTimelineReceipt)
            self.assertLess(
                receipt.freeze_event_index,
                receipt.confirmatory_started_event_index,
            )
            self.assertLessEqual(
                receipt.reveal_event_index,
                receipt.result_event_index,
            )
            ledger: EventLedger = values["ledger"]  # type: ignore[assignment]
            ledger.record(
                run_id="confirmatory-timeline-run",
                actor_role=Role.CLAIM_VERIFIER,
                state_before="CONFIRM",
                requested_state_after="CONFIRM",
                artifact_hashes=(record.sha256,),
                code_version="confirmatory-timeline-fixture-v1",
                configuration_hash=digest(
                    "confirmatory-timeline-configuration"
                ),
                reason=(
                    "admit the structural confirmatory timeline fixture"
                ),
                event_id="confirmatory-timeline-receipt-admitted",
                event_type="CHECKPOINT",
                timestamp="2020-01-01T00:00:01Z",
                metadata={
                    "artifact_types": [record.logical_type],
                    "artifact_record_hashes": [str(record.record_hash)],
                },
            )
            authority = register_r_check_authority(
                values["registry"],  # type: ignore[arg-type]
                ledger,
                run_id="confirmatory-timeline-run",
                r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E3,
                source_artifact_sha256s=(record.sha256,),
            )
            resolved = resolve_r_check_authority(
                values["registry"],  # type: ignore[arg-type]
                ledger,
                authority_artifact_sha256=authority.sha256,
                run_id="confirmatory-timeline-run",
            )
            self.assertEqual(resolved.scope, AuthorityScope.SYSTEM_FIXTURE)
            self.assertEqual(resolved.status, AuthorityStatus.UNTESTED)
            self.assertEqual(
                resolved.reason_code,
                "SCIENTIFIC_CONFIRMATORY_AUTHORITY_UNAVAILABLE",
            )

    def test_missing_or_ledger_reordered_confirmatory_events_reject(self) -> None:
        for mode in ("missing-start", "result-before-start"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                values = _prepared_confirmatory_timeline(root)
                _append_confirmatory_timeline_event(
                    values, "freeze", timestamp="2026-08-29T00:00:00Z"
                )
                if mode == "result-before-start":
                    _append_confirmatory_timeline_event(
                        values, "result", timestamp="2026-08-29T00:02:00Z"
                    )
                    _append_confirmatory_timeline_event(
                        values, "start", timestamp="2026-08-29T00:01:00Z"
                    )
                    message = "event sequence"
                else:
                    _append_confirmatory_timeline_event(
                        values, "result", timestamp="2026-08-29T00:02:00Z"
                    )
                    message = "one exact freeze, start, reveal, and result"
                with self.assertRaisesRegex(ScientificPromotionError, message):
                    register_confirmatory_timeline_receipt(
                        values["registry"],  # type: ignore[arg-type]
                        values["ledger"],  # type: ignore[arg-type]
                        **self._receipt_arguments(values),  # type: ignore[arg-type]
                    )

    def test_substituted_custody_parents_reject_before_event_labels(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_confirmatory_timeline(root)
            registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
            fresh_record = values["fresh_record"]
            protocol_record = values["protocol_record"]
            forged_custody = _timeline_artifact(
                registry,
                canonical_json_bytes(
                    {
                        "study_id": values["study_id"],
                        "study_version": values["study_version"],
                        "variant": "substituted-parent-chain",
                    }
                )
                + b"\n",
                "custody_record",
                Role.HOLDOUT_CUSTODIAN,
                fresh_record.parent_artifacts,
            )
            forged_result = _timeline_artifact(
                registry,
                canonical_json_bytes(
                    {
                        "input_hashes": {
                            "frozen_protocol": protocol_record.sha256,
                            "custody_record": forged_custody.sha256,
                        },
                        "scientific_protocol_sha256": values["protocol_sha256"],
                    }
                )
                + b"\n",
                "machine_results",
                Role.EXPERIMENT_RUNNER,
                (protocol_record.sha256, forged_custody.sha256),
            )
            values["custody_record"] = forged_custody
            values["result_record"] = forged_result
            for index, kind in enumerate(("freeze", "start", "result")):
                _append_confirmatory_timeline_event(
                    values,
                    kind,
                    timestamp=f"2026-08-29T00:0{index}:00Z",
                )
            with self.assertRaisesRegex(ScientificPromotionError, "artifact.*chain"):
                register_confirmatory_timeline_receipt(
                    registry,
                    values["ledger"],  # type: ignore[arg-type]
                    **self._receipt_arguments(values),  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
