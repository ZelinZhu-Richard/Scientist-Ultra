from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.experiments import (
    AblationResult as ManifestAblationResult,
    EvidenceClass,
    ExperimentPhase,
    FrozenRunSpec,
    OutputArtifact,
    OutputManifest,
    SeedRunResult,
    SeedRunStatus,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import utc_now
from scientist_one.research_state import (
    Metric as StateMetric,
    MetricDirection as StateMetricDirection,
    ObjectLink,
    ObjectReference,
    RecordStatus,
    Result as StateResult,
    Run as StateRun,
    StatisticalTest as StateStatisticalTest,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    BASELINE_EXCLUSION_EVIDENCE_SCHEMA,
    BASELINE_EXCLUSION_SCIENTIFIC_PURPOSE,
    CHECKED_SUPERIORITY_ABLATION_OUTPUT_SCHEMA,
    CHECKED_SUPERIORITY_AGGREGATE_SCHEMA,
    CHECKED_BOOTSTRAP_RESAMPLES_V1,
    CHECKED_BOOTSTRAP_SEED_V1,
    CHECKED_DIRECTIONAL_EFFECT_METHOD_V1,
    CHECKED_SUPERIORITY_CONFIGURATION_SCHEMA,
    CHECKED_SUPERIORITY_CONTRACT_SCHEMA,
    CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2,
    CHECKED_SUPERIORITY_EVALUATOR_IMPLEMENTATION_SCHEMA,
    CHECKED_SUPERIORITY_EVALUATOR_SCHEMA,
    CHECKED_SUPERIORITY_EVALUATOR_TRACE_SCHEMA,
    CHECKED_SUPERIORITY_OBLIGATION_EVIDENCE_SCHEMA,
    CHECKED_SUPERIORITY_OBLIGATIONS_SCHEMA,
    CHECKED_SUPERIORITY_PAIRED_OUTPUT_SCHEMA,
    CHECKED_SUPERIORITY_SCIENTIFIC_PURPOSE,
    CHECKED_SUPERIORITY_STATISTICS_SCHEMA,
    CHECKED_UNIT_SEED_AGGREGATION_ALGORITHM_V1,
    PROXY_INFERENCE_EVIDENCE_SCHEMA,
    PROXY_INFERENCE_VALIDATION_METHOD,
    BaselineExclusion,
    BaselineRegistry,
    CheckedSuperiorityPromotion,
    EvaluationContract,
    EvaluatorAssessment,
    ExperimentPlan,
    ExperimentStage,
    HypothesisEvaluationPolicy,
    MetricObservation,
    MetricDirection as ScientificMetricDirection,
    MetricScope,
    MetricUnit,
    ProxyInferenceContract,
    ReportingRegime,
    ScientificPromotionError,
    ScientificResultPromotionReceipt,
    ScientificResultPromotionStatus,
    SeedReportingPlan,
    StatisticalEvidence,
    StatisticalPlan,
    SuperiorityValidationStatus,
    register_baseline_exclusion_verification,
    register_checked_superiority_promotion,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
    register_proxy_inference_verification,
    register_scientific_result_state_projections,
    record_scientific_design_freeze,
    record_scientific_result_observed,
    require_frozen_evaluation_contract,
    require_scientific_result_promotion_authority,
    require_scientific_result_state_projections,
    require_baseline_exclusion_verification,
    require_proxy_inference_verification,
    validate_superiority_claim,
)
from scientist_one.security import canonical_json_bytes


STATE_CODE_VERSION = "research-os-vnext:test-state-kernel"

try:
    from .test_scientific_design import (
        make_baseline,
        make_conditions,
        make_contract,
        make_metric,
    )
except ImportError:  # pytest/direct execution loads tests as top-level modules.
    from test_scientific_design import (  # type: ignore[no-redef]
        make_baseline,
        make_conditions,
        make_contract,
        make_metric,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _put_json(
    registry: ArtifactRegistry,
    value: object,
    *,
    logical_type: str,
    role: Role,
    parents: tuple[str, ...] = (),
    schema_version: str = "1.0",
) -> ArtifactRecord:
    return registry.put_json(
        value,
        logical_type=logical_type,
        origin=f"focused scientific-authority boundary fixture: {logical_type}",
        creator_role=role,
        creation_command=("scientist-one", "test-scientific-authority-boundary"),
        parent_artifacts=parents,
        schema_version=schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _checked_contract(
    *,
    metric_direction: ScientificMetricDirection = (
        ScientificMetricDirection.HIGHER_IS_BETTER
    ),
    baseline_value: float = 0.0,
    outcome_neutral: bool = False,
    target_value: float = 1.0,
) -> EvaluationContract:
    metric = make_metric(
        direction=metric_direction,
        target_value=(
            target_value
            if metric_direction is ScientificMetricDirection.TARGET_IS_BEST
            else None
        ),
    )
    contract = make_contract(
        primary_metric=metric,
        baseline_registry=BaselineRegistry(
            (
                make_baseline(
                    expected_metric=baseline_value,
                    reported_metric=None,
                    observed_metric=baseline_value,
                ),
            )
        ),
        seed_reporting=SeedReportingPlan(
            seeds=(7, 11, 19),
            regime=ReportingRegime.ALL_SEEDS,
            selection_policy="Report every frozen seed without selection.",
            selection_defined_before_results=True,
            preserve_all_runs=True,
            technical_retry_rule="No confirmatory retries.",
        ),
        statistical_plan=StatisticalPlan(
            primary_test="two-sided exact paired sign test with ties removed",
            alpha=0.05,
            effect_size="paired mean directional difference",
            confidence_interval="paired bootstrap 95 percent interval",
            resampling_unit="subject",
            comparison_family_size=1,
            multiplicity_correction="not applicable",
            minimum_effect=0.10,
            minimum_sample_size=20,
            power_or_sensitivity="The boundary fixture detects only a large paired effect.",
        ),
    )
    if not outcome_neutral:
        return contract
    return replace(
        contract,
        version=2,
        hypothesis_evaluation_policies=tuple(
            HypothesisEvaluationPolicy(
                policy_id=f"policy-{hypothesis.hypothesis_id}",
                hypothesis_id=hypothesis.hypothesis_id,
                metric_id=contract.primary_metric.metric_id,
                meaningful_effect=contract.statistical_plan.minimum_effect,
                falsification_effect=contract.statistical_plan.minimum_effect,
                alpha=contract.statistical_plan.alpha,
                minimum_sample_size=contract.statistical_plan.minimum_sample_size,
            )
            for hypothesis in contract.hypothesis_register.hypotheses
        ),
    )


def _payload_descriptor(path: str, logical_type: str, value: object) -> OutputArtifact:
    encoded = canonical_json_bytes(value) + b"\n"
    return OutputArtifact(
        path=path,
        sha256=hashlib.sha256(encoded).hexdigest(),
        size=len(encoded),
        logical_type=logical_type,
    )


def _registered_inputs(
    root: Path,
    *,
    omit_ablation: bool = False,
    metric_direction: ScientificMetricDirection = (
        ScientificMetricDirection.HIGHER_IS_BETTER
    ),
    candidate_value: float = 1.0,
    baseline_value: float = 0.0,
    units_per_seed: int = 24,
    seed_status: SeedRunStatus = SeedRunStatus.SUCCESS,
    outcome_neutral: bool = False,
    reordered_unit_grid_seed: int | None = None,
    candidate_values_by_seed: dict[int, float] | None = None,
    target_value: float = 1.0,
    include_unconsumed_manifest_output: bool = False,
    evaluator_algorithm: str = CHECKED_UNIT_SEED_AGGREGATION_ALGORITHM_V1,
) -> dict[str, object]:
    registry = ArtifactRegistry(root)
    contract = _checked_contract(
        metric_direction=metric_direction,
        baseline_value=baseline_value,
        outcome_neutral=outcome_neutral,
        target_value=target_value,
    )
    frozen_design = _put_json(
        registry,
        {"design": "frozen-checked-boundary", "version": 1},
        logical_type="frozen_scientific_inputs",
        role=Role.EVIDENCE_CURATOR,
    )
    contract_record = _put_json(
        registry,
        {
            "schema_version": (
                CHECKED_SUPERIORITY_CONTRACT_SCHEMA_V2
                if outcome_neutral
                else CHECKED_SUPERIORITY_CONTRACT_SCHEMA
            ),
            "evaluation_contract": contract,
        },
        logical_type="evaluation_contract",
        role=Role.PROTOCOL_DESIGNER,
        parents=(frozen_design.sha256,),
        schema_version="2.0" if outcome_neutral else "1.0",
    )
    code_record = _put_json(
        registry,
        {"implementation": "closed-paired-boundary-v1"},
        logical_type="experiment_code",
        role=Role.IMPLEMENTER,
        parents=(frozen_design.sha256,),
    )
    data_record = _put_json(
        registry,
        {"dataset": contract.dataset.dataset_id, "split": "confirmatory-v1"},
        logical_type="experiment_dataset",
        role=Role.EVIDENCE_CURATOR,
        parents=(frozen_design.sha256,),
    )
    configuration_record = _put_json(
        registry,
        {
            "schema_version": CHECKED_SUPERIORITY_CONFIGURATION_SCHEMA,
            "contract_artifact_sha256": contract_record.sha256,
            "contract_sha256": contract.sha256,
            "dataset_id": contract.dataset.dataset_id,
            "dataset_split_id": contract.dataset.confirmatory_split_id,
            "evaluator_id": contract.candidate_conditions.evaluator,
            "metric_id": contract.primary_metric.metric_id,
            "metric_unit": contract.primary_metric.unit.value,
            "metric_scope": contract.primary_metric.scope.value,
            "executed_baseline_ids": ["baseline-strong"],
        },
        logical_type="experiment_configuration",
        role=Role.PROTOCOL_DESIGNER,
        parents=(contract_record.sha256, data_record.sha256),
    )
    evaluator_source = _put_json(
        registry,
        {"algorithm": "paired arithmetic mean", "version": "1.0"},
        logical_type="evaluator_source",
        role=Role.IMPLEMENTER,
    )
    evaluator_implementation = _put_json(
        registry,
        {
            "schema_version": CHECKED_SUPERIORITY_EVALUATOR_IMPLEMENTATION_SCHEMA,
            "evaluator_id": contract.candidate_conditions.evaluator,
            "evaluator_version": "1.0",
            "metric_id": contract.primary_metric.metric_id,
            "metric_unit": contract.primary_metric.unit.value,
            "metric_scope": contract.primary_metric.scope.value,
            "algorithm": evaluator_algorithm,
        },
        logical_type="evaluator_implementation",
        role=Role.PROTOCOL_DESIGNER,
        parents=(evaluator_source.sha256,),
    )
    required_ablations = tuple(
        item.ablation_id for item in contract.ablations if item.required
    )
    plan_records = tuple(
        register_frozen_experiment_plan(
            registry,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            plan=ExperimentPlan(
                experiment_id=contract.hypothesis_register.primary.planned_experiment,
                hypothesis_id=contract.hypothesis_register.primary.hypothesis_id,
                stage=ExperimentStage.CONFIRMATORY,
                contract_sha256=contract.sha256,
                dataset_split_id=contract.dataset.confirmatory_split_id,
                seed=seed,
                evaluator_id=contract.candidate_conditions.evaluator,
                uses_protected_resource=True,
                results_seen_before_plan=False,
            ),
        )
        for seed in contract.seed_reporting.seeds
    )
    spec = FrozenRunSpec(
        run_id="confirmatory-run-1",
        experiment_id=contract.hypothesis_register.primary.planned_experiment,
        hypothesis_id=contract.hypothesis_register.primary.hypothesis_id,
        phase=ExperimentPhase.CONFIRMATORY,
        argv=("/usr/bin/python3", "-I", "run-paired-boundary.py"),
        working_directory=".",
        code_sha256=code_record.sha256,
        data_sha256=data_record.sha256,
        configuration_sha256=configuration_record.sha256,
        evaluator_sha256=evaluator_implementation.sha256,
        seeds=contract.seed_reporting.seeds,
        required_ablations=required_ablations,
        evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
        scientific_purpose=CHECKED_SUPERIORITY_SCIENTIFIC_PURPOSE,
        metadata={
            "evaluation_split": contract.dataset.confirmatory_split_id,
        },
    )
    spec_record = register_frozen_run_spec(
        registry,
        contract=contract,
        contract_artifact_sha256=contract_record.sha256,
        experiment_plan_artifact_sha256s=tuple(
            item.sha256 for item in plan_records
        ),
        spec=spec,
    )
    ledger_run_id = "global-run-1"
    ledger = EventLedger(root, "runs/global-run-1/events.jsonl")
    record_scientific_design_freeze(
        registry,
        ledger,
        run_id=ledger_run_id,
        contract=contract,
        contract_artifact_sha256=contract_record.sha256,
        experiment_plan_artifact_sha256s=tuple(
            item.sha256 for item in plan_records
        ),
        frozen_run_spec_artifact_sha256=spec_record.sha256,
    )

    raw_payloads: list[dict[str, object]] = []
    raw_descriptors: list[OutputArtifact] = []
    for seed in spec.seeds:
        seed_candidate_value = (
            candidate_value
            if candidate_values_by_seed is None
            else candidate_values_by_seed[seed]
        )
        unit_ids = [f"unit-{index}" for index in range(units_per_seed)]
        if seed == reordered_unit_grid_seed:
            unit_ids.reverse()
        payload: dict[str, object] = {
            "schema_version": CHECKED_SUPERIORITY_PAIRED_OUTPUT_SCHEMA,
            "run_id": spec.run_id,
            "spec_sha256": spec.sha256,
            "experiment_id": spec.experiment_id,
            "hypothesis_id": spec.hypothesis_id,
            "seed": seed,
            "evaluator_sha256": evaluator_implementation.sha256,
            "metric_id": contract.primary_metric.metric_id,
            "metric_unit": contract.primary_metric.unit.value,
            "metric_scope": contract.primary_metric.scope.value,
            "baseline_id": "baseline-strong",
            "paired_unit_ids": unit_ids,
            "candidate_values": [seed_candidate_value] * units_per_seed,
            "baseline_values": [baseline_value] * units_per_seed,
            "candidate_observation": seed_candidate_value,
            "baseline_observation": baseline_value,
        }
        raw_payloads.append(payload)
        raw_descriptors.append(
            _payload_descriptor(
                f"seed-{seed}.json", "paired_experiment_output", payload
            )
        )

    ablation_payloads: list[dict[str, object]] = []
    ablation_descriptors: list[OutputArtifact] = []
    manifest_ablations: list[ManifestAblationResult] = []
    if not omit_ablation:
        for item in contract.ablations:
            if not item.required:
                continue
            payload = {
                "schema_version": CHECKED_SUPERIORITY_ABLATION_OUTPUT_SCHEMA,
                "run_id": spec.run_id,
                "spec_sha256": spec.sha256,
                "ablation_id": item.ablation_id,
                "hypothesis_id": item.hypothesis_id,
                "intervention": item.intervention,
                "result_summary": "The frozen intervention removed the directed effect.",
                "status": "PASS",
            }
            descriptor = _payload_descriptor(
                f"ablation-{item.ablation_id}.json", "ablation_output", payload
            )
            ablation_payloads.append(payload)
            ablation_descriptors.append(descriptor)
            manifest_ablations.append(
                ManifestAblationResult(item.ablation_id, descriptor.sha256, "PASS")
            )
    unconsumed_payload = {
        "schema_version": "system-fixture-unconsumed-output/v1",
        "value": "must never be ignored by checked result replay",
    }
    unconsumed_descriptor = _payload_descriptor(
        "unconsumed.json",
        "unrelated_output",
        unconsumed_payload,
    )
    optional_descriptors = (
        (unconsumed_descriptor,) if include_unconsumed_manifest_output else ()
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
                seed,
                seed_status,
                (
                    candidate_value
                    if candidate_values_by_seed is None
                    else candidate_values_by_seed[seed]
                ),
                descriptor.sha256,
            )
            for seed, descriptor in zip(spec.seeds, raw_descriptors)
        ),
        artifacts=tuple(
            (*raw_descriptors, *ablation_descriptors, *optional_descriptors)
        ),
        ablations=tuple(manifest_ablations),
    )
    manifest_record = _put_json(
        registry,
        manifest.to_dict(),
        logical_type="experiment_output_manifest",
        role=Role.EXPERIMENT_RUNNER,
        parents=(spec_record.sha256,),
    )
    raw_records = tuple(
        _put_json(
            registry,
            payload,
            logical_type="experiment_output.paired_experiment_output",
            role=Role.EXPERIMENT_RUNNER,
            parents=(manifest_record.sha256, spec_record.sha256),
        )
        for payload in raw_payloads
    )
    ablation_records = tuple(
        _put_json(
            registry,
            payload,
            logical_type="experiment_output.ablation_output",
            role=Role.EXPERIMENT_RUNNER,
            parents=(manifest_record.sha256, spec_record.sha256),
        )
        for payload in ablation_payloads
    )
    unconsumed_record = (
        _put_json(
            registry,
            unconsumed_payload,
            logical_type="experiment_output.unrelated_output",
            role=Role.EXPERIMENT_RUNNER,
            parents=(manifest_record.sha256, spec_record.sha256),
        )
        if include_unconsumed_manifest_output
        else None
    )
    assert tuple(item.sha256 for item in raw_records) == tuple(
        item.sha256 for item in raw_descriptors
    )
    assert tuple(item.sha256 for item in ablation_records) == tuple(
        item.sha256 for item in ablation_descriptors
    )
    if unconsumed_record is not None:
        assert unconsumed_record.sha256 == unconsumed_descriptor.sha256
    record_scientific_result_observed(
        registry,
        ledger,
        run_id=ledger_run_id,
        contract=contract,
        contract_artifact_sha256=contract_record.sha256,
        experiment_plan_artifact_sha256s=tuple(
            item.sha256 for item in plan_records
        ),
        frozen_run_spec_artifact_sha256=spec_record.sha256,
        output_manifest_artifact_sha256=manifest_record.sha256,
    )
    paired_unit_ids = list(raw_payloads[0]["paired_unit_ids"])
    candidate_values = [
        math.fsum(float(payload["candidate_values"][index]) for payload in raw_payloads)
        / len(raw_payloads)
        for index in range(units_per_seed)
    ]
    baseline_values = [
        math.fsum(float(payload["baseline_values"][index]) for payload in raw_payloads)
        / len(raw_payloads)
        for index in range(units_per_seed)
    ]
    aggregate_value: dict[str, object] = {
        "schema_version": CHECKED_SUPERIORITY_AGGREGATE_SCHEMA,
        "contract_artifact_sha256": contract_record.sha256,
        "contract_sha256": contract.sha256,
        "run_spec_sha256": spec_record.sha256,
        "output_manifest_sha256": manifest_record.sha256,
        "metric_id": contract.primary_metric.metric_id,
        "metric_unit": contract.primary_metric.unit.value,
        "metric_scope": contract.primary_metric.scope.value,
        "executed_baseline_ids": ["baseline-strong"],
        "seed_order": list(spec.seeds),
        "paired_unit_ids": paired_unit_ids,
        "candidate_values": candidate_values,
        "baseline_values": baseline_values,
        "candidate_observation": candidate_value,
        "baseline_observation": baseline_value,
        "improvement_effect": candidate_value - baseline_value,
        "sample_size": len(candidate_values),
        "scientific_evidence_eligible": True,
    }
    aggregate_record = _put_json(
        registry,
        aggregate_value,
        logical_type="aggregate_experiment_result",
        role=Role.STATISTICIAN,
        parents=(
            contract_record.sha256,
            spec_record.sha256,
            manifest_record.sha256,
            *(item.sha256 for item in raw_records),
            *(item.sha256 for item in ablation_records),
        ),
    )
    exact_sign_p = (
        1.0
        if candidate_value == baseline_value
        else 2.0 / (2 ** len(candidate_values))
    )
    statistics_value = {
        "schema_version": CHECKED_SUPERIORITY_STATISTICS_SCHEMA,
        "contract_artifact_sha256": contract_record.sha256,
        "aggregate_result_sha256": aggregate_record.sha256,
        "test": "two_sided_exact_sign",
        "effect_method": CHECKED_DIRECTIONAL_EFFECT_METHOD_V1,
        "confidence_method": "paired_bootstrap_percentile",
        "confidence_level": 0.95,
        "bootstrap_seed": CHECKED_BOOTSTRAP_SEED_V1,
        "bootstrap_resamples": CHECKED_BOOTSTRAP_RESAMPLES_V1,
        "resampling_unit": "subject",
        "improvement_effect": candidate_value - baseline_value,
        "confidence_low": candidate_value - baseline_value,
        "confidence_high": candidate_value - baseline_value,
        "raw_p_value": exact_sign_p,
        "adjusted_p_value": exact_sign_p,
        "multiplicity_correction": "not applicable",
        "sample_size": len(candidate_values),
    }
    statistics_record = _put_json(
        registry,
        statistics_value,
        logical_type="statistical_analysis",
        role=Role.STATISTICIAN,
        parents=(
            contract_record.sha256,
            aggregate_record.sha256,
            *(item.sha256 for item in raw_records),
        ),
    )
    trace_value = {
        "schema_version": CHECKED_SUPERIORITY_EVALUATOR_TRACE_SCHEMA,
        "run_spec_sha256": spec_record.sha256,
        "output_manifest_sha256": manifest_record.sha256,
        "evaluator_implementation_sha256": evaluator_implementation.sha256,
        "access_events": [
            {
                "seed": seed,
                "action": "EVALUATE",
                "output_artifact_sha256": record.sha256,
            }
            for seed, record in zip(spec.seeds, raw_records)
        ],
        "query_events": [],
        "selection_trials": [],
        "branch_events": [],
        "source_artifact_hashes": [item.sha256 for item in raw_records],
    }
    trace_record = _put_json(
        registry,
        trace_value,
        logical_type="evaluator_integrity_trace",
        role=Role.EXPERIMENT_RUNNER,
        parents=(
            spec_record.sha256,
            manifest_record.sha256,
            *(item.sha256 for item in raw_records),
        ),
    )
    evaluator_value = {
        "schema_version": CHECKED_SUPERIORITY_EVALUATOR_SCHEMA,
        "contract_artifact_sha256": contract_record.sha256,
        "aggregate_result_sha256": aggregate_record.sha256,
        "run_spec_sha256": spec_record.sha256,
        "evaluator_implementation_sha256": evaluator_implementation.sha256,
        "evaluator_version": "1.0",
        "trace_sha256": trace_record.sha256,
        "assessment": {
            "evaluator_id": contract.candidate_conditions.evaluator,
            "evaluator_version": "1.0",
            "signals": [],
            "passed": True,
        },
    }
    evaluator_record = _put_json(
        registry,
        evaluator_value,
        logical_type="evaluator_integrity_assessment",
        role=Role.SCIENTIFIC_REVIEWER,
        parents=(
            contract_record.sha256,
            aggregate_record.sha256,
            evaluator_implementation.sha256,
            trace_record.sha256,
        ),
    )

    obligation_specs: list[tuple[str, str, str]] = []
    obligation_specs.extend(("ROBUSTNESS", item, "PASS") for item in contract.robustness_tests)
    obligation_specs.extend(("STOPPING", item, "MET") for item in contract.stopping_criteria)
    obligation_specs.extend(("SUCCESS", item, "MET") for item in contract.success_criteria)
    obligation_specs.extend(("FAILURE", item, "NOT_TRIGGERED") for item in contract.failure_criteria)
    obligation_records: list[ArtifactRecord] = []
    obligation_entries: list[dict[str, object]] = []
    for kind, text, result in obligation_specs:
        obligation_sha256 = _digest({"kind": kind, "text": text})
        source_hashes = (manifest_record.sha256, raw_records[0].sha256)
        evidence = _put_json(
            registry,
            {
                "schema_version": CHECKED_SUPERIORITY_OBLIGATION_EVIDENCE_SCHEMA,
                "contract_artifact_sha256": contract_record.sha256,
                "run_spec_sha256": spec_record.sha256,
                "output_manifest_sha256": manifest_record.sha256,
                "kind": kind,
                "obligation_sha256": obligation_sha256,
                "result": result,
                "source_artifact_hashes": list(source_hashes),
            },
            logical_type="scientific_obligation_evidence",
            role=Role.EXPERIMENT_RUNNER,
            parents=source_hashes,
        )
        obligation_records.append(evidence)
        obligation_entries.append(
            {
                "kind": kind,
                "obligation_sha256": obligation_sha256,
                "evidence_sha256": evidence.sha256,
                "result": result,
            }
        )
    obligations_value = {
        "schema_version": CHECKED_SUPERIORITY_OBLIGATIONS_SCHEMA,
        "contract_artifact_sha256": contract_record.sha256,
        "contract_sha256": contract.sha256,
        "run_spec_sha256": spec_record.sha256,
        "output_manifest_sha256": manifest_record.sha256,
        "entries": obligation_entries,
    }
    obligations_record = _put_json(
        registry,
        obligations_value,
        logical_type="scientific_obligation_verification",
        role=Role.SCIENTIFIC_REVIEWER,
        parents=(
            contract_record.sha256,
            spec_record.sha256,
            manifest_record.sha256,
            *(item.sha256 for item in obligation_records),
        ),
    )
    arbitrary_eligibility = _put_json(
        registry,
        {"scientific_evidence_eligible": True, "passed": True},
        logical_type="scientific_evidence_eligibility",
        role=Role.SCIENTIFIC_REVIEWER,
        parents=(contract_record.sha256, aggregate_record.sha256),
    )
    return locals()


def _attempt_checked(values: dict[str, object], **changes: object) -> None:
    arguments: dict[str, object] = {
        "receipt_id": "superiority-claim-1",
        "contract": values["contract"],
        "contract_artifact_sha256": values["contract_record"].sha256,
        "evidence_eligibility_sha256": values["arbitrary_eligibility"].sha256,
        "aggregate_result_sha256": values["aggregate_record"].sha256,
        "statistical_analysis_sha256": values["statistics_record"].sha256,
        "evaluator_assessment_sha256": values["evaluator_record"].sha256,
        "scientific_obligations_sha256": values["obligations_record"].sha256,
        "claimed_scope": MetricScope.END_TO_END,
    }
    arguments.update(changes)
    register_checked_superiority_promotion(
        values["registry"], **arguments  # type: ignore[arg-type]
    )


def _result_promotion_candidate(values: dict[str, object]) -> dict[str, object]:
    registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
    contract: EvaluationContract = values["contract"]  # type: ignore[assignment]
    exact_sign_p = 2.0 / (2 ** 24)
    checked = CheckedSuperiorityPromotion(
        receipt_id="checked-superiority-result-1",
        contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
        contract_sha256=contract.sha256,
        evidence_eligibility_sha256=values["arbitrary_eligibility"].sha256,  # type: ignore[union-attr]
        aggregate_result_sha256=values["aggregate_record"].sha256,  # type: ignore[union-attr]
        statistical_analysis_sha256=values["statistics_record"].sha256,  # type: ignore[union-attr]
        evaluator_assessment_sha256=values["evaluator_record"].sha256,  # type: ignore[union-attr]
        scientific_obligations_sha256=values["obligations_record"].sha256,  # type: ignore[union-attr]
        proxy_inference_verification_sha256=None,
        baseline_exclusion_receipt_sha256s=(),
        contract_record_hash=str(values["contract_record"].record_hash),  # type: ignore[union-attr]
        eligibility_record_hash=str(values["arbitrary_eligibility"].record_hash),  # type: ignore[union-attr]
        aggregate_record_hash=str(values["aggregate_record"].record_hash),  # type: ignore[union-attr]
        statistical_record_hash=str(values["statistics_record"].record_hash),  # type: ignore[union-attr]
        evaluator_record_hash=str(values["evaluator_record"].record_hash),  # type: ignore[union-attr]
        metric_id=contract.primary_metric.metric_id,
        metric_unit=contract.primary_metric.unit,
        claimed_scope=MetricScope.END_TO_END,
        baseline_id="baseline-strong",
        candidate_value=1.0,
        baseline_value=0.0,
        improvement_effect=1.0,
        confidence_low=1.0,
        confidence_high=1.0,
        adjusted_p_value=exact_sign_p,
        sample_size=24,
        evaluator_id=contract.candidate_conditions.evaluator,
        evaluator_version="1.0",
        scientific_evidence_eligible=True,
    )
    checked_record = _put_json(
        registry,
        checked.to_dict(),
        logical_type="checked_superiority_promotion",
        role=Role.CLAIM_VERIFIER,
        parents=checked.source_artifact_hashes,
    )
    result_projection_record, statistical_projection_record = (
        register_scientific_result_state_projections(
            registry,
            values["ledger"],  # type: ignore[arg-type]
            ledger_run_id=values["ledger_run_id"],  # type: ignore[arg-type]
            result_id="result-1",
            statistical_test_id="statistical-test-result-1",
            canonical_state_code_version=STATE_CODE_VERSION,
            checked_superiority_receipt_artifact_sha256=checked_record.sha256,
        )
    )
    receipt = ScientificResultPromotionReceipt(
        receipt_id="scientific-result-promotion-1",
        ledger_run_id="global-run-1",
        execution_run_id="confirmatory-run-1",
        result_id="result-1",
        contract_artifact_sha256=checked.contract_artifact_sha256,
        scientific_timeline_receipt_artifact_sha256=None,
        checked_superiority_receipt_artifact_sha256=checked_record.sha256,
        domain_validity_receipt_artifact_sha256=None,
        backend_execution_authority_artifact_sha256=None,
        confirmation_authority_artifact_sha256=None,
        evidence_eligibility_sha256=checked.evidence_eligibility_sha256,
        aggregate_result_sha256=checked.aggregate_result_sha256,
        statistical_analysis_sha256=checked.statistical_analysis_sha256,
        evaluator_assessment_sha256=checked.evaluator_assessment_sha256,
        scientific_obligations_sha256=checked.scientific_obligations_sha256,
        frozen_run_spec_artifact_sha256=values["spec_record"].sha256,  # type: ignore[union-attr]
        output_manifest_artifact_sha256=values["manifest_record"].sha256,  # type: ignore[union-attr]
        result_state_projection_artifact_sha256=result_projection_record.sha256,
        statistical_state_projection_artifact_sha256=(
            statistical_projection_record.sha256
        ),
    )
    receipt_record = _put_json(
        registry,
        receipt.to_dict(),
        logical_type="scientific_result_promotion_authority",
        role=Role.CLAIM_VERIFIER,
        parents=receipt.source_artifact_hashes,
    )
    return locals()


def _materialize_projected_result_state(
    values: dict[str, object],
    candidate: dict[str, object],
    *,
    result_changes: dict[str, object] | None = None,
    statistical_changes: dict[str, object] | None = None,
    materialize_statistical: bool = True,
    include_result_receipt: bool = True,
    include_statistical_receipt: bool = True,
    extra_result_parent: str | None = None,
    extra_statistical_parent: str | None = None,
    result_parent_mode: str = "exact",
    statistical_parent_mode: str = "exact",
    equal_state_timestamps: bool = False,
) -> dict[str, object]:
    """Append exact post-projection canonical-state boundary fixtures."""

    registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
    ledger: EventLedger = values["ledger"]  # type: ignore[assignment]
    receipt_record: ArtifactRecord = candidate["receipt_record"]  # type: ignore[assignment]
    projection = require_scientific_result_state_projections(
        registry,
        ledger,
        expected_ledger_run_id="global-run-1",
        expected_execution_run_id="confirmatory-run-1",
        expected_canonical_state_code_version=STATE_CODE_VERSION,
        expected_result_id="result-1",
        result_state_projection_artifact_sha256=(
            candidate["result_projection_record"].sha256  # type: ignore[union-attr]
        ),
        statistical_state_projection_artifact_sha256=(
            candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
        ),
    )
    result_value = projection.result_state_projection
    statistical_value = projection.statistical_state_projection
    state_run = StateRun(
        object_id=result_value.run_id,
        producer=Role.EXPERIMENT_RUNNER,
        status=RecordStatus.COMPLETE,
        created_at=result_value.observed_at,
        code_version=result_value.canonical_state_code_version,
        experiment_id=result_value.experiment_id,
        code_revision=result_value.canonical_state_code_version,
        dataset_ids=(values["contract"].dataset.dataset_id,),  # type: ignore[union-attr]
        configuration_artifact_hash=values["spec"].configuration_sha256,  # type: ignore[union-attr]
        random_seeds=statistical_value.seed_order,
        output_artifact_hashes=result_value.raw_source_artifact_hashes,
        evaluator_version="checked-superiority-state-projection-v2",
        started_at=result_value.observed_at,
        completed_at=result_value.observed_at,
    )
    state_metric = StateMetric(
        object_id=result_value.metric_id,
        producer=Role.PROTOCOL_DESIGNER,
        status=RecordStatus.ACTIVE,
        created_at=result_value.observed_at,
        code_version=result_value.canonical_state_code_version,
        name=result_value.metric_id,
        direction={
            ScientificMetricDirection.HIGHER_IS_BETTER: (
                StateMetricDirection.HIGHER_IS_BETTER
            ),
            ScientificMetricDirection.LOWER_IS_BETTER: (
                StateMetricDirection.LOWER_IS_BETTER
            ),
            ScientificMetricDirection.TARGET_IS_BEST: (
                StateMetricDirection.TARGET_IS_BETTER
            ),
        }[result_value.metric_direction],
        unit=result_value.metric_unit.value,
    )
    state_run_record = registry.put_bytes(
        state_run.canonical_bytes(),
        logical_type=state_run.logical_type,
        origin="two-phase canonical Run parent boundary fixture",
        creator_role=state_run.producer,
        creation_command=("scientist-one", "research-state", "materialize"),
        parent_artifacts=(),
        schema_version=state_run.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=state_run.created_at,
    )
    state_metric_record = registry.put_bytes(
        state_metric.canonical_bytes(),
        logical_type=state_metric.logical_type,
        origin="two-phase canonical Metric parent boundary fixture",
        creator_role=state_metric.producer,
        creation_command=("scientist-one", "research-state", "materialize"),
        parent_artifacts=(),
        schema_version=state_metric.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=state_metric.created_at,
    )
    result_parents = (
        ObjectReference(
            "Run",
            state_run.object_id,
            state_run.content_hash,  # type: ignore[arg-type]
            "aggregates",
            True,
        ),
        ObjectReference(
            "Metric",
            state_metric.object_id,
            state_metric.content_hash,  # type: ignore[arg-type]
            "reports",
            True,
        ),
    )
    if result_parent_mode == "reordered":
        result_parents = tuple(reversed(result_parents))
    elif result_parent_mode == "wrong_relation":
        result_parents = (
            replace(result_parents[0], relation="uses"),
            result_parents[1],
        )
    elif result_parent_mode == "unevaluated":
        result_parents = (
            replace(result_parents[0], evaluated=False),
            result_parents[1],
        )
    elif result_parent_mode == "extra_typed":
        result_parents = (
            *result_parents,
            replace(result_parents[1], relation="contextualizes"),
        )
    elif result_parent_mode != "exact":
        raise ValueError("unsupported Result parent substitution fixture")
    result_sources = result_value.state_source_artifact_hashes
    result_evaluations = (
        (receipt_record.sha256,) if include_result_receipt else ()
    )
    result_arguments: dict[str, object] = {
        "object_id": result_value.result_id,
        "producer": Role.STATISTICIAN,
        "status": RecordStatus.COMPLETE,
        "created_at": utc_now(),
        "code_version": result_value.canonical_state_code_version,
        "authority_artifact_hashes": tuple(
            sorted((*result_sources, *result_evaluations))
        ),
        "parents": result_parents,
        "relationships": (),
        "metadata": {},
        "run_ids": (result_value.run_id,),
        "metric_id": result_value.metric_id,
        "value": result_value.state_value,
        "unit": result_value.metric_unit.value,
        "direction": {
            ScientificMetricDirection.HIGHER_IS_BETTER: (
                StateMetricDirection.HIGHER_IS_BETTER
            ),
            ScientificMetricDirection.LOWER_IS_BETTER: (
                StateMetricDirection.LOWER_IS_BETTER
            ),
            ScientificMetricDirection.TARGET_IS_BEST: (
                StateMetricDirection.TARGET_IS_BETTER
            ),
        }[result_value.metric_direction],
        "uncertainty": result_value.state_uncertainty,
        "source_artifact_hashes": result_sources,
        "evaluation_artifact_hashes": result_evaluations,
        "code_revision": result_value.canonical_state_code_version,
        "observed_at": result_value.observed_at,
    }
    result_arguments.update(result_changes or {})
    final_result = StateResult(**result_arguments)  # type: ignore[arg-type]
    final_result_record = registry.put_bytes(
        final_result.canonical_bytes(),
        logical_type=final_result.logical_type,
        origin="two-phase canonical Result boundary fixture",
        creator_role=final_result.producer,
        creation_command=("scientist-one", "research-state", "materialize"),
        parent_artifacts=tuple(
            sorted(
                {
                    *final_result.authority_artifact_hashes,
                    state_run_record.sha256,
                    state_metric_record.sha256,
                    *((extra_result_parent,) if extra_result_parent is not None else ()),
                }
            )
        ),
        schema_version=final_result.schema_version,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at=final_result.created_at,
    )
    result_event_id = f"rs-{final_result_record.sha256[:48]}"
    if not any(event.event_id == result_event_id for event in ledger.events()):
        state = ledger.assert_valid().events[-1].requested_state_after
        ledger.record(
            run_id="global-run-1",
            actor_role=final_result.producer,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(final_result_record.sha256,),
            code_version=STATE_CODE_VERSION,
            configuration_hash=values["spec"].configuration_sha256,  # type: ignore[union-attr]
            reason="materialized projected Result boundary fixture",
            event_id=result_event_id,
            timestamp=final_result.created_at,
            event_type="CHECKPOINT",
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": final_result.object_type,
                "object_id": final_result.object_id,
                "revision": final_result.revision,
                "content_hash": final_result.content_hash,
                "artifact_hash": final_result_record.sha256,
                "supersedes_content_hash": None,
                "schema_version": final_result.schema_version,
            },
        )
    final_statistical = None
    final_statistical_record = None
    if materialize_statistical:
        statistical_sources = (
            *statistical_value.state_source_artifact_hashes,
            *((receipt_record.sha256,) if include_statistical_receipt else ()),
        )
        statistical_arguments: dict[str, object] = {
            "object_id": statistical_value.statistical_test_id,
            "producer": Role.STATISTICIAN,
            "status": RecordStatus.COMPLETE,
            "created_at": (
                final_result.created_at if equal_state_timestamps else utc_now()
            ),
            "code_version": statistical_value.canonical_state_code_version,
            "authority_artifact_hashes": tuple(sorted(statistical_sources)),
            "parents": (
                ObjectReference(
                    "Result",
                    final_result.object_id,
                    final_result.content_hash,  # type: ignore[arg-type]
                    "tests",
                    True,
                ),
            ),
            "relationships": (),
            "metadata": {},
            "result_ids": (final_result.object_id,),
            "test_name": statistical_value.contract_primary_test,
            "null_hypothesis": statistical_value.null_hypothesis,
            "alternative": statistical_value.alternative,
            "method_configuration": statistical_value.state_method_configuration,
            "outcome": statistical_value.state_outcome,
            "source_artifact_hashes": statistical_sources,
        }
        if statistical_parent_mode == "wrong_relation":
            statistical_arguments["parents"] = (
                replace(
                    statistical_arguments["parents"][0],  # type: ignore[index]
                    relation="reports",
                ),
            )
        elif statistical_parent_mode == "unevaluated":
            statistical_arguments["parents"] = (
                replace(
                    statistical_arguments["parents"][0],  # type: ignore[index]
                    evaluated=False,
                ),
            )
        elif statistical_parent_mode == "extra_typed":
            statistical_arguments["parents"] = (
                *statistical_arguments["parents"],  # type: ignore[misc]
                result_parents[1],
            )
            if extra_statistical_parent is None:
                extra_statistical_parent = state_metric_record.sha256
        elif statistical_parent_mode != "exact":
            raise ValueError("unsupported StatisticalTest parent substitution fixture")
        statistical_arguments.update(statistical_changes or {})
        final_statistical = StateStatisticalTest(  # type: ignore[arg-type]
            **statistical_arguments
        )
        final_statistical_record = registry.put_bytes(
            final_statistical.canonical_bytes(),
            logical_type=final_statistical.logical_type,
            origin="two-phase canonical StatisticalTest boundary fixture",
            creator_role=final_statistical.producer,
            creation_command=("scientist-one", "research-state", "materialize"),
            parent_artifacts=tuple(
                sorted(
                    {
                        *final_statistical.authority_artifact_hashes,
                        final_result_record.sha256,
                        *(
                            (extra_statistical_parent,)
                            if extra_statistical_parent is not None
                            else ()
                        ),
                    }
                )
            ),
            schema_version=final_statistical.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=final_statistical.created_at,
        )
        state = ledger.assert_valid().events[-1].requested_state_after
        ledger.record(
            run_id="global-run-1",
            actor_role=final_statistical.producer,
            state_before=state,
            requested_state_after=state,
            artifact_hashes=(final_statistical_record.sha256,),
            code_version=STATE_CODE_VERSION,
            configuration_hash=values["spec"].configuration_sha256,  # type: ignore[union-attr]
            reason="materialized projected StatisticalTest boundary fixture",
            event_id=f"rs-{final_statistical_record.sha256[:48]}",
            timestamp=final_statistical.created_at,
            event_type="CHECKPOINT",
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": final_statistical.object_type,
                "object_id": final_statistical.object_id,
                "revision": final_statistical.revision,
                "content_hash": final_statistical.content_hash,
                "artifact_hash": final_statistical_record.sha256,
                "supersedes_content_hash": None,
                "schema_version": final_statistical.schema_version,
            },
        )
    return locals()


class CheckedSuperiorityBoundaryTests(unittest.TestCase):
    def test_frozen_contract_rehydrates_exact_nested_authority(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            contract = require_frozen_evaluation_contract(
                values["registry"],  # type: ignore[arg-type]
                contract_artifact_sha256=values["contract_record"].sha256,  # type: ignore[union-attr]
            )
            self.assertEqual(contract, values["contract"])

            # Use the canonical persisted value, then introduce a nested field
            # that a parallel permissive parser might otherwise ignore.
            wrapper = json.loads(
                values["registry"].get_bytes(  # type: ignore[union-attr]
                    values["contract_record"].sha256  # type: ignore[union-attr]
                )
            )
            wrapper["evaluation_contract"]["dataset"]["split_alias"] = "confirmatory-v1"
            malformed = _put_json(
                values["registry"],  # type: ignore[arg-type]
                wrapper,
                logical_type="evaluation_contract",
                role=Role.PROTOCOL_DESIGNER,
                parents=values["contract_record"].parent_artifacts,  # type: ignore[union-attr]
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "schema is incomplete or contains unknown fields",
            ):
                require_frozen_evaluation_contract(
                    values["registry"],  # type: ignore[arg-type]
                    contract_artifact_sha256=malformed.sha256,
                )

    def test_result_promotion_is_typed_blocked_without_backend_issuer(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            ledger = values["ledger"]
            resolution = require_scientific_result_promotion_authority(
                values["registry"],  # type: ignore[arg-type]
                ledger,
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_canonical_state_code_version=STATE_CODE_VERSION,
                expected_result_id="result-1",
                promotion_receipt_artifact_sha256=candidate["receipt_record"].sha256,  # type: ignore[union-attr]
                scientific_timeline_receipt_artifact_sha256=None,
                domain_validity_receipt_artifact_sha256=None,
                backend_execution_authority_artifact_sha256=None,
                confirmation_authority_artifact_sha256=None,
            )
            self.assertEqual(
                resolution.status,
                ScientificResultPromotionStatus.BLOCKED_REQUIRED_SCIENTIFIC_AUTHORITIES_UNAVAILABLE,
            )
            self.assertFalse(resolution.scientific_evidence_eligible)
            self.assertIsNone(resolution.promotion)
            projection = resolution.statistical_projection
            self.assertIsNotNone(projection)
            assert projection is not None
            self.assertEqual(projection.checked_procedure_id, "two_sided_exact_sign")
            self.assertEqual(
                projection.contract_primary_test,
                values["contract"].statistical_plan.primary_test,  # type: ignore[union-attr]
            )
            self.assertEqual(projection.seed_order, (7, 11, 19))
            self.assertEqual(projection.baseline_id, "baseline-strong")
            self.assertEqual(
                projection.statistical_state_projection_artifact_sha256,
                candidate["statistical_projection_record"].sha256,  # type: ignore[union-attr]
            )
            event_count = len(ledger.assert_valid().events)
            repeated = register_scientific_result_state_projections(
                values["registry"],  # type: ignore[arg-type]
                ledger,
                ledger_run_id="global-run-1",
                result_id="result-1",
                statistical_test_id="statistical-test-result-1",
                canonical_state_code_version=STATE_CODE_VERSION,
                checked_superiority_receipt_artifact_sha256=(
                    candidate["checked_record"].sha256  # type: ignore[union-attr]
                ),
            )
            self.assertEqual(
                tuple(record.sha256 for record in repeated),
                (
                    candidate["result_projection_record"].sha256,  # type: ignore[union-attr]
                    candidate["statistical_projection_record"].sha256,  # type: ignore[union-attr]
                ),
            )
            self.assertEqual(len(ledger.assert_valid().events), event_count)

    def test_state_projection_registration_rejects_post_result_materialization(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
            projection = require_scientific_result_state_projections(
                registry,
                values["ledger"],  # type: ignore[arg-type]
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_canonical_state_code_version=STATE_CODE_VERSION,
                expected_result_id="result-1",
                result_state_projection_artifact_sha256=(
                    candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                ),
                statistical_state_projection_artifact_sha256=(
                    candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                ),
            )
            result_projection = projection.result_state_projection
            late_result = StateResult(
                object_id="result-late",
                producer=Role.STATISTICIAN,
                status=RecordStatus.COMPLETE,
                created_at=utc_now(),
                code_version=result_projection.canonical_state_code_version,
                authority_artifact_hashes=(
                    result_projection.aggregate_result_sha256,
                ),
                run_ids=(result_projection.run_id,),
                metric_id=result_projection.metric_id,
                value=result_projection.state_value,
                unit=result_projection.metric_unit.value,
                direction=StateMetricDirection.HIGHER_IS_BETTER,
                uncertainty=result_projection.state_uncertainty,
                source_artifact_hashes=(
                    result_projection.aggregate_result_sha256,
                ),
                code_revision=result_projection.canonical_state_code_version,
                observed_at=result_projection.observed_at,
            )
            registry.put_bytes(
                late_result.canonical_bytes(),
                logical_type=late_result.logical_type,
                origin="post-result canonical-state substitution fixture",
                creator_role=late_result.producer,
                creation_command=("scientist-one", "forge-post-projection-state"),
                parent_artifacts=late_result.authority_artifact_hashes,
                schema_version=late_result.schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=late_result.created_at,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "must precede canonical Result/StatisticalTest",
            ):
                register_scientific_result_state_projections(
                    registry,
                    values["ledger"],  # type: ignore[arg-type]
                    ledger_run_id="global-run-1",
                    result_id="result-late",
                    statistical_test_id="statistical-test-late",
                    canonical_state_code_version=STATE_CODE_VERSION,
                    checked_superiority_receipt_artifact_sha256=(
                        candidate["checked_record"].sha256  # type: ignore[union-attr]
                    ),
                )

    def test_v2_projection_receipt_allows_final_state_to_cite_without_cycle(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            receipt_record = candidate["receipt_record"]
            result_projection_record = candidate["result_projection_record"]
            statistical_projection_record = candidate[
                "statistical_projection_record"
            ]
            receipt = candidate["receipt"]
            self.assertIn(
                result_projection_record.sha256,
                receipt.source_artifact_hashes,
            )
            self.assertIn(
                statistical_projection_record.sha256,
                receipt.source_artifact_hashes,
            )
            self.assertNotIn(
                receipt_record.sha256,
                result_projection_record.parent_artifacts,
            )
            self.assertNotIn(
                receipt_record.sha256,
                statistical_projection_record.parent_artifacts,
            )
            materialized = _materialize_projected_result_state(
                values,
                candidate,
                materialize_statistical=False,
            )
            intermediate = require_scientific_result_state_projections(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_canonical_state_code_version=STATE_CODE_VERSION,
                expected_result_id="result-1",
                result_state_projection_artifact_sha256=result_projection_record.sha256,
                statistical_state_projection_artifact_sha256=(
                    statistical_projection_record.sha256
                ),
                promotion_receipt_artifact_sha256=receipt_record.sha256,
            )
            self.assertEqual(intermediate.result_id, "result-1")
            self.assertIsNotNone(materialized["final_result_record"])
            self.assertGreater(
                materialized["final_result"].created_at,  # type: ignore[union-attr]
                intermediate.result_state_projection.observed_at,
            )

            # Add the dependent StatisticalTest only after the exact Result.
            _materialize_projected_result_state(
                values,
                candidate,
                result_changes={
                    "created_at": materialized["final_result"].created_at,  # type: ignore[union-attr]
                },
                materialize_statistical=True,
            )
            final = require_scientific_result_promotion_authority(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_canonical_state_code_version=STATE_CODE_VERSION,
                expected_result_id="result-1",
                promotion_receipt_artifact_sha256=receipt_record.sha256,
                scientific_timeline_receipt_artifact_sha256=None,
                domain_validity_receipt_artifact_sha256=None,
                backend_execution_authority_artifact_sha256=None,
                confirmation_authority_artifact_sha256=None,
            )
            self.assertFalse(final.scientific_evidence_eligible)
            event_count = len(values["ledger"].assert_valid().events)  # type: ignore[union-attr]
            repeated = register_scientific_result_state_projections(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                ledger_run_id="global-run-1",
                result_id="result-1",
                statistical_test_id="statistical-test-result-1",
                canonical_state_code_version=STATE_CODE_VERSION,
                checked_superiority_receipt_artifact_sha256=(
                    candidate["checked_record"].sha256  # type: ignore[union-attr]
                ),
            )
            self.assertEqual(
                tuple(record.sha256 for record in repeated),
                (result_projection_record.sha256, statistical_projection_record.sha256),
            )
            self.assertEqual(
                len(values["ledger"].assert_valid().events),  # type: ignore[union-attr]
                event_count,
            )

    def test_result_promotion_rejects_identity_and_authority_substitution(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            ledger = values["ledger"]
            common = {
                "promotion_receipt_artifact_sha256": candidate["receipt_record"].sha256,
                "scientific_timeline_receipt_artifact_sha256": None,
                "domain_validity_receipt_artifact_sha256": None,
                "backend_execution_authority_artifact_sha256": None,
                "confirmation_authority_artifact_sha256": None,
            }
            for name, changes in (
                ("wrong-ledger-run", {"expected_ledger_run_id": "other-run"}),
                (
                    "wrong-execution-run",
                    {"expected_execution_run_id": "other-execution"},
                ),
                (
                    "wrong-state-code",
                    {
                        "expected_canonical_state_code_version": (
                            "research-os-vnext:other-state-kernel"
                        )
                    },
                ),
                ("wrong-result", {"expected_result_id": "other-result"}),
            ):
                with self.subTest(name=name), self.assertRaisesRegex(
                    ScientificPromotionError,
                    "another .*result|differs from frozen execution",
                ):
                    require_scientific_result_promotion_authority(
                        values["registry"],  # type: ignore[arg-type]
                        ledger,
                        expected_ledger_run_id=changes.get(
                            "expected_ledger_run_id", "global-run-1"
                        ),
                        expected_execution_run_id=changes.get(
                            "expected_execution_run_id", "confirmatory-run-1"
                        ),
                        expected_canonical_state_code_version=changes.get(
                            "expected_canonical_state_code_version",
                            STATE_CODE_VERSION,
                        ),
                        expected_result_id=changes.get("expected_result_id", "result-1"),
                        **common,  # type: ignore[arg-type]
                    )

            unrelated = _put_json(
                values["registry"],  # type: ignore[arg-type]
                {"authority": "unrelated"},
                logical_type="unrelated_authority",
                role=Role.SCIENTIFIC_REVIEWER,
            )
            asserted_substitution = dict(common)
            asserted_substitution[
                "scientific_timeline_receipt_artifact_sha256"
            ] = unrelated.sha256
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "authority assertion was substituted",
            ):
                require_scientific_result_promotion_authority(
                    values["registry"],  # type: ignore[arg-type]
                    ledger,
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    expected_canonical_state_code_version=STATE_CODE_VERSION,
                    expected_result_id="result-1",
                    **asserted_substitution,  # type: ignore[arg-type]
                )
            for argument in (
                "scientific_timeline_receipt_artifact_sha256",
                "domain_validity_receipt_artifact_sha256",
                "backend_execution_authority_artifact_sha256",
                "confirmation_authority_artifact_sha256",
            ):
                altered_receipt = replace(
                    candidate["receipt"],  # type: ignore[arg-type]
                    **{argument: unrelated.sha256},
                )
                altered_record = _put_json(
                    values["registry"],  # type: ignore[arg-type]
                    altered_receipt.to_dict(),
                    logical_type="scientific_result_promotion_authority",
                    role=Role.CLAIM_VERIFIER,
                    parents=altered_receipt.source_artifact_hashes,
                )
                altered = dict(common)
                altered["promotion_receipt_artifact_sha256"] = altered_record.sha256
                altered[argument] = unrelated.sha256
                with self.subTest(argument=argument), self.assertRaises(
                    ScientificPromotionError
                ):
                    require_scientific_result_promotion_authority(
                        values["registry"],  # type: ignore[arg-type]
                        ledger,
                        expected_ledger_run_id="global-run-1",
                        expected_execution_run_id="confirmatory-run-1",
                        expected_canonical_state_code_version=STATE_CODE_VERSION,
                        expected_result_id="result-1",
                        **altered,  # type: ignore[arg-type]
                    )

    def test_target_metric_direction_is_not_supported_by_checked_procedure_v1(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(
                Path(directory),
                metric_direction=ScientificMetricDirection.TARGET_IS_BEST,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "TARGET_IS_BEST",
            ):
                _result_promotion_candidate(values)

    def test_canonical_state_rejects_projection_substitution(self) -> None:
        result_cases = (
            ("run", {"run_ids": ("other-execution",)}),
            ("metric", {"metric_id": "other-metric"}),
            (
                "value",
                {
                    "value": {
                        "baseline": 0.0,
                        "candidate": 2.0,
                        "improvement": 2.0,
                    }
                },
            ),
            (
                "metadata",
                {"metadata": {"scientific_evidence_eligible": True}},
            ),
            (
                "relationship",
                {
                    "relationships": (
                        ObjectLink(
                            "Metric",
                            "unrelated-metric",
                            "annotates",
                            False,
                        ),
                    )
                },
            ),
        )
        for name, changes in result_cases:
            with self.subTest(name=name), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                candidate = _result_promotion_candidate(values)
                _materialize_projected_result_state(
                    values,
                    candidate,
                    result_changes=changes,
                    materialize_statistical=False,
                )
                with self.assertRaisesRegex(
                    ScientificPromotionError,
                    "canonical Result differs",
                ):
                    require_scientific_result_state_projections(
                        values["registry"],  # type: ignore[arg-type]
                        values["ledger"],  # type: ignore[arg-type]
                        expected_ledger_run_id="global-run-1",
                        expected_execution_run_id="confirmatory-run-1",
                        expected_canonical_state_code_version=STATE_CODE_VERSION,
                        expected_result_id="result-1",
                        result_state_projection_artifact_sha256=(
                            candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        statistical_state_projection_artifact_sha256=(
                            candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        promotion_receipt_artifact_sha256=(
                            candidate["receipt_record"].sha256  # type: ignore[union-attr]
                        ),
                    )

        for name, arguments in (
            (
                "omitted-receipt",
                {"include_result_receipt": False},
            ),
            (
                "statistical-outcome",
                {
                    "statistical_changes": {
                        "outcome": {
                            "schema_version": "scientific-result-statistical-projection/v1",
                            "checked_procedure_id": "two_sided_exact_sign",
                            "improvement_effect": 9.0,
                        }
                    }
                },
            ),
            (
                "statistical-metadata",
                {
                    "statistical_changes": {
                        "metadata": {"scientific_evidence_eligible": True}
                    }
                },
            ),
            (
                "statistical-relationship",
                {
                    "statistical_changes": {
                        "relationships": (
                            ObjectLink(
                                "Result",
                                "unrelated-result",
                                "annotates",
                                False,
                            ),
                        )
                    }
                },
            ),
        ):
            with self.subTest(name=name), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                candidate = _result_promotion_candidate(values)
                _materialize_projected_result_state(
                    values,
                    candidate,
                    **arguments,  # type: ignore[arg-type]
                )
                with self.assertRaisesRegex(
                    ScientificPromotionError,
                    "canonical Result differs|canonical StatisticalTest differs",
                ):
                    require_scientific_result_state_projections(
                        values["registry"],  # type: ignore[arg-type]
                        values["ledger"],  # type: ignore[arg-type]
                        expected_ledger_run_id="global-run-1",
                        expected_execution_run_id="confirmatory-run-1",
                        expected_canonical_state_code_version=STATE_CODE_VERSION,
                        expected_result_id="result-1",
                        result_state_projection_artifact_sha256=(
                            candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        statistical_state_projection_artifact_sha256=(
                            candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        promotion_receipt_artifact_sha256=(
                            candidate["receipt_record"].sha256  # type: ignore[union-attr]
                        ),
                    )

        for target, mode in (
            ("Result", "reordered"),
            ("Result", "wrong_relation"),
            ("Result", "unevaluated"),
            ("Result", "extra_typed"),
            ("StatisticalTest", "wrong_relation"),
            ("StatisticalTest", "unevaluated"),
            ("StatisticalTest", "extra_typed"),
        ):
            with (
                self.subTest(typed_parent=f"{target}-{mode}"),
                TemporaryDirectory() as directory,
            ):
                values = _registered_inputs(Path(directory))
                candidate = _result_promotion_candidate(values)
                _materialize_projected_result_state(
                    values,
                    candidate,
                    materialize_statistical=(target == "StatisticalTest"),
                    result_parent_mode=(mode if target == "Result" else "exact"),
                    statistical_parent_mode=(
                        mode if target == "StatisticalTest" else "exact"
                    ),
                )
                with self.assertRaisesRegex(
                    ScientificPromotionError,
                    "exact evaluated Run and Metric|exact evaluated Result",
                ):
                    require_scientific_result_state_projections(
                        values["registry"],  # type: ignore[arg-type]
                        values["ledger"],  # type: ignore[arg-type]
                        expected_ledger_run_id="global-run-1",
                        expected_execution_run_id="confirmatory-run-1",
                        expected_canonical_state_code_version=STATE_CODE_VERSION,
                        expected_result_id="result-1",
                        result_state_projection_artifact_sha256=(
                            candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        statistical_state_projection_artifact_sha256=(
                            candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        promotion_receipt_artifact_sha256=(
                            candidate["receipt_record"].sha256  # type: ignore[union-attr]
                        ),
                    )

        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            _materialize_projected_result_state(
                values,
                candidate,
                equal_state_timestamps=True,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "StatisticalTest must be created after its Result",
            ):
                require_scientific_result_state_projections(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    expected_canonical_state_code_version=STATE_CODE_VERSION,
                    expected_result_id="result-1",
                    result_state_projection_artifact_sha256=(
                        candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                    ),
                    statistical_state_projection_artifact_sha256=(
                        candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                    ),
                    promotion_receipt_artifact_sha256=(
                        candidate["receipt_record"].sha256  # type: ignore[union-attr]
                    ),
                )

        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            observed_at = require_scientific_result_state_projections(
                values["registry"],  # type: ignore[arg-type]
                values["ledger"],  # type: ignore[arg-type]
                expected_ledger_run_id="global-run-1",
                expected_execution_run_id="confirmatory-run-1",
                expected_canonical_state_code_version=STATE_CODE_VERSION,
                expected_result_id="result-1",
                result_state_projection_artifact_sha256=(
                    candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                ),
                statistical_state_projection_artifact_sha256=(
                    candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                ),
            ).result_state_projection.observed_at
            _materialize_projected_result_state(
                values,
                candidate,
                result_changes={"created_at": observed_at},
                materialize_statistical=False,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "must occur after its inert projection",
            ):
                require_scientific_result_state_projections(
                    values["registry"],  # type: ignore[arg-type]
                    values["ledger"],  # type: ignore[arg-type]
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    expected_canonical_state_code_version=STATE_CODE_VERSION,
                    expected_result_id="result-1",
                    result_state_projection_artifact_sha256=(
                        candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                    ),
                    statistical_state_projection_artifact_sha256=(
                        candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                    ),
                    promotion_receipt_artifact_sha256=(
                        candidate["receipt_record"].sha256  # type: ignore[union-attr]
                    ),
                )

        for target in ("Result", "StatisticalTest"):
            with self.subTest(extra_parent=target), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                candidate = _result_promotion_candidate(values)
                unrelated = _put_json(
                    values["registry"],  # type: ignore[arg-type]
                    {"unrelated": target},
                    logical_type="unrelated_state_parent",
                    role=Role.EVIDENCE_CURATOR,
                )
                _materialize_projected_result_state(
                    values,
                    candidate,
                    materialize_statistical=(target == "StatisticalTest"),
                    extra_result_parent=(
                        unrelated.sha256 if target == "Result" else None
                    ),
                    extra_statistical_parent=(
                        unrelated.sha256 if target == "StatisticalTest" else None
                    ),
                )
                with self.assertRaisesRegex(
                    ScientificPromotionError,
                    "provenance differs from projected authority",
                ):
                    require_scientific_result_state_projections(
                        values["registry"],  # type: ignore[arg-type]
                        values["ledger"],  # type: ignore[arg-type]
                        expected_ledger_run_id="global-run-1",
                        expected_execution_run_id="confirmatory-run-1",
                        expected_canonical_state_code_version=STATE_CODE_VERSION,
                        expected_result_id="result-1",
                        result_state_projection_artifact_sha256=(
                            candidate["result_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        statistical_state_projection_artifact_sha256=(
                            candidate["statistical_projection_record"].sha256  # type: ignore[union-attr]
                        ),
                        promotion_receipt_artifact_sha256=(
                            candidate["receipt_record"].sha256  # type: ignore[union-attr]
                        ),
                    )

    def test_result_projection_rejects_unamended_contract_identity_collision(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
            ledger = values["ledger"]
            # Keep the original same-ID/timestamp-only substitution attack.
            # Raw registration deliberately bypasses the genesis publisher so
            # the actual downstream owner must detect the competing root.
            other_contract = replace(
                values["contract"],  # type: ignore[arg-type]
                frozen_at="2026-08-29T12:00:02Z",
            )
            other_contract_record = _put_json(
                registry,
                {
                    "schema_version": CHECKED_SUPERIORITY_CONTRACT_SCHEMA,
                    "evaluation_contract": other_contract,
                },
                logical_type="evaluation_contract",
                role=Role.PROTOCOL_DESIGNER,
                parents=values["contract_record"].parent_artifacts,  # type: ignore[union-attr]
            )
            wrong_contract_receipt = replace(
                candidate["receipt"],  # type: ignore[arg-type]
                contract_artifact_sha256=other_contract_record.sha256,
            )
            wrong_contract_record = _put_json(
                registry,
                wrong_contract_receipt.to_dict(),
                logical_type="scientific_result_promotion_authority",
                role=Role.CLAIM_VERIFIER,
                parents=wrong_contract_receipt.source_artifact_hashes,
            )
            before = (registry.verify_all(raise_on_error=True), ledger.assert_valid())
            with self.assertRaisesRegex(
                ScientificPromotionError, "competing unamended roots",
            ):
                require_scientific_result_promotion_authority(
                    registry, ledger,
                    promotion_receipt_artifact_sha256=wrong_contract_record.sha256,
                    expected_ledger_run_id="global-run-1",
                    expected_execution_run_id="confirmatory-run-1",
                    expected_canonical_state_code_version=STATE_CODE_VERSION,
                    expected_result_id="result-1",
                    scientific_timeline_receipt_artifact_sha256=None,
                    domain_validity_receipt_artifact_sha256=None,
                    backend_execution_authority_artifact_sha256=None,
                    confirmation_authority_artifact_sha256=None,
                )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.assert_valid()), before,
            )

    def test_result_projection_rejects_contract_and_statistical_state_substitution(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            candidate = _result_promotion_candidate(values)
            registry: ArtifactRegistry = values["registry"]  # type: ignore[assignment]
            ledger = values["ledger"]
            common = {
                "expected_ledger_run_id": "global-run-1",
                "expected_execution_run_id": "confirmatory-run-1",
                "expected_canonical_state_code_version": STATE_CODE_VERSION,
                "expected_result_id": "result-1",
                "scientific_timeline_receipt_artifact_sha256": None,
                "domain_validity_receipt_artifact_sha256": None,
                "backend_execution_authority_artifact_sha256": None,
                "confirmation_authority_artifact_sha256": None,
            }

            other_contract = replace(
                values["contract"],  # type: ignore[arg-type]
                contract_id="foreign-projection-contract",
                frozen_at="2026-08-29T12:00:02Z",
            )
            other_contract_record = _put_json(
                registry,
                {
                    "schema_version": CHECKED_SUPERIORITY_CONTRACT_SCHEMA,
                    "evaluation_contract": other_contract,
                },
                logical_type="evaluation_contract",
                role=Role.PROTOCOL_DESIGNER,
                parents=values["contract_record"].parent_artifacts,  # type: ignore[union-attr]
            )
            wrong_contract_receipt = replace(
                candidate["receipt"],  # type: ignore[arg-type]
                contract_artifact_sha256=other_contract_record.sha256,
            )
            wrong_contract_record = _put_json(
                registry,
                wrong_contract_receipt.to_dict(),
                logical_type="scientific_result_promotion_authority",
                role=Role.CLAIM_VERIFIER,
                parents=wrong_contract_receipt.source_artifact_hashes,
            )
            before = (registry.verify_all(raise_on_error=True), ledger.assert_valid())
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "differs from checked authority closure",
            ):
                require_scientific_result_promotion_authority(
                    registry,
                    ledger,
                    promotion_receipt_artifact_sha256=wrong_contract_record.sha256,
                    **common,  # type: ignore[arg-type]
                )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.assert_valid()), before,
            )

            original_projection_record = candidate["statistical_projection_record"]
            wrong_projection = json.loads(
                registry.get_bytes(original_projection_record.sha256)
            )
            wrong_projection["checked_procedure_id"] = "caller-labelled-test"
            wrong_test_record = _put_json(
                registry,
                wrong_projection,
                logical_type="scientific_statistical_state_projection",
                role=Role.CLAIM_VERIFIER,
                parents=original_projection_record.parent_artifacts,
            )
            wrong_state_receipt = replace(
                candidate["receipt"],  # type: ignore[arg-type]
                statistical_state_projection_artifact_sha256=(
                    wrong_test_record.sha256
                ),
            )
            wrong_state_record = _put_json(
                registry,
                wrong_state_receipt.to_dict(),
                logical_type="scientific_result_promotion_authority",
                role=Role.CLAIM_VERIFIER,
                parents=wrong_state_receipt.source_artifact_hashes,
            )
            before = (registry.verify_all(raise_on_error=True), ledger.assert_valid())
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "differs from deterministic raw-source replay",
            ):
                require_scientific_result_promotion_authority(
                    registry,
                    ledger,
                    promotion_receipt_artifact_sha256=wrong_state_record.sha256,
                    **common,  # type: ignore[arg-type]
                )
            self.assertEqual(
                (registry.verify_all(raise_on_error=True), ledger.assert_valid()), before,
            )

    def test_exact_real_spec_manifest_boundary_still_blocks_unavailable_attestation(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "no supported backend-produced.*attestation",
            ):
                _attempt_checked(values)

    def test_arbitrary_eligibility_json_and_boolean_flips_never_promote(self) -> None:
        for value in (True, False):
            with self.subTest(value=value), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                eligibility_record = _put_json(
                    values["registry"],
                    {
                        "scientific_evidence_eligible": value,
                        "passed": value,
                    },
                    logical_type="scientific_evidence_eligibility",
                    role=Role.SCIENTIFIC_REVIEWER,
                    parents=(
                        values["contract_record"].sha256,
                        values["aggregate_record"].sha256,
                    ),
                )
                with self.assertRaisesRegex(
                    ScientificPromotionError, "no supported backend-produced"
                ):
                    _attempt_checked(
                        values,
                        evidence_eligibility_sha256=eligibility_record.sha256,
                    )

        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            aggregate = dict(values["aggregate_value"])
            aggregate["scientific_evidence_eligible"] = False
            record = _put_json(
                values["registry"],
                aggregate,
                logical_type="aggregate_experiment_result",
                role=Role.STATISTICIAN,
                parents=values["aggregate_record"].parent_artifacts,
            )
            with self.assertRaisesRegex(
                ScientificPromotionError,
                "statistical analysis lacks exact",
            ):
                _attempt_checked(values, aggregate_result_sha256=record.sha256)

    def test_fabricated_tiny_run_spec_is_rejected_before_labels(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            dummy = _put_json(
                values["registry"],
                {"schema_version": "focused-frozen-run-spec/v1", "run_id": "fake"},
                logical_type="frozen_run_spec",
                role=Role.EXPERIMENT_RUNNER,
                parents=values["spec_record"].parent_artifacts,
            )
            aggregate = dict(values["aggregate_value"])
            aggregate["run_spec_sha256"] = dummy.sha256
            record = _put_json(
                values["registry"],
                aggregate,
                logical_type="aggregate_experiment_result",
                role=Role.STATISTICIAN,
                parents=(
                    values["contract_record"].sha256,
                    dummy.sha256,
                    values["manifest_record"].sha256,
                    *(item.sha256 for item in values["raw_records"]),
                    *(item.sha256 for item in values["ablation_records"]),
                ),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "run-spec schema"):
                _attempt_checked(values, aggregate_result_sha256=record.sha256)

    def test_aggregate_arrays_order_and_parents_are_rederived_from_raw_bytes(self) -> None:
        cases = (
            ({"candidate_values": [0.5] * 24}, None, "arrays differ"),
            (
                {"paired_unit_ids": list(reversed([f"unit-{i}" for i in range(24)]))},
                None,
                "paired-unit.*order",
            ),
            ({"scientific_evidence_eligible": False}, "reordered", "raw parents"),
        )
        for changes, parent_mode, message in cases:
            with self.subTest(changes=changes), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                aggregate = dict(values["aggregate_value"])
                aggregate.update(changes)
                parents = values["aggregate_record"].parent_artifacts
                if parent_mode == "reordered":
                    parents = (parents[1], parents[0], *parents[2:])
                record = _put_json(
                    values["registry"],
                    aggregate,
                    logical_type="aggregate_experiment_result",
                    role=Role.STATISTICIAN,
                    parents=parents,
                )
                with self.assertRaisesRegex(ScientificPromotionError, message):
                    _attempt_checked(values, aggregate_result_sha256=record.sha256)

    def test_duplicate_manifest_values_and_wrong_seed_order_reject(self) -> None:
        for mode, message in (("duplicate", "duplicate artifact"), ("seed-order", "reordered seed")):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                manifest = json.loads(canonical_json_bytes(values["manifest"].to_dict()))
                if mode == "duplicate":
                    manifest["artifacts"].append(dict(manifest["artifacts"][0]))
                else:
                    manifest["seed_results"] = list(reversed(manifest["seed_results"]))
                forged_manifest = _put_json(
                    values["registry"],
                    manifest,
                    logical_type="experiment_output_manifest",
                    role=Role.EXPERIMENT_RUNNER,
                    parents=(values["spec_record"].sha256,),
                )
                aggregate = dict(values["aggregate_value"])
                aggregate["output_manifest_sha256"] = forged_manifest.sha256
                forged_aggregate = _put_json(
                    values["registry"],
                    aggregate,
                    logical_type="aggregate_experiment_result",
                    role=Role.STATISTICIAN,
                    parents=(
                        values["contract_record"].sha256,
                        values["spec_record"].sha256,
                        forged_manifest.sha256,
                        *(item.sha256 for item in values["raw_records"]),
                        *(item.sha256 for item in values["ablation_records"]),
                    ),
                )
                with self.assertRaisesRegex(ScientificPromotionError, message):
                    _attempt_checked(
                        values, aggregate_result_sha256=forged_aggregate.sha256
                    )

    def test_evaluator_empty_label_or_selection_trace_is_not_authority(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            label_only = _put_json(
                values["registry"],
                {
                    "schema_version": CHECKED_SUPERIORITY_EVALUATOR_SCHEMA,
                    "contract_artifact_sha256": values["contract_record"].sha256,
                    "aggregate_result_sha256": values["aggregate_record"].sha256,
                    "assessment": {
                        "evaluator_id": "evaluator-v1",
                        "evaluator_version": "1.0",
                        "signals": [],
                        "passed": True,
                    },
                    "selection_trials": 0,
                },
                logical_type="evaluator_integrity_assessment",
                role=Role.SCIENTIFIC_REVIEWER,
                parents=(values["contract_record"].sha256,),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "schema"):
                _attempt_checked(values, evaluator_assessment_sha256=label_only.sha256)

        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory))
            trace = dict(values["trace_value"])
            trace["selection_trials"] = [{"trial": 1, "score": 1.0}]
            trace_record = _put_json(
                values["registry"],
                trace,
                logical_type="evaluator_integrity_trace",
                role=Role.EXPERIMENT_RUNNER,
                parents=values["trace_record"].parent_artifacts,
            )
            assessment = dict(values["evaluator_value"])
            assessment["trace_sha256"] = trace_record.sha256
            assessment_record = _put_json(
                values["registry"],
                assessment,
                logical_type="evaluator_integrity_assessment",
                role=Role.SCIENTIFIC_REVIEWER,
                parents=(
                    values["contract_record"].sha256,
                    values["aggregate_record"].sha256,
                    values["evaluator_implementation"].sha256,
                    trace_record.sha256,
                ),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "selection/branch"):
                _attempt_checked(
                    values, evaluator_assessment_sha256=assessment_record.sha256
                )

    def test_missing_ablation_and_obligation_coverage_reject(self) -> None:
        with TemporaryDirectory() as directory:
            values = _registered_inputs(Path(directory), omit_ablation=True)
            with self.assertRaisesRegex(ScientificPromotionError, "required ablation"):
                _attempt_checked(values)
        for removed_kind in ("ROBUSTNESS", "STOPPING"):
            with self.subTest(kind=removed_kind), TemporaryDirectory() as directory:
                values = _registered_inputs(Path(directory))
                obligation = dict(values["obligations_value"])
                entries = [
                    item
                    for item in obligation["entries"]
                    if item["kind"] != removed_kind
                ]
                obligation["entries"] = entries
                kept_hashes = tuple(item["evidence_sha256"] for item in entries)
                record = _put_json(
                    values["registry"],
                    obligation,
                    logical_type="scientific_obligation_verification",
                    role=Role.SCIENTIFIC_REVIEWER,
                    parents=(
                        values["contract_record"].sha256,
                        values["spec_record"].sha256,
                        values["manifest_record"].sha256,
                        *kept_hashes,
                    ),
                )
                with self.assertRaisesRegex(ScientificPromotionError, "missing or extra"):
                    _attempt_checked(values, scientific_obligations_sha256=record.sha256)

    def test_value_only_path_remains_explicitly_diagnostic(self) -> None:
        contract = make_contract()
        diagnostic = validate_superiority_claim(
            contract,
            executed_baseline_ids=("baseline-strong",),
            candidate_observation=MetricObservation("accuracy", 0.76, MetricUnit.FRACTION),
            baseline_observation=MetricObservation("accuracy", 0.70, MetricUnit.FRACTION),
            statistical_evidence=StatisticalEvidence(
                improvement_effect=0.06,
                confidence_low=0.03,
                confidence_high=0.09,
                adjusted_p_value=0.02,
                sample_size=50,
                multiplicity_correction="Holm",
                artifact_sha256="0" * 64,
            ),
            evaluator_assessment=EvaluatorAssessment("evaluator-v1", "v1", (), True),
            evidence_metric_id="accuracy",
            claimed_scope=MetricScope.END_TO_END,
        )
        self.assertFalse(diagnostic.authoritative)
        self.assertIs(diagnostic.status, SuperiorityValidationStatus.DIAGNOSTIC_ONLY)


class ProxyInferenceReceiptTests(unittest.TestCase):
    def _fixture(self, root: Path, *, evidence_hash: str | None = None) -> dict[str, object]:
        registry = ArtifactRegistry(root)
        raw = _put_json(
            registry,
            {"paired_validation_run": "proxy-validation-1"},
            logical_type="proxy_validation_raw_output",
            role=Role.EXPERIMENT_RUNNER,
        )
        evidence = _put_json(
            registry,
            {
                "schema_version": PROXY_INFERENCE_EVIDENCE_SCHEMA,
                "validation_run_id": "proxy-validation-1",
                "proxy_metric_id": "proxy-score",
                "end_to_end_metric_id": "accuracy",
                "validation_method": PROXY_INFERENCE_VALIDATION_METHOD,
                "source_artifact_hashes": [raw.sha256],
                "proxy_values": [0.1, 0.5, 0.9],
                "end_to_end_values": [0.2, 0.6, 0.95],
            },
            logical_type="proxy_inference_paired_evidence",
            role=Role.STATISTICIAN,
            parents=(raw.sha256,),
        )
        proxy_metric = make_metric(
            metric_id="proxy-score", name="Frozen proxy", scope=MetricScope.PROXY
        )
        end_metric = make_metric(metric_id="accuracy", scope=MetricScope.END_TO_END)
        inference = ProxyInferenceContract(
            proxy_metric_id="proxy-score",
            end_to_end_metric_id="accuracy",
            justification="Frozen paired validation establishes monotone claim scope.",
            validation_method=PROXY_INFERENCE_VALIDATION_METHOD,
            evidence_ids=(evidence_hash or evidence.sha256,),
            independently_verified=False,
        )
        contract = make_contract(
            primary_metric=proxy_metric,
            secondary_metrics=(end_metric,),
            candidate_conditions=make_conditions(metric_id="proxy-score"),
            baseline_registry=BaselineRegistry(
                (make_baseline(conditions=make_conditions(metric_id="proxy-score")),)
            ),
            proxy_inferences=(inference,),
        )
        parent = _put_json(
            registry,
            {"frozen": "proxy-contract-parent"},
            logical_type="frozen_scientific_inputs",
            role=Role.EVIDENCE_CURATOR,
        )
        contract_record = _put_json(
            registry,
            {
                "schema_version": CHECKED_SUPERIORITY_CONTRACT_SCHEMA,
                "evaluation_contract": contract,
            },
            logical_type="evaluation_contract",
            role=Role.PROTOCOL_DESIGNER,
            parents=(parent.sha256,),
        )
        return locals()

    def test_honest_receipt_re_resolves_but_boolean_does_not_replace_it(self) -> None:
        with TemporaryDirectory() as directory:
            values = self._fixture(Path(directory))
            record = register_proxy_inference_verification(
                values["registry"],
                receipt_id="proxy-verification-1",
                claim_id="claim-1",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                proxy_metric_id="proxy-score",
                end_to_end_metric_id="accuracy",
                claimed_scope=MetricScope.END_TO_END,
            )
            resolved = require_proxy_inference_verification(
                values["registry"],
                receipt_artifact_sha256=record.sha256,
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                claim_id="claim-1",
                evidence_metric_id="proxy-score",
                claimed_scope=MetricScope.END_TO_END,
            )
            self.assertEqual(resolved.directional_agreement, 1.0)
            self.assertFalse(values["inference"].independently_verified)

    def test_missing_sha_only_evidence_wrong_claim_and_forged_parents_reject(self) -> None:
        with TemporaryDirectory() as directory:
            values = self._fixture(Path(directory), evidence_hash="f" * 64)
            with self.assertRaisesRegex(ScientificPromotionError, "missing|unresolved"):
                register_proxy_inference_verification(
                    values["registry"],
                    receipt_id="missing-evidence",
                    claim_id="claim-1",
                    contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    proxy_metric_id="proxy-score",
                    end_to_end_metric_id="accuracy",
                    claimed_scope=MetricScope.END_TO_END,
                )
        with TemporaryDirectory() as directory:
            values = self._fixture(Path(directory))
            valid = register_proxy_inference_verification(
                values["registry"],
                receipt_id="proxy-verification-1",
                claim_id="claim-1",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                proxy_metric_id="proxy-score",
                end_to_end_metric_id="accuracy",
                claimed_scope=MetricScope.END_TO_END,
            )
            with self.assertRaisesRegex(ScientificPromotionError, "another claim"):
                require_proxy_inference_verification(
                    values["registry"],
                    receipt_artifact_sha256=valid.sha256,
                    contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    claim_id="claim-2",
                    evidence_metric_id="proxy-score",
                    claimed_scope=MetricScope.END_TO_END,
                )
            forged_value = json.loads(values["registry"].get_bytes(valid.sha256))
            forged_value["receipt_id"] = "proxy-verification-forged"
            forged_value["validation_run_ids"] = ["substituted-run"]
            forged = _put_json(
                values["registry"],
                forged_value,
                logical_type=valid.logical_type,
                role=Role.SCIENTIFIC_REVIEWER,
                parents=tuple(reversed(valid.parent_artifacts)),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "stale|differs"):
                require_proxy_inference_verification(
                    values["registry"],
                    receipt_artifact_sha256=forged.sha256,
                    contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    claim_id="claim-1",
                    evidence_metric_id="proxy-score",
                    claimed_scope=MetricScope.END_TO_END,
                )


class BaselineExclusionReceiptTests(unittest.TestCase):
    def _fixture(self, root: Path) -> dict[str, object]:
        registry = ArtifactRegistry(root)
        source = _put_json(
            registry,
            {"resource_measurement": "frozen-budget-boundary"},
            logical_type="baseline_resource_measurement",
            role=Role.EXPERIMENT_RUNNER,
        )
        placeholder = BaselineExclusion(
            reason="Required baseline exceeds the frozen fair compute budget.",
            evidence_ids=("0" * 64,),
            scientifically_unavoidable=False,
            preserves_claim_validity=False,
        )
        baseline = make_baseline(
            conditions=make_conditions(compute_budget=200.0),
            exclusion=placeholder,
        )
        provisional = make_contract(baseline_registry=BaselineRegistry((baseline,)))
        resource_context = {
            "baseline_id": baseline.baseline_id,
            "implementation": baseline.implementation,
            "implementation_version": baseline.implementation_version,
            "required_compute_budget": baseline.conditions.compute_budget,
            "available_compute_budget": provisional.candidate_conditions.compute_budget,
            "contract_compute_budget": provisional.compute_budget,
        }
        fairness_context = {
            "baseline_id": baseline.baseline_id,
            "metric_id": provisional.primary_metric.metric_id,
            "metric_unit": provisional.primary_metric.unit.value,
            "metric_scope": provisional.primary_metric.scope.value,
            "candidate_conditions_sha256": _digest(provisional.candidate_conditions),
            "baseline_conditions_sha256": _digest(baseline.conditions),
            "mismatches": ["compute_budget"],
            "scientific_purpose": BASELINE_EXCLUSION_SCIENTIFIC_PURPOSE,
        }
        evidence = _put_json(
            registry,
            {
                "schema_version": BASELINE_EXCLUSION_EVIDENCE_SCHEMA,
                "baseline_id": baseline.baseline_id,
                "implementation_version": baseline.implementation_version,
                "exclusion_reason": placeholder.reason,
                "resource_context_sha256": _digest(resource_context),
                "fairness_context_sha256": _digest(fairness_context),
                "constraint": "REQUIRED_COMPUTE_EXCEEDS_FROZEN_BUDGET",
                "required_compute_budget": 200.0,
                "available_compute_budget": 100.0,
                "source_artifact_hashes": [source.sha256],
            },
            logical_type="baseline_exclusion_evidence",
            role=Role.EVIDENCE_CURATOR,
            parents=(source.sha256,),
        )
        exclusion = replace(placeholder, evidence_ids=(evidence.sha256,))
        baseline = replace(baseline, exclusion=exclusion)
        contract = make_contract(baseline_registry=BaselineRegistry((baseline,)))
        parent = _put_json(
            registry,
            {"frozen": "baseline-contract-parent"},
            logical_type="frozen_scientific_inputs",
            role=Role.EVIDENCE_CURATOR,
        )
        contract_record = _put_json(
            registry,
            {
                "schema_version": CHECKED_SUPERIORITY_CONTRACT_SCHEMA,
                "evaluation_contract": contract,
            },
            logical_type="evaluation_contract",
            role=Role.PROTOCOL_DESIGNER,
            parents=(parent.sha256,),
        )
        return locals()

    def test_honest_receipt_resolves_with_false_legacy_booleans(self) -> None:
        with TemporaryDirectory() as directory:
            values = self._fixture(Path(directory))
            record = register_baseline_exclusion_verification(
                values["registry"],
                receipt_id="baseline-exclusion-1",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                baseline_id="baseline-strong",
            )
            resolved = require_baseline_exclusion_verification(
                values["registry"],
                receipt_artifact_sha256=record.sha256,
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                baseline_id="baseline-strong",
            )
            self.assertEqual(resolved.baseline_id, "baseline-strong")
            self.assertFalse(values["exclusion"].strong)

    def test_forged_wrong_baseline_contract_evidence_and_parents_reject(self) -> None:
        with TemporaryDirectory() as directory:
            values = self._fixture(Path(directory))
            valid = register_baseline_exclusion_verification(
                values["registry"],
                receipt_id="baseline-exclusion-1",
                contract=values["contract"],
                contract_artifact_sha256=values["contract_record"].sha256,
                baseline_id="baseline-strong",
            )
            with self.assertRaisesRegex(ScientificPromotionError, "another baseline|unknown"):
                require_baseline_exclusion_verification(
                    values["registry"],
                    receipt_artifact_sha256=valid.sha256,
                    contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    baseline_id="baseline-wrong",
                )
            forged_value = json.loads(values["registry"].get_bytes(valid.sha256))
            forged_value["receipt_id"] = "baseline-exclusion-forged"
            forged_value["evidence_artifact_hashes"] = ["f" * 64]
            forged = _put_json(
                values["registry"],
                forged_value,
                logical_type=valid.logical_type,
                role=Role.SCIENTIFIC_REVIEWER,
                parents=tuple(reversed(valid.parent_artifacts)),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "stale|differs"):
                require_baseline_exclusion_verification(
                    values["registry"],
                    receipt_artifact_sha256=forged.sha256,
                    contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    baseline_id="baseline-strong",
                )
            changed = replace(values["contract"], frozen_at="2026-08-30T00:00:00Z")
            with self.assertRaisesRegex(ScientificPromotionError, "registered frozen contract"):
                require_baseline_exclusion_verification(
                    values["registry"],
                    receipt_artifact_sha256=valid.sha256,
                    contract=changed,
                    contract_artifact_sha256=values["contract_record"].sha256,
                    baseline_id="baseline-strong",
                )


if __name__ == "__main__":
    unittest.main()
