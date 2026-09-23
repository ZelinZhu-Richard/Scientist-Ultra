from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import scientist_one.research_state as research_state_module
import scientist_one.ledger as ledger_module
import scientist_one.scientific_design as scientific_design_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.claims import (
    CLAIM_GRAPH_RESOLVER_ID,
    ClaimDecision as GraphClaimDecision,
    ClaimEvidenceUse,
    ClaimEvidenceGraph,
    EvidenceKind as GraphEvidenceKind,
    EvidenceLink as GraphEvidenceLink,
    EvidenceNode as GraphEvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    REQUIRED_EVIDENCE_KINDS,
    artifact_registry_resolver,
)
from scientist_one.errors import ValidationError
from scientist_one.domains import (
    DomainKind,
    GenericMLExample,
    GenericMLValidityEvidence,
    SplitRole as DomainSplitRole,
    materialize_domain_validity,
    register_domain_evidence_source,
    register_domain_raw_fixture_source,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.research_state import (
    Ablation,
    Baseline,
    BaselineStatus,
    CanonicalResearchObject,
    Challenge,
    ChallengeResolution,
    ChallengeSeverity,
    Claim,
    ClaimReview,
    ClaimSemanticsEvidenceScope,
    ClaimStrength,
    ClaimType,
    ComputeProfile,
    Critique,
    Dataset,
    Decision,
    Evidence,
    Experiment,
    Hypothesis,
    HypothesisStatus,
    Implementation,
    Method,
    Metric,
    MetricDirection,
    MetricLevel,
    ObjectLink,
    ObjectReference,
    PriorWork,
    RESEARCH_OBJECT_TYPES,
    RecordStatus,
    ReferenceVerificationDepth,
    ReproducibilityPackage,
    ReproductionStatus,
    ResearchQuestion,
    ResearchQuestionOutcome,
    ResearchStateRepository,
    ScopedResearchStateAuthority,
    resolve_bound_research_state_authority,
    resolve_current_research_state_bindings,
    resolve_research_state_authority,
    Result,
    Run,
    Split,
    SplitRole,
    StateIssueCode,
    StatisticalTest,
    VenueAssessment,
    VenueFit,
    VerificationStatus,
    build_claim_semantics_judgment_request,
    render_markdown,
    register_scientific_claim_evidence_projection,
    register_scientific_dataset_acquisition_plan,
    register_scientific_dataset_usage_proposal,
    register_claim_semantics_receipt,
    register_claim_semantics_proposal,
    register_research_state_snapshot,
    require_claim_semantics_receipt,
    require_claim_semantics_proposal,
    require_scientific_dataset_acquisition_plan,
    revise_research_object,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    require_scientific_result_state_projections,
    scientific_ablation_component_id,
)
from scientist_one.security import canonical_json_bytes


STAMP = "2026-08-29T12:00:00Z"
STAMP_2 = "2026-08-29T12:00:01Z"
CONFIG_HASH = "c" * 64
SCIENTIFIC_V2_STATE_CODE_VERSION = "research-os-vnext:test-state-kernel"


def _load_scientific_v2_producer_helpers() -> dict[str, object]:
    """Load the frozen producer fixture without importing its test class."""

    tests_root = Path(__file__).resolve().parent
    inserted = str(tests_root) not in sys.path
    if inserted:
        sys.path.insert(0, str(tests_root))
    try:
        helpers = runpy.run_path(str(tests_root / "test_superiority_authority.py"))
    finally:
        if inserted:
            sys.path.remove(str(tests_root))
    return helpers


def _scientific_v2_source_fixture(root: Path) -> dict[str, object]:
    """Create only frozen producer authority, then return a public repository."""

    helpers = _load_scientific_v2_producer_helpers()
    # The shared producer helper predates the run-scoped public state resolver.
    # Override only its registry constructor; the returned object is still the
    # concrete public ArtifactRegistry, and no canonical state bytes are written
    # by the producer helper.
    def registry_factory(fixture_root: Path) -> ArtifactRegistry:
        return ArtifactRegistry(
            fixture_root,
            "runs/global-run-1/registry",
        )
    registered_inputs = helpers["_registered_inputs"]
    promotion_candidate = helpers["_result_promotion_candidate"]
    helper_globals = registered_inputs.__globals__  # type: ignore[union-attr]
    original_registry = helper_globals["ArtifactRegistry"]
    try:
        helper_globals["ArtifactRegistry"] = registry_factory
        values = registered_inputs(root)  # type: ignore[operator]
    finally:
        helper_globals["ArtifactRegistry"] = original_registry
    candidate = promotion_candidate(values)  # type: ignore[operator]
    registry = values["registry"]
    ledger = values["ledger"]
    projection = require_scientific_result_state_projections(
        registry,  # type: ignore[arg-type]
        ledger,  # type: ignore[arg-type]
        expected_ledger_run_id="global-run-1",
        expected_execution_run_id="confirmatory-run-1",
        expected_canonical_state_code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
        expected_result_id="result-1",
        result_state_projection_artifact_sha256=(
            candidate["result_projection_record"].sha256
        ),
        statistical_state_projection_artifact_sha256=(
            candidate["statistical_projection_record"].sha256
        ),
        promotion_receipt_artifact_sha256=candidate["receipt_record"].sha256,
    )
    spec = values["spec"]
    last_state = ledger.assert_valid().events[-1].requested_state_after
    repository = ResearchStateRepository(
        registry,  # type: ignore[arg-type]
        ledger,  # type: ignore[arg-type]
        run_id="global-run-1",
        code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
        configuration_hash=spec.configuration_sha256,
        state=last_state,
    )
    return {
        "values": values,
        "candidate": candidate,
        "projection": projection,
        "registry": registry,
        "ledger": ledger,
        "repository": repository,
    }


def _timestamp_after(value: str, microseconds: int) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (
        parsed + timedelta(microseconds=microseconds)
    ).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _scientific_v2_state_graph(
    source: dict[str, object],
    mutations: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Project the frozen producer into one exact public canonical graph."""

    mutations = mutations or {}
    values = source["values"]
    candidate = source["candidate"]
    projection = source["projection"]
    ledger = source["ledger"]
    registry = source["registry"]
    contract = values["contract"]
    spec = values["spec"]
    result_projection = projection.result_state_projection
    statistical_projection = projection.statistical_state_projection
    contract_record = values["contract_record"]
    spec_record = values["spec_record"]
    manifest_record = values["manifest_record"]
    data_record = values["data_record"]
    configuration_record = values["configuration_record"]
    code_record = values["code_record"]
    evaluator_record = values["evaluator_implementation"]
    receipt_record = candidate["receipt_record"]

    next_offset = 0
    ledger_head_time = ledger.assert_valid().events[-1].timestamp

    def timestamp() -> str:
        nonlocal next_offset
        next_offset += 1
        return _timestamp_after(ledger_head_time, next_offset)

    def arguments(key: str, values_: dict[str, object]) -> dict[str, object]:
        return {**values_, **mutations.get(key, {})}

    method_id = f"method-{code_record.sha256}"
    implementation_id = "implementation-" + hashlib.sha256(
        canonical_json_bytes(
            {
                "code_sha256": code_record.sha256,
                "configuration_sha256": configuration_record.sha256,
            }
        )
    ).hexdigest()
    method = Method(
        **arguments(
            "Method",
            {
                "object_id": method_id,
                "producer": Role.PROTOCOL_DESIGNER,
                "status": RecordStatus.FROZEN,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (code_record.sha256,),
                "name": "UNAVAILABLE",
                "description": "UNAVAILABLE",
                "assumptions": (),
                "component_ids": tuple(
                    scientific_ablation_component_id(
                        item.ablation_id,
                        item.component_changed,
                    )
                    for item in contract.ablations
                ),
            },
        )
    )
    implementation = Implementation(
        **arguments(
            "Implementation",
            {
                "object_id": implementation_id,
                "producer": Role.IMPLEMENTER,
                "status": RecordStatus.FROZEN,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (
                    code_record.sha256,
                    configuration_record.sha256,
                ),
                "parents": (
                    ObjectReference(
                        "Method",
                        method.object_id,
                        method.content_hash,
                        "implements",
                        True,
                    ),
                ),
                "method_id": method.object_id,
                "code_artifact_hashes": (code_record.sha256,),
                "code_revision": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "configuration_artifact_hashes": (
                    configuration_record.sha256,
                ),
            },
        )
    )
    primary_hypothesis = contract.hypothesis_register.primary
    hypothesis = Hypothesis(
        **arguments(
            "Hypothesis",
            {
                "object_id": primary_hypothesis.hypothesis_id,
                "producer": Role.HYPOTHESIS_DESIGNER,
                "status": RecordStatus.FROZEN,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (contract_record.sha256,),
                "statement": primary_hypothesis.statement,
                "motivation": primary_hypothesis.motivation,
                "prior_evidence_ids": primary_hypothesis.prior_evidence_ids,
                "prediction": primary_hypothesis.prediction,
                "falsification_condition": (
                    primary_hypothesis.falsification_condition
                ),
                "planned_experiment_ids": (
                    primary_hypothesis.planned_experiment,
                ),
                "hypothesis_status": HypothesisStatus.UNTESTED,
            },
        )
    )
    dataset = Dataset(
        **arguments(
            "Dataset",
            {
                "object_id": contract.dataset.dataset_id,
                "producer": Role.EVIDENCE_CURATOR,
                "status": RecordStatus.FROZEN,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (data_record.sha256,),
                "name": "UNAVAILABLE",
                "version": f"sha256:{data_record.sha256}",
                "artifact_hashes": (data_record.sha256,),
                "access_status": "UNSPECIFIED",
                "license": "UNSPECIFIED",
            },
        )
    )
    split_specs = (
        (contract.dataset.train_split_id, SplitRole.TRAIN),
        (contract.dataset.development_split_id, SplitRole.EXPLORATORY),
        (contract.dataset.validation_split_id, SplitRole.VALIDATION),
        (contract.dataset.confirmatory_split_id, SplitRole.CONFIRMATORY),
    )
    splits: list[Split] = []
    for split_id, split_role in split_specs:
        splits.append(
            Split(
                **arguments(
                    f"Split:{split_id}",
                    {
                        "object_id": split_id,
                        "producer": Role.PROTOCOL_DESIGNER,
                        "status": RecordStatus.FROZEN,
                        "created_at": timestamp(),
                        "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                        "authority_artifact_hashes": (
                            contract_record.sha256,
                            data_record.sha256,
                        ),
                        "parents": (
                            ObjectReference(
                                "Dataset",
                                dataset.object_id,
                                dataset.content_hash,
                                "partitions",
                                True,
                            ),
                        ),
                        "dataset_id": dataset.object_id,
                        "split_role": split_role,
                        "unit_type": "UNSPECIFIED",
                        "definition_artifact_hashes": (),
                    },
                )
            )
        )
    metric_direction = {
        "HIGHER_IS_BETTER": MetricDirection.HIGHER_IS_BETTER,
        "LOWER_IS_BETTER": MetricDirection.LOWER_IS_BETTER,
        "TARGET_IS_BEST": MetricDirection.TARGET_IS_BETTER,
    }
    metric_specs = (contract.primary_metric, *contract.secondary_metrics)
    metrics: list[Metric] = []
    for metric_spec in metric_specs:
        metrics.append(
            Metric(
                **arguments(
                    f"Metric:{metric_spec.metric_id}",
                    {
                        "object_id": metric_spec.metric_id,
                        "producer": Role.PROTOCOL_DESIGNER,
                        "status": RecordStatus.FROZEN,
                        "created_at": timestamp(),
                        "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                        "authority_artifact_hashes": (contract_record.sha256,),
                        "name": metric_spec.name,
                        "direction": metric_direction[metric_spec.direction.value],
                        "unit": metric_spec.unit.value,
                        "evidence_level": MetricLevel(metric_spec.scope.value),
                    },
                )
            )
        )
    baselines: list[Baseline] = []
    for baseline_spec in contract.baseline_registry.entries:
        metric_id = baseline_spec.conditions.metric_id

        def optional_metric(value: object) -> dict[str, object]:
            return {} if value is None else {metric_id: value}

        baseline_implementation_id = "baseline-implementation-" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "implementation": baseline_spec.implementation,
                    "implementation_version": baseline_spec.implementation_version,
                }
            )
        ).hexdigest()
        baseline_paper_id = "baseline-paper-" + hashlib.sha256(
            canonical_json_bytes({"paper_locator": baseline_spec.paper_locator})
        ).hexdigest()
        baselines.append(
            Baseline(
                **arguments(
                    f"Baseline:{baseline_spec.baseline_id}",
                    {
                        "object_id": baseline_spec.baseline_id,
                        "producer": Role.PROTOCOL_DESIGNER,
                        "status": RecordStatus.FROZEN,
                        "created_at": timestamp(),
                        "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                        "authority_artifact_hashes": (contract_record.sha256,),
                        "name": baseline_spec.name,
                        "method_id": (
                            f"baseline-method-{baseline_spec.baseline_id}"
                        ),
                        "implementation_id": baseline_implementation_id,
                        "paper_id": baseline_paper_id,
                        "metric_ids": (metric_id,),
                        "baseline_status": BaselineStatus(
                            baseline_spec.status.value
                        ),
                        "reported_metrics": optional_metric(
                            baseline_spec.reported_metric
                        ),
                        "expected_metrics": optional_metric(
                            baseline_spec.expected_metric
                        ),
                        "observed_metrics": optional_metric(
                            baseline_spec.observed_metric
                        ),
                        "tuning_budget": {
                            "hyperparameter_search": (
                                baseline_spec.conditions.hyperparameter_search
                            ),
                            "trials": baseline_spec.conditions.tuning_trials,
                        },
                        "compute_budget": {
                            "budget": baseline_spec.conditions.compute_budget,
                            "hardware_class": (
                                baseline_spec.conditions.hardware_class
                            ),
                        },
                        "implementation_confidence": (
                            baseline_spec.implementation_confidence
                        ),
                        "fairness_assessment": (
                            baseline_spec.fairness_assessment
                        ),
                    },
                )
            )
        )
    experiment_parents = (
        ObjectReference(
            "Hypothesis",
            hypothesis.object_id,
            hypothesis.content_hash,
            "tests",
            True,
        ),
        ObjectReference(
            "Implementation",
            implementation.object_id,
            implementation.content_hash,
            "uses",
            True,
        ),
        ObjectReference(
            "Dataset",
            dataset.object_id,
            dataset.content_hash,
            "uses",
            True,
        ),
        *tuple(
            ObjectReference(
                "Split", item.object_id, item.content_hash, "binds_split", True
            )
            for item in splits
        ),
        *tuple(
            ObjectReference(
                "Metric", item.object_id, item.content_hash, "evaluates", True
            )
            for item in metrics
        ),
        *tuple(
            ObjectReference(
                "Baseline",
                item.object_id,
                item.content_hash,
                "compares_with",
                True,
            )
            for item in baselines
        ),
    )
    experiment = Experiment(
        **arguments(
            "Experiment",
            {
                "object_id": result_projection.experiment_id,
                "producer": Role.PROTOCOL_DESIGNER,
                "status": RecordStatus.FROZEN,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (
                    contract_record.sha256,
                    configuration_record.sha256,
                ),
                "parents": experiment_parents,
                "hypothesis_ids": (hypothesis.object_id,),
                "scientific_purpose": spec.scientific_purpose,
                "implementation_id": implementation.object_id,
                "dataset_ids": (dataset.object_id,),
                "split_ids": tuple(item.object_id for item in splits),
                "metric_ids": tuple(item.object_id for item in metrics),
                "baseline_ids": tuple(item.object_id for item in baselines),
                "configuration_artifact_hashes": tuple(
                    sorted(
                        (contract_record.sha256, configuration_record.sha256)
                    )
                ),
                "compute_profile": ComputeProfile(spec.compute_profile.mode.value),
                "seed_policy": {
                    "best_of_n": contract.seed_reporting.best_of_n,
                    "preserve_all_runs": (
                        contract.seed_reporting.preserve_all_runs
                    ),
                    "regime": contract.seed_reporting.regime.value,
                    "run_seed_policy": spec.seed_policy,
                    "seeds": list(contract.seed_reporting.seeds),
                    "selection_defined_before_results": (
                        contract.seed_reporting.selection_defined_before_results
                    ),
                    "selection_policy": (
                        contract.seed_reporting.selection_policy
                    ),
                    "technical_retry_rule": (
                        contract.seed_reporting.technical_retry_rule
                    ),
                },
                "expected_output_types": spec.expected_outputs,
                "evaluator": contract.candidate_conditions.evaluator,
                "budget": {
                    "max_cpu_workers": contract.compute_budget.max_cpu_workers,
                    "max_gpu_jobs": contract.compute_budget.max_gpu_jobs,
                    "max_runs": contract.compute_budget.max_runs,
                    "max_tuning_trials": (
                        contract.compute_budget.max_tuning_trials
                    ),
                    "max_wall_seconds": contract.compute_budget.max_wall_seconds,
                },
                "termination_conditions": {
                    "failure": list(contract.failure_criteria),
                    "run": list(spec.termination_conditions),
                    "stopping": list(contract.stopping_criteria),
                    "success": list(contract.success_criteria),
                },
            },
        )
    )
    evaluator_value = json.loads(registry.get_bytes(evaluator_record.sha256))
    run = Run(
        **arguments(
            "Run",
            {
                "object_id": result_projection.run_id,
                "producer": Role.EXPERIMENT_RUNNER,
                "status": RecordStatus.COMPLETE,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (
                    configuration_record.sha256,
                    spec_record.sha256,
                    manifest_record.sha256,
                    *result_projection.raw_source_artifact_hashes,
                ),
                "parents": (
                    ObjectReference(
                        "Experiment",
                        experiment.object_id,
                        experiment.content_hash,
                        "executes",
                        True,
                    ),
                ),
                "experiment_id": experiment.object_id,
                "code_revision": result_projection.execution_code_revision,
                "dataset_ids": (dataset.object_id,),
                "configuration_artifact_hash": configuration_record.sha256,
                "compute_profile": ComputeProfile(spec.compute_profile.mode.value),
                "random_seeds": spec.seeds,
                "output_artifact_hashes": (
                    spec_record.sha256,
                    manifest_record.sha256,
                    *result_projection.raw_source_artifact_hashes,
                ),
                "evaluator_version": evaluator_value["evaluator_version"],
                "started_at": spec_record.created_at,
                "completed_at": manifest_record.created_at,
            },
        )
    )
    primary_metric = next(
        item for item in metrics if item.object_id == result_projection.metric_id
    )
    result_sources = result_projection.state_source_artifact_hashes
    result_evaluations = (receipt_record.sha256,)
    result = Result(
        **arguments(
            "Result",
            {
                "object_id": result_projection.result_id,
                "producer": Role.STATISTICIAN,
                "status": RecordStatus.COMPLETE,
                "created_at": timestamp(),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": (
                    *result_sources,
                    *result_evaluations,
                ),
                "parents": (
                    ObjectReference(
                        "Run", run.object_id, run.content_hash, "aggregates", True
                    ),
                    ObjectReference(
                        "Metric",
                        primary_metric.object_id,
                        primary_metric.content_hash,
                        "reports",
                        True,
                    ),
                ),
                "run_ids": (run.object_id,),
                "metric_id": primary_metric.object_id,
                "value": result_projection.state_value,
                "unit": result_projection.metric_unit.value,
                "direction": metric_direction[
                    result_projection.metric_direction.value
                ],
                "uncertainty": result_projection.state_uncertainty,
                "source_artifact_hashes": result_sources,
                "evaluation_artifact_hashes": result_evaluations,
                "code_revision": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "observed_at": result_projection.observed_at,
            },
        )
    )
    statistical_sources = (
        *statistical_projection.state_source_artifact_hashes,
        receipt_record.sha256,
    )
    statistical_test = StatisticalTest(
        **arguments(
            "StatisticalTest",
            {
                "object_id": statistical_projection.statistical_test_id,
                "producer": Role.STATISTICIAN,
                "status": RecordStatus.COMPLETE,
                # Result-only completion shares Result's timestamp; its ledger
                # append index is the ordering authority.  The exact child can
                # therefore extend the bundle at the next microsecond.
                "created_at": _timestamp_after(result.created_at, 1),
                "code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
                "authority_artifact_hashes": statistical_sources,
                "parents": (
                    ObjectReference(
                        "Result",
                        result.object_id,
                        result.content_hash,
                        "tests",
                        True,
                    ),
                ),
                "result_ids": (result.object_id,),
                "test_name": statistical_projection.contract_primary_test,
                "null_hypothesis": statistical_projection.null_hypothesis,
                "alternative": statistical_projection.alternative,
                "method_configuration": (
                    statistical_projection.state_method_configuration
                ),
                "outcome": statistical_projection.state_outcome,
                "source_artifact_hashes": statistical_sources,
            },
        )
    )
    ancestors = (
        method,
        implementation,
        hypothesis,
        dataset,
        *splits,
        *metrics,
        *baselines,
        experiment,
        run,
    )
    return {
        "ancestors": ancestors,
        "method": method,
        "implementation": implementation,
        "hypothesis": hypothesis,
        "dataset": dataset,
        "splits": tuple(splits),
        "metrics": tuple(metrics),
        "baselines": tuple(baselines),
        "experiment": experiment,
        "run": run,
        "result": result,
        "statistical_test": statistical_test,
    }


def _scientific_v2_completion_identity(
    source: dict[str, object],
    graph: dict[str, object],
    *,
    include_statistical_test: bool = False,
) -> tuple[str, str, dict[str, object]]:
    """Derive the deterministic completion identity without writing state."""

    repository = source["repository"]
    result = graph["result"]
    statistical_test = (
        graph["statistical_test"] if include_statistical_test else None
    )
    incoming = (*graph["ancestors"], result)
    if statistical_test is not None:
        incoming = (*incoming, statistical_test)
    ordered = tuple(
        sorted(
            incoming,
            key=lambda record: datetime.fromisoformat(
                record.created_at.replace("Z", "+00:00")
            ),
        )
    )
    prospective = repository._prospective_scientific_bundle_artifacts(ordered)
    payload = {
        "schema_version": "scientific-result-state-bundle-completion/v1",
        "ledger_run_id": "global-run-1",
        "execution_run_id": result.run_ids[0],
        "canonical_state_code_version": SCIENTIFIC_V2_STATE_CODE_VERSION,
        "result_id": result.object_id,
        "statistical_test_id": (
            statistical_test.object_id
            if statistical_test is not None
            else None
        ),
        "promotion_receipt_artifact_sha256": (
            source["candidate"]["receipt_record"].sha256
        ),
        "objects": [
            {
                "object_type": record.object_type,
                "object_id": record.object_id,
                "content_hash": record.content_hash,
                "artifact_sha256": prospective[record.content_hash].sha256,
                "artifact_record_hash": str(
                    prospective[record.content_hash].record_hash
                ),
                "created_at": record.created_at,
            }
            for record in ordered
        ],
        # This fixture intentionally has non-authoritative Dataset/Split
        # projections, so it cannot become scientific evidence eligible.
        "scientific_evidence_eligible": False,
    }
    digest = hashlib.sha256(canonical_json_bytes(payload) + b"\n").hexdigest()
    completion_time = ordered[-1].created_at
    metadata = {
        "research_state_operation": "BUNDLE_COMPLETE",
        "result_id": result.object_id,
        "statistical_test_id": (
            statistical_test.object_id
            if statistical_test is not None
            else None
        ),
        "bundle_receipt_artifact_sha256": digest,
        "object_artifact_hashes": [
            prospective[record.content_hash].sha256 for record in ordered
        ],
    }
    return digest, completion_time, metadata


class CanonicalObjectTests(unittest.TestCase):
    def common(self, object_id: str, producer: Role) -> dict[str, object]:
        return {
            "object_id": object_id,
            "producer": producer,
            "created_at": STAMP,
            "status": RecordStatus.ACTIVE,
        }

    def objects(self) -> tuple[CanonicalResearchObject, ...]:
        return (
            ResearchQuestion(
                **self.common("rq-1", Role.PROBLEM_INVESTIGATOR),
                research_goal="Determine whether the bounded intervention helps.",
                question="Does the intervention improve the declared endpoint?",
                falsification_condition="The confirmatory interval includes the null margin.",
                gate_outcome=ResearchQuestionOutcome.PROCEED,
            ),
            PriorWork(
                **self.common("prior-1", Role.EVIDENCE_CURATOR),
                title="A verified prior work",
                source_identifier="doi:10.0000/example",
                evidence_ids=("evidence-1",),
                verification_depth=ReferenceVerificationDepth.LEVEL_3,
                comparison_dimensions={"mechanism": "different"},
            ),
            Dataset(
                **self.common("dataset-1", Role.EVIDENCE_CURATOR),
                name="bounded fixture",
                version="v1",
                artifact_hashes=("a" * 64,),
                access_status="AVAILABLE",
                license="fixture-only",
            ),
            Split(
                **self.common("split-1", Role.PROTOCOL_DESIGNER),
                dataset_id="dataset-1",
                split_role=SplitRole.CONFIRMATORY,
                unit_type="subject",
                definition_artifact_hashes=("b" * 64,),
            ),
            Metric(
                **self.common("metric-1", Role.PROTOCOL_DESIGNER),
                name="accuracy",
                direction=MetricDirection.HIGHER_IS_BETTER,
                unit="fraction",
                evidence_level=MetricLevel.END_TO_END,
            ),
            Baseline(
                **self.common("baseline-1", Role.PROTOCOL_DESIGNER),
                name="strong baseline",
                method_id="method-1",
                implementation_id="implementation-1",
                paper_id="prior-1",
                metric_ids=("metric-1",),
                baseline_status=BaselineStatus.MUST_RUN,
                implementation_confidence=0.9,
                fairness_assessment="Equivalent data and compute.",
            ),
            Hypothesis(
                **self.common("hypothesis-1", Role.HYPOTHESIS_DESIGNER),
                statement="The intervention improves accuracy.",
                motivation="Prior evidence exposes a specific weakness.",
                prior_evidence_ids=("evidence-1",),
                prediction="Mean accuracy increases.",
                falsification_condition="The effect is non-positive.",
                planned_experiment_ids=("experiment-1",),
                hypothesis_status=HypothesisStatus.UNTESTED,
            ),
            Method(
                **self.common("method-1", Role.HYPOTHESIS_DESIGNER),
                name="bounded method",
                description="A deterministic fixture method.",
                assumptions=("Independent analysis units",),
                component_ids=("component-1",),
            ),
            Implementation(
                **self.common("implementation-1", Role.IMPLEMENTER),
                method_id="method-1",
                code_artifact_hashes=("d" * 64,),
                code_revision="code-v1",
            ),
            Experiment(
                **self.common("experiment-1", Role.PROTOCOL_DESIGNER),
                hypothesis_ids=("hypothesis-1",),
                scientific_purpose="Test the frozen prediction.",
                implementation_id="implementation-1",
                dataset_ids=("dataset-1",),
                split_ids=("split-1",),
                metric_ids=("metric-1",),
                baseline_ids=("baseline-1",),
                compute_profile=ComputeProfile.LOCAL_MAC,
                seed_policy={"seeds": [1, 2]},
                expected_output_types=("result",),
                evaluator="accuracy-v1",
                budget={"runs": 2},
                termination_conditions={"max_failures": 1},
            ),
            Run(
                **self.common("run-1", Role.EXPERIMENT_RUNNER),
                experiment_id="experiment-1",
                code_revision="code-v1",
                dataset_ids=("dataset-1",),
                configuration_artifact_hash="e" * 64,
                compute_profile=ComputeProfile.LOCAL_MAC,
                random_seeds=(1, 2),
                output_artifact_hashes=("f" * 64,),
                evaluator_version="accuracy-v1",
                started_at=STAMP,
                completed_at=STAMP_2,
            ),
            Result(
                **self.common("result-1", Role.EXPERIMENT_RUNNER),
                run_ids=("run-1",),
                metric_id="metric-1",
                value=0.75,
                unit="fraction",
                direction=MetricDirection.HIGHER_IS_BETTER,
                uncertainty={"lower": 0.7, "upper": 0.8},
                source_artifact_hashes=("f" * 64,),
                code_revision="code-v1",
                observed_at=STAMP_2,
            ),
            StatisticalTest(
                **self.common("stat-test-1", Role.STATISTICIAN),
                result_ids=("result-1",),
                test_name="paired permutation",
                null_hypothesis="The paired difference is zero.",
                alternative="The paired difference is positive.",
                method_configuration={"permutations": 1000},
                outcome={"p_value": 0.02},
                source_artifact_hashes=("f" * 64,),
            ),
            Ablation(
                **self.common("ablation-1", Role.EXPERIMENT_RUNNER),
                hypothesis_id="hypothesis-1",
                experiment_ids=("experiment-1",),
                removed_component_ids=("component-1",),
                result_ids=("result-1",),
            ),
            Claim(
                **self.common("claim-1", Role.EXPERIMENT_RUNNER),
                claim_type=ClaimType.NUMERICAL,
                claim_text="Accuracy was 0.75 in the declared fixture.",
                scope="Declared fixture and metric only.",
                evidence_ids=("evidence-1",),
                source_artifact_ids=("f" * 64,),
                verification_method="Exact result-artifact comparison.",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
                expressed_strength=ClaimStrength.SUPPORTED,
                permitted_strength=ClaimStrength.SUPPORTED,
                review_history=(
                    ClaimReview(
                        reviewer=Role.CLAIM_VERIFIER,
                        timestamp=STAMP_2,
                        verification_status=VerificationStatus.VERIFIED,
                        reason="The exact source value and scope match.",
                        evidence_ids=("evidence-1",),
                        source_artifact_ids=("f" * 64,),
                    ),
                ),
            ),
            Evidence(
                **self.common("evidence-1", Role.CLAIM_VERIFIER),
                evidence_kind="RESULT_ARTIFACT",
                source_artifact_hashes=("f" * 64,),
                supports_claim_ids=("claim-1",),
                verification_depth=ReferenceVerificationDepth.LEVEL_5,
                locator="result.value",
                verification_status=VerificationStatus.VERIFIED,
                verified_at=STAMP_2,
            ),
            Critique(
                **self.common("critique-1", Role.SCIENTIFIC_REVIEWER),
                target_ids=("claim-1",),
                findings=({"severity": "MINOR", "text": "Scope must remain narrow."},),
                verdict="CONDITIONAL_PASS",
                reviewer_input_hashes=("f" * 64,),
            ),
            Decision(
                **self.common("decision-1", Role.ORCHESTRATOR),
                decision_type="PROMOTION",
                outcome="CONTINUE",
                alternatives=("STOP",),
                evidence_ids=("evidence-1",),
                governing_rule="Only verified scoped claims may progress.",
                uncertainty=0.2,
                reason="The declared evidence is sufficient for the fixture.",
                consequences=("Run the next bounded check.",),
            ),
            Challenge(
                **self.common("challenge-1", Role.ADVERSARIAL_REVIEWER),
                target_claim_ids=("claim-1",),
                severity=ChallengeSeverity.MAJOR,
                finding="The result may depend on one split.",
                resolution_status=ChallengeResolution.UNRESOLVED,
                evidence_ids=("evidence-1",),
            ),
            VenueAssessment(
                **self.common("venue-1", Role.SCIENTIFIC_REVIEWER),
                venue="fixture workshop",
                profile="ML_WORKSHOP",
                classification=VenueFit.NOT_READY,
                evidence_ids=("evidence-1",),
                blockers=("No real external validation.",),
                assessed_at=STAMP_2,
            ),
            ReproducibilityPackage(
                **self.common("repro-1", Role.REPRODUCTION_VERIFIER),
                run_ids=("run-1",),
                manifest_artifact_hashes=("1" * 64,),
                environment_artifact_hashes=("2" * 64,),
                source_revision="code-v1",
                evaluator_version="accuracy-v1",
                reproduction_status=ReproductionStatus.PASS,
                reproduced_at=STAMP_2,
            ),
        )

    def test_all_required_types_are_strict_immutable_and_round_trip(self) -> None:
        expected = {
            "ResearchQuestion", "PriorWork", "Dataset", "Split", "Metric",
            "Baseline", "Hypothesis", "Method", "Implementation", "Experiment",
            "Run", "Result", "StatisticalTest", "Ablation", "Claim", "Evidence",
            "Critique", "Decision", "Challenge", "VenueAssessment",
            "ReproducibilityPackage",
        }
        records = self.objects()
        self.assertEqual(set(RESEARCH_OBJECT_TYPES), expected)
        self.assertEqual({item.object_type for item in records}, expected)
        self.assertEqual(len({item.content_hash for item in records}), len(records))
        for item in records:
            self.assertEqual(CanonicalResearchObject.from_dict(item.to_dict()), item)
            self.assertEqual(item.content_hash, CanonicalResearchObject.from_dict(item.to_dict()).content_hash)
            self.assertIn("Derived view only", render_markdown(item))
            with self.assertRaises(FrozenInstanceError):
                item.object_id = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            records[0].metadata["changed"] = True  # type: ignore[index]

        unknown = records[0].to_dict()
        unknown["unknown"] = True
        with self.assertRaises(ValidationError):
            CanonicalResearchObject.from_dict(unknown)
        tampered = records[0].to_dict()
        tampered["question"] = "A different question"
        with self.assertRaises(ValidationError):
            CanonicalResearchObject.from_dict(tampered)
        with self.assertRaises(ValidationError):
            ResearchQuestion(
                **self.common("rq-large", Role.PROBLEM_INVESTIGATOR),
                research_goal="g",
                question="x" * (32 * 1024 + 1),
                falsification_condition="f",
            )

    def test_claim_taxonomy_and_evidence_bounded_strength(self) -> None:
        self.assertEqual(
            {item.value for item in ClaimType},
            {
                "NUMERICAL", "CITATION", "METHODOLOGICAL", "COMPARATIVE",
                "QUALITATIVE", "NOVELTY", "ROBUSTNESS", "GENERALIZATION",
                "EFFICIENCY", "THEORETICAL", "CAUSAL", "CONCLUSION",
                "LIMITATION",
            },
        )
        with self.assertRaises(ValidationError):
            Claim(
                **self.common("claim-overstated", Role.EXPERIMENT_RUNNER),
                claim_type=ClaimType.COMPARATIVE,
                claim_text="An overstated claim.",
                scope="fixture",
                verification_method="deterministic check",
                expressed_strength=ClaimStrength.STRONG,
                permitted_strength=ClaimStrength.QUALIFIED,
            )
        with self.assertRaises(ValidationError):
            Claim(
                **self.common("claim-unverified", Role.EXPERIMENT_RUNNER),
                claim_type=ClaimType.QUALITATIVE,
                claim_text="An unverified claim.",
                scope="fixture",
                verification_method="pending",
                permitted_strength=ClaimStrength.LIMITED,
            )
        claim = next(item for item in self.objects() if isinstance(item, Claim))
        self.assertTrue(claim.allows(ClaimStrength.QUALIFIED))
        self.assertFalse(claim.allows(ClaimStrength.STRONG))
        with self.assertRaises(ValidationError):
            claim.require_allowed(ClaimStrength.STRONG)

        with self.assertRaises(ValidationError):
            Claim(
                **self.common("claim-verifier-produced", Role.CLAIM_VERIFIER),
                claim_type=ClaimType.QUALITATIVE,
                claim_text="A verifier-produced claim.",
                scope="fixture",
                verification_method="forbidden self-verification path",
            )
        with self.assertRaises(ValidationError):
            Claim(
                **self.common("claim-wrong-reviewer", Role.EXPERIMENT_RUNNER),
                claim_type=ClaimType.QUALITATIVE,
                claim_text="A claim without authoritative final verification.",
                scope="fixture",
                evidence_ids=("evidence-1",),
                source_artifact_ids=("a" * 64,),
                verification_method="invalid reviewer",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.5,
                expressed_strength=ClaimStrength.QUALIFIED,
                permitted_strength=ClaimStrength.QUALIFIED,
                review_history=(
                    ClaimReview(
                        reviewer=Role.SCIENTIFIC_REVIEWER,
                        timestamp=STAMP_2,
                        verification_status=VerificationStatus.VERIFIED,
                        reason="Scientific review is not claim-verifier authority.",
                        evidence_ids=("evidence-1",),
                        source_artifact_ids=("a" * 64,),
                    ),
                ),
            )


class ResearchStateRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.registry = ArtifactRegistry(self.root, "runs/run-1/registry")
        self.ledger = EventLedger(self.root, "runs/run-1/events.jsonl")
        self.repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="run-1",
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            state=MacroState.GROUND,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def question(self, object_id: str = "rq-1") -> ResearchQuestion:
        return ResearchQuestion(
            object_id=object_id,
            producer=Role.PROBLEM_INVESTIGATOR,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            research_goal="Test a bounded fixture.",
            question="Does the declared intervention improve the endpoint?",
            falsification_condition="The declared effect is non-positive.",
            # A descriptive ACTIVE question is intentionally not a promoted
            # research-gate result; promoted questions require typed brief
            # and investigation authorities in focused tests below.
            gate_outcome=None,
        )

    def test_positive_research_question_requires_typed_gate_receipt(self) -> None:
        promoted = replace(
            self.question("rq-positive-without-receipt"),
            status=RecordStatus.FROZEN,
            gate_outcome=ResearchQuestionOutcome.PROCEED,
            content_hash=None,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "requires explicit authority artifacts",
        ):
            self.repository.materialize(promoted)

    def test_positive_research_question_rejects_receipt_without_judgment(self) -> None:
        authority = self.registry.put_json(
            {"diagnostic": "proposal replay without semantic judgment"},
            logical_type="research_question_gate_receipt",
            origin="focused missing-judgment authority boundary",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-missing-judgment"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        promoted = replace(
            self.question("rq-positive-without-judgment"),
            status=RecordStatus.FROZEN,
            gate_outcome=ResearchQuestionOutcome.PROCEED,
            authority_artifact_hashes=(authority.sha256,),
            content_hash=None,
        )
        stated = SimpleNamespace(semantic_judgment_artifact_sha256=None)
        with patch.object(
            scientific_design_module.ResearchQuestionGateReceipt,
            "from_dict",
            return_value=stated,
        ), self.assertRaisesRegex(
            ValidationError,
            "positive research-question gate authority is invalid",
        ):
            self.repository.materialize(promoted)

    def test_research_question_receipt_v3_uses_stable_registry_envelope(self) -> None:
        digest = "a" * 64
        receipt = scientific_design_module.ResearchQuestionGateReceipt(
            receipt_id="receipt-envelope-v3",
            run_id="run-1",
            ledger_path=self.ledger.relative_path.as_posix(),
            gate_event_id="event-envelope-v3",
            gate_event_hash=digest,
            gate_event_index=0,
            object_id="brief-envelope-v3",
            question_object_id="rq-envelope-v3",
            research_goal="Exercise the versioned payload envelope.",
            question="Does the versioned payload survive registry replay?",
            falsification_condition="The payload cannot be replayed.",
            proposal_artifact_sha256=digest,
            proposal_record_hash=digest,
            proposal_sha256=digest,
            outcome=scientific_design_module.ResearchGateOutcome.PROCEED,
            verification_status=(
                scientific_design_module.ScientificGateVerificationStatus.NON_EVIDENTIARY
            ),
            goal_artifact_sha256=digest,
            goal_record_hash=digest,
            goal_sha256=digest,
            investigation_state_artifact_sha256=digest,
            investigation_state_record_hash=digest,
            investigation_state_sha256=digest,
            research_brief_artifact_sha256=digest,
            research_brief_record_hash=digest,
            research_brief_sha256=digest,
            selected_direction_id="direction-envelope-v3",
            criteria_projection_sha256=digest,
            semantic_judgment_artifact_sha256=None,
            semantic_judgment_record_hash=None,
            semantic_judgment_structured_output_sha256=None,
            evidence_artifact_hashes=(digest,),
            evidence_record_hashes=(digest,),
        )
        with patch.object(
            scientific_design_module,
            "_derive_research_question_gate_receipt",
            return_value=(receipt, ()),
        ):
            record = scientific_design_module.register_research_question_gate_receipt(
                self.registry,
                self.ledger,
                receipt_id=receipt.receipt_id,
                run_id=receipt.run_id,
                proposal_artifact_sha256=receipt.proposal_artifact_sha256,
            )
            restored = scientific_design_module.require_research_question_gate_receipt(
                self.registry,
                self.ledger,
                receipt_artifact_sha256=record.sha256,
                expected_run_id=receipt.run_id,
                expected_object_id=receipt.object_id,
                expected_question_object_id=receipt.question_object_id,
            )
        self.assertEqual(restored, receipt)
        self.assertEqual(record.schema_version, "1.0")
        self.assertEqual(
            json.loads(self.registry.get_bytes(record.sha256))["schema_version"],
            "research-question-gate-receipt/v3",
        )

    def test_prior_work_rejects_non_evidentiary_and_unrelated_evidence(self) -> None:
        reference_a = self.registry.put_json(
            {"fixture": "reference-a"},
            logical_type="reference_verification",
            origin="focused prior-work reference A",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-prior-work-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        evidence = Evidence(
            object_id="evidence-prior-work-reference-a",
            producer=Role.CLAIM_VERIFIER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP,
            authority_artifact_hashes=(reference_a.sha256,),
            evidence_kind="standalone verified reference",
            source_artifact_hashes=(reference_a.sha256,),
            verification_depth=ReferenceVerificationDepth.LEVEL_5,
            locator=f"artifact:{reference_a.sha256}",
            verification_status=VerificationStatus.VERIFIED,
            verified_at=reference_a.created_at,
        )
        with patch.object(
            ResearchStateRepository,
            "_validate_verified_evidence_boundary",
            return_value=None,
        ):
            materialized_evidence = self.repository.materialize(evidence)

        investigation_source = self.registry.put_json(
            {"fixture": "investigation literature"},
            logical_type="investigation_literature_record",
            origin="focused non-evidentiary investigation source",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "test-prior-work-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        non_evidentiary = PriorWork(
            object_id="prior-work-investigation-with-evidence",
            producer=Role.EVIDENCE_CURATOR,
            status=RecordStatus.DRAFT,
            created_at=STAMP_2,
            authority_artifact_hashes=(investigation_source.sha256,),
            parents=(
                ObjectReference(
                    "Evidence",
                    evidence.object_id,
                    materialized_evidence.research_object.content_hash,
                    "verified_by",
                    True,
                ),
            ),
            title="Non-evidentiary investigation projection",
            source_identifier="fixture:investigation",
            evidence_ids=(evidence.object_id,),
            verification_depth=ReferenceVerificationDepth.LEVEL_3,
            comparison_dimensions={},
        )
        with self.assertRaisesRegex(
            ValidationError,
            "non-evidentiary investigation prior work cannot claim canonical Evidence",
        ):
            self.repository.materialize(non_evidentiary)

        scholarly_b = self.registry.put_json(
            {"fixture": "scholarly-record-b"},
            logical_type="normalized_scholarly_record",
            origin="focused prior-work scholarly source B",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "test-prior-work-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        reference_b = self.registry.put_json(
            {
                "scholarly_record_artifact_hash": scholarly_b.sha256,
                "ranking_target_sha256": "b" * 64,
                "citation_id": "reference-b",
                "claim_text": "Reference B supports only its own projection.",
                "claim_target_sha256": "c" * 64,
            },
            logical_type="reference_verification",
            origin="focused prior-work reference B",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-prior-work-authority"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        identifier = SimpleNamespace(
            kind=SimpleNamespace(value="doi"),
            value="10.0000/reference-b",
        )
        resolved_reference = SimpleNamespace(
            reference=SimpleNamespace(
                identifier=identifier,
                title="Verified reference B",
                reference_text="Verified reference B",
            ),
            verification=SimpleNamespace(level=5),
        )
        unrelated = PriorWork(
            object_id="prior-work-reference-b-with-evidence-a",
            producer=Role.EVIDENCE_CURATOR,
            status=RecordStatus.VERIFIED,
            created_at="2026-08-29T12:00:02Z",
            authority_artifact_hashes=(reference_b.sha256,),
            parents=(
                ObjectReference(
                    "Evidence",
                    evidence.object_id,
                    materialized_evidence.research_object.content_hash,
                    "verified_by",
                    True,
                ),
            ),
            title="Verified reference B",
            source_identifier="doi:10.0000/reference-b",
            evidence_ids=(evidence.object_id,),
            verification_depth=ReferenceVerificationDepth.LEVEL_5,
            comparison_dimensions={},
        )
        with patch.object(
            ResearchStateRepository,
            "_validate_verified_evidence_boundary",
            return_value=None,
        ), patch.object(
            scientific_design_module,
            "_resolve_registry_scholarly_record",
            return_value=SimpleNamespace(scholarly_record=object()),
        ), patch.object(
            scientific_design_module,
            "_resolve_registry_reference_verification",
            return_value=resolved_reference,
        ), patch(
            "scientist_one.literature.CitationGraphNode.from_record",
            return_value=object(),
        ), self.assertRaisesRegex(
            ValidationError,
            "exact reference authority",
        ):
            self.repository.materialize(unrelated)

    def test_materialization_rejects_over_depth_parent_graph_iteratively(self) -> None:
        materialized = self.repository.materialize(
            self.question("rq-depth-000")
        )
        for depth in range(1, research_state_module.MAX_CANONICAL_ANCESTRY_DEPTH + 1):
            timestamp = (
                datetime.fromisoformat(STAMP.replace("Z", "+00:00"))
                + timedelta(seconds=depth)
            ).isoformat().replace("+00:00", "Z")
            candidate = replace(
                self.question(f"rq-depth-{depth:03d}"),
                created_at=timestamp,
                parents=(
                    ObjectReference(
                        materialized.research_object.object_type,
                        materialized.research_object.object_id,
                        materialized.research_object.content_hash,
                        "derived_from",
                        True,
                    ),
                ),
                content_hash=None,
            )
            materialized = self.repository.materialize(candidate)

        rejected_depth = research_state_module.MAX_CANONICAL_ANCESTRY_DEPTH + 1
        rejected = replace(
            self.question(f"rq-depth-{rejected_depth:03d}"),
            created_at=(
                datetime.fromisoformat(STAMP.replace("Z", "+00:00"))
                + timedelta(seconds=rejected_depth)
            ).isoformat().replace("+00:00", "Z"),
            parents=(
                ObjectReference(
                    materialized.research_object.object_type,
                    materialized.research_object.object_id,
                    materialized.research_object.content_hash,
                    "derived_from",
                    True,
                ),
            ),
            content_hash=None,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exceeds the ancestry depth limit",
        ):
            self.repository.materialize(rejected)

    def raw_artifact(self, content: bytes, logical_type: str = "fixture.source") -> str:
        return self.registry.put_bytes(
            content,
            logical_type=logical_type,
            origin="test fixture",
            creator_role=Role.IMPLEMENTER,
            creation_command=("scientist-one", "test-fixture"),
            created_at=STAMP,
        ).sha256

    def unissued_snapshot(
        self,
        current_hashes: tuple[str, ...],
        *,
        snapshot_id: str,
        ledger_head_hash: str,
        ledger_event_count: int,
        created_at: str,
    ):
        records = tuple(
            self.registry.get_metadata(digest) for digest in current_hashes
        )
        return self.registry.put_json(
            {
                "canonical_object_count": len(current_hashes),
                "current_artifact_hashes": list(current_hashes),
                "current_artifact_record_hashes": [
                    str(record.record_hash) for record in records
                ],
                "issued_at": created_at,
                "ledger_event_count_before_snapshot": ledger_event_count,
                "ledger_head_hash_before_snapshot": ledger_head_hash,
                "materialization_creation_command": list(
                    self.repository.creation_command
                ),
                "object_types": sorted(
                    {
                        self.repository.load_artifact(digest).object_type
                        for digest in current_hashes
                    }
                ),
                "prior_snapshot_artifact_hash": None,
                "repository_code_version": self.repository.code_version,
                "repository_configuration_hash": (
                    self.repository.configuration_hash
                ),
                "repository_state": self.repository.state.value,
                "run_id": self.repository.run_id,
                "snapshot_id": snapshot_id,
                "snapshot_schema_version": (
                    research_state_module.RESEARCH_STATE_SNAPSHOT_PAYLOAD_SCHEMA
                ),
                "state_valid": True,
            },
            logical_type="canonical_research_state_snapshot",
            origin="issued canonical research-state snapshot",
            creator_role=Role.ORCHESTRATOR,
            creation_command=(
                research_state_module.RESEARCH_STATE_SNAPSHOT_CREATION_COMMAND
            ),
            parent_artifacts=current_hashes,
            schema_version=(
                research_state_module.RESEARCH_STATE_SNAPSHOT_ARTIFACT_SCHEMA_VERSION
            ),
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=created_at,
        )

    def claim_graph_bundle(
        self,
        *,
        claim_id: str = "claim-boundary",
        claim_text: str = "The bounded fixture result is larger than its baseline.",
        claim_producer: Role = Role.EXPERIMENT_RUNNER,
        graph_creator: Role = Role.CLAIM_VERIFIER,
        graph_validation: str = "PASS",
        graph_frozen: bool = True,
        variant: str = "valid",
        resolver_id: str = CLAIM_GRAPH_RESOLVER_ID,
        include_verification_receipt_parents: bool = True,
        confirmatory: bool = False,
        evidence_use: ClaimEvidenceUse = ClaimEvidenceUse.SCIENTIFIC,
        evidence_parent_overrides: dict[
            GraphEvidenceKind, tuple[str, ...]
        ] | None = None,
    ) -> tuple[object, tuple[object, ...]]:
        table = self.registry.put_bytes(
            (
                "method,score,variant\n"
                f"baseline,0.4,{variant}\n"
                f"candidate,0.6,{variant}\n"
            ).encode("utf-8"),
            logical_type="results_table",
            origin=f"claim boundary table {variant}",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "claim-boundary-fixture"),
            schema_version="1.0",
            mime_type="text/csv",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        provisional: list[GraphEvidenceNode] = []
        evidence_artifacts: list[object] = []
        parent_overrides = evidence_parent_overrides or {}
        for index, kind in enumerate(sorted(REQUIRED_EVIDENCE_KINDS, key=lambda item: item.value), 1):
            default_parents = (
                (table.sha256,)
                if kind is GraphEvidenceKind.FIGURE_OR_TABLE
                else ()
            )
            parents = parent_overrides.get(kind, default_parents)
            evidence_artifact = self.registry.put_json(
                {
                    "claim_id": claim_id,
                    "claim_text": claim_text,
                    "evidence_kind": kind.value,
                    "supports_claim": True,
                    "variant": variant,
                },
                logical_type=f"claim_evidence.{kind.value}",
                origin=f"claim boundary evidence {variant} {kind.value}",
                creator_role=Role.EXPERIMENT_RUNNER,
                creation_command=("scientist-one", "claim-boundary-fixture"),
                parent_artifacts=parents,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=STAMP,
            )
            evidence_artifacts.append(evidence_artifact)
            provisional.append(
                GraphEvidenceNode(
                    evidence_id=f"{claim_id}-evidence-{index:02d}",
                    kind=kind,
                    artifact_hash=evidence_artifact.sha256,
                    description=f"Bounded {kind.value} support.",
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                )
            )
        material_claim = MaterialClaim(
            claim_id=claim_id,
            text=claim_text,
            evidence_links=tuple(
                GraphEvidenceLink(item.evidence_id, item.kind) for item in provisional
            ),
            producer_role=claim_producer,
            confirmatory=confirmatory,
            evidence_use=evidence_use,
        )
        nodes: list[GraphEvidenceNode] = []
        receipt_artifacts: list[object] = []
        for node in provisional:
            receipt = EvidenceSupportReceipt.for_claim(
                material_claim,
                node,
                verifier_id="claim-boundary-verifier",
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale="Registry bytes and the narrow fixture scope match.",
            )
            receipt_artifact = self.registry.put_json(
                receipt.to_dict(),
                logical_type=f"claim_support_receipt.{node.kind.value}",
                origin=f"claim boundary receipt {variant} {node.kind.value}",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "claim-boundary-verify"),
                parent_artifacts=(node.artifact_hash,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=STAMP,
            )
            self.assertEqual(receipt_artifact.sha256, receipt.sha256)
            receipt_artifacts.append(receipt_artifact)
            nodes.append(replace(node, verification_receipt_hash=receipt_artifact.sha256))
        resolver = artifact_registry_resolver(
            self.registry,
            resolver_id=resolver_id,
        )
        graph = ClaimEvidenceGraph(evidence_resolver=resolver)
        for node in nodes:
            graph.add_evidence(node)
        graph.add_claim(material_claim)
        decision = graph.verify_claim(
            claim_id,
            verifier_id="claim-boundary-verifier",
            verifier_role=Role.CLAIM_VERIFIER,
            confirmatory_evidence_valid=True,
            raise_on_rejection=True,
        )
        self.assertIs(decision.decision, GraphClaimDecision.ELIGIBLE)
        verification_receipt_artifacts: list[object] = []
        for node in nodes:
            receipt = resolver(material_claim, node)
            receipt_artifact = self.registry.put_bytes(
                receipt.canonical_bytes,
                logical_type=(
                    "claim_evidence_verification_receipt."
                    f"{node.kind.value}"
                ),
                origin=f"claim boundary verification receipt {variant} {node.kind.value}",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "claim-boundary-resolve"),
                parent_artifacts=(
                    node.artifact_hash,
                    receipt.support_receipt_hash,
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=STAMP,
            )
            self.assertEqual(receipt_artifact.sha256, receipt.sha256)
            verification_receipt_artifacts.append(receipt_artifact)
        self.assertEqual(
            set(decision.evidence_receipt_hashes),
            {item.sha256 for item in verification_receipt_artifacts},
        )
        graph_value = graph.to_dict()
        graph_artifact = self.registry.put_json(
            {
                "decision": graph_value["decisions"][0],
                "graph": graph_value,
                "variant": variant,
            },
            logical_type="claim_evidence_graph",
            origin=f"claim boundary graph {variant}",
            creator_role=graph_creator,
            creation_command=("scientist-one", "claim-boundary-graph"),
            parent_artifacts=tuple(
                [item.sha256 for item in evidence_artifacts]
                + [item.sha256 for item in receipt_artifacts]
                + (
                    [item.sha256 for item in verification_receipt_artifacts]
                    if include_verification_receipt_parents
                    else []
                )
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result=graph_validation,
            frozen=graph_frozen,
            created_at=STAMP,
        )
        return graph_artifact, tuple(
            [*receipt_artifacts, *verification_receipt_artifacts]
        )

    def claim_semantics(
        self,
        graph_artifact_hash: str,
        *,
        claim_id: str = "claim-boundary",
        claim_type: ClaimType = ClaimType.COMPARATIVE,
        scope: str = "Bounded fixture only.",
        confidence: float = 0.9,
        expressed_strength: ClaimStrength = ClaimStrength.QUALIFIED,
        permitted_strength: ClaimStrength = ClaimStrength.QUALIFIED,
        verification_method: str = (
            "Fresh registry-resolved ClaimEvidenceGraph verification."
        ),
        dependency_claim_state_artifact_hashes: tuple[str, ...] = (),
    ) -> object:
        return register_claim_semantics_receipt(
            self.registry,
            self.ledger,
            receipt_id=f"semantics-{claim_id}",
            run_id="run-1",
            claim_graph_artifact_hash=graph_artifact_hash,
            claim_id=claim_id,
            claim_type=claim_type,
            scope=scope,
            confidence=confidence,
            expressed_strength=expressed_strength,
            permitted_strength=permitted_strength,
            verification_method=verification_method,
            dependency_claim_state_artifact_hashes=(
                dependency_claim_state_artifact_hashes
            ),
            evidence_scope=(
                ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE
            ),
        )

    def test_materialization_and_supersession_use_registry_and_ledger(self) -> None:
        first = self.repository.materialize(self.question())
        self.assertEqual(first.artifact.logical_type, "research_state.research_question")
        self.assertEqual(self.registry.get_bytes(first.artifact.sha256), first.research_object.canonical_bytes())
        self.assertEqual(first.event.event_type, "CHECKPOINT")
        self.assertEqual(first.event.metadata["research_state_operation"], "MATERIALIZED")
        self.assertEqual(self.repository.load_artifact(first.artifact.sha256), first.research_object)

        second_record = revise_research_object(
            first.research_object,
            created_at=STAMP_2,
            status=RecordStatus.ACTIVE,
            question="Does the frozen intervention improve the declared endpoint?",
        )
        second = self.repository.materialize(second_record)
        self.assertEqual(second.event.event_type, "CORRECTION")
        self.assertEqual(second.event.supersedes_event_id, first.event.event_id)
        self.assertEqual(second.event.metadata["research_state_operation"], "SUPERSEDED")
        self.assertIn(first.artifact.sha256, second.artifact.parent_artifacts)
        self.assertEqual(self.repository.latest("ResearchQuestion", "rq-1"), second_record)

        retry = self.repository.materialize(second_record)
        self.assertEqual(retry.artifact.sha256, second.artifact.sha256)
        self.assertEqual(retry.event.event_id, second.event.event_id)
        self.assertEqual(self.ledger.validate(raise_on_error=True).event_count, 2)
        report = self.repository.validate_state()
        self.assertTrue(report.valid, report.issues)
        self.assertIn(StateIssueCode.STALE_OBJECT, {item.code for item in report.issues})
        self.assertIn("Derived view only", second_record.to_markdown())

    def test_materialization_rejects_mixed_repository_identity_before_write(
        self,
    ) -> None:
        self.repository.materialize(self.question("rq-identity-anchor"))
        candidate = self.question("rq-identity-candidate")
        repositories = (
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.CLAIMS,
                creation_command=self.repository.creation_command,
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.GROUND,
                creation_command=("scientist-one", "wrong-state-writer"),
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="wrong-run",
                code_version="code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.GROUND,
                creation_command=self.repository.creation_command,
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="wrong-code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.GROUND,
                creation_command=self.repository.creation_command,
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="code-v1",
                configuration_hash="f" * 64,
                state=MacroState.GROUND,
                creation_command=self.repository.creation_command,
            ),
        )
        for repository in repositories:
            with self.subTest(repository=repository.creation_command):
                record_count = len(self.registry.list_records())
                event_count = self.ledger.assert_valid().event_count
                with self.assertRaises(ValidationError):
                    repository.materialize(candidate)
                self.assertEqual(len(self.registry.list_records()), record_count)
                self.assertEqual(
                    self.ledger.assert_valid().event_count,
                    event_count,
                )

    def test_first_materialization_rechecks_ledger_identity_before_write(
        self,
    ) -> None:
        self.ledger.record(
            run_id="run-1",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="operational-code-v1",
            configuration_hash=CONFIG_HASH,
            reason="initialize the empty canonical-state repository",
            event_id="canonical-state-empty-repository-initialized",
            timestamp=STAMP,
            event_type="CHECKPOINT",
            metadata={"test_fixture": "empty-canonical-state-repository"},
        )
        candidate = self.question("rq-first-identity-candidate")
        repositories = (
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="wrong-run",
                code_version="code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.GROUND,
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="code-v1",
                configuration_hash="f" * 64,
                state=MacroState.GROUND,
            ),
            ResearchStateRepository(
                self.registry,
                self.ledger,
                run_id="run-1",
                code_version="code-v1",
                configuration_hash=CONFIG_HASH,
                state=MacroState.CLAIMS,
            ),
        )
        for repository in repositories:
            with self.subTest(
                run_id=repository.run_id,
                configuration_hash=repository.configuration_hash,
                state=repository.state,
            ):
                record_count = len(self.registry.list_records())
                event_count = self.ledger.assert_valid().event_count
                with self.assertRaises(ValidationError):
                    repository.materialize(candidate)
                self.assertEqual(len(self.registry.list_records()), record_count)
                self.assertEqual(
                    self.ledger.assert_valid().event_count,
                    event_count,
                )
        materialized = self.repository.materialize(candidate)
        self.assertEqual(materialized.research_object, candidate)
        self.assertEqual(
            materialized.event.code_version,
            self.repository.code_version,
        )

    def test_materialize_rejects_invalid_reason_and_capacity_before_registry_write(
        self,
    ) -> None:
        candidate = self.question("rq-preflight-event-validation")
        for invalid_reason in ("", "   ", "x" * 8193, 7):
            with self.subTest(invalid_reason=repr(invalid_reason)):
                registry_count = len(self.registry.list_records())
                event_count = self.ledger.assert_valid().event_count
                with self.assertRaises(ValidationError):
                    self.repository.materialize(
                        candidate,
                        reason=invalid_reason,  # type: ignore[arg-type]
                    )
                self.assertEqual(
                    len(self.registry.list_records()),
                    registry_count,
                )
                self.assertEqual(
                    self.ledger.assert_valid().event_count,
                    event_count,
                )

        ledger_result = self.ledger.assert_valid()
        registry_count = len(self.registry.list_records())
        original_limit = research_state_module.MAX_LEDGER_BYTES
        research_state_module.MAX_LEDGER_BYTES = (
            ledger_result.valid_prefix_bytes + 1
        )
        try:
            with self.assertRaisesRegex(
                ValidationError,
                "ledger byte capacity",
            ):
                self.repository.materialize(candidate)
        finally:
            research_state_module.MAX_LEDGER_BYTES = original_limit
        self.assertEqual(len(self.registry.list_records()), registry_count)
        self.assertEqual(
            self.ledger.assert_valid().event_count,
            ledger_result.event_count,
        )

    def test_exact_orphan_artifact_retry_remains_resumable(self) -> None:
        candidate = self.question("rq-orphan-retry")
        with patch.object(
            self.ledger,
            "_append_locked",
            side_effect=RuntimeError("simulated interruption after artifact write"),
        ), self.assertRaisesRegex(RuntimeError, "simulated interruption"):
            self.repository.materialize(candidate)

        state_records = tuple(
            item
            for item in self.registry.list_records()
            if item.logical_type == candidate.logical_type
        )
        self.assertEqual(len(state_records), 1)
        self.assertEqual(self.ledger.assert_valid().event_count, 0)

        child = Method(
            object_id="method-orphan-consumer",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at=STAMP_2,
            status=RecordStatus.ACTIVE,
            name="orphan consumer",
            description="Must not become visible before its evaluated parent.",
            parents=(
                ObjectReference(
                    "ResearchQuestion",
                    candidate.object_id,
                    candidate.content_hash,
                    "evaluated_input",
                    True,
                ),
            ),
        )
        registry_count = len(self.registry.list_records())
        with self.assertRaisesRegex(ValidationError, "inert"):
            self.repository.materialize(child)
        self.assertEqual(len(self.registry.list_records()), registry_count)
        self.assertEqual(self.ledger.assert_valid().event_count, 0)

        resumed = self.repository.materialize(candidate)
        self.assertEqual(resumed.artifact, state_records[0])
        self.assertEqual(self.ledger.assert_valid().event_count, 1)
        materialized_child = self.repository.materialize(child)
        events = self.ledger.assert_valid().events
        self.assertLess(
            events.index(resumed.event),
            events.index(materialized_child.event),
        )
        self.assertTrue(self.repository.validate_state().valid)

    def test_concurrent_materializers_cannot_mix_repository_identity(self) -> None:
        self.ledger.record(
            run_id="run-1",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            reason="bootstrap concurrent materialization fixture",
            event_id="concurrent-materialization-bootstrap",
            timestamp="2026-08-29T11:59:59Z",
            event_type="CHECKPOINT",
            metadata={"test_fixture": "concurrent-materialization"},
        )
        writer_a = self.repository
        writer_b = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="run-1",
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            state=MacroState.GROUND,
            creation_command=("scientist-one", "writer-b"),
        )
        candidate_a = self.question("rq-concurrent-a")
        candidate_b = self.question("rq-concurrent-b")
        original_put = self.registry._put_bytes_locked
        writer_a_inside_commit = threading.Event()
        release_writer_a = threading.Event()
        successes: list[tuple[ResearchStateRepository, object]] = []
        failures: list[Exception] = []

        def hold_writer_a(guard, data, **kwargs):
            if data == candidate_a.canonical_bytes():
                writer_a_inside_commit.set()
                if not release_writer_a.wait(timeout=5):
                    raise RuntimeError("writer A commit was not released")
            return original_put(guard, data, **kwargs)

        def materialize(
            repository: ResearchStateRepository,
            candidate: ResearchQuestion,
        ) -> None:
            try:
                successes.append((repository, repository.materialize(candidate)))
            except Exception as exc:  # captured for deterministic thread join
                failures.append(exc)

        with patch.object(
            self.registry,
            "_put_bytes_locked",
            side_effect=hold_writer_a,
        ):
            writer_a_thread = threading.Thread(
                target=materialize,
                args=(writer_a, candidate_a),
            )
            writer_b_thread = threading.Thread(
                target=materialize,
                args=(writer_b, candidate_b),
            )
            writer_a_thread.start()
            self.assertTrue(writer_a_inside_commit.wait(timeout=5))
            writer_b_thread.start()
            time.sleep(0.05)
            self.assertTrue(writer_b_thread.is_alive())
            release_writer_a.set()
            for thread in (writer_a_thread, writer_b_thread):
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())

        self.assertEqual(len(successes), 1, failures)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ValidationError)
        self.assertEqual(
            len(
                tuple(
                    item
                    for item in self.registry.list_records()
                    if item.logical_type.startswith("research_state.")
                )
            ),
            1,
        )
        self.assertEqual(self.ledger.assert_valid().event_count, 2)
        self.assertIs(successes[0][0], writer_a)
        self.assertTrue(writer_a.validate_state().valid)

    def test_verified_claim_is_a_distinct_producer_view_of_checked_registry_graph(self) -> None:
        claim_text = "The bounded fixture result is larger than its baseline."
        graph, receipts = self.claim_graph_bundle(
            claim_text=claim_text,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
        )
        semantics = self.claim_semantics(graph.sha256)
        evidence = Evidence(
            object_id="evidence-claim-boundary",
            producer=Role.CLAIM_VERIFIER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP,
            evidence_kind="registry-resolved claim graph",
            source_artifact_hashes=(graph.sha256, *tuple(item.sha256 for item in receipts)),
            supports_claim_ids=("claim-boundary",),
            verification_depth=ReferenceVerificationDepth.LEVEL_5,
            locator=f"claim-graph:{graph.sha256}",
            verification_status=VerificationStatus.VERIFIED,
            verified_at=STAMP,
            authority_artifact_hashes=(
                graph.sha256,
                *tuple(item.sha256 for item in receipts),
            ),
        )
        materialized_evidence = self.repository.materialize(evidence)
        claim = Claim(
            object_id="claim-boundary",
            producer=Role.EXPERIMENT_RUNNER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP_2,
            parents=(
                ObjectReference(
                    "Evidence",
                    evidence.object_id,
                    evidence.content_hash,
                    "verified_by",
                    True,
                ),
            ),
            claim_type=ClaimType.COMPARATIVE,
            claim_text=claim_text,
            scope="Bounded fixture only.",
            evidence_ids=(evidence.object_id,),
            source_artifact_ids=(graph.sha256, semantics.sha256),
            verification_method="Fresh registry-resolved ClaimEvidenceGraph verification.",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.9,
            expressed_strength=ClaimStrength.QUALIFIED,
            permitted_strength=ClaimStrength.QUALIFIED,
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP_2,
                    verification_status=VerificationStatus.VERIFIED,
                    reason="Every graph source and receipt resolved from the registry.",
                    evidence_ids=(evidence.object_id,),
                    source_artifact_ids=(
                        graph.sha256,
                        *tuple(item.sha256 for item in receipts),
                        semantics.sha256,
                    ),
                ),
            ),
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            authority_artifact_hashes=(
                graph.sha256,
                *tuple(item.sha256 for item in receipts),
                semantics.sha256,
            ),
        )
        semantic_splices = {
            "qualitative relabel": replace(
                claim,
                claim_type=ClaimType.QUALITATIVE,
                content_hash=None,
            ),
            "scope splice": replace(
                claim,
                scope="An unbounded population that was never attested.",
                content_hash=None,
            ),
            "strength promotion": replace(
                claim,
                expressed_strength=ClaimStrength.STRONG,
                permitted_strength=ClaimStrength.STRONG,
                content_hash=None,
            ),
            "dependency splice": replace(
                claim,
                dependency_claim_ids=("claim-from-another-record",),
                content_hash=None,
            ),
        }
        for label, splice in semantic_splices.items():
            with self.subTest(label=label), self.assertRaises(ValidationError):
                self.repository.materialize(splice)
        unused_receipt = self.registry.put_json(
            {"unused": True},
            logical_type=(
                f"claim_support_receipt.{GraphEvidenceKind.RESULT.value}"
            ),
            origin="unrelated allowlisted receipt",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "state-authority-test"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_2,
        )
        extra_authority = replace(
            claim,
            review_history=(
                replace(
                    claim.review_history[-1],
                    source_artifact_ids=(
                        *claim.review_history[-1].source_artifact_ids,
                        unused_receipt.sha256,
                    ),
                ),
            ),
            authority_artifact_hashes=(
                *claim.authority_artifact_hashes,
                unused_receipt.sha256,
            ),
            content_hash=None,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "authority differs from its exact graph",
        ):
            self.repository.materialize(extra_authority)
        materialized_claim = self.repository.materialize(claim)
        self.assertIn(materialized_evidence.artifact.sha256, materialized_claim.artifact.parent_artifacts)
        self.assertIn(graph.sha256, materialized_claim.artifact.parent_artifacts)
        self.assertIs(materialized_claim.event.actor_role, Role.EXPERIMENT_RUNNER)
        self.assertTrue(self.repository.validate_state().valid)

    def test_claim_and_evidence_materialization_rejects_hash_and_authority_bypass(self) -> None:
        claim_text = "The bounded fixture result is larger than its baseline."
        graph, receipts = self.claim_graph_bundle(claim_text=claim_text)
        evidence = Evidence(
            object_id="evidence-claim-boundary",
            producer=Role.CLAIM_VERIFIER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP,
            evidence_kind="registry-resolved claim graph",
            source_artifact_hashes=(graph.sha256, *tuple(item.sha256 for item in receipts)),
            supports_claim_ids=("claim-boundary",),
            verification_depth=ReferenceVerificationDepth.LEVEL_5,
            locator=f"claim-graph:{graph.sha256}",
            verification_status=VerificationStatus.VERIFIED,
            verified_at=STAMP,
            authority_artifact_hashes=(
                graph.sha256,
                *tuple(item.sha256 for item in receipts),
            ),
        )
        self.repository.materialize(evidence)
        arbitrary = self.raw_artifact(b'{"looks_like":"evidence"}\n', "fixture.arbitrary")
        bypass = Claim(
            object_id="claim-boundary",
            producer=Role.EXPERIMENT_RUNNER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP_2,
            parents=(
                ObjectReference(
                    "Evidence",
                    evidence.object_id,
                    evidence.content_hash,
                    "verified_by",
                    True,
                ),
            ),
            claim_type=ClaimType.COMPARATIVE,
            claim_text=claim_text,
            scope="Bounded fixture only.",
            evidence_ids=(evidence.object_id,),
            source_artifact_ids=(arbitrary,),
            verification_method="A SHA-shaped string is not verification.",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.9,
            expressed_strength=ClaimStrength.QUALIFIED,
            permitted_strength=ClaimStrength.QUALIFIED,
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP_2,
                    verification_status=VerificationStatus.VERIFIED,
                    reason="Invalid arbitrary source.",
                    evidence_ids=(evidence.object_id,),
                    source_artifact_ids=(arbitrary,),
                ),
            ),
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(bypass)

        missing_parent = replace(
            bypass,
            source_artifact_ids=(graph.sha256,),
            parents=(),
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP_2,
                    verification_status=VerificationStatus.VERIFIED,
                    reason="Graph resolves but canonical Evidence is not bound.",
                    evidence_ids=(evidence.object_id,),
                    source_artifact_ids=(graph.sha256,),
                ),
            ),
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(missing_parent)

        wrong_creator_graph, wrong_receipts = self.claim_graph_bundle(
            graph_creator=Role.EXPERIMENT_RUNNER,
            variant="wrong-creator",
        )
        wrong_creator_evidence = replace(
            evidence,
            object_id="evidence-wrong-creator",
            source_artifact_hashes=(
                wrong_creator_graph.sha256,
                *tuple(item.sha256 for item in wrong_receipts),
            ),
            locator=f"claim-graph:{wrong_creator_graph.sha256}",
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(wrong_creator_evidence)

        missing_receipt_graph, missing_receipts = self.claim_graph_bundle(
            variant="missing-verification-receipt-parent",
            include_verification_receipt_parents=False,
        )
        missing_receipt_evidence = replace(
            evidence,
            object_id="evidence-missing-verification-receipt-parent",
            source_artifact_hashes=(
                missing_receipt_graph.sha256,
                *tuple(item.sha256 for item in missing_receipts),
            ),
            locator=f"claim-graph:{missing_receipt_graph.sha256}",
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(missing_receipt_evidence)

        unstable_graph, unstable_receipts = self.claim_graph_bundle(
            variant="unstable-resolver",
            resolver_id="unstable-claim-resolver",
        )
        unstable_evidence = replace(
            evidence,
            object_id="evidence-unstable-resolver",
            source_artifact_hashes=(
                unstable_graph.sha256,
                *tuple(item.sha256 for item in unstable_receipts),
            ),
            locator=f"claim-graph:{unstable_graph.sha256}",
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(unstable_evidence)

        with self.assertRaises(ValidationError):
            Evidence(
                object_id="evidence-self-certified",
                producer=Role.EXPERIMENT_RUNNER,
                status=RecordStatus.VERIFIED,
                created_at=STAMP,
                evidence_kind="self-certified evidence",
                source_artifact_hashes=(graph.sha256,),
                supports_claim_ids=("claim-boundary",),
                verification_depth=ReferenceVerificationDepth.LEVEL_5,
                locator=f"claim-graph:{graph.sha256}",
                verification_status=VerificationStatus.VERIFIED,
                verified_at=STAMP,
            )

    def test_validation_detects_changed_inputs_wrong_code_and_missing_relationships(self) -> None:
        parent_v1 = self.repository.materialize(self.question("rq-parent"))
        evaluated_child = Method(
            object_id="method-evaluated",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            name="evaluated child",
            description="Depends on an evaluated parent revision.",
            parents=(
                ObjectReference(
                    "ResearchQuestion",
                    "rq-parent",
                    parent_v1.research_object.content_hash,
                    "evaluated_input",
                    True,
                ),
            ),
        )
        derived_child = Method(
            object_id="method-derived",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            name="derived child",
            description="Depends on a current parent revision.",
            parents=(
                ObjectReference(
                    "ResearchQuestion",
                    "rq-parent",
                    parent_v1.research_object.content_hash,
                    "derived_from",
                    False,
                ),
            ),
        )
        self.repository.materialize(evaluated_child)
        self.repository.materialize(derived_child)
        missing_link = Decision(
            object_id="decision-missing-link",
            producer=Role.SCIENTIFIC_REVIEWER,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            decision_type="TEST",
            outcome="WAIT",
            governing_rule="Required relationships must resolve.",
            uncertainty=1.0,
            reason="Exercise the deterministic validator.",
            relationships=(ObjectLink("Evidence", "missing-evidence", "governed_by", True),),
        )
        self.repository.materialize(missing_link)

        code_hash = self.raw_artifact(b"print('fixture')\n", "experiment_code")
        implementation = Implementation(
            object_id="implementation-1",
            producer=Role.IMPLEMENTER,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            method_id="method-derived",
            code_artifact_hashes=(code_hash,),
            code_revision="code-v1",
            authority_artifact_hashes=(code_hash,),
        )
        self.repository.materialize(implementation)
        parent_v2 = revise_research_object(
            parent_v1.research_object,
            created_at=STAMP_2,
            question="Does the revised intervention improve the endpoint?",
        )
        self.repository.materialize(parent_v2)

        repository_at_new_code = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id="run-1",
            code_version="code-v2",
            configuration_hash=CONFIG_HASH,
            state=MacroState.GROUND,
        )
        report = repository_at_new_code.validate_state()
        self.assertFalse(report.valid)
        codes = {item.code for item in report.issues}
        self.assertIn(StateIssueCode.CHANGED_AFTER_EVALUATION, codes)
        self.assertIn(StateIssueCode.OUTDATED_DERIVED_ARTIFACT, codes)
        self.assertIn(StateIssueCode.WRONG_CODE, codes)
        self.assertIn(StateIssueCode.MISSING_RELATIONSHIP, codes)

        evaluated_material = next(
            item for item in self.registry.list_records()
            if item.sha256 in {
                stored.sha256
                for stored in self.registry.list_records()
                if stored.logical_type == "research_state.method"
            }
            and self.repository.load_artifact(item.sha256).object_id == "method-evaluated"
        )
        self.assertIn(parent_v1.artifact.sha256, evaluated_material.parent_artifacts)

    def test_materialization_rejects_missing_stale_and_wrong_code_dependencies(self) -> None:
        missing_parent = Method(
            object_id="method-missing",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at=STAMP,
            name="missing parent",
            description="Invalid dependency.",
            parents=(ObjectReference("ResearchQuestion", "missing", "a" * 64, "derived_from"),),
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(missing_parent)

        code_hash = self.raw_artifact(b"fixture\n")
        wrong_code = Implementation(
            object_id="implementation-wrong-code",
            producer=Role.IMPLEMENTER,
            created_at=STAMP,
            method_id="method-1",
            code_artifact_hashes=(code_hash,),
            code_revision="code-v0",
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(wrong_code)

        first = self.repository.materialize(self.question("rq-stale"))
        second = self.repository.materialize(
            revise_research_object(first.research_object, created_at=STAMP_2, question="A revised question?")
        )
        stale_child = Method(
            object_id="method-stale",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at=STAMP_2,
            name="stale child",
            description="Attempts to derive from a superseded revision.",
            parents=(
                ObjectReference(
                    "ResearchQuestion",
                    "rq-stale",
                    first.research_object.content_hash,
                    "derived_from",
                ),
            ),
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(stale_child)
        self.assertEqual(self.repository.latest("ResearchQuestion", "rq-stale"), second.research_object)

    def method_authority(
        self,
        *,
        method_id: str,
        description: str,
        logical_type: str = "method_definition",
        creator_role: Role = Role.HYPOTHESIS_DESIGNER,
        payload_method_id: str | None = None,
        correct_parent: bool = True,
        validation_result: str = "PASS",
        frozen: bool = True,
    ) -> object:
        configuration = self.registry.put_json(
            {"configuration_id": f"config-{method_id}"},
            logical_type="experiment_configuration",
            origin="typed method configuration",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        if correct_parent:
            parents = (configuration.sha256,)
        else:
            unrelated = self.registry.put_json(
                {"unrelated": True},
                logical_type="fixture.unrelated",
                origin="wrong method parent",
                creator_role=Role.IMPLEMENTER,
                creation_command=("scientist-one", "state-authority-test"),
                mime_type="application/json",
                created_at=STAMP,
            )
            parents = (unrelated.sha256,)
        return self.registry.put_json(
            {
                "assumptions": [],
                "component_ids": [],
                "description": description,
                "method_id": payload_method_id or method_id,
                "name": method_id,
                "tuning_trials": 0,
            },
            logical_type=logical_type,
            origin="typed method definition",
            creator_role=creator_role,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=parents,
            mime_type="application/json",
            validation_result=validation_result,
            frozen=frozen,
            created_at=STAMP,
        )

    def frozen_method(
        self,
        method_id: str,
        authority_hash: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> Method:
        return Method(
            object_id=method_id,
            producer=Role.HYPOTHESIS_DESIGNER,
            status=RecordStatus.FROZEN,
            created_at=STAMP,
            name=method_id,
            description=f"Description for {method_id}.",
            authority_artifact_hashes=(authority_hash,),
            metadata=metadata or {},
        )

    def test_method_authority_rejects_metadata_role_type_payload_parent_and_status_laundering(self) -> None:
        good_id = "method-authority-good"
        good_description = f"Description for {good_id}."
        good_source = self.method_authority(
            method_id=good_id,
            description=good_description,
        )
        materialized = self.repository.materialize(
            self.frozen_method(good_id, good_source.sha256)
        )
        self.assertEqual(
            set(materialized.artifact.parent_artifacts), {good_source.sha256}
        )

        metadata_only_id = "method-authority-metadata-only"
        metadata_only_source = self.method_authority(
            method_id=metadata_only_id,
            description=f"Description for {metadata_only_id}.",
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(
                Method(
                    object_id=metadata_only_id,
                    producer=Role.HYPOTHESIS_DESIGNER,
                    status=RecordStatus.FROZEN,
                    created_at=STAMP,
                    name=metadata_only_id,
                    description=f"Description for {metadata_only_id}.",
                    metadata={"method_artifact_hash": metadata_only_source.sha256},
                )
            )

        cases = (
            {
                "method_id": "method-authority-wrong-role",
                "creator_role": Role.ORCHESTRATOR,
            },
            {
                "method_id": "method-authority-wrong-type",
                "logical_type": "fixture.method_definition",
            },
            {
                "method_id": "method-authority-wrong-payload",
                "payload_method_id": "method-authority-other",
            },
            {
                "method_id": "method-authority-wrong-parent",
                "correct_parent": False,
            },
            {
                "method_id": "method-authority-pending-source",
                "validation_result": "PENDING",
                "frozen": False,
            },
        )
        for case in cases:
            method_id = str(case["method_id"])
            source = self.method_authority(
                method_id=method_id,
                description=f"Description for {method_id}.",
                logical_type=case.get("logical_type", "method_definition"),
                creator_role=case.get(
                    "creator_role", Role.HYPOTHESIS_DESIGNER
                ),
                payload_method_id=case.get("payload_method_id"),
                correct_parent=case.get("correct_parent", True),
                validation_result=case.get("validation_result", "PASS"),
                frozen=case.get("frozen", True),
            )
            with self.subTest(method_id=method_id), self.assertRaises(
                ValidationError
            ):
                self.repository.materialize(
                    self.frozen_method(method_id, source.sha256)
                )

    def test_public_snapshot_resolves_exact_state_and_rejects_wrong_run_and_parents(self) -> None:
        method_id = "method-snapshot-authority"
        source = self.method_authority(
            method_id=method_id,
            description=f"Description for {method_id}.",
        )
        materialized = self.repository.materialize(
            self.frozen_method(method_id, source.sha256)
        )
        current = (materialized.artifact.sha256,)
        snapshot = register_research_state_snapshot(
            self.repository,
            snapshot_id="method-snapshot-authority",
            created_at=STAMP_2,
        )
        authority = resolve_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=snapshot.sha256,
            expected_code_version="code-v1",
        )
        binding = authority.object("Method", method_id)
        self.assertEqual(authority.method(method_id), materialized.research_object)
        self.assertEqual(
            authority.binding_for_artifact(materialized.artifact.sha256), binding
        )
        self.assertEqual(binding.authority_artifact_hashes, (source.sha256,))
        self.assertEqual(binding.authority_logical_types, ("method_definition",))
        self.assertIs(
            binding.authority_creator_roles[0], Role.HYPOTHESIS_DESIGNER
        )
        self.assertFalse(binding.scientific_evidence_eligible)

        with self.assertRaises(ValidationError):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-2",
                snapshot_artifact_hash=snapshot.sha256,
            )
        bad_snapshot = self.registry.put_json(
            {
                "canonical_object_count": 1,
                "current_artifact_hashes": list(current),
                "fixture_notice": "declared state without direct parent custody",
                "object_types": ["Method"],
                "state_valid": True,
            },
            logical_type="canonical_research_state_snapshot",
            origin="invalid state snapshot",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        with self.assertRaises(ValidationError):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=bad_snapshot.sha256,
            )

    def test_bound_snapshot_survives_unrelated_append_but_not_supersession(
        self,
    ) -> None:
        bound = self.repository.materialize(self.question("rq-bound-paper"))
        current = (bound.artifact.sha256,)
        snapshot = register_research_state_snapshot(
            self.repository,
            snapshot_id="bound-paper",
            created_at=STAMP_2,
        )
        issued = resolve_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=snapshot.sha256,
        )

        self.repository.materialize(
            replace(
                self.question("rq-unrelated-later"),
                created_at="2026-08-29T12:00:02Z",
                content_hash=None,
            )
        )
        with self.assertRaisesRegex(ValidationError, "snapshot is stale"):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=snapshot.sha256,
            )
        replayed = resolve_bound_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=snapshot.sha256,
            state_artifact_hashes=current,
            ledger_head_hash=issued.ledger_head_hash,
            ledger_event_count=issued.ledger_event_count,
            expected_code_version=issued.code_version,
            expected_configuration_hash=issued.configuration_hash,
        )
        self.assertEqual(replayed.entries, issued.entries)
        self.assertEqual(replayed.ledger_head_hash, issued.ledger_head_hash)
        self.assertEqual(replayed.ledger_event_count, issued.ledger_event_count)

        self.repository.materialize(
            revise_research_object(
                bound.research_object,
                created_at="2026-08-29T12:00:03Z",
                question="Does the revised bound intervention improve the endpoint?",
            )
        )
        with self.assertRaisesRegex(ValidationError, "superseded|corrected"):
            resolve_bound_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=snapshot.sha256,
                state_artifact_hashes=current,
                ledger_head_hash=issued.ledger_head_hash,
                ledger_event_count=issued.ledger_event_count,
                expected_code_version=issued.code_version,
                expected_configuration_hash=issued.configuration_hash,
            )

    def test_registry_only_posthoc_snapshot_cannot_claim_an_older_prefix(
        self,
    ) -> None:
        first = self.repository.materialize(self.question("rq-posthoc-first"))
        old_prefix = self.ledger.assert_valid()
        assert old_prefix.head_hash is not None
        self.repository.materialize(
            replace(
                self.question("rq-posthoc-later"),
                created_at="2026-08-29T12:00:02Z",
                content_hash=None,
            )
        )
        forged = self.unissued_snapshot(
            (first.artifact.sha256,),
            snapshot_id="posthoc-rollback",
            ledger_head_hash=old_prefix.head_hash,
            ledger_event_count=old_prefix.event_count,
            created_at="2026-08-29T12:00:03Z",
        )
        with self.assertRaisesRegex(ValidationError, "issuance"):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=forged.sha256,
            )
        with self.assertRaisesRegex(ValidationError, "issuance"):
            resolve_bound_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=forged.sha256,
                state_artifact_hashes=(first.artifact.sha256,),
                ledger_head_hash=old_prefix.head_hash,
                ledger_event_count=old_prefix.event_count,
                expected_code_version="code-v1",
                expected_configuration_hash=CONFIG_HASH,
            )

    def test_snapshot_reader_rejects_noncanonical_state_order(self) -> None:
        self.repository.materialize(self.question("rq-order-first"))
        self.repository.materialize(
            replace(
                self.question("rq-order-second"),
                created_at=STAMP_2,
                content_hash=None,
            )
        )
        report = self.repository.validate_state()
        self.assertTrue(report.valid)
        reversed_hashes = tuple(reversed(report.current_artifact_hashes))
        self.assertNotEqual(reversed_hashes, report.current_artifact_hashes)
        ledger_result = self.ledger.assert_valid()
        assert ledger_result.head_hash is not None
        forged = self.unissued_snapshot(
            reversed_hashes,
            snapshot_id="noncanonical-order",
            ledger_head_hash=ledger_result.head_hash,
            ledger_event_count=ledger_result.event_count,
            created_at="2026-08-29T12:00:02Z",
        )
        with self.assertRaisesRegex(ValidationError, "invalid object set"):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=forged.sha256,
            )

    def test_snapshot_reader_rejects_one_byte_over_artifact_limit(self) -> None:
        materialized = self.repository.materialize(
            self.question("rq-oversized-snapshot")
        )
        ledger_result = self.ledger.assert_valid()
        assert ledger_result.head_hash is not None
        current = (materialized.artifact.sha256,)
        materialization_command: list[str] = []
        payload = {
            "canonical_object_count": 1,
            "current_artifact_hashes": list(current),
            "current_artifact_record_hashes": [
                str(materialized.artifact.record_hash)
            ],
            "issued_at": STAMP_2,
            "ledger_event_count_before_snapshot": ledger_result.event_count,
            "ledger_head_hash_before_snapshot": ledger_result.head_hash,
            "materialization_creation_command": materialization_command,
            "object_types": ["ResearchQuestion"],
            "prior_snapshot_artifact_hash": None,
            "repository_code_version": self.repository.code_version,
            "repository_configuration_hash": (
                self.repository.configuration_hash
            ),
            "repository_state": self.repository.state.value,
            "run_id": self.repository.run_id,
            "snapshot_id": "oversized-snapshot",
            "snapshot_schema_version": (
                research_state_module.RESEARCH_STATE_SNAPSHOT_PAYLOAD_SCHEMA
            ),
            "state_valid": True,
        }
        target_size = research_state_module.MAX_CANONICAL_OBJECT_BYTES + 1
        while True:
            raw = canonical_json_bytes(payload) + b"\n"
            remaining = target_size - len(raw)
            if remaining == 0:
                break
            self.assertGreater(remaining, 0)
            materialization_command.append("")
            probe_size = len(canonical_json_bytes(payload) + b"\n")
            materialization_command.pop()
            item_overhead = probe_size - len(raw)
            if remaining > item_overhead + 4096:
                materialization_command.append("x" * 4096)
            elif remaining > item_overhead:
                materialization_command.append(
                    "x" * (remaining - item_overhead)
                )
            else:
                shrink = item_overhead + 1 - remaining
                self.assertTrue(materialization_command)
                self.assertGreater(len(materialization_command[-1]), shrink)
                materialization_command[-1] = (
                    materialization_command[-1][:-shrink]
                )
                materialization_command.append("x")
        self.assertEqual(len(raw), target_size)
        forged = self.registry.put_bytes(
            raw,
            logical_type="canonical_research_state_snapshot",
            origin="issued canonical research-state snapshot",
            creator_role=Role.ORCHESTRATOR,
            creation_command=(
                research_state_module.RESEARCH_STATE_SNAPSHOT_CREATION_COMMAND
            ),
            parent_artifacts=current,
            schema_version=(
                research_state_module.RESEARCH_STATE_SNAPSHOT_ARTIFACT_SCHEMA_VERSION
            ),
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_2,
        )
        with self.assertRaisesRegex(ValidationError, "byte bound"):
            research_state_module._read_canonical_research_state_snapshot(
                self.registry,
                forged.sha256,
            )

    def test_non_lineage_correction_revokes_state_and_blocks_new_authority(
        self,
    ) -> None:
        parent = self.repository.materialize(self.question("rq-corrected-parent"))
        snapshot = register_research_state_snapshot(
            self.repository,
            snapshot_id="before-correction",
            created_at=STAMP_2,
        )
        issued = resolve_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=snapshot.sha256,
        )
        self.ledger.append_correction(
            parent.event.event_id,
            actor_role=Role.ORCHESTRATOR,
            reason="withdraw the canonical parent materialization",
            corrected_fields={"authority": "WITHDRAWN"},
            event_id="withdraw-canonical-parent",
            timestamp="2026-08-29T12:00:02Z",
        )
        self.assertFalse(self.repository.validate_state().valid)
        child = Method(
            object_id="method-corrected-parent-consumer",
            producer=Role.HYPOTHESIS_DESIGNER,
            created_at="2026-08-29T12:00:03Z",
            status=RecordStatus.ACTIVE,
            name="corrected parent consumer",
            description="A withdrawn parent cannot authorize a child.",
            parents=(
                ObjectReference(
                    "ResearchQuestion",
                    parent.research_object.object_id,
                    parent.research_object.content_hash,
                    "evaluated_input",
                    True,
                ),
            ),
        )
        registry_count = len(self.registry.list_records())
        event_count = self.ledger.assert_valid().event_count
        with self.assertRaisesRegex(ValidationError, "non-lineage correction"):
            self.repository.materialize(child)
        with self.assertRaisesRegex(ValidationError, "non-lineage correction"):
            register_research_state_snapshot(
                self.repository,
                snapshot_id="after-correction",
                created_at="2026-08-29T12:00:03Z",
            )
        self.assertEqual(len(self.registry.list_records()), registry_count)
        self.assertEqual(self.ledger.assert_valid().event_count, event_count)
        with self.assertRaises(ValidationError):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=snapshot.sha256,
            )
        with self.assertRaises(ValidationError):
            resolve_bound_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=snapshot.sha256,
                state_artifact_hashes=(parent.artifact.sha256,),
                ledger_head_hash=issued.ledger_head_hash,
                ledger_event_count=issued.ledger_event_count,
                expected_code_version=issued.code_version,
                expected_configuration_hash=issued.configuration_hash,
            )

    def test_snapshot_issuance_is_idempotent_resumable_and_revocable(self) -> None:
        self.repository.materialize(self.question("rq-snapshot-retry"))
        event_count = self.ledger.assert_valid().event_count
        with patch.object(
            self.ledger,
            "_append_locked",
            side_effect=RuntimeError("snapshot issuance interrupted"),
        ), self.assertRaisesRegex(RuntimeError, "interrupted"):
            register_research_state_snapshot(
                self.repository,
                snapshot_id="resumable-snapshot",
                created_at=STAMP_2,
            )
        self.assertEqual(self.ledger.assert_valid().event_count, event_count)
        orphan = next(
            item
            for item in self.registry.list_records()
            if item.logical_type == "canonical_research_state_snapshot"
        )
        resumed = register_research_state_snapshot(
            self.repository,
            snapshot_id="resumable-snapshot",
            created_at=STAMP_2,
        )
        self.assertEqual(resumed, orphan)
        issued = resolve_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=resumed.sha256,
        )
        completed_count = self.ledger.assert_valid().event_count
        self.assertEqual(
            register_research_state_snapshot(
                self.repository,
                snapshot_id="resumable-snapshot",
                created_at=STAMP_2,
            ),
            resumed,
        )
        self.assertEqual(
            self.ledger.assert_valid().event_count,
            completed_count,
        )
        self.ledger.record(
            run_id="run-1",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            reason="append an unrelated checkpoint after completed issuance",
            event_id="post-snapshot-unrelated-checkpoint",
            timestamp="2026-08-29T12:00:02Z",
            event_type="CHECKPOINT",
            metadata={"test_fixture": "post-snapshot-idempotent-retry"},
        )
        post_checkpoint_count = self.ledger.assert_valid().event_count
        self.assertEqual(
            register_research_state_snapshot(
                self.repository,
                snapshot_id="resumable-snapshot",
                created_at=STAMP_2,
            ),
            resumed,
        )
        self.assertEqual(
            self.ledger.assert_valid().event_count,
            post_checkpoint_count,
        )
        issuance_event_id = f"rss-{resumed.sha256[:48]}"
        self.ledger.append_correction(
            issuance_event_id,
            actor_role=Role.ORCHESTRATOR,
            reason="withdraw the snapshot issuance",
            corrected_fields={"authority": "WITHDRAWN"},
            event_id="withdraw-snapshot-issuance",
            timestamp="2026-08-29T12:00:03Z",
        )
        with self.assertRaisesRegex(ValidationError, "issuance was later corrected"):
            resolve_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=resumed.sha256,
            )
        with self.assertRaisesRegex(ValidationError, "issuance was later corrected"):
            resolve_bound_research_state_authority(
                self.registry,
                self.ledger,
                run_id="run-1",
                snapshot_artifact_hash=resumed.sha256,
                state_artifact_hashes=tuple(
                    sorted(item.artifact_sha256 for item in issued.entries)
                ),
                ledger_head_hash=issued.ledger_head_hash,
                ledger_event_count=issued.ledger_event_count,
                expected_code_version=issued.code_version,
                expected_configuration_hash=issued.configuration_hash,
            )

    def test_snapshot_issuance_rejects_backdating_before_any_prefix_event(
        self,
    ) -> None:
        self.repository.materialize(
            replace(
                self.question("rq-latest-prefix-time"),
                created_at="2026-08-29T12:00:02Z",
                content_hash=None,
            )
        )
        self.ledger.record(
            run_id="run-1",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            reason="exercise a non-monotonic unrelated event timestamp",
            event_id="backdated-unrelated-checkpoint",
            timestamp=STAMP,
            event_type="CHECKPOINT",
            metadata={"test_fixture": "snapshot-backdating"},
        )
        record_count = len(self.registry.list_records())
        event_count = self.ledger.assert_valid().event_count
        with self.assertRaisesRegex(ValidationError, "predate"):
            register_research_state_snapshot(
                self.repository,
                snapshot_id="backdated-snapshot",
                created_at=STAMP_2,
            )
        self.assertEqual(len(self.registry.list_records()), record_count)
        self.assertEqual(self.ledger.assert_valid().event_count, event_count)

    def test_completed_final_snapshot_retry_revalidates_prior_issuance(
        self,
    ) -> None:
        self.repository.materialize(self.question("rq-final-retry-prior"))
        prior = register_research_state_snapshot(
            self.repository,
            snapshot_id="final-retry-prior",
            created_at=STAMP_2,
        )
        final = register_research_state_snapshot(
            self.repository,
            snapshot_id="final-retry",
            created_at="2026-08-29T12:00:02Z",
            prior_snapshot_artifact_hash=prior.sha256,
        )
        self.assertEqual(
            register_research_state_snapshot(
                self.repository,
                snapshot_id="final-retry",
                created_at="2026-08-29T12:00:02Z",
                prior_snapshot_artifact_hash=prior.sha256,
            ),
            final,
        )
        self.ledger.append_correction(
            f"rss-{prior.sha256[:48]}",
            actor_role=Role.ORCHESTRATOR,
            reason="withdraw the final snapshot's required prior issuance",
            corrected_fields={"authority": "WITHDRAWN"},
            event_id="withdraw-final-snapshot-prior",
            timestamp="2026-08-29T12:00:03Z",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "issuance was later corrected",
        ):
            register_research_state_snapshot(
                self.repository,
                snapshot_id="final-retry",
                created_at="2026-08-29T12:00:02Z",
                prior_snapshot_artifact_hash=prior.sha256,
            )

    def test_scoped_state_authority_ignores_unrelated_objects_but_rejects_stale_target(self) -> None:
        experiment = Experiment(
            object_id="experiment-scoped-authority",
            producer=Role.PROTOCOL_DESIGNER,
            created_at=STAMP,
            status=RecordStatus.ACTIVE,
            hypothesis_ids=("hypothesis-scoped",),
            scientific_purpose="Exercise the exact scoped state resolver.",
            implementation_id="implementation-scoped",
            dataset_ids=("dataset-scoped",),
            split_ids=("split-scoped",),
            metric_ids=("metric-scoped",),
            baseline_ids=("baseline-scoped",),
            compute_profile=ComputeProfile.LOCAL_MAC,
            seed_policy={"seeds": [1]},
            expected_output_types=("result",),
            evaluator="scoped-evaluator-v1",
            budget={"runs": 1},
            termination_conditions={"max_failures": 0},
        )
        first = self.repository.materialize(experiment)

        second_record = revise_research_object(
            experiment,
            created_at="2026-08-29T12:00:02Z",
            scientific_purpose="Exercise the supersession check.",
        )
        second = self.repository.materialize(second_record)

        # This later canonical-shaped object is intentionally invalid: it is
        # FROZEN without semantic authority and has no materialization event.
        # A whole-state replay rejects it, while the scoped resolver must not
        # traverse it because it is unrelated to the requested Experiment.
        unrelated = ResearchQuestion(
            object_id="rq-unrelated-invalid",
            producer=Role.PROBLEM_INVESTIGATOR,
            created_at=STAMP_2,
            status=RecordStatus.FROZEN,
            research_goal="Remain outside the scoped authority graph.",
            question="Should unrelated downstream state affect this binding?",
            falsification_condition="The scoped target changes.",
            gate_outcome=ResearchQuestionOutcome.PROCEED,
        )
        self.registry.put_bytes(
            unrelated.canonical_bytes(),
            logical_type=unrelated.logical_type,
            origin=(
                f"research-state:{unrelated.object_type}:"
                f"{unrelated.object_id}:r1"
            ),
            creator_role=unrelated.producer,
            creation_command=self.repository.creation_command,
            schema_version=unrelated.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=unrelated.created_at,
        )
        self.assertFalse(self.repository.validate_state().valid)

        authority = resolve_current_research_state_bindings(
            self.registry,
            self.ledger,
            run_id="run-1",
            state_artifact_hashes=(second.artifact.sha256,),
        )
        self.assertIsInstance(authority, ScopedResearchStateAuthority)
        self.assertEqual(
            authority.object("Experiment", experiment.object_id).research_object,
            second_record,
        )
        self.assertEqual(
            authority.binding_for_artifact(second.artifact.sha256).artifact_sha256,
            second.artifact.sha256,
        )

        with self.assertRaises(ValidationError):
            resolve_current_research_state_bindings(
                self.registry,
                self.ledger,
                run_id="run-1",
                state_artifact_hashes=(first.artifact.sha256,),
            )

    def test_shared_ancestor_replays_all_equivalent_result_branches(self) -> None:
        """Schema-only: shared ancestors never select a favorable Result hash."""

        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            metric = graph["metrics"][0]
            first_result = graph["result"]
            second_result = replace(
                first_result,
                object_id="result-shared-ancestor-2",
                created_at=_timestamp_after(first_result.created_at, 1),
                content_hash=None,
            )
            by_content = {
                metric.content_hash: SimpleNamespace(research_object=metric),
                first_result.content_hash: SimpleNamespace(
                    research_object=first_result
                ),
                second_result.content_hash: SimpleNamespace(
                    research_object=second_result
                ),
            }
            contract_record = source["values"]["contract_record"]
            expected = tuple(sorted(metric.authority_artifact_hashes))
            projected = SimpleNamespace(result_state_projection=object())
            resolved_result = research_state_module._ResolvedObjectAuthority(
                (),
                False,
            )
            with (
                patch.object(
                    repository,
                    "_resolve_scientific_result_promotion",
                    return_value=(object(), projected, object(), object()),
                ),
                patch.object(
                    repository,
                    "_expected_scientific_result_ancestor_authority",
                    return_value=expected,
                ) as expected_authority,
                patch.object(
                    repository,
                    "_resolve_object_authority",
                    return_value=resolved_result,
                ) as replay_result,
            ):
                resolution = (
                    repository._resolve_scientific_result_ancestor_authority(
                        metric,
                        (contract_record,),
                        by_content,
                    )
                )
            self.assertIsNotNone(resolution)
            self.assertFalse(resolution.scientific_evidence_eligible)
            self.assertEqual(expected_authority.call_count, 2)
            self.assertEqual(replay_result.call_count, 2)

            with (
                patch.object(
                    repository,
                    "_resolve_scientific_result_promotion",
                    return_value=(object(), projected, object(), object()),
                ),
                patch.object(
                    repository,
                    "_expected_scientific_result_ancestor_authority",
                    side_effect=(expected, ("f" * 64,)),
                ),
                patch.object(
                    repository,
                    "_resolve_object_authority",
                    return_value=resolved_result,
                ),
            ):
                with self.assertRaisesRegex(
                    ValidationError,
                    "containing scientific Result projection|project different",
                ):
                    repository._resolve_scientific_result_ancestor_authority(
                        metric,
                        (contract_record,),
                        by_content,
                    )

    def test_validate_state_freshly_resolves_directly_inserted_semantic_authority(self) -> None:
        method_id = "method-direct-insertion"
        bad_source = self.method_authority(
            method_id=method_id,
            description=f"Description for {method_id}.",
            payload_method_id="method-different-payload",
        )
        forged = self.frozen_method(method_id, bad_source.sha256)
        artifact = self.registry.put_bytes(
            forged.canonical_bytes(),
            logical_type=forged.logical_type,
            origin=f"research-state:Method:{method_id}:r1",
            creator_role=forged.producer,
            creation_command=self.repository.creation_command,
            parent_artifacts=(bad_source.sha256,),
            schema_version=forged.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        self.ledger.record(
            run_id="run-1",
            actor_role=Role.HYPOTHESIS_DESIGNER,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(artifact.sha256,),
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            reason="forge labels around semantically wrong method authority",
            event_id=f"rs-{artifact.sha256[:48]}",
            timestamp=STAMP,
            event_type="CHECKPOINT",
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": "Method",
                "object_id": method_id,
                "revision": 1,
                "content_hash": forged.content_hash,
                "artifact_hash": artifact.sha256,
                "supersedes_content_hash": None,
                "schema_version": forged.schema_version,
            },
        )
        report = self.repository.validate_state()
        self.assertFalse(report.valid)
        self.assertIn(
            StateIssueCode.SEMANTIC_AUTHORITY_INVALID,
            {item.code for item in report.issues},
        )

    def test_confirmatory_claim_without_timeline_fails_and_system_fixture_is_ineligible(self) -> None:
        claim_text = "The bounded fixture result is larger than its baseline."
        confirmatory_graph, confirmatory_receipts = self.claim_graph_bundle(
            claim_id="claim-confirmatory-laundering",
            claim_text=claim_text,
            confirmatory=True,
        )
        confirmatory_sources = (
            confirmatory_graph.sha256,
            *tuple(item.sha256 for item in confirmatory_receipts),
        )
        laundering_claim = Claim(
            object_id="claim-confirmatory-laundering",
            producer=Role.EXPERIMENT_RUNNER,
            status=RecordStatus.VERIFIED,
            created_at=STAMP_2,
            claim_type=ClaimType.COMPARATIVE,
            claim_text=claim_text,
            scope="Bounded confirmatory fixture only.",
            source_artifact_ids=(confirmatory_graph.sha256,),
            verification_method="Serialized eligibility cannot replace timeline custody.",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.9,
            expressed_strength=ClaimStrength.QUALIFIED,
            permitted_strength=ClaimStrength.QUALIFIED,
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP_2,
                    verification_status=VerificationStatus.VERIFIED,
                    reason="Graph bytes resolve but no timeline receipt exists.",
                    source_artifact_ids=confirmatory_sources,
                ),
            ),
            confirmatory=True,
            evidence_use=ClaimEvidenceUse.SCIENTIFIC,
            authority_artifact_hashes=confirmatory_sources,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(laundering_claim)

        forged_claim_authority = self.registry.put_json(
            {
                "schema_version": "confirmatory-claim-authority/v1",
                "authority_id": "forged-state-authority",
                "run_id": "run-1",
                "claim_id": laundering_claim.object_id,
                "claim_graph_artifact_hash": confirmatory_graph.sha256,
                "timeline_receipt_artifact_hash": "d" * 64,
                "evidence_sources": [],
                "claim_evidence_closure_hashes": [],
                "authority": {
                    "scope": "SCIENTIFIC_EVIDENCE",
                    "scientific_gate_passed": True,
                },
            },
            logical_type="confirmatory_claim_authority",
            origin="claim-scoped live replay of confirmatory timeline and custody authority",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=(
                "scientist-one",
                "record-confirmatory-claim-authority",
            ),
            parent_artifacts=(confirmatory_graph.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_2,
        )
        scientific_proposal = register_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_id="proposal-claim-confirmatory-laundering",
            run_id="run-1",
            claim_graph_artifact_hash=confirmatory_graph.sha256,
            claim_id=laundering_claim.object_id,
            claim_type=laundering_claim.claim_type,
            scope=laundering_claim.scope,
            confidence=laundering_claim.confidence,
            expressed_strength=laundering_claim.expressed_strength,
            permitted_strength=laundering_claim.permitted_strength,
            verification_method=laundering_claim.verification_method,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "code lacks explicit source authority parents",
        ):
            build_claim_semantics_judgment_request(
                self.registry,
                self.ledger,
                proposal_artifact_hash=scientific_proposal.sha256,
                expected_run_id="run-1",
            )
        fixture_evidence = next(
            item
            for item in self.registry.list_records()
            if item.logical_type == "claim_evidence.code"
            and item.origin == "claim boundary evidence valid code"
        )
        retained_fixture = research_state_module._claim_semantics_retained_source(
            fixture_evidence,
            self.registry.get_bytes(fixture_evidence.sha256),
        )
        self.assertEqual(retained_fixture["origin"], fixture_evidence.origin)
        self.assertEqual(
            retained_fixture["creation_command"],
            list(fixture_evidence.creation_command),
        )
        self.assertEqual(retained_fixture["created_at"], fixture_evidence.created_at)
        self.assertEqual(retained_fixture["size"], fixture_evidence.size)
        self.assertEqual(retained_fixture["path"], fixture_evidence.path)
        self.assertEqual(
            retained_fixture["artifact_record_hash"],
            str(fixture_evidence.record_hash),
        )
        with self.assertRaises(ValidationError):
            require_claim_semantics_proposal(
                self.registry,
                self.ledger,
                proposal_artifact_hash=scientific_proposal.sha256,
                expected_run_id="run-substituted",
            )
        forged_proposal_payload = json.loads(
            self.registry.get_bytes(scientific_proposal.sha256)
        )
        forged_proposal_payload["proposal_id"] = (
            "proposal-claim-confirmatory-wrong-parent"
        )
        wrong_parent_proposal = self.registry.put_json(
            forged_proposal_payload,
            logical_type="claim_semantics_proposal",
            origin=(
                "candidate scientific claim semantics retained for independent review"
            ),
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "propose-claim-semantics"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_2,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "differs from its exact graph or dependencies",
        ):
            require_claim_semantics_proposal(
                self.registry,
                self.ledger,
                proposal_artifact_hash=wrong_parent_proposal.sha256,
                expected_run_id="run-1",
            )

        scientific_method_id = "method-claim-semantics-mixed-source"
        scientific_method_source = self.method_authority(
            method_id=scientific_method_id,
            description=f"Description for {scientific_method_id}.",
        )
        scientific_method = self.repository.materialize(
            self.frozen_method(
                scientific_method_id,
                scientific_method_source.sha256,
            )
        )
        scientific_code = self.registry.put_bytes(
            b"def score(value):\n    return value\n",
            logical_type="experiment_code",
            origin="reviewed scientific implementation source",
            creator_role=Role.IMPLEMENTER,
            creation_command=("scientist-one", "state-authority-test"),
            schema_version="1.0",
            mime_type="text/x-python",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        scientific_configuration = self.registry.put_json(
            {"configuration_id": "claim-semantics-mixed-source"},
            logical_type="experiment_configuration",
            origin="reviewed scientific implementation configuration",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(scientific_code.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        implementation = self.repository.materialize(
            Implementation(
                object_id="implementation-claim-semantics-mixed-source",
                producer=Role.IMPLEMENTER,
                status=RecordStatus.FROZEN,
                created_at=STAMP,
                code_version="code-v1",
                method_id=scientific_method_id,
                parents=(
                    ObjectReference(
                        "Method",
                        scientific_method_id,
                        scientific_method.research_object.content_hash,
                        "implements",
                        True,
                    ),
                ),
                code_artifact_hashes=(scientific_code.sha256,),
                code_revision="code-v1",
                configuration_artifact_hashes=(
                    scientific_configuration.sha256,
                ),
                authority_artifact_hashes=(
                    scientific_code.sha256,
                    scientific_configuration.sha256,
                ),
            )
        )
        mixed_graph, _mixed_receipts = self.claim_graph_bundle(
            claim_id="claim-semantics-mixed-source",
            claim_text=claim_text,
            variant="mixed-source",
            evidence_parent_overrides={
                GraphEvidenceKind.CODE: (implementation.artifact.sha256,),
            },
        )
        mixed_proposal = register_claim_semantics_proposal(
            self.registry,
            self.ledger,
            proposal_id="proposal-claim-semantics-mixed-source",
            run_id="run-1",
            claim_graph_artifact_hash=mixed_graph.sha256,
            claim_id="claim-semantics-mixed-source",
            claim_type=ClaimType.COMPARATIVE,
            scope=laundering_claim.scope,
            confidence=laundering_claim.confidence,
            expressed_strength=laundering_claim.expressed_strength,
            permitted_strength=laundering_claim.permitted_strength,
            verification_method=laundering_claim.verification_method,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "dataset_or_fixture lacks explicit source authority parents",
        ):
            build_claim_semantics_judgment_request(
                self.registry,
                self.ledger,
                proposal_artifact_hash=mixed_proposal.sha256,
                expected_run_id="run-1",
            )

        with self.assertRaises(ValidationError):
            register_claim_semantics_receipt(
                self.registry,
                self.ledger,
                receipt_id="scientific-semantics-with-forged-authority",
                run_id="run-1",
                claim_graph_artifact_hash=confirmatory_graph.sha256,
                claim_id=laundering_claim.object_id,
                claim_type=laundering_claim.claim_type,
                scope=laundering_claim.scope,
                confidence=laundering_claim.confidence,
                expressed_strength=laundering_claim.expressed_strength,
                permitted_strength=laundering_claim.permitted_strength,
                verification_method=laundering_claim.verification_method,
                evidence_scope=ClaimSemanticsEvidenceScope.SCIENTIFIC_EVIDENCE,
                semantic_proposal_artifact_hash=scientific_proposal.sha256,
                semantic_authority_artifact_hash=forged_claim_authority.sha256,
            )
        forged_semantics = self.registry.put_json(
            {
                "schema_version": "claim-semantics-receipt/v1",
                "receipt_id": "semantics-claim-confirmatory-laundering",
                "run_id": "run-1",
                "claim_graph_artifact_hash": confirmatory_graph.sha256,
                "claim_graph_artifact_record_hash": str(
                    confirmatory_graph.record_hash
                ),
                "claim_id": laundering_claim.object_id,
                "claim_text": claim_text,
                "claim_producer_role": Role.EXPERIMENT_RUNNER.value,
                "claim_evidence_use": ClaimEvidenceUse.SCIENTIFIC.value,
                "claim_type": ClaimType.COMPARATIVE.value,
                "scope": laundering_claim.scope,
                "confidence": laundering_claim.confidence,
                "expressed_strength": ClaimStrength.QUALIFIED.value,
                "permitted_strength": ClaimStrength.QUALIFIED.value,
                "verification_method": laundering_claim.verification_method,
                "dependency_bindings": [],
                "evidence_scope": "SCIENTIFIC_EVIDENCE",
                "semantic_proposal_artifact_hash": scientific_proposal.sha256,
                "semantic_authority_artifact_hash": forged_claim_authority.sha256,
                "scientific_writer_eligible": True,
            },
            logical_type="claim_semantics_receipt",
            origin=(
                "claim-verifier-attested audited-live scientific claim semantics"
            ),
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "record-claim-semantics"),
            parent_artifacts=(
                confirmatory_graph.sha256,
                scientific_proposal.sha256,
                forged_claim_authority.sha256,
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP_2,
        )
        with self.assertRaises(ValidationError):
            require_claim_semantics_receipt(
                self.registry,
                self.ledger,
                receipt_artifact_hash=forged_semantics.sha256,
                expected_run_id="run-1",
                expected_claim_graph_artifact_hash=confirmatory_graph.sha256,
                expected_claim_id=laundering_claim.object_id,
            )
        forged_sources = (
            *confirmatory_sources,
            forged_claim_authority.sha256,
            forged_semantics.sha256,
        )
        forged_claim = replace(
            laundering_claim,
            source_artifact_ids=(
                confirmatory_graph.sha256,
                forged_semantics.sha256,
            ),
            review_history=(
                replace(
                    laundering_claim.review_history[-1],
                    source_artifact_ids=forged_sources,
                ),
            ),
            authority_artifact_hashes=forged_sources,
            content_hash=None,
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(forged_claim)

        fixture_graph, fixture_receipts = self.claim_graph_bundle(
            claim_id="claim-system-fixture",
            claim_text=claim_text,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            variant="system-fixture",
        )
        fixture_sources = (
            fixture_graph.sha256,
            *tuple(item.sha256 for item in fixture_receipts),
        )
        fixture_semantics = self.claim_semantics(
            fixture_graph.sha256,
            claim_id="claim-system-fixture",
            scope=laundering_claim.scope,
            verification_method=laundering_claim.verification_method,
        )
        fixture_sources = (*fixture_sources, fixture_semantics.sha256)
        fixture_claim = replace(
            laundering_claim,
            object_id="claim-system-fixture",
            source_artifact_ids=(
                fixture_graph.sha256,
                fixture_semantics.sha256,
            ),
            review_history=(
                ClaimReview(
                    reviewer=Role.CLAIM_VERIFIER,
                    timestamp=STAMP_2,
                    verification_status=VerificationStatus.VERIFIED,
                    reason="Exact graph remains a system fixture.",
                    source_artifact_ids=fixture_sources,
                ),
            ),
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
            authority_artifact_hashes=fixture_sources,
            content_hash=None,
        )
        materialized = self.repository.materialize(fixture_claim)
        with self.assertRaisesRegex(
            ValidationError,
            "cannot depend on non-writer-eligible state",
        ):
            register_claim_semantics_proposal(
                self.registry,
                self.ledger,
                proposal_id="proposal-with-fixture-dependency",
                run_id="run-1",
                claim_graph_artifact_hash=confirmatory_graph.sha256,
                claim_id=laundering_claim.object_id,
                claim_type=laundering_claim.claim_type,
                scope=laundering_claim.scope,
                confidence=laundering_claim.confidence,
                expressed_strength=laundering_claim.expressed_strength,
                permitted_strength=laundering_claim.permitted_strength,
                verification_method=laundering_claim.verification_method,
                dependency_claim_state_artifact_hashes=(
                    materialized.artifact.sha256,
                ),
            )
        current_report = self.repository.validate_state(
            expected_code_version="code-v1"
        )
        self.assertTrue(current_report.valid)
        snapshot = register_research_state_snapshot(
            self.repository,
            snapshot_id="system-fixture-claim",
            created_at=STAMP_2,
        )
        authority = resolve_research_state_authority(
            self.registry,
            self.ledger,
            run_id="run-1",
            snapshot_artifact_hash=snapshot.sha256,
        )
        claim_binding = authority.object("Claim", fixture_claim.object_id)
        resolved_semantics = authority.claim_semantics(fixture_claim.object_id)
        self.assertIs(claim_binding.claim_semantics, resolved_semantics)
        self.assertIs(
            resolved_semantics.evidence_scope,
            ClaimSemanticsEvidenceScope.NON_EVIDENTIARY_FIXTURE,
        )
        self.assertFalse(resolved_semantics.scientific_writer_eligible)
        self.assertFalse(claim_binding.scientific_evidence_eligible)

    def test_scientific_dataset_boundary_rejects_caller_usage_and_unsigned_transport(
        self,
    ) -> None:
        source = {
            "schema_version": "scientific-dataset-source/v1",
            "dataset_id": "dataset-scientific-boundary",
            "name": "Audited public Dataset",
            "version": "2026-08-29",
            "license": {
                "spdx_id": "CC-BY-4.0",
                "canonical_url": (
                    "https://creativecommons.org/licenses/by/4.0/"
                ),
            },
            "data": [{"unit_id": "subject-1", "value": 1.0}],
        }
        projection = research_state_module._scientific_dataset_source_projection(
            json.dumps(source, sort_keys=True).encode("utf-8")
        )
        self.assertEqual(
            projection["dataset_id"],
            "dataset-scientific-boundary",
        )
        self.assertEqual(projection["data_item_count"], 1)

        caller_authorized = dict(source)
        caller_authorized["usage_authorized"] = True
        with self.assertRaisesRegex(ValidationError, "envelope is incomplete"):
            research_state_module._scientific_dataset_source_projection(
                json.dumps(caller_authorized, sort_keys=True).encode("utf-8")
            )
        wrong_license = {
            **source,
            "license": {
                "spdx_id": "CC-BY-4.0",
                "canonical_url": "https://attacker.invalid/license",
            },
        }
        with self.assertRaisesRegex(ValidationError, "supported public license"):
            research_state_module._scientific_dataset_source_projection(
                json.dumps(wrong_license, sort_keys=True).encode("utf-8")
            )

        self.ledger.record(
            run_id="run-1",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=(),
            code_version="code-v1",
            configuration_hash=CONFIG_HASH,
            reason="initialize scientific Dataset boundary test",
            event_id="dataset-boundary-initialized",
            timestamp=STAMP,
            event_type="CHECKPOINT",
            metadata={"test_fixture": "scientific-dataset-boundary"},
        )
        source_bytes = json.dumps(source, sort_keys=True).encode("utf-8")
        with self.assertRaisesRegex(ValidationError, "canonical pinned HTTPS"):
            register_scientific_dataset_acquisition_plan(
                self.registry,
                self.ledger,
                run_id="run-1",
                dataset_id="dataset-scientific-boundary",
                name="Audited public Dataset",
                version="2026-08-29",
                source_url="http://attacker.invalid/data.json",
                expected_body_sha256=hashlib.sha256(source_bytes).hexdigest(),
                license_identifier="CC-BY-4.0",
                license_url="https://creativecommons.org/licenses/by/4.0/",
                intended_use="Evaluate the preregistered bounded intervention.",
                processing_scope=("parse declared numeric fields",),
                derivative_output_scope=("aggregate statistics",),
                redistribution_plan="DERIVED_AGGREGATES_ONLY",
                attribution_notice="Attribute the declared Dataset publisher.",
            )
        plan = register_scientific_dataset_acquisition_plan(
            self.registry,
            self.ledger,
            run_id="run-1",
            dataset_id="dataset-scientific-boundary",
            name="Audited public Dataset",
            version="2026-08-29",
            source_url=(
                "https://datasets.example.org/public/data.json?"
                "version=2026-08-29"
            ),
            expected_body_sha256=hashlib.sha256(source_bytes).hexdigest(),
            license_identifier="CC-BY-4.0",
            license_url="https://creativecommons.org/licenses/by/4.0/",
            intended_use="Evaluate the preregistered bounded intervention.",
            processing_scope=("parse declared numeric fields",),
            derivative_output_scope=("aggregate statistics",),
            redistribution_plan="DERIVED_AGGREGATES_ONLY",
            attribution_notice="Attribute the declared Dataset publisher.",
        )
        resolved_plan = require_scientific_dataset_acquisition_plan(
            self.registry,
            self.ledger,
            run_id="run-1",
            plan_artifact_hash=plan.sha256,
            expected_dataset_id="dataset-scientific-boundary",
            expected_version="2026-08-29",
        )
        self.assertEqual(resolved_plan.policy_id, "scientific-dataset-pinned-json/v1")
        self.assertEqual(resolved_plan.license_obligations,
                         ("attribute-source", "link-license", "mark-changes"))

        fake_response = self.registry.put_json(
            source,
            logical_type="external_response_receipt",
            origin="caller-labelled external Dataset response",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "state-authority-test"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        fake_transport = self.registry.put_json(
            {"network_used": True, "caller_asserted": True},
            logical_type="audited_transport_execution_authority",
            origin="caller-labelled transport authority",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(fake_response.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        fake_contract = self.registry.put_json(
            {"caller_asserted": "evaluation contract"},
            logical_type="evaluation_contract",
            origin="caller-labelled Dataset contract",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(plan.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "accepted audited-live transport authority",
        ):
            register_scientific_dataset_usage_proposal(
                self.registry,
                self.ledger,
                run_id="run-1",
                acquisition_plan_artifact_hash=plan.sha256,
                evaluation_contract_artifact_hash=fake_contract.sha256,
                transport_authority_artifact_hash=fake_transport.sha256,
                response_receipt_artifact_hash=fake_response.sha256,
            )

    def test_scientific_claim_evidence_projection_rejects_payload_and_parent_splices(
        self,
    ) -> None:
        method_id = "method-projection-source"
        method_source = self.method_authority(
            method_id=method_id,
            description=f"Description for {method_id}.",
        )
        method = self.repository.materialize(
            self.frozen_method(method_id, method_source.sha256)
        )
        code = self.registry.put_bytes(
            b"def score(value):\n    return value\n",
            logical_type="experiment_code",
            origin="projection implementation code",
            creator_role=Role.IMPLEMENTER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="text/x-python",
            created_at=STAMP,
        )
        configuration = self.registry.put_json(
            {"configuration_id": "projection-source"},
            logical_type="experiment_configuration",
            origin="projection implementation configuration",
            creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(code.sha256,),
            mime_type="application/json",
            created_at=STAMP,
        )
        implementation = self.repository.materialize(
            Implementation(
                object_id="implementation-projection-source",
                producer=Role.IMPLEMENTER,
                status=RecordStatus.FROZEN,
                created_at=STAMP,
                code_version="code-v1",
                parents=(
                    ObjectReference(
                        "Method",
                        method_id,
                        method.research_object.content_hash,
                        "implements",
                        True,
                    ),
                ),
                method_id=method_id,
                code_artifact_hashes=(code.sha256,),
                code_revision="code-v1",
                configuration_artifact_hashes=(configuration.sha256,),
                authority_artifact_hashes=(code.sha256, configuration.sha256),
            )
        )
        source = implementation.artifact
        projection = register_scientific_claim_evidence_projection(
            self.registry,
            evidence_id="projection-evidence",
            evidence_kind=GraphEvidenceKind.CODE,
            claim_id="projection-claim",
            claim_text="The exact source supports this bounded claim.",
            producer_role=Role.EXPERIMENT_RUNNER,
            source_artifact_hashes=(source.sha256,),
        )
        research_state_module._require_scientific_claim_evidence_projection(
            self.registry,
            artifact=projection,
            evidence_id="projection-evidence",
            evidence_kind=GraphEvidenceKind.CODE,
            claim_id="projection-claim",
            claim_text="The exact source supports this bounded claim.",
            claim_producer_role=Role.EXPERIMENT_RUNNER,
        )

        altered_payload = json.loads(self.registry.get_bytes(projection.sha256))
        altered_payload["claim_text"] = "A qualitative relabel replaces the source."
        altered = self.registry.put_json(
            altered_payload,
            logical_type="claim_evidence.code",
            origin="exact scientific claim-evidence projection projection-claim:code",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=(
                "scientist-one",
                "project-scientific-claim-evidence",
            ),
            parent_artifacts=(source.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "projection differs from its exact sources",
        ):
            research_state_module._require_scientific_claim_evidence_projection(
                self.registry,
                artifact=altered,
                evidence_id="projection-evidence",
                evidence_kind=GraphEvidenceKind.CODE,
                claim_id="projection-claim",
                claim_text="The exact source supports this bounded claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
            )

        unrelated = self.registry.put_json(
            {"unrelated": True},
            logical_type="fixture.unrelated",
            origin="unrelated projection parent",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        spliced_payload = json.loads(self.registry.get_bytes(projection.sha256))
        spliced_payload["source_artifact_hashes"].append(unrelated.sha256)
        spliced_payload["source_artifact_record_hashes"].append(
            str(unrelated.record_hash)
        )
        spliced = self.registry.put_json(
            spliced_payload,
            logical_type="claim_evidence.code",
            origin="exact scientific claim-evidence projection projection-claim:code",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=(
                "scientist-one",
                "project-scientific-claim-evidence",
            ),
            parent_artifacts=(source.sha256, unrelated.sha256),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "unrelated or reordered direct parents",
        ):
            research_state_module._require_scientific_state_evidence_source(
                self.registry,
                self.ledger,
                run_id="run-1",
                evidence_kind=GraphEvidenceKind.CODE,
                evidence_artifact=spliced,
                evidence_id="projection-evidence",
                claim_id="projection-claim",
                claim_text="The exact source supports this bounded claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=True,
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                assertion_text="Exact bounded code source.",
            )

        caller_review = self.repository.materialize(
            Challenge(
                object_id="challenge-caller-limitation",
                producer=Role.ADVERSARIAL_REVIEWER,
                status=RecordStatus.ACTIVE,
                created_at=STAMP_2,
                target_claim_ids=("claim-not-materialized",),
                severity=ChallengeSeverity.MAJOR,
                finding="A caller-authored limitation without a typed finding.",
                resolution_status=ChallengeResolution.UNRESOLVED,
                evidence_ids=(),
            )
        )
        limitation = register_scientific_claim_evidence_projection(
            self.registry,
            evidence_id="projection-limitation",
            evidence_kind=GraphEvidenceKind.LIMITATION,
            claim_id="projection-claim",
            claim_text="The exact source supports this bounded claim.",
            producer_role=Role.EXPERIMENT_RUNNER,
            source_artifact_hashes=(caller_review.artifact.sha256,),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "lacks source-owned qualifier authority",
        ):
            research_state_module._require_scientific_state_evidence_source(
                self.registry,
                self.ledger,
                run_id="run-1",
                evidence_kind=GraphEvidenceKind.LIMITATION,
                evidence_artifact=limitation,
                evidence_id="projection-limitation",
                claim_id="projection-claim",
                claim_text="The exact source supports this bounded claim.",
                claim_producer_role=Role.EXPERIMENT_RUNNER,
                claim_confirmatory=True,
                claim_evidence_use=ClaimEvidenceUse.SCIENTIFIC,
                assertion_text="Caller-authored limitation.",
            )

    def test_generic_typed_bytes_cannot_launder_reproduction_pass(self) -> None:
        manifest = self.registry.put_json(
            {"looks_like": "manifest"},
            logical_type="experiment_output_manifest",
            origin="generic bytes",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        environment = self.registry.put_json(
            {"looks_like": "environment"},
            logical_type="execution_environment",
            origin="generic bytes",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        fake_report = self.registry.put_json(
            {"status": "PASS"},
            logical_type="reproduction_report",
            origin="generic bytes",
            creator_role=Role.REPRODUCTION_VERIFIER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        package = ReproducibilityPackage(
            object_id="repro-fake-pass",
            producer=Role.REPRODUCTION_VERIFIER,
            status=RecordStatus.COMPLETE,
            created_at=STAMP_2,
            run_ids=("run-1",),
            manifest_artifact_hashes=(manifest.sha256,),
            environment_artifact_hashes=(environment.sha256,),
            source_revision="code-v1",
            evaluator_version="evaluator-v1",
            reproduction_status=ReproductionStatus.PASS,
            reproduced_at=STAMP_2,
            authority_artifact_hashes=(
                manifest.sha256,
                environment.sha256,
                fake_report.sha256,
            ),
        )
        with self.assertRaises(ValidationError):
            self.repository.materialize(package)

    def test_result_rejects_aggregate_seed_from_another_run(self) -> None:
        def insert_parent(record: CanonicalResearchObject) -> None:
            artifact = self.registry.put_bytes(
                record.canonical_bytes(),
                logical_type=record.logical_type,
                origin=(
                    f"research-state:{record.object_type}:"
                    f"{record.object_id}:r{record.revision}"
                ),
                creator_role=record.producer,
                creation_command=self.repository.creation_command,
                schema_version=record.schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=record.created_at,
            )
            self.ledger.record(
                run_id=self.repository.run_id,
                actor_role=record.producer,
                state_before=self.repository.state,
                requested_state_after=self.repository.state,
                artifact_hashes=(artifact.sha256,),
                code_version=self.repository.code_version,
                configuration_hash=self.repository.configuration_hash,
                reason="admit bounded semantic-rejection fixture parent",
                event_id=f"rs-{artifact.sha256[:48]}",
                timestamp=record.created_at,
                event_type="CHECKPOINT",
                metadata={
                    "research_state_operation": "MATERIALIZED",
                    "object_type": record.object_type,
                    "object_id": record.object_id,
                    "revision": record.revision,
                    "content_hash": record.content_hash,
                    "artifact_hash": artifact.sha256,
                    "supersedes_content_hash": record.supersedes_content_hash,
                    "schema_version": record.schema_version,
                },
            )

        metric = Metric(
            object_id="metric-cross-run",
            producer=Role.PROTOCOL_DESIGNER,
            status=RecordStatus.FROZEN,
            created_at=STAMP,
            code_version="code-v1",
            name="Cross-run fixture accuracy",
            direction=MetricDirection.HIGHER_IS_BETTER,
            unit="fraction",
            evidence_level=MetricLevel.END_TO_END,
        )
        foreign_seed = self.registry.put_json(
            {"run_id": "experiment-run-a", "seed": 7, "metric": 0.75},
            logical_type="experiment_output.seed_result",
            origin="foreign run seed result",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        local_seed = self.registry.put_json(
            {"run_id": "experiment-run-b", "seed": 7, "metric": 0.75},
            logical_type="experiment_output.seed_result",
            origin="evaluated run seed result",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP,
        )
        run = Run(
            object_id="experiment-run-b",
            producer=Role.EXPERIMENT_RUNNER,
            status=RecordStatus.COMPLETE,
            created_at=STAMP,
            code_version="code-v1",
            experiment_id="experiment-cross-run",
            code_revision="code-v1",
            configuration_artifact_hash="a" * 64,
            compute_profile=ComputeProfile.LOCAL_MAC,
            random_seeds=(7,),
            output_artifact_hashes=(local_seed.sha256,),
            evaluator_version="accuracy-v1",
            started_at=STAMP,
            completed_at=STAMP_2,
        )
        insert_parent(metric)
        insert_parent(run)

        aggregate = self.registry.put_json(
            {
                "baseline_accuracy": 0.5,
                "candidate_accuracy": 0.75,
                "effect": 0.25,
                "metric_id": metric.object_id,
                "scientific_evidence_eligible": False,
                "seed_distribution": [
                    {"metric": 0.75, "seed": 7, "status": "SUCCESS"}
                ],
            },
            logical_type="aggregate_experiment_result",
            origin="aggregate from a substituted run",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(foreign_seed.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        seed_report = self.registry.put_json(
            {
                "report": {
                    "regime": "ALL_SEEDS",
                    "selected_run_id": None,
                    "total_runs": 1,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "invalid_runs": 0,
                    "successful_distribution": [0.75],
                },
                "runs": [{"artifact_sha256": foreign_seed.sha256}],
            },
            logical_type="all_seed_report",
            origin="all-seed report from a substituted run",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(foreign_seed.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        evaluator = self.registry.put_json(
            {"assessment": {"passed": True, "signals": []}},
            logical_type="evaluator_integrity_assessment",
            origin="cross-run evaluator fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(seed_report.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        statistics = self.registry.put_json(
            {
                "adjusted_p_value": 0.01,
                "bootstrap": {"interval": [0.7, 0.8]},
            },
            logical_type="statistical_analysis",
            origin="cross-run statistics fixture",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(aggregate.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        result_id = "result-cross-run"
        raw_domain = register_domain_raw_fixture_source(
            self.registry,
            run_id="run-1",
            domain=DomainKind.GENERIC_ML,
            object_id=result_id,
            task_id="cross-run-fixture",
            source_id="bounded-input",
            payload={"fixture_observation": "cross-run substitution regression"},
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        domain_source = register_domain_evidence_source(
            self.registry,
            run_id="run-1",
            domain=DomainKind.GENERIC_ML,
            object_id=result_id,
            task_id="cross-run-fixture",
            evidence=GenericMLValidityEvidence(
                examples=(
                    GenericMLExample("train", DomainSplitRole.TRAIN),
                    GenericMLExample("validation", DomainSplitRole.VALIDATION),
                    GenericMLExample("test", DomainSplitRole.TEST),
                ),
                preprocessing_fit_splits=(DomainSplitRole.TRAIN,),
                benchmark_version="fixture-v1",
                pretrained_contamination_checked=True,
                seed_policy_frozen=True,
                checkpoint_selection_split=DomainSplitRole.VALIDATION,
                metric_implementation_verified=True,
                hyperparameter_budget_equivalent=True,
                compute_budget_equivalent=True,
                robustness_evaluated=True,
            ),
            supporting_artifact_hashes=(raw_domain.sha256,),
        )
        domain_receipt = materialize_domain_validity(
            self.registry,
            source_artifact_sha256=domain_source.sha256,
            expected_run_id="run-1",
            expected_domain=DomainKind.GENERIC_ML,
            expected_object_id=result_id,
            expected_task_id="cross-run-fixture",
        )
        result = Result(
            object_id=result_id,
            producer=Role.STATISTICIAN,
            status=RecordStatus.COMPLETE,
            created_at=STAMP_2,
            code_version="code-v1",
            parents=(
                ObjectReference(
                    "Run",
                    run.object_id,
                    run.content_hash,
                    "aggregates",
                    True,
                ),
                ObjectReference(
                    "Metric",
                    metric.object_id,
                    metric.content_hash,
                    "reports",
                    True,
                ),
            ),
            run_ids=(run.object_id,),
            metric_id=metric.object_id,
            value={"baseline": 0.5, "candidate": 0.75, "improvement": 0.25},
            unit="fraction",
            direction=MetricDirection.HIGHER_IS_BETTER,
            uncertainty={"confidence_interval": [0.7, 0.8], "p_value": 0.01},
            source_artifact_hashes=(aggregate.sha256,),
            evaluation_artifact_hashes=(
                seed_report.sha256,
                evaluator.sha256,
                statistics.sha256,
                domain_receipt.sha256,
            ),
            code_revision="code-v1",
            observed_at=STAMP_2,
            authority_artifact_hashes=(
                aggregate.sha256,
                seed_report.sha256,
                evaluator.sha256,
                statistics.sha256,
                domain_receipt.sha256,
            ),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "aggregate seed authority does not belong to one evaluated canonical Run",
        ):
            self.repository.materialize(result)

        empty_aggregate = self.registry.put_json(
            {
                "baseline_accuracy": 0.5,
                "candidate_accuracy": 0.75,
                "effect": 0.25,
                "metric_id": metric.object_id,
                "scientific_evidence_eligible": False,
                "seed_distribution": [],
            },
            logical_type="aggregate_experiment_result",
            origin="empty aggregate substitution regression",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        empty_seed_report = self.registry.put_json(
            {
                "report": {
                    "failed_runs": 0,
                    "invalid_runs": 0,
                    "regime": "ALL_SEEDS",
                    "selected_run_id": None,
                    "successful_distribution": [],
                    "successful_runs": 0,
                    "total_runs": 0,
                },
                "runs": [],
            },
            logical_type="all_seed_report",
            origin="empty seed report substitution regression",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        empty_result = replace(
            result,
            content_hash=None,
            source_artifact_hashes=(empty_aggregate.sha256,),
            evaluation_artifact_hashes=(
                empty_seed_report.sha256,
                evaluator.sha256,
                statistics.sha256,
                domain_receipt.sha256,
            ),
            authority_artifact_hashes=(
                empty_aggregate.sha256,
                empty_seed_report.sha256,
                evaluator.sha256,
                statistics.sha256,
                domain_receipt.sha256,
            ),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "aggregate result requires non-empty seed authority",
        ):
            self.repository.materialize(empty_result)

        labelled_aggregate = self.registry.put_json(
            {
                "baseline_accuracy": 0.5,
                "candidate_accuracy": 0.75,
                "effect": 0.25,
                "metric_id": metric.object_id,
                # This producer-authored label was the former promotion seam.
                "scientific_evidence_eligible": True,
                "seed_distribution": [
                    {"metric": 0.75, "seed": 7, "status": "SUCCESS"}
                ],
            },
            logical_type="aggregate_experiment_result",
            origin="aggregate with a caller-authored scientific label",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(local_seed.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        labelled_seed_report = self.registry.put_json(
            {
                "report": {
                    "regime": "ALL_SEEDS",
                    "selected_run_id": None,
                    "total_runs": 1,
                    "successful_runs": 1,
                    "failed_runs": 0,
                    "invalid_runs": 0,
                    "successful_distribution": [0.75],
                },
                "runs": [{"artifact_sha256": local_seed.sha256}],
            },
            logical_type="all_seed_report",
            origin="complete all-seed report for label-laundering regression",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(local_seed.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        labelled_evaluator = self.registry.put_json(
            {
                "assessment": {"passed": True, "signals": []},
                "regression": "caller-label",
            },
            logical_type="evaluator_integrity_assessment",
            origin="complete evaluator report for label-laundering regression",
            creator_role=Role.SCIENTIFIC_REVIEWER,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(labelled_seed_report.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        labelled_statistics = self.registry.put_json(
            {
                "adjusted_p_value": 0.01,
                "bootstrap": {"interval": [0.7, 0.8]},
                "regression": "caller-label",
            },
            logical_type="statistical_analysis",
            origin="complete statistics for label-laundering regression",
            creator_role=Role.STATISTICIAN,
            creation_command=("scientist-one", "state-authority-test"),
            parent_artifacts=(labelled_aggregate.sha256,),
            mime_type="application/json",
            created_at=STAMP_2,
        )
        labelled_result = replace(
            result,
            content_hash=None,
            source_artifact_hashes=(labelled_aggregate.sha256,),
            evaluation_artifact_hashes=(
                labelled_seed_report.sha256,
                labelled_evaluator.sha256,
                labelled_statistics.sha256,
                domain_receipt.sha256,
            ),
            authority_artifact_hashes=(
                labelled_aggregate.sha256,
                labelled_seed_report.sha256,
                labelled_evaluator.sha256,
                labelled_statistics.sha256,
                domain_receipt.sha256,
            ),
        )
        materialized_labelled = self.repository.materialize(labelled_result)
        stored = self.repository._stored_objects()
        by_content, _by_identity = self.repository._indexes(stored)
        resolved = self.repository._resolve_object_authority(
            materialized_labelled.research_object,
            by_content,
        )
        self.assertFalse(resolved.scientific_evidence_eligible)

    def test_public_scientific_result_v2_bundle_extends_result_then_replays_test(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]

            result_only = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                reason="public Result-v2 fixture materialization",
            )
            self.assertEqual(len(result_only), len(graph["ancestors"]) + 1)
            result_materialized = next(
                item
                for item in result_only
                if isinstance(item.research_object, Result)
            )
            result_scope = resolve_current_research_state_bindings(
                registry,
                ledger,
                run_id="global-run-1",
                state_artifact_hashes=(result_materialized.artifact.sha256,),
            )
            self.assertEqual(
                result_scope.object("Result", "result-1").research_object,
                graph["result"],
            )

            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(
                ValidationError,
                "materialize_scientific_result_bundle",
            ):
                repository.materialize(graph["statistical_test"])
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            projected_test = graph["statistical_test"]
            legacy_method = {
                "ties": "removed",
                "bootstrap_resamples": 1000,
                "bootstrap_seed": 7,
                "resampling_unit": "task",
            }
            legacy_outcome = {
                "effect": 0.25,
                "p_value": 0.01,
                "sample_size": 10,
                "confidence_interval": [0.1, 0.4],
            }
            analysis = registry.put_json(
                {
                    "test": projected_test.test_name,
                    "null_hypothesis": projected_test.null_hypothesis,
                    "alternative": projected_test.alternative,
                    "effect": legacy_outcome["effect"],
                    "adjusted_p_value": legacy_outcome["p_value"],
                    "independent_unit_count": legacy_outcome["sample_size"],
                    "bootstrap": {
                        "resamples": legacy_method["bootstrap_resamples"],
                        "fixed_seed": legacy_method["bootstrap_seed"],
                        "resampling_unit": legacy_method["resampling_unit"],
                        "interval": legacy_outcome["confidence_interval"],
                    },
                },
                logical_type="statistical_analysis",
                origin="legacy-looking source-bound child regression",
                creator_role=Role.STATISTICIAN,
                creation_command=("scientist-one", "state-authority-test"),
                mime_type="application/json",
                created_at=projected_test.created_at,
            )
            legacy_looking = replace(
                projected_test,
                content_hash=None,
                method_configuration=legacy_method,
                outcome=legacy_outcome,
                source_artifact_hashes=(analysis.sha256,),
                authority_artifact_hashes=(analysis.sha256,),
            )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaisesRegex(
                ValidationError,
                "materialize_scientific_result_bundle",
            ):
                repository.materialize(legacy_looking)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            # A child must extend the completed Result prefix.  A child whose
            # timestamp is older than its exact Result parent is rejected
            # before either registry or ledger changes.
            older_statistical_test = replace(
                graph["statistical_test"],
                content_hash=None,
                created_at=_timestamp_after(graph["result"].created_at, -1),
            )
            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            with self.assertRaises(ValidationError):
                repository.materialize_scientific_result_bundle(
                    ancestors=graph["ancestors"],
                    result=graph["result"],
                    statistical_test=older_statistical_test,
                    reason="reject an older StatisticalTest extension",
                )
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count)

            completed = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                statistical_test=graph["statistical_test"],
                reason="public StatisticalTest-v2 fixture extension",
            )
            result_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, Result)
            )
            statistical_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, StatisticalTest)
            )
            final_scope = resolve_current_research_state_bindings(
                registry,
                ledger,
                run_id="global-run-1",
                state_artifact_hashes=(
                    result_materialized.artifact.sha256,
                    statistical_materialized.artifact.sha256,
                ),
            )
            self.assertEqual(
                final_scope.object("Result", "result-1").research_object,
                graph["result"],
            )
            self.assertEqual(
                final_scope.object(
                    "StatisticalTest",
                    "statistical-test-result-1",
                ).research_object,
                graph["statistical_test"],
            )
            self.assertFalse(
                final_scope.object(
                    "Result",
                    "result-1",
                ).scientific_evidence_eligible
            )
            completions = tuple(
                item
                for item in registry.list_records()
                if item.logical_type
                == "scientific_result_state_bundle_completion"
            )
            self.assertEqual(len(completions), 2)
            self.assertEqual(
                {
                    json.loads(registry.get_bytes(item.sha256))[
                        "statistical_test_id"
                    ]
                    for item in completions
                },
                {None, "statistical-test-result-1"},
            )

            # A Result-only retry after the child exists is an idempotent prefix
            # retry, never a contradictory third completion with a null child.
            event_count = ledger.assert_valid().event_count
            completion_count = len(completions)
            repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                reason="idempotent Result-only retry after Test completion",
            )
            self.assertEqual(ledger.assert_valid().event_count, event_count)
            self.assertEqual(
                sum(
                    item.logical_type
                    == "scientific_result_state_bundle_completion"
                    for item in registry.list_records()
                ),
                completion_count,
            )

    def test_scientific_result_scope_rejects_completion_and_ancestor_corrections(
        self,
    ) -> None:
        for correction_kind in ("completion", "method-ancestor"):
            with self.subTest(correction_kind=correction_kind):
                with tempfile.TemporaryDirectory() as directory:
                    source = _scientific_v2_source_fixture(Path(directory))
                    graph = _scientific_v2_state_graph(source)
                    repository = source["repository"]
                    registry = source["registry"]
                    ledger = source["ledger"]
                    completed = (
                        repository.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                            reason=(
                                "materialize source-bound correction regression"
                            ),
                        )
                    )
                    result_materialized = next(
                        item
                        for item in completed
                        if isinstance(item.research_object, Result)
                    )
                    if correction_kind == "completion":
                        completion = next(
                            item
                            for item in registry.list_records()
                            if item.logical_type
                            == "scientific_result_state_bundle_completion"
                        )
                        superseded_event_id = (
                            f"rsb-{completion.sha256[:48]}"
                        )
                    else:
                        method_materialized = next(
                            item
                            for item in completed
                            if isinstance(item.research_object, Method)
                        )
                        superseded_event_id = method_materialized.event.event_id
                    ledger.append_correction(
                        superseded_event_id,
                        actor_role=Role.ORCHESTRATOR,
                        reason=(
                            "withdraw a required source-bound authority event"
                        ),
                        corrected_fields={"authority": "WITHDRAWN"},
                        event_id=f"withdraw-{correction_kind}",
                        timestamp=_timestamp_after(
                            ledger.assert_valid().events[-1].timestamp,
                            1,
                        ),
                    )
                    with self.assertRaisesRegex(
                        ValidationError,
                        "corrected|non-lineage correction",
                    ):
                        resolve_current_research_state_bindings(
                            registry,
                            ledger,
                            run_id="global-run-1",
                            state_artifact_hashes=(
                                result_materialized.artifact.sha256,
                            ),
                        )

    def test_scientific_bundle_rejects_mixed_repository_identity_before_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            assert isinstance(repository, ResearchStateRepository)
            assert isinstance(registry, ArtifactRegistry)
            assert isinstance(ledger, EventLedger)
            anchor_time = _timestamp_after(ledger.assert_valid().events[-1].timestamp, 1)
            repository.materialize(
                replace(
                    self.question("rq-scientific-bundle-identity"),
                    created_at=anchor_time,
                    code_version=repository.code_version,
                    content_hash=None,
                )
            )
            graph = _scientific_v2_state_graph(source)
            other_state = (
                MacroState.CLAIMS
                if repository.state != MacroState.CLAIMS
                else MacroState.GROUND
            )
            wrong_repositories = (
                ResearchStateRepository(
                    registry,
                    ledger,
                    run_id=repository.run_id,
                    code_version=repository.code_version,
                    configuration_hash=repository.configuration_hash,
                    state=other_state,
                    creation_command=repository.creation_command,
                ),
                ResearchStateRepository(
                    registry,
                    ledger,
                    run_id=repository.run_id,
                    code_version=repository.code_version,
                    configuration_hash=repository.configuration_hash,
                    state=repository.state,
                    creation_command=("scientist-one", "wrong-bundle-writer"),
                ),
                ResearchStateRepository(
                    registry,
                    ledger,
                    run_id="wrong-run",
                    code_version=repository.code_version,
                    configuration_hash=repository.configuration_hash,
                    state=repository.state,
                    creation_command=repository.creation_command,
                ),
                ResearchStateRepository(
                    registry,
                    ledger,
                    run_id=repository.run_id,
                    code_version="wrong-code-v1",
                    configuration_hash=repository.configuration_hash,
                    state=repository.state,
                    creation_command=repository.creation_command,
                ),
                ResearchStateRepository(
                    registry,
                    ledger,
                    run_id=repository.run_id,
                    code_version=repository.code_version,
                    configuration_hash="f" * 64,
                    state=repository.state,
                    creation_command=repository.creation_command,
                ),
            )
            for wrong in wrong_repositories:
                with self.subTest(command=wrong.creation_command):
                    record_count = len(registry.list_records())
                    event_count = ledger.assert_valid().event_count
                    with self.assertRaises(ValidationError):
                        wrong.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                            statistical_test=graph["statistical_test"],
                        )
                    self.assertEqual(len(registry.list_records()), record_count)
                    self.assertEqual(ledger.assert_valid().event_count, event_count)

    def test_scientific_result_v2_semantic_mutations_are_preflight_atomic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            contract = source["values"]["contract"]
            primary_metric_id = contract.primary_metric.metric_id
            split_id = contract.dataset.train_split_id
            good = _scientific_v2_state_graph(source)
            state_count = sum(
                item.logical_type.startswith("research_state.")
                for item in registry.list_records()
            )
            event_count = ledger.assert_valid().event_count

            for invalid_reason in ("", "   ", "x" * 8193, 7):
                with self.subTest(invalid_reason=repr(invalid_reason)):
                    with self.assertRaises(ValidationError):
                        repository.materialize_scientific_result_bundle(
                            ancestors=good["ancestors"],
                            result=good["result"],
                            reason=invalid_reason,  # type: ignore[arg-type]
                        )
                    self.assertEqual(
                        sum(
                            item.logical_type.startswith("research_state.")
                            for item in registry.list_records()
                        ),
                        state_count,
                    )
                    self.assertEqual(ledger.assert_valid().event_count, event_count)

            cases: list[tuple[str, dict[str, dict[str, object]]]] = [
                (
                    "Method object ID",
                    {"Method": {"object_id": "method-caller-controlled"}},
                ),
                ("Method name", {"Method": {"name": "CALLER_METHOD"}}),
                (
                    "Method description",
                    {"Method": {"description": "CALLER_DESCRIPTION"}},
                ),
                (
                    "Method assumptions",
                    {"Method": {"assumptions": ("caller assumption",)}},
                ),
                (
                    "Method components",
                    {"Method": {"component_ids": ("caller-component",)}},
                ),
                (
                    "Implementation object ID",
                    {
                        "Implementation": {
                            "object_id": "implementation-caller-controlled"
                        }
                    },
                ),
                (
                    "Implementation code artifacts",
                    {
                        "Implementation": {
                            "code_artifact_hashes": (
                                source["values"]["configuration_record"].sha256,
                            ),
                        }
                    },
                ),
                (
                    "Implementation configuration artifacts",
                    {
                        "Implementation": {
                            "configuration_artifact_hashes": (
                                source["values"]["code_record"].sha256,
                            ),
                        }
                    },
                ),
                (
                    "Hypothesis object ID",
                    {
                        "Hypothesis": {
                            "object_id": "hypothesis-caller-controlled"
                        }
                    },
                ),
                (
                    "Hypothesis statement",
                    {"Hypothesis": {"statement": "CALLER_STATEMENT"}},
                ),
                (
                    "Hypothesis motivation",
                    {"Hypothesis": {"motivation": "CALLER_MOTIVATION"}},
                ),
                (
                    "Hypothesis prior evidence",
                    {
                        "Hypothesis": {
                            "prior_evidence_ids": ("caller-evidence",)
                        }
                    },
                ),
                (
                    "Hypothesis prediction",
                    {"Hypothesis": {"prediction": "CALLER_PREDICTION"}},
                ),
                (
                    "Hypothesis falsification condition",
                    {
                        "Hypothesis": {
                            "falsification_condition": "CALLER_FALSIFICATION"
                        }
                    },
                ),
                (
                    "Hypothesis planned experiment",
                    {
                        "Hypothesis": {
                            "planned_experiment_ids": ("caller-experiment",)
                        }
                    },
                ),
                ("Dataset name", {"Dataset": {"name": "CALLER_DATASET"}}),
                (
                    "Dataset version",
                    {"Dataset": {"version": "CALLER_VERSION"}},
                ),
                (
                    "Dataset access status",
                    {"Dataset": {"access_status": "AVAILABLE"}},
                ),
                (
                    "Dataset license",
                    {"Dataset": {"license": "CALLER_LICENSE"}},
                ),
                (
                    "Split unit",
                    {f"Split:{split_id}": {"unit_type": "subject"}},
                ),
                (
                    "Split definition artifacts",
                    {
                        f"Split:{split_id}": {
                            "definition_artifact_hashes": (
                                source["values"]["contract_record"].sha256,
                            )
                        }
                    },
                ),
                (
                    "Split Dataset ID",
                    {
                        f"Split:{split_id}": {
                            "dataset_id": "caller-dataset"
                        }
                    },
                ),
                (
                    "Split role",
                    {
                        f"Split:{split_id}": {
                            "split_role": SplitRole.VALIDATION
                        }
                    },
                ),
            ]

            for metric in good["metrics"]:
                metric_key = f"Metric:{metric.object_id}"
                label = (
                    "primary Metric"
                    if metric.object_id == primary_metric_id
                    else f"secondary Metric {metric.object_id}"
                )
                cases.append(
                    (
                        f"{label} name",
                        {metric_key: {"name": "CALLER_METRIC_NAME"}},
                    )
                )
                direction = (
                    MetricDirection.DESCRIPTIVE_ONLY
                    if metric.direction
                    is not MetricDirection.DESCRIPTIVE_ONLY
                    else MetricDirection.LOWER_IS_BETTER
                )
                direction_mutations: dict[str, dict[str, object]] = {
                    metric_key: {"direction": direction}
                }
                if metric.object_id == primary_metric_id:
                    direction_mutations["Result"] = {"direction": direction}
                cases.append((f"{label} direction", direction_mutations))
                unit_mutations: dict[str, dict[str, object]] = {
                    metric_key: {"unit": "CALLER_UNIT"}
                }
                if metric.object_id == primary_metric_id:
                    unit_mutations["Result"] = {"unit": "CALLER_UNIT"}
                cases.append((f"{label} unit", unit_mutations))
                metric_level = (
                    MetricLevel.INTERMEDIATE
                    if metric.evidence_level is not MetricLevel.INTERMEDIATE
                    else MetricLevel.END_TO_END
                )
                cases.append(
                    (
                        f"{label} scope",
                        {metric_key: {"evidence_level": metric_level}},
                    )
                )
                cases.extend(
                    (
                        (
                            f"{label} lifecycle",
                            {metric_key: {"status": RecordStatus.DRAFT}},
                        ),
                        (
                            f"{label} contract authority",
                            {metric_key: {"authority_artifact_hashes": ()}},
                        ),
                        (
                            f"{label} unexpected parent",
                            {
                                metric_key: {
                                    "parents": (
                                        ObjectReference(
                                            "Dataset",
                                            good["dataset"].object_id,
                                            good["dataset"].content_hash,
                                            "reports",
                                            True,
                                        ),
                                    )
                                }
                            },
                        ),
                    )
                )

            for baseline, baseline_spec in zip(
                good["baselines"],
                contract.baseline_registry.entries,
            ):
                baseline_key = f"Baseline:{baseline.object_id}"
                metric_id = baseline_spec.conditions.metric_id
                cases.extend(
                    (
                        (
                            f"Baseline {baseline.object_id} object ID",
                            {
                                baseline_key: {
                                    "object_id": "baseline-caller-controlled"
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} name",
                            {baseline_key: {"name": "CALLER_BASELINE"}},
                        ),
                        (
                            f"Baseline {baseline.object_id} Method ID",
                            {baseline_key: {"method_id": "caller-method"}},
                        ),
                        (
                            f"Baseline {baseline.object_id} Implementation ID",
                            {
                                baseline_key: {
                                    "implementation_id": "caller-implementation"
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} paper ID",
                            {baseline_key: {"paper_id": "caller-paper"}},
                        ),
                        (
                            f"Baseline {baseline.object_id} Metric IDs",
                            {
                                baseline_key: {
                                    "metric_ids": (
                                        contract.secondary_metrics[0].metric_id,
                                    )
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} status",
                            {
                                baseline_key: {
                                    "baseline_status": BaselineStatus.SHOULD_RUN
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} reported metrics",
                            {
                                baseline_key: {
                                    "reported_metrics": {metric_id: 0.25}
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} expected metrics",
                            {
                                baseline_key: {
                                    "expected_metrics": {metric_id: 0.25}
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} observed metrics",
                            {
                                baseline_key: {
                                    "observed_metrics": {metric_id: 0.25}
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} tuning search",
                            {
                                baseline_key: {
                                    "tuning_budget": {
                                        "hyperparameter_search": "CALLER_SEARCH",
                                        "trials": (
                                            baseline_spec.conditions.tuning_trials
                                        ),
                                    }
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} tuning trials",
                            {
                                baseline_key: {
                                    "tuning_budget": {
                                        "hyperparameter_search": (
                                            baseline_spec.conditions
                                            .hyperparameter_search
                                        ),
                                        "trials": (
                                            baseline_spec.conditions.tuning_trials
                                            + 1
                                        ),
                                    }
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} compute budget",
                            {
                                baseline_key: {
                                    "compute_budget": {
                                        "budget": (
                                            baseline_spec.conditions.compute_budget
                                            + 1.0
                                        ),
                                        "hardware_class": (
                                            baseline_spec.conditions.hardware_class
                                        ),
                                    }
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} hardware class",
                            {
                                baseline_key: {
                                    "compute_budget": {
                                        "budget": (
                                            baseline_spec.conditions.compute_budget
                                        ),
                                        "hardware_class": "CALLER_HARDWARE",
                                    }
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} confidence",
                            {
                                baseline_key: {
                                    "implementation_confidence": 0.25
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} fairness",
                            {
                                baseline_key: {
                                    "fairness_assessment": "CALLER_FAIRNESS"
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} lifecycle",
                            {
                                baseline_key: {
                                    "status": RecordStatus.DRAFT
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} contract authority",
                            {
                                baseline_key: {
                                    "authority_artifact_hashes": ()
                                }
                            },
                        ),
                        (
                            f"Baseline {baseline.object_id} unexpected parent",
                            {
                                baseline_key: {
                                    "parents": (
                                        ObjectReference(
                                            "Dataset",
                                            good["dataset"].object_id,
                                            good["dataset"].content_hash,
                                            "reports",
                                            True,
                                        ),
                                    )
                                }
                            },
                        ),
                    )
                )

            experiment = good["experiment"]
            alternate_compute = (
                ComputeProfile.GPU_CLOUD
                if experiment.compute_profile is ComputeProfile.LOCAL_MAC
                else ComputeProfile.LOCAL_MAC
            )
            cases.extend(
                (
                    (
                        "Experiment purpose",
                        {"Experiment": {"scientific_purpose": "CALLER_PURPOSE"}},
                    ),
                    (
                        "Experiment compute profile",
                        {"Experiment": {"compute_profile": alternate_compute}},
                    ),
                    (
                        "Experiment outputs",
                        {
                            "Experiment": {
                                "expected_output_types": ("CALLER_OUTPUT",)
                            }
                        },
                    ),
                    (
                        "Experiment evaluator",
                        {"Experiment": {"evaluator": "CALLER_EVALUATOR"}},
                    ),
                    (
                        "Experiment configuration",
                        {
                            "Experiment": {
                                "configuration_artifact_hashes": (
                                    source["values"]["contract_record"].sha256,
                                )
                            }
                        },
                    ),
                    (
                        "Experiment Hypothesis IDs",
                        {
                            "Experiment": {
                                "hypothesis_ids": ("caller-hypothesis",)
                            }
                        },
                    ),
                    (
                        "Experiment Implementation ID",
                        {
                            "Experiment": {
                                "implementation_id": "caller-implementation"
                            }
                        },
                    ),
                    (
                        "Experiment Dataset IDs",
                        {"Experiment": {"dataset_ids": ("caller-dataset",)}},
                    ),
                    (
                        "Experiment Split IDs",
                        {
                            "Experiment": {
                                "split_ids": tuple(
                                    reversed(experiment.split_ids)
                                )
                            }
                        },
                    ),
                    (
                        "Experiment Metric IDs",
                        {
                            "Experiment": {
                                "metric_ids": tuple(
                                    reversed(experiment.metric_ids)
                                )
                            }
                        },
                    ),
                    (
                        "Experiment Baseline IDs",
                        {
                            "Experiment": {
                                "baseline_ids": ("caller-baseline",)
                            }
                        },
                    ),
                )
            )
            seed_alternatives = {
                "best_of_n": not bool(experiment.seed_policy["best_of_n"]),
                "preserve_all_runs": not bool(
                    experiment.seed_policy["preserve_all_runs"]
                ),
                "regime": "CALLER_REGIME",
                "run_seed_policy": "CALLER_SEED_POLICY",
                "seeds": [999],
                "selection_defined_before_results": not bool(
                    experiment.seed_policy[
                        "selection_defined_before_results"
                    ]
                ),
                "selection_policy": "CALLER_SELECTION_POLICY",
                "technical_retry_rule": "CALLER_RETRY_RULE",
            }
            for key, value in seed_alternatives.items():
                changed_seed_policy = dict(experiment.seed_policy)
                changed_seed_policy[key] = value
                cases.append(
                    (
                        f"Experiment seed policy {key}",
                        {"Experiment": {"seed_policy": changed_seed_policy}},
                    )
                )
            for key, value in experiment.budget.items():
                changed_budget = dict(experiment.budget)
                changed_budget[key] = value + 1
                cases.append(
                    (
                        f"Experiment budget {key}",
                        {"Experiment": {"budget": changed_budget}},
                    )
                )
            for key in experiment.termination_conditions:
                changed_termination = dict(experiment.termination_conditions)
                changed_termination[key] = ["CALLER_TERMINATION"]
                cases.append(
                    (
                        f"Experiment termination {key}",
                        {
                            "Experiment": {
                                "termination_conditions": changed_termination
                            }
                        },
                    )
                )

            run = good["run"]
            cases.extend(
                (
                    (
                        "Run producer role",
                        {"Run": {"producer": Role.REPRODUCTION_VERIFIER}},
                    ),
                    (
                        "Run execution code",
                        {
                            "Run": {
                                "code_revision": SCIENTIFIC_V2_STATE_CODE_VERSION
                            }
                        },
                    ),
                    (
                        "Run compute profile",
                        {"Run": {"compute_profile": alternate_compute}},
                    ),
                    (
                        "Run evaluator",
                        {"Run": {"evaluator_version": "CALLER_EVALUATOR"}},
                    ),
                    (
                        "Run start timestamp",
                        {"Run": {"started_at": "2026-01-01T00:00:00Z"}},
                    ),
                    (
                        "Run completion timestamp",
                        {"Run": {"completed_at": run.started_at}},
                    ),
                    (
                        "Run output order",
                        {
                            "Run": {
                                "output_artifact_hashes": tuple(
                                    reversed(run.output_artifact_hashes)
                                )
                            }
                        },
                    ),
                    (
                        "Run configuration",
                        {
                            "Run": {
                                "configuration_artifact_hash": (
                                    source["values"]["contract_record"].sha256
                                )
                            }
                        },
                    ),
                    (
                        "Run seeds",
                        {"Run": {"random_seeds": (999,)}},
                    ),
                    (
                        "Run Dataset IDs",
                        {"Run": {"dataset_ids": ("caller-dataset",)}},
                    ),
                    (
                        "lifecycle status",
                        {"Dataset": {"status": RecordStatus.ACTIVE}},
                    ),
                    (
                        "lifecycle metadata",
                        {"Metric:accuracy": {"metadata": {"caller": True}}},
                    ),
                    (
                        "lifecycle relationships",
                        {
                            "Baseline:baseline-strong": {
                                "relationships": (
                                    ObjectLink(
                                        "Metric",
                                        primary_metric_id,
                                        "caller_link",
                                        True,
                                    ),
                                )
                            }
                        },
                    ),
                    (
                        "lifecycle code version",
                        {"Dataset": {"code_version": "caller-state-version"}},
                    ),
                    (
                        "lifecycle duplicate timestamp",
                        {"Result": {"created_at": run.created_at}},
                    ),
                )
            )
            for name, mutations in cases:
                with self.subTest(name=name):
                    graph = _scientific_v2_state_graph(source, mutations)
                    with self.assertRaises(ValidationError):
                        repository.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                        )
                    self.assertEqual(
                        sum(
                            item.logical_type.startswith("research_state.")
                            for item in registry.list_records()
                        ),
                        state_count,
                    )
                    self.assertEqual(ledger.assert_valid().event_count, event_count)

    def test_scientific_result_v2_rejects_split_and_dual_identity_splices(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            good = _scientific_v2_state_graph(source)
            split = good["splits"][0]
            primary_metric = good["metrics"][0]
            event_count = ledger.assert_valid().event_count
            state_count = sum(
                item.logical_type.startswith("research_state.")
                for item in registry.list_records()
            )
            result_projection = source["projection"].result_state_projection
            result_sources = result_projection.state_source_artifact_hashes
            with self.assertRaisesRegex(
                ValidationError,
                "result code revision and envelope code version disagree",
            ):
                _scientific_v2_state_graph(
                    source,
                    {
                        "Result": {
                            "code_revision": (
                                result_projection.execution_code_revision
                            )
                        }
                    },
                )
            self.assertEqual(ledger.assert_valid().event_count, event_count)
            cases = (
                (
                    "Split relation",
                    {
                        f"Split:{split.object_id}": {
                            "parents": (
                                replace(split.parents[0], relation="uses"),
                            )
                        }
                    },
                ),
                (
                    "Run execution code",
                    {
                        "Run": {
                            "code_revision": SCIENTIFIC_V2_STATE_CODE_VERSION
                        }
                    },
                ),
                (
                    "Metric and Result direction",
                    {
                        f"Metric:{primary_metric.object_id}": {
                            "direction": MetricDirection.LOWER_IS_BETTER
                        },
                        "Result": {
                            "direction": MetricDirection.LOWER_IS_BETTER
                        },
                    },
                ),
                (
                    "Result receipt",
                    {
                        "Result": {
                            "authority_artifact_hashes": result_sources,
                            "evaluation_artifact_hashes": (),
                        }
                    },
                ),
                (
                    "Result parent relation",
                    {
                        "Result": {
                            "parents": (
                                replace(good["result"].parents[0], relation="uses"),
                                good["result"].parents[1],
                            )
                        }
                    },
                ),
            )
            for name, mutations in cases:
                with self.subTest(name=name):
                    graph = _scientific_v2_state_graph(source, mutations)
                    with self.assertRaises(ValidationError):
                        repository.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                        )
                    self.assertEqual(ledger.assert_valid().event_count, event_count)
                    self.assertEqual(
                        sum(
                            item.logical_type.startswith("research_state.")
                            for item in registry.list_records()
                        ),
                        state_count,
                    )

            repository.materialize_scientific_result_bundle(
                ancestors=good["ancestors"],
                result=good["result"],
            )
            result_completion_event_count = ledger.assert_valid().event_count
            result_completion_state_count = sum(
                item.logical_type.startswith("research_state.")
                for item in registry.list_records()
            )
            statistical_sources = (
                source["projection"].statistical_state_projection
                .state_source_artifact_hashes
            )
            for name, mutations in (
                (
                    "StatisticalTest receipt",
                    {
                        "StatisticalTest": {
                            "authority_artifact_hashes": statistical_sources,
                            "source_artifact_hashes": statistical_sources,
                        }
                    },
                ),
                (
                    "StatisticalTest parent",
                    {
                        "StatisticalTest": {
                            "parents": (
                                replace(
                                    good["statistical_test"].parents[0],
                                    relation="reports",
                                ),
                            )
                        }
                    },
                ),
            ):
                with self.subTest(name=name):
                    graph = _scientific_v2_state_graph(source, mutations)
                    with self.assertRaises(ValidationError):
                        repository.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                            statistical_test=graph["statistical_test"],
                        )
                    self.assertEqual(
                        ledger.assert_valid().event_count,
                        result_completion_event_count,
                    )
                    self.assertEqual(
                        sum(
                            item.logical_type.startswith("research_state.")
                            for item in registry.list_records()
                        ),
                        result_completion_state_count,
                    )

    def test_scientific_result_v2_completion_collisions_are_preflight_atomic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for collision_kind in ("receipt", "event"):
                with self.subTest(collision_kind=collision_kind):
                    fixture_root = Path(directory) / collision_kind
                    fixture_root.mkdir()
                    source = _scientific_v2_source_fixture(fixture_root)
                    graph = _scientific_v2_state_graph(source)
                    repository = source["repository"]
                    registry = source["registry"]
                    ledger = source["ledger"]

                    if collision_kind == "receipt":
                        registry.put_json(
                            {
                                "ledger_run_id": "global-run-1",
                                "result_id": graph["result"].object_id,
                                "statistical_test_id": None,
                                "collision": True,
                            },
                            logical_type=(
                                "scientific_result_state_bundle_completion"
                            ),
                            origin="injected completion-receipt collision",
                            creator_role=Role.CLAIM_VERIFIER,
                            creation_command=(
                                "scientist-one",
                                "state-authority-test",
                            ),
                            parent_artifacts=(
                                source["candidate"]["receipt_record"].sha256,
                            ),
                            schema_version="1.0",
                            mime_type="application/json",
                            validation_result="PASS",
                            frozen=True,
                        )
                    else:
                        digest, _completion_time, _metadata = (
                            _scientific_v2_completion_identity(source, graph)
                        )
                        ledger_head = ledger.assert_valid().events[-1]
                        ledger.record(
                            run_id="global-run-1",
                            actor_role=Role.CLAIM_VERIFIER,
                            state_before=repository.state,
                            requested_state_after=repository.state,
                            artifact_hashes=(
                                source["candidate"]["receipt_record"].sha256,
                            ),
                            code_version=SCIENTIFIC_V2_STATE_CODE_VERSION,
                            configuration_hash=repository.configuration_hash,
                            reason="injected completion-event collision",
                            event_id=f"rsb-{digest[:48]}",
                            timestamp=ledger_head.timestamp,
                            event_type="CHECKPOINT",
                            metadata={"collision": True},
                        )

                    registry_count = len(registry.list_records())
                    event_count = ledger.assert_valid().event_count
                    with self.assertRaisesRegex(
                        ValidationError,
                        "completion.*collid|collides.*completion",
                    ):
                        repository.materialize_scientific_result_bundle(
                            ancestors=graph["ancestors"],
                            result=graph["result"],
                        )
                    self.assertEqual(len(registry.list_records()), registry_count)
                    self.assertEqual(ledger.assert_valid().event_count, event_count)
                    self.assertFalse(
                        any(
                            item.logical_type.startswith("research_state.")
                            for item in registry.list_records()
                        )
                    )

    def test_scientific_result_v2_completion_receipt_without_event_resumes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            initial_event_count = ledger.assert_valid().event_count
            original_append = ledger._append_locked

            def interrupt_completion_event(guard, build_event):
                def inspect_event(current):
                    event = build_event(current)
                    if event.event_id.startswith("rsb-"):
                        raise RuntimeError(
                            "injected completion event interruption"
                        )
                    return event

                return original_append(guard, inspect_event)

            ledger._append_locked = interrupt_completion_event
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected completion event interruption",
                ):
                    repository.materialize_scientific_result_bundle(
                        ancestors=graph["ancestors"],
                        result=graph["result"],
                    )
            finally:
                ledger._append_locked = original_append

            completions = tuple(
                item
                for item in registry.list_records()
                if item.logical_type
                == "scientific_result_state_bundle_completion"
            )
            self.assertEqual(len(completions), 1)
            self.assertEqual(
                sum(
                    item.logical_type.startswith("research_state.")
                    for item in registry.list_records()
                ),
                len(graph["ancestors"]) + 1,
            )
            self.assertEqual(
                ledger.assert_valid().event_count,
                initial_event_count + len(graph["ancestors"]) + 1,
            )
            self.assertFalse(
                any(
                    event.event_id.startswith("rsb-")
                    for event in ledger.assert_valid().events
                )
            )
            result_record = next(
                item
                for item in registry.list_records()
                if item.logical_type == "research_state.result"
            )
            with self.assertRaisesRegex(
                ValidationError,
                "bundle-completion|bundle completion",
            ):
                resolve_current_research_state_bindings(
                    registry,
                    ledger,
                    run_id="global-run-1",
                    state_artifact_hashes=(result_record.sha256,),
                )

            registry_count = len(registry.list_records())
            event_count = ledger.assert_valid().event_count
            resumed = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                reason="resume completion receipt lacking its event",
            )
            self.assertEqual(len(resumed), len(graph["ancestors"]) + 1)
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(ledger.assert_valid().event_count, event_count + 1)
            scoped = resolve_current_research_state_bindings(
                registry,
                ledger,
                run_id="global-run-1",
                state_artifact_hashes=(result_record.sha256,),
            )
            self.assertEqual(
                scoped.object("Result", "result-1").research_object,
                graph["result"],
            )

    def test_scientific_result_v2_ledger_byte_capacity_is_preflight_atomic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            registry_count = len(registry.list_records())
            ledger_result = ledger.assert_valid()
            original_limit = research_state_module.MAX_LEDGER_BYTES
            # Simulate a valid ledger with only one byte of remaining capacity;
            # even the first deterministic state event cannot fit.
            research_state_module.MAX_LEDGER_BYTES = (
                ledger_result.valid_prefix_bytes + 1
            )
            try:
                with self.assertRaisesRegex(
                    ValidationError,
                    "ledger byte capacity",
                ):
                    repository.materialize_scientific_result_bundle(
                        ancestors=graph["ancestors"],
                        result=graph["result"],
                    )
            finally:
                research_state_module.MAX_LEDGER_BYTES = original_limit
            self.assertEqual(len(registry.list_records()), registry_count)
            self.assertEqual(
                ledger.assert_valid().event_count,
                ledger_result.event_count,
            )
            self.assertFalse(
                any(
                    item.logical_type.startswith("research_state.")
                    for item in registry.list_records()
                )
            )

    def test_scientific_result_v2_interruption_has_no_completion_and_retries_prefix(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            original = repository._persist_prevalidated_scientific_bundle_record

            def interrupt_after_dataset(record, **kwargs):
                materialized = original(record, **kwargs)
                if isinstance(record, Dataset):
                    raise RuntimeError("injected mid-ancestor interruption")
                return materialized

            repository._persist_prevalidated_scientific_bundle_record = (
                interrupt_after_dataset
            )
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "injected mid-ancestor interruption",
                ):
                    repository.materialize_scientific_result_bundle(
                        ancestors=graph["ancestors"],
                        result=graph["result"],
                    )
            finally:
                repository._persist_prevalidated_scientific_bundle_record = (
                    original
                )
            self.assertFalse(
                any(
                    item.logical_type
                    == "scientific_result_state_bundle_completion"
                    for item in registry.list_records()
                )
            )
            prefix = []
            for record in graph["ancestors"]:
                prefix.append(record)
                if isinstance(record, Dataset):
                    break
            expected_prefix_hashes = {
                hashlib.sha256(record.canonical_bytes()).hexdigest()
                for record in prefix
            }
            state_records = tuple(
                item
                for item in registry.list_records()
                if item.logical_type.startswith("research_state.")
            )
            self.assertEqual(
                {item.sha256 for item in state_records},
                expected_prefix_hashes,
            )
            self.assertEqual(
                {item.logical_type for item in state_records},
                {
                    "research_state.method",
                    "research_state.implementation",
                    "research_state.hypothesis",
                    "research_state.dataset",
                },
            )
            self.assertFalse(
                any(
                    item.logical_type
                    in {
                        "research_state.split",
                        "research_state.metric",
                        "research_state.baseline",
                        "research_state.experiment",
                        "research_state.run",
                        "research_state.result",
                        "research_state.statistical_test",
                    }
                    for item in registry.list_records()
                )
            )
            prefix_metadata = {
                item.sha256: item for item in state_records
            }
            prefix_events = {
                event.event_id: event.event_hash
                for event in ledger.assert_valid().events
                if event.event_id
                in {f"rs-{digest[:48]}" for digest in expected_prefix_hashes}
            }
            self.assertEqual(len(prefix_events), len(prefix))

            retried = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                reason="resume exact interrupted scientific Result prefix",
            )
            self.assertEqual(len(retried), len(graph["ancestors"]) + 1)
            self.assertEqual(
                {
                    digest: registry.get_metadata(digest)
                    for digest in expected_prefix_hashes
                },
                prefix_metadata,
            )
            self.assertEqual(
                {
                    event.event_id: event.event_hash
                    for event in ledger.assert_valid().events
                    if event.event_id in prefix_events
                },
                prefix_events,
            )
            result_record = next(
                item
                for item in registry.list_records()
                if item.logical_type == "research_state.result"
            )
            scoped = resolve_current_research_state_bindings(
                registry,
                ledger,
                run_id="global-run-1",
                state_artifact_hashes=(result_record.sha256,),
            )
            self.assertEqual(
                scoped.object("Result", "result-1").research_object,
                graph["result"],
            )
            materialization_events = tuple(
                event
                for event in ledger.assert_valid().events
                if event.metadata.get("research_state_operation")
                == "MATERIALIZED"
            )
            self.assertEqual(
                len(materialization_events),
                len(graph["ancestors"]) + 1,
            )

    def test_scientific_result_table_resumes_exact_artifact_only_prefix(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            completed = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                statistical_test=graph["statistical_test"],
            )
            result_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, Result)
            )
            test_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, StatisticalTest)
            )
            metric = next(
                item
                for item in graph["ancestors"]
                if isinstance(item, Metric)
            )
            resolved_sources = (
                graph["result"],
                graph["statistical_test"],
                metric,
                result_materialized.artifact,
                test_materialized.artifact,
                repository,
            )
            initial_events = ledger.assert_valid().event_count
            def interrupt_table_event(guard, build_event):
                raise RuntimeError("injected result-table interruption")

            with (
                patch.object(
                    research_state_module,
                    "_resolve_scientific_result_table_sources",
                    return_value=resolved_sources,
                ),
                patch.object(
                    ledger,
                    "_append_locked",
                    side_effect=interrupt_table_event,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "injected result-table interruption",
                ),
            ):
                research_state_module.register_scientific_result_table(
                    registry,
                    ledger,
                    run_id="global-run-1",
                    result_state_artifact_hash=(
                        result_materialized.artifact.sha256
                    ),
                    statistical_test_state_artifact_hash=(
                        test_materialized.artifact.sha256
                    ),
                )
            tables = tuple(
                item
                for item in registry.list_records()
                if item.logical_type
                == research_state_module.SCIENTIFIC_RESULT_TABLE_LOGICAL_TYPE
            )
            self.assertEqual(len(tables), 1)
            self.assertEqual(ledger.assert_valid().event_count, initial_events)

            with patch.object(
                research_state_module,
                "_resolve_scientific_result_table_sources",
                return_value=resolved_sources,
            ):
                resumed = (
                    research_state_module.register_scientific_result_table(
                        registry,
                        ledger,
                        run_id="global-run-1",
                        result_state_artifact_hash=(
                            result_materialized.artifact.sha256
                        ),
                        statistical_test_state_artifact_hash=(
                            test_materialized.artifact.sha256
                        ),
                    )
                )
                retried = (
                    research_state_module.register_scientific_result_table(
                        registry,
                        ledger,
                        run_id="global-run-1",
                        result_state_artifact_hash=(
                            result_materialized.artifact.sha256
                        ),
                        statistical_test_state_artifact_hash=(
                            test_materialized.artifact.sha256
                        ),
                    )
                )
            self.assertEqual(resumed, tables[0])
            self.assertEqual(retried, resumed)
            self.assertEqual(
                ledger.assert_valid().event_count,
                initial_events + 1,
            )
            self.assertEqual(
                sum(
                    event.event_id
                    == f"scientific-result-table-{resumed.sha256[:32]}"
                    for event in ledger.assert_valid().events
                ),
                1,
            )

    def test_scientific_result_table_preflights_capacity_and_event_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _scientific_v2_source_fixture(Path(directory))
            graph = _scientific_v2_state_graph(source)
            repository = source["repository"]
            registry = source["registry"]
            ledger = source["ledger"]
            completed = repository.materialize_scientific_result_bundle(
                ancestors=graph["ancestors"],
                result=graph["result"],
                statistical_test=graph["statistical_test"],
            )
            result_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, Result)
            )
            test_materialized = next(
                item
                for item in completed
                if isinstance(item.research_object, StatisticalTest)
            )
            metric = next(
                item
                for item in graph["ancestors"]
                if isinstance(item, Metric)
            )
            resolved_sources = (
                graph["result"],
                graph["statistical_test"],
                metric,
                result_materialized.artifact,
                test_materialized.artifact,
                repository,
            )
            table_bytes = research_state_module._scientific_result_table_bytes(
                graph["result"],
                metric,
                graph["statistical_test"],
            )
            table_hash = hashlib.sha256(table_bytes).hexdigest()
            initial_registry_count = len(registry.list_records())
            with (
                patch.object(
                    research_state_module,
                    "_resolve_scientific_result_table_sources",
                    return_value=resolved_sources,
                ),
                patch.object(
                    research_state_module,
                    "MAX_REGISTRY_RECORDS",
                    initial_registry_count,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "registry capacity",
                ),
            ):
                research_state_module.register_scientific_result_table(
                    registry,
                    ledger,
                    run_id="global-run-1",
                    result_state_artifact_hash=(
                        result_materialized.artifact.sha256
                    ),
                    statistical_test_state_artifact_hash=(
                        test_materialized.artifact.sha256
                    ),
                )
            self.assertEqual(
                len(registry.list_records()),
                initial_registry_count,
            )

            ledger.record(
                run_id="global-run-1",
                actor_role=Role.STATISTICIAN,
                state_before=repository.state,
                requested_state_after=repository.state,
                artifact_hashes=(result_materialized.artifact.sha256,),
                code_version=repository.code_version,
                configuration_hash=repository.configuration_hash,
                reason="inject a result-table event-ID collision",
                event_id=f"scientific-result-table-{table_hash[:32]}",
                timestamp=graph["statistical_test"].created_at,
                event_type="CHECKPOINT",
                metadata={"collision": True},
            )
            before_collision = len(registry.list_records())
            with (
                patch.object(
                    research_state_module,
                    "_resolve_scientific_result_table_sources",
                    return_value=resolved_sources,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "event precedes|event collides",
                ),
            ):
                research_state_module.register_scientific_result_table(
                    registry,
                    ledger,
                    run_id="global-run-1",
                    result_state_artifact_hash=(
                        result_materialized.artifact.sha256
                    ),
                    statistical_test_state_artifact_hash=(
                        test_materialized.artifact.sha256
                    ),
                )
            self.assertEqual(len(registry.list_records()), before_collision)
            self.assertFalse(
                any(
                    item.logical_type
                    == research_state_module.SCIENTIFIC_RESULT_TABLE_LOGICAL_TYPE
                    for item in registry.list_records()
                )
            )

    def test_scientific_result_table_serializes_capacity_and_event_id_races(
        self,
    ) -> None:
        for race_kind in ("capacity", "event-id"):
            with self.subTest(race_kind=race_kind), tempfile.TemporaryDirectory() as directory:
                outer = Path(directory)
                root = outer / "project"
                root.mkdir()
                source = _scientific_v2_source_fixture(root)
                graph = _scientific_v2_state_graph(source)
                repository = source["repository"]
                registry = source["registry"]
                ledger = source["ledger"]
                completed = repository.materialize_scientific_result_bundle(
                    ancestors=graph["ancestors"],
                    result=graph["result"],
                    statistical_test=graph["statistical_test"],
                )
                result_materialized = next(
                    item
                    for item in completed
                    if isinstance(item.research_object, Result)
                )
                test_materialized = next(
                    item
                    for item in completed
                    if isinstance(item.research_object, StatisticalTest)
                )
                metric = next(
                    item
                    for item in graph["ancestors"]
                    if isinstance(item, Metric)
                )
                resolved_sources = (
                    graph["result"],
                    graph["statistical_test"],
                    metric,
                    result_materialized.artifact,
                    test_materialized.artifact,
                    repository,
                )
                table_bytes = research_state_module._scientific_result_table_bytes(
                    graph["result"],
                    metric,
                    graph["statistical_test"],
                )
                table_hash = hashlib.sha256(table_bytes).hexdigest()
                table_event_id = f"scientific-result-table-{table_hash[:32]}"
                initial_event_count = ledger.assert_valid().event_count
                maximum_events = initial_event_count + 1
                started = outer / f"rival-{race_kind}-started"
                source_root = Path(research_state_module.__file__).parents[1]
                rival: subprocess.Popen[str] | None = None
                original_put = registry._put_bytes_locked
                child_program = (
                    "import pathlib,sys\n"
                    "sys.path.insert(0,sys.argv.pop(1))\n"
                    "import scientist_one.ledger as ledger_module\n"
                    "from scientist_one.ledger import EventLedger\n"
                    "from scientist_one.roles import Role\n"
                    "root=pathlib.Path(sys.argv[1]); relative=sys.argv[2]\n"
                    "started=pathlib.Path(sys.argv[3]); maximum=int(sys.argv[4])\n"
                    "event_id=sys.argv[5]; state=sys.argv[6]; code=sys.argv[7]\n"
                    "configuration=sys.argv[8]\n"
                    "if maximum >= 0: ledger_module.MAX_LEDGER_EVENTS=maximum\n"
                    "ledger=EventLedger(root,relative)\n"
                    "started.write_text('started',encoding='utf-8')\n"
                    "try:\n"
                    " ledger.record(run_id='global-run-1',actor_role=Role.STATISTICIAN,"
                    "state_before=state,requested_state_after=state,artifact_hashes=(),"
                    "code_version=code,configuration_hash=configuration,"
                    "reason='concurrent result-table rival',event_id=event_id,"
                    "event_type='CHECKPOINT',metadata={'rival':True})\n"
                    "except Exception as exc:\n"
                    " print(type(exc).__name__+':'+str(exc))\n"
                    " raise SystemExit(0)\n"
                    "raise SystemExit(9)\n"
                )

                def publish_then_start_rival(guard, data, **metadata):
                    nonlocal rival
                    record = original_put(guard, data, **metadata)
                    if (
                        rival is None
                        and metadata.get("logical_type")
                        == research_state_module.SCIENTIFIC_RESULT_TABLE_LOGICAL_TYPE
                    ):
                        rival_event_id = (
                            table_event_id
                            if race_kind == "event-id"
                            else "scientific-result-table-capacity-rival"
                        )
                        rival = subprocess.Popen(
                            [
                                sys.executable,
                                "-I",
                                "-S",
                                "-B",
                                "-c",
                                child_program,
                                str(source_root),
                                str(root),
                                ledger.relative_path.as_posix(),
                                str(started),
                                str(maximum_events if race_kind == "capacity" else -1),
                                rival_event_id,
                                repository.state.value,
                                repository.code_version,
                                repository.configuration_hash,
                            ],
                            cwd=root,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            close_fds=True,
                        )
                        deadline = time.monotonic() + 10
                        while not started.exists() and time.monotonic() < deadline:
                            if rival.poll() is not None:
                                break
                            time.sleep(0.01)
                        self.assertTrue(started.exists())
                        time.sleep(0.1)
                        self.assertIsNone(rival.poll())
                    return record

                constant_patches = [
                    patch.object(
                        research_state_module,
                        "MAX_LEDGER_EVENTS",
                        maximum_events,
                    ),
                    patch.object(
                        ledger_module,
                        "MAX_LEDGER_EVENTS",
                        maximum_events,
                    ),
                ] if race_kind == "capacity" else []
                registration_completed = False
                try:
                    for constant_patch in constant_patches:
                        constant_patch.start()
                    with (
                        patch.object(
                            research_state_module,
                            "_resolve_scientific_result_table_sources",
                            return_value=resolved_sources,
                        ),
                        patch.object(
                            registry,
                            "_put_bytes_locked",
                            side_effect=publish_then_start_rival,
                        ),
                    ):
                        table = research_state_module.register_scientific_result_table(
                            registry,
                            ledger,
                            run_id="global-run-1",
                            result_state_artifact_hash=(
                                result_materialized.artifact.sha256
                            ),
                            statistical_test_state_artifact_hash=(
                                test_materialized.artifact.sha256
                            ),
                        )
                        registration_completed = True
                finally:
                    for constant_patch in reversed(constant_patches):
                        constant_patch.stop()
                    if (
                        not registration_completed
                        and rival is not None
                        and rival.poll() is None
                    ):
                        rival.terminate()
                self.assertIsNotNone(rival)
                assert rival is not None
                rival_output, rival_error = rival.communicate(timeout=10)
                self.assertEqual(rival.returncode, 0, rival_output + rival_error)
                if race_kind == "capacity":
                    self.assertIn("limit", rival_output)
                else:
                    self.assertIn("event ID already exists", rival_output)
                events = ledger.assert_valid().events
                self.assertEqual(
                    sum(event.event_id == table_event_id for event in events),
                    1,
                )
                self.assertEqual(events[-1].event_id, table_event_id)
                self.assertEqual(table.sha256, table_hash)


if __name__ == "__main__":
    unittest.main()
