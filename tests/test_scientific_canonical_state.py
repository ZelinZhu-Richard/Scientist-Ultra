"""Bounded canonical-state regressions for Phase-2 scientific owners.

All values in this module are inert mechanical fixtures.  No production
scientific backend verifier is installed and no fixture is evidence.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import scientist_one.research_state as research_state_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.research_state import (
    ComputeProfile,
    Experiment,
    MetricDirection as StateMetricDirection,
    RecordStatus,
    Result,
    Run,
    require_current_scientific_execution_run,
    require_scientific_reproducibility_package,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    HypothesisStatus,
    MetricDirection,
    MetricScope,
    MetricUnit,
    SCIENTIFIC_EXECUTION_CANONICAL_RUN_SCHEMA,
    SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3,
    SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3,
    ScientificDesignError,
    ScientificResultCanonicalProjectionV3,
    ScientificResultOutcome,
)


STAMP = "2026-09-04T12:00:00Z"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _projection(
    *,
    outcome: ScientificResultOutcome = ScientificResultOutcome.NEGATIVE,
    status: HypothesisStatus = HypothesisStatus.NOT_SUPPORTED,
) -> ScientificResultCanonicalProjectionV3:
    return ScientificResultCanonicalProjectionV3(
        ledger_run_id="ledger-run",
        execution_run_id="execution-run",
        result_id="result-primary",
        experiment_id="experiment-primary",
        hypothesis_id="hypothesis-primary",
        promotion_receipt_artifact_sha256=_hash("promotion"),
        contract_artifact_sha256=_hash("contract"),
        checked_result_assessment_artifact_sha256=_hash("assessment"),
        scientific_execution_authority_artifact_sha256=_hash("execution"),
        frozen_run_spec_artifact_sha256=_hash("spec"),
        output_manifest_artifact_sha256=_hash("manifest"),
        environment_artifact_sha256=_hash("environment"),
        aggregate_result_sha256=_hash("aggregate"),
        statistical_analysis_sha256=_hash("statistics"),
        configuration_artifact_sha256=_hash("configuration"),
        data_artifact_sha256=_hash("data"),
        evaluator_artifact_sha256=_hash("evaluator"),
        output_artifact_sha256s=(_hash("output-a"), _hash("output-b")),
        metric_id="metric-primary",
        metric_unit=MetricUnit.FRACTION,
        metric_direction=MetricDirection.HIGHER_IS_BETTER,
        metric_scope=MetricScope.END_TO_END,
        baseline_id="baseline-primary",
        baseline_value=0.50,
        candidate_value=0.49,
        improvement_effect=-0.01,
        confidence_low=-0.03,
        confidence_high=0.01,
        raw_p_value=0.40,
        adjusted_p_value=0.40,
        sample_size=40,
        hypothesis_status=status,
        outcome=outcome,
        contract_primary_test="two-sided exact paired test",
        contract_effect_size="paired directional mean difference",
        checked_procedure_id="paired-procedure-v1",
        checked_effect_method="paired arithmetic mean",
        confidence_method="paired bootstrap",
        confidence_level=0.95,
        bootstrap_seed=7,
        bootstrap_resamples=1000,
        resampling_unit="subject",
        multiplicity_correction="holm",
        seed_order=(7, 11),
        execution_code_revision=f"sha256:{_hash('code')}",
        canonical_state_code_version="canonical-state-v3",
        evaluator_version="evaluator-v1",
        run_started_at="2026-09-04T12:00:00Z",
        run_completed_at="2026-09-04T12:00:01.250000Z",
        observed_at="2026-09-04T12:00:01.250000Z",
    )


def _experiment(object_id: str = "experiment-primary") -> Experiment:
    return Experiment(
        object_id=object_id,
        producer=Role.PROTOCOL_DESIGNER,
        status=RecordStatus.FROZEN,
        created_at=STAMP,
        code_version="canonical-state-v3",
        hypothesis_ids=("hypothesis-primary",),
        scientific_purpose="Exercise a bounded structural regression.",
        implementation_id="implementation-primary",
        dataset_ids=("dataset-primary",),
        split_ids=("split-confirmatory",),
        metric_ids=("metric-primary",),
        baseline_ids=("baseline-primary",),
        compute_profile=ComputeProfile.LOCAL_MAC,
        seed_policy={"seeds": [7, 11]},
        expected_output_types=("aggregate",),
        evaluator="evaluator-v1",
        budget={"runs": 2},
        termination_conditions={"max_failures": 1},
    )


def _result(object_id: str = "result-primary") -> Result:
    return Result(
        object_id=object_id,
        producer=Role.STATISTICIAN,
        status=RecordStatus.COMPLETE,
        created_at="2026-09-04T12:00:02Z",
        code_version="canonical-state-v3",
        run_ids=("execution-run",),
        metric_id="metric-primary",
        value={"improvement": -0.01},
        unit="FRACTION",
        direction=StateMetricDirection.HIGHER_IS_BETTER,
        uncertainty={"confidence_low": -0.03, "confidence_high": 0.01},
        source_artifact_hashes=(_hash("aggregate"),),
        evaluation_artifact_hashes=(_hash("promotion"),),
        code_revision="canonical-state-v3",
        observed_at="2026-09-04T12:00:01.250000Z",
    )


class ScientificCanonicalStateTests(unittest.TestCase):
    def test_outcome_neutral_projection_retains_adverse_result(self) -> None:
        projection = _projection()

        self.assertEqual(
            projection.state_metadata,
            {
                "schema_version": SCIENTIFIC_RESULT_CANONICAL_STATE_SCHEMA_V3,
                "checked_result_assessment_artifact_sha256": _hash("assessment"),
                "hypothesis_id": "hypothesis-primary",
                "hypothesis_status": "NOT_SUPPORTED",
                "scientific_result_outcome": "NEGATIVE",
                "superiority_authority_artifact_sha256": None,
            },
        )
        self.assertEqual(
            projection.run_metadata["schema_version"],
            SCIENTIFIC_EXECUTION_CANONICAL_RUN_SCHEMA,
        )
        self.assertEqual(
            projection.statistical_state_metadata["schema_version"],
            SCIENTIFIC_STATISTICAL_CANONICAL_STATE_SCHEMA_V3,
        )
        self.assertEqual(
            projection.statistical_state_outcome["scientific_result_outcome"],
            "NEGATIVE",
        )
        self.assertIn(
            projection.promotion_receipt_artifact_sha256,
            projection.state_authority_artifact_hashes,
        )
        self.assertIn(
            projection.scientific_execution_authority_artifact_sha256,
            projection.run_authority_artifact_hashes,
        )
        self.assertFalse(projection.scientific_authority)

    def test_projection_rejects_semantically_inconsistent_or_reversed_state(
        self,
    ) -> None:
        projection = _projection()
        with self.assertRaises(ScientificDesignError):
            replace(
                projection,
                outcome=ScientificResultOutcome.FALSIFIED,
                hypothesis_status=HypothesisStatus.NOT_SUPPORTED,
            )
        with self.assertRaises(ScientificDesignError):
            replace(projection, confidence_low=0.2, confidence_high=-0.2)
        with self.assertRaises(ScientificDesignError):
            replace(
                projection,
                run_started_at="2026-09-04T12:00:02Z",
                run_completed_at="2026-09-04T12:00:01Z",
                observed_at="2026-09-04T12:00:01Z",
            )

    def test_run_timestamp_order_is_parsed_not_compared_lexically(self) -> None:
        common = {
            "object_id": "execution-run",
            "producer": Role.EXPERIMENT_RUNNER,
            "status": RecordStatus.COMPLETE,
            "created_at": "2026-09-04T12:00:02Z",
            "code_version": f"sha256:{_hash('code')}",
            "experiment_id": "experiment-primary",
            "code_revision": f"sha256:{_hash('code')}",
            "dataset_ids": ("dataset-primary",),
            "configuration_artifact_hash": _hash("configuration"),
            "compute_profile": ComputeProfile.LOCAL_MAC,
            "random_seeds": (7,),
            "output_artifact_hashes": (_hash("output"),),
            "evaluator_version": "evaluator-v1",
        }
        valid = Run(
            **common,
            started_at="2026-09-04T12:00:00Z",
            completed_at="2026-09-04T12:00:00.900000Z",
        )
        self.assertEqual(valid.completed_at, "2026-09-04T12:00:00.900000Z")
        with self.assertRaisesRegex(ValidationError, "completion precedes start"):
            Run(
                **common,
                started_at="2026-09-04T12:00:00.900000Z",
                completed_at="2026-09-04T12:00:00Z",
            )

    def test_reproduction_anchor_requires_the_exact_result_revision(self) -> None:
        anchor_result = _result()
        other_result = _result("result-other")
        experiment = _experiment()
        self.assertTrue(
            research_state_module._scientific_reproduction_matches_anchor(
                anchor_result=anchor_result,
                anchor_experiment=experiment,
                reproduction_results=(anchor_result,),
                reproduction_experiments=((experiment,), (experiment,)),
            )
        )
        self.assertFalse(
            research_state_module._scientific_reproduction_matches_anchor(
                anchor_result=anchor_result,
                anchor_experiment=experiment,
                reproduction_results=(other_result,),
                reproduction_experiments=((experiment,), (experiment,)),
            )
        )

    def test_typed_fixture_blobs_cannot_resolve_as_canonical_science(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/ledger-run/registry")
            ledger = EventLedger(root, "runs/ledger-run/events.jsonl")
            result_record = registry.put_json(
                {"fixture": "result"},
                logical_type="research_state.result",
                origin="SYSTEM_FIXTURE non-evidentiary forged state",
                creator_role=Role.STATISTICIAN,
                creation_command=("scientist-one", "test-only-forgery"),
                frozen=True,
            )
            run_records = tuple(
                registry.put_json(
                    {"fixture": label},
                    logical_type="research_state.run",
                    origin="SYSTEM_FIXTURE non-evidentiary forged state",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "test-only-forgery"),
                    frozen=True,
                )
                for label in ("original", "rerun")
            )
            package_record = registry.put_json(
                {"fixture": "package", "scientific_evidence": False},
                logical_type="research_state.reproducibility_package",
                origin="SYSTEM_FIXTURE non-evidentiary forged state",
                creator_role=Role.REPRODUCTION_VERIFIER,
                creation_command=("scientist-one", "test-only-forgery"),
                parent_artifacts=(
                    result_record.sha256,
                    *(item.sha256 for item in run_records),
                ),
                frozen=True,
            )
            records_before = tuple(registry.list_records())
            events_before = ledger.events()
            with self.assertRaises(ValidationError):
                require_current_scientific_execution_run(
                    registry,
                    ledger,
                    run_id="ledger-run",
                    run_state_artifact_sha256=run_records[0].sha256,
                    expected_execution_run_id="original-execution",
                )
            with self.assertRaises(ValidationError):
                require_scientific_reproducibility_package(
                    registry,
                    ledger,
                    package_state_artifact_sha256=package_record.sha256,
                    expected_ledger_run_id="ledger-run",
                    expected_package_id="package-primary",
                )
            self.assertEqual(tuple(registry.list_records()), records_before)
            self.assertEqual(ledger.events(), events_before)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
