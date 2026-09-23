"""Finite non-evidentiary tests for the closed Generic-ML projection format.

These tests exercise pure parsers and API boundaries only.  They neither
provision a production trust root nor mint execution/domain authority.
"""

from __future__ import annotations

import inspect
import unittest

from scientist_one.domains import (
    SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
    SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
    SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
    require_projection_backed_scientific_domain_validity,
)
from scientist_one.generic_ml_projection import (
    GENERIC_ML_COMPARISON_SCOPE,
    GENERIC_ML_DATASET_ROW_SCHEMA,
    GENERIC_ML_FROZEN_MODEL_CONFIGURATION_SCHEMA,
    GENERIC_ML_FROZEN_MODEL_DEFINITION_SCHEMA,
    GENERIC_ML_MODEL_SCHEMA,
    GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
    GENERIC_ML_OBSERVATIONS_SCHEMA,
    GENERIC_ML_POLICY_SCHEMA,
    GENERIC_ML_PREDICTIONS_SCHEMA,
    GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA,
    GENERIC_ML_PROJECTION_AUTHORITY_SCHEMA,
    GENERIC_ML_ROBUSTNESS_SCHEMA,
    GENERIC_ML_ROBUSTNESS_TEST_ID,
    GenericMLPairedMetricProjectionAuthority,
    GenericMLProjectionError,
    derive_paired_correctness,
    parse_bounded_integer_classification_dataset,
    parse_frozen_model_configuration,
    parse_integer_linear_model,
    partition_generic_ml_manifest_outputs,
    register_generic_ml_paired_metric_projection_authority,
    require_generic_ml_paired_metric_projection_authority,
    require_reference_accuracy_policy,
    validate_duplicate_inference_robustness,
    validate_generic_ml_observation_shape,
)
from scientist_one.security import canonical_json_bytes


H = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
H4 = "d" * 64
H5 = "e" * 64
H6 = "f" * 64


def _dataset_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "scientific-dataset-source/v1",
            "dataset_id": "bounded-classification",
            "name": "bounded classification fixture",
            "version": "1",
            "license": {
                "spdx_id": "CC0-1.0",
                "canonical_url": "https://creativecommons.org/publicdomain/zero/1.0/",
            },
            "data": [
                {
                    "schema_version": GENERIC_ML_DATASET_ROW_SCHEMA,
                    "unit_id": "unit-a",
                    "features": [-1, 0],
                    "label": 0,
                },
                {
                    "schema_version": GENERIC_ML_DATASET_ROW_SCHEMA,
                    "unit_id": "unit-b",
                    "features": [1, 0],
                    "label": 1,
                },
            ],
        }
    )


def _model_bytes(*, role: str, condition_id: str, weights: list[list[int]]) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": GENERIC_ML_MODEL_SCHEMA,
            "execution_run_id": "execution-run",
            "frozen_run_spec_artifact_sha256": H,
            "frozen_run_spec_sha256": H2,
            "seed": 7,
            "role": role,
            "condition_id": condition_id,
            "code_sha256": H3,
            "configuration_sha256": H4,
            "algorithm": "LINEAR_ARGMAX_INTEGER_V1",
            "class_labels": [0, 1],
            "weights": weights,
            "bias": [0, 0],
        }
    )


def _policy() -> dict[str, object]:
    return {
        "schema_version": "scientific-domain-policy/v1",
        "domain": "GENERIC_ML",
        "source_format_id": "trusted-kernel-generic-ml-observations",
        "source_format_version": GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        "preprocessing_fit_split_ids": [],
        "checkpoint_selection_split_id": None,
        "early_stopping": {"enabled": False, "monitor_split_id": None},
        "augmentation": {
            "mode": "NONE",
            "fit_split_ids": [],
            "application_split_ids": [],
        },
        "metric_policy": {
            "schema_version": GENERIC_ML_POLICY_SCHEMA,
            "metric_id": "accuracy",
            "semantics": "EXACT_INTEGER_LABEL_MATCH",
            "aggregation": "MICRO_EXAMPLE_MEAN",
            "unit": "FRACTION",
            "direction": "HIGHER_IS_BETTER",
        },
        "generalization_scope": "WITHIN_DATASET_ONLY",
        "comparison_scope": GENERIC_ML_COMPARISON_SCOPE,
    }


def _frozen_definition(
    *, role: str, condition_id: str, weights: list[list[int]]
) -> dict[str, object]:
    return {
        "schema_version": GENERIC_ML_FROZEN_MODEL_DEFINITION_SCHEMA,
        "role": role,
        "condition_id": condition_id,
        "algorithm": "LINEAR_ARGMAX_INTEGER_V1",
        "class_labels": [0, 1],
        "weights": weights,
        "bias": [0, 0],
    }


def _frozen_configuration(*, seeds: tuple[int, ...] = (7,)) -> dict[str, object]:
    return {
        "schema_version": GENERIC_ML_FROZEN_MODEL_CONFIGURATION_SCHEMA,
        "contract_artifact_sha256": H,
        "contract_sha256": H2,
        "dataset_id": "bounded-classification",
        "dataset_split_id": "confirmatory",
        "evaluator_id": "reference-evaluator",
        "metric_id": "accuracy",
        "metric_unit": "FRACTION",
        "metric_scope": "PER_EXAMPLE",
        "executed_baseline_ids": ["baseline-condition"],
        "comparison_scope": GENERIC_ML_COMPARISON_SCOPE,
        "seed_model_definitions": [
            {
                "seed": seed,
                "candidate_model": _frozen_definition(
                    role="CANDIDATE",
                    condition_id="candidate-condition",
                    weights=[[-1, 0], [1, 0]],
                ),
                "baseline_model": _frozen_definition(
                    role="BASELINE",
                    condition_id="baseline-condition",
                    weights=[[1, 0], [-1, 0]],
                ),
            }
            for seed in seeds
        ],
    }


class GenericMLPureProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = parse_bounded_integer_classification_dataset(_dataset_bytes())
        self.candidate = parse_integer_linear_model(
            _model_bytes(
                role="CANDIDATE",
                condition_id="candidate-condition",
                weights=[[-1, 0], [1, 0]],
            ),
            execution_run_id="execution-run",
            frozen_run_spec_artifact_sha256=H,
            frozen_run_spec_sha256=H2,
            seed=7,
            role="CANDIDATE",
            condition_id="candidate-condition",
            code_sha256=H3,
            configuration_sha256=H4,
            expected_class_labels=(0, 1),
            feature_count=2,
        )
        self.baseline = parse_integer_linear_model(
            _model_bytes(
                role="BASELINE",
                condition_id="baseline-condition",
                weights=[[1, 0], [-1, 0]],
            ),
            execution_run_id="execution-run",
            frozen_run_spec_artifact_sha256=H,
            frozen_run_spec_sha256=H2,
            seed=7,
            role="BASELINE",
            condition_id="baseline-condition",
            code_sha256=H3,
            configuration_sha256=H4,
            expected_class_labels=(0, 1),
            feature_count=2,
        )

    def _predictions(self) -> dict[str, object]:
        return {
            "schema_version": GENERIC_ML_PREDICTIONS_SCHEMA,
            "execution_run_id": "execution-run",
            "frozen_run_spec_artifact_sha256": H,
            "frozen_run_spec_sha256": H2,
            "seed": 7,
            "evaluator_artifact_sha256": H3,
            "confirmatory_split_authority_artifact_sha256": H4,
            "metric_policy": _policy()["metric_policy"],
            "candidate_model_artifact_sha256": H5,
            "baseline_model_artifact_sha256": H6,
            "rows": [
                {
                    "unit_id": row.unit_id,
                    "unit_hash": row.unit_hash,
                    "candidate_prediction": self.candidate.predict(row.features),
                    "baseline_prediction": self.baseline.predict(row.features),
                }
                for row in self.rows
            ],
        }

    def test_dataset_labels_and_model_counts_are_derived(self) -> None:
        self.assertEqual(tuple(row.label for row in self.rows), (0, 1))
        self.assertEqual(self.candidate.parameter_count, 6)
        self.assertEqual(self.baseline.parameter_count, 6)
        self.assertEqual(
            tuple(self.candidate.predict(row.features) for row in self.rows),
            (0, 1),
        )
        with self.assertRaises(GenericMLProjectionError):
            parse_integer_linear_model(
                _model_bytes(
                    role="CANDIDATE",
                    condition_id="candidate-condition",
                    weights=[[-1, 0], [1, 0]],
                ),
                execution_run_id="execution-run",
                frozen_run_spec_artifact_sha256=H,
                frozen_run_spec_sha256=H2,
                seed=8,
                role="CANDIDATE",
                condition_id="candidate-condition",
                code_sha256=H3,
                configuration_sha256=H4,
                expected_class_labels=(0, 1),
                feature_count=2,
            )

    def test_models_are_exactly_precommitted_before_execution(self) -> None:
        configuration = _frozen_configuration()
        frozen = parse_frozen_model_configuration(
            canonical_json_bytes(configuration),
            contract_artifact_sha256=H,
            contract_sha256=H2,
            dataset_id="bounded-classification",
            dataset_split_id="confirmatory",
            evaluator_id="reference-evaluator",
            metric_id="accuracy",
            metric_unit="FRACTION",
            metric_scope="PER_EXAMPLE",
            executed_baseline_ids=("baseline-condition",),
            seed_order=(7,),
            candidate_condition_id="candidate-condition",
            baseline_condition_id="baseline-condition",
            expected_class_labels=(0, 1),
            feature_count=2,
        )
        self.assertEqual(frozen, ((self.candidate, self.baseline),))
        for mutation in ("seed", "condition", "score", "missing"):
            changed = _frozen_configuration()
            definition = changed["seed_model_definitions"][0]
            if mutation == "seed":
                definition["seed"] = 8
            elif mutation == "condition":
                definition["baseline_model"]["condition_id"] = "substituted"
            elif mutation == "score":
                definition["candidate_model"]["score"] = 1.0
            else:
                changed["seed_model_definitions"] = []
            with self.assertRaises(GenericMLProjectionError, msg=mutation):
                parse_frozen_model_configuration(
                    canonical_json_bytes(changed),
                    contract_artifact_sha256=H,
                    contract_sha256=H2,
                    dataset_id="bounded-classification",
                    dataset_split_id="confirmatory",
                    evaluator_id="reference-evaluator",
                    metric_id="accuracy",
                    metric_unit="FRACTION",
                    metric_scope="PER_EXAMPLE",
                    executed_baseline_ids=("baseline-condition",),
                    seed_order=(7,),
                    candidate_condition_id="candidate-condition",
                    baseline_condition_id="baseline-condition",
                    expected_class_labels=(0, 1),
                    feature_count=2,
                )

    def test_paired_correctness_is_exact_micro_accuracy(self) -> None:
        require_reference_accuracy_policy(
            _policy()["metric_policy"],
            metric_id="accuracy",
            metric_unit="FRACTION",
            metric_direction="HIGHER_IS_BETTER",
            metric_aggregation="MICRO_EXAMPLE_MEAN",
        )
        for mutation in ("metric_id", "semantics", "aggregation"):
            changed = dict(_policy()["metric_policy"])
            changed[mutation] = {
                "metric_id": "balanced-accuracy",
                "semantics": "TOP_K_LABEL_MATCH",
                "aggregation": "BALANCED_CLASS_MEAN",
            }[mutation]
            with self.assertRaises(GenericMLProjectionError):
                require_reference_accuracy_policy(
                    changed,
                    metric_id="accuracy",
                    metric_unit="FRACTION",
                    metric_direction="HIGHER_IS_BETTER",
                    metric_aggregation="MICRO_EXAMPLE_MEAN",
                )
        candidate, baseline, candidate_mean, baseline_mean = derive_paired_correctness(
            canonical_json_bytes(self._predictions()),
            execution_run_id="execution-run",
            frozen_run_spec_artifact_sha256=H,
            frozen_run_spec_sha256=H2,
            seed=7,
            evaluator_artifact_sha256=H3,
            confirmatory_split_authority_artifact_sha256=H4,
            metric_policy=_policy()["metric_policy"],
            candidate_model_artifact_sha256=H5,
            baseline_model_artifact_sha256=H6,
            candidate_model=self.candidate,
            baseline_model=self.baseline,
            rows=self.rows,
        )
        self.assertEqual(candidate, (1.0, 1.0))
        self.assertEqual(baseline, (0.0, 0.0))
        self.assertEqual((candidate_mean, baseline_mean), (1.0, 0.0))

    def test_predictions_reject_labels_scores_and_wrong_model_outputs(self) -> None:
        for extra_name, extra_value in (("expected_label", 0), ("score", 1.0), ("PASS", True)):
            value = self._predictions()
            value["rows"][0][extra_name] = extra_value
            with self.assertRaises(GenericMLProjectionError):
                derive_paired_correctness(
                    canonical_json_bytes(value),
                    execution_run_id="execution-run",
                    frozen_run_spec_artifact_sha256=H,
                    frozen_run_spec_sha256=H2,
                    seed=7,
                    evaluator_artifact_sha256=H3,
                    confirmatory_split_authority_artifact_sha256=H4,
                    metric_policy=_policy()["metric_policy"],
                    candidate_model_artifact_sha256=H5,
                    baseline_model_artifact_sha256=H6,
                    candidate_model=self.candidate,
                    baseline_model=self.baseline,
                    rows=self.rows,
                )
        value = self._predictions()
        value["rows"][0]["candidate_prediction"] = 1
        with self.assertRaises(GenericMLProjectionError):
            derive_paired_correctness(
                canonical_json_bytes(value),
                execution_run_id="execution-run",
                frozen_run_spec_artifact_sha256=H,
                frozen_run_spec_sha256=H2,
                seed=7,
                evaluator_artifact_sha256=H3,
                confirmatory_split_authority_artifact_sha256=H4,
                metric_policy=_policy()["metric_policy"],
                candidate_model_artifact_sha256=H5,
                baseline_model_artifact_sha256=H6,
                candidate_model=self.candidate,
                baseline_model=self.baseline,
                rows=self.rows,
            )

    def test_robustness_is_replayed_not_a_status_label(self) -> None:
        value = {
            "schema_version": GENERIC_ML_ROBUSTNESS_SCHEMA,
            "execution_run_id": "execution-run",
            "frozen_run_spec_artifact_sha256": H,
            "frozen_run_spec_sha256": H2,
            "seed": 7,
            "robustness_test_id": GENERIC_ML_ROBUSTNESS_TEST_ID,
            "evaluator_artifact_sha256": H3,
            "confirmatory_split_authority_artifact_sha256": H4,
            "candidate_model_artifact_sha256": H5,
            "rows": [
                {
                    "unit_id": row.unit_id,
                    "unit_hash": row.unit_hash,
                    "first_prediction": self.candidate.predict(row.features),
                    "second_prediction": self.candidate.predict(row.features),
                }
                for row in self.rows
            ],
        }
        validate_duplicate_inference_robustness(
            canonical_json_bytes(value),
            execution_run_id="execution-run",
            frozen_run_spec_artifact_sha256=H,
            frozen_run_spec_sha256=H2,
            seed=7,
            evaluator_artifact_sha256=H3,
            confirmatory_split_authority_artifact_sha256=H4,
            candidate_model_artifact_sha256=H5,
            candidate_model=self.candidate,
            rows=self.rows,
        )
        value["status"] = "PASS"
        with self.assertRaises(GenericMLProjectionError):
            validate_duplicate_inference_robustness(
                canonical_json_bytes(value),
                execution_run_id="execution-run",
                frozen_run_spec_artifact_sha256=H,
                frozen_run_spec_sha256=H2,
                seed=7,
                evaluator_artifact_sha256=H3,
                confirmatory_split_authority_artifact_sha256=H4,
                candidate_model_artifact_sha256=H5,
                candidate_model=self.candidate,
                rows=self.rows,
            )

    def test_observations_require_policy_inventory_and_full_seed_order(self) -> None:
        def seed(seed_value: int, digest: str) -> dict[str, object]:
            return {
                "seed": seed_value,
                "candidate_model_artifact_sha256": digest,
                "candidate_model_record_hash": H2,
                "baseline_model_artifact_sha256": H3,
                "baseline_model_record_hash": H4,
                "paired_predictions_artifact_sha256": H5,
                "paired_predictions_record_hash": H6,
            }

        def robust(seed_value: int, digest: str) -> dict[str, object]:
            return {
                "seed": seed_value,
                "robustness_test_id": GENERIC_ML_ROBUSTNESS_TEST_ID,
                "artifact_sha256": digest,
                "artifact_record_hash": H2,
            }

        value = {
            "schema_version": GENERIC_ML_OBSERVATIONS_SCHEMA,
            "actual_domain_policy": _policy(),
            "loaded_pretrained_resource_inventory": {
                "schema_version": GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA,
                "completeness": "EXHAUSTIVE",
                "artifact_sha256s": [],
            },
            "seed_outputs": [seed(3, H), seed(7, H2)],
            "robustness_outputs": [robust(3, H3), robust(7, H4)],
        }
        outputs, robustness = validate_generic_ml_observation_shape(
            value,
            prospective_policy=_policy(),
            seed_order=(3, 7),
        )
        self.assertEqual(tuple(item["seed"] for item in outputs), (3, 7))
        self.assertEqual(tuple(item["seed"] for item in robustness), (3, 7))
        for mutation in ("reorder", "missing", "pass", "pretrained", "policy"):
            changed = {
                **value,
                "seed_outputs": [dict(item) for item in value["seed_outputs"]],
                "robustness_outputs": [
                    dict(item) for item in value["robustness_outputs"]
                ],
                "loaded_pretrained_resource_inventory": dict(
                    value["loaded_pretrained_resource_inventory"]
                ),
                "actual_domain_policy": dict(value["actual_domain_policy"]),
            }
            if mutation == "reorder":
                changed["seed_outputs"].reverse()
            elif mutation == "missing":
                changed["robustness_outputs"].pop()
            elif mutation == "pass":
                changed["seed_outputs"][0]["status"] = "PASS"
            elif mutation == "pretrained":
                changed["loaded_pretrained_resource_inventory"]["artifact_sha256s"] = [H]
            else:
                changed["actual_domain_policy"]["preprocessing_fit_split_ids"] = ["holdout"]
            with self.assertRaises(GenericMLProjectionError, msg=mutation):
                validate_generic_ml_observation_shape(
                    changed,
                    prospective_policy=_policy(),
                    seed_order=(3, 7),
                )

    def test_new_authority_is_disjoint_and_source_only_at_registration(self) -> None:
        self.assertNotEqual(
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
            GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        )
        self.assertNotEqual(
            SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
            SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
        )
        self.assertEqual(
            set(inspect.signature(register_generic_ml_paired_metric_projection_authority).parameters),
            {
                "registry",
                "ledger",
                "scientific_domain_evidence_source_artifact_sha256",
            },
        )
        require_parameters = set(
            inspect.signature(require_generic_ml_paired_metric_projection_authority).parameters
        )
        self.assertFalse({"score", "metric", "seed", "status", "passed"} & require_parameters)
        self.assertIn("projection_artifact_sha256", require_parameters)
        self.assertIn("projection", GENERIC_ML_PROJECTION_AUTHORITY_SCHEMA)
        self.assertIn(
            "frozen_model_configuration_artifact_sha256",
            GenericMLPairedMetricProjectionAuthority.__dataclass_fields__,
        )
        self.assertIn(
            "ledger",
            inspect.signature(
                require_projection_backed_scientific_domain_validity
            ).parameters,
        )

    def test_manifest_partition_rejects_missing_or_extra_domain_outputs(self) -> None:
        domain_indexes, ablation_indexes = partition_generic_ml_manifest_outputs(
            output_artifact_sha256s=(H, H2, H3),
            output_artifact_record_hashes=(H4, H5, H6),
            output_logical_types=(
                "experiment_output.generic_ml_model",
                "experiment_output.ablation_output",
                "experiment_output.generic_ml_paired_predictions",
            ),
            expected_domain_output_artifact_sha256s=(H, H3),
            required_ablation_count=1,
        )
        self.assertEqual(domain_indexes, (0, 2))
        self.assertEqual(ablation_indexes, (1,))
        for expected in ((H,), (H, H2, H3)):
            with self.assertRaises(GenericMLProjectionError):
                partition_generic_ml_manifest_outputs(
                    output_artifact_sha256s=(H, H2, H3),
                    output_artifact_record_hashes=(H4, H5, H6),
                    output_logical_types=(
                        "experiment_output.generic_ml_model",
                        "experiment_output.ablation_output",
                        "experiment_output.generic_ml_paired_predictions",
                    ),
                    expected_domain_output_artifact_sha256s=expected,
                    required_ablation_count=1,
                )


if __name__ == "__main__":
    unittest.main()
