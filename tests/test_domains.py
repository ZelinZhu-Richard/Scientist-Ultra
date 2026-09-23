"""Offline clean/adversarial tests for domain-owned validity predicates."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.domains import (
    DOMAIN_ADAPTERS,
    DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
    DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
    AugmentationMode,
    AugmentationPolicyEvidence,
    ComparisonDisposition,
    DomainAdapter,
    DomainEvidenceScope,
    DomainInputError,
    DomainKind,
    DomainValidityLimitation,
    DomainValidityStatus,
    EarlyStoppingPolicyEvidence,
    GenericMLAdapter,
    GenericMLExample,
    GenericMLValidityEvidence,
    MLPolicyTiming,
    MedicalAnalysisUnit,
    MedicalClassificationSemantics,
    MedicalClassificationTarget,
    MedicalClinicalInterpretationEvidence,
    MedicalClinicalUse,
    MedicalImageRepresentation,
    MedicalImageObservation,
    MedicalImagingAdapter,
    MedicalImagingValidityEvidence,
    MedicalMetric,
    MedicalRegistrationReference,
    MedicalRegistrationSemantics,
    MedicalRegistrationTransform,
    MedicalSegmentationSemantics,
    MedicalSegmentationTarget,
    MedicalTask,
    MedicalThresholdBasis,
    MedicalThresholdRelation,
    MedicalThresholdUnit,
    MetricDirection,
    MetricScope,
    ModelResourceComparisonEvidence,
    ObjectiveDirection,
    OperationsResearchAdapter,
    OperationsResearchValidityEvidence,
    OptimizationInstanceResult,
    PretrainedContaminationStatus,
    PretrainedResourceEvidence,
    PretrainedResourcePolicyEvidence,
    RecommenderInteraction,
    RecommenderSplitStrategy,
    RecommenderSystemsAdapter,
    RecommenderValidityEvidence,
    SplitRole,
    SystemsAdapter,
    SystemsClaimScope,
    SystemsMeasurement,
    SystemsValidityEvidence,
    TimeSeriesAdapter,
    TimeSeriesValidityEvidence,
    TimeSeriesWindow,
    get_domain_adapter,
    materialize_domain_validity,
    register_domain_evidence_source,
    register_domain_raw_fixture_source,
    require_scientific_domain_validity,
    resolve_domain_validity,
)
from scientist_one.roles import Role
from scientist_one.security import safe_json_loads


def _codes(outcome: object) -> set[str]:
    return set(outcome.machine_codes)  # type: ignore[attr-defined]


def _sha256(hex_character: str) -> str:
    return hex_character * 64


def clean_generic_ml() -> GenericMLValidityEvidence:
    return GenericMLValidityEvidence(
        examples=(
            GenericMLExample("train-1", SplitRole.TRAIN),
            GenericMLExample("validation-1", SplitRole.VALIDATION),
            GenericMLExample("test-1", SplitRole.TEST),
        ),
        preprocessing_fit_splits=(SplitRole.TRAIN,),
        benchmark_version="benchmark-v1",
        pretrained_contamination_checked=True,
        seed_policy_frozen=True,
        checkpoint_selection_split=SplitRole.VALIDATION,
        metric_implementation_verified=True,
        hyperparameter_budget_equivalent=True,
        compute_budget_equivalent=True,
        robustness_evaluated=True,
        early_stopping_policy=EarlyStoppingPolicyEvidence(
            enabled=True,
            monitor_split=SplitRole.VALIDATION,
            policy_artifact_sha256=_sha256("a"),
            timing=MLPolicyTiming.FROZEN_BEFORE_RESULTS,
        ),
        augmentation_policy=AugmentationPolicyEvidence(
            mode=AugmentationMode.TRAINING_ONLY,
            fit_splits=(SplitRole.TRAIN,),
            application_splits=(SplitRole.TRAIN,),
            policy_artifact_sha256=_sha256("b"),
            timing=MLPolicyTiming.FROZEN_BEFORE_RESULTS,
        ),
        model_resource_comparison=ModelResourceComparisonEvidence(
            candidate_parameter_count=1_024,
            baseline_parameter_count=1_024,
            candidate_resource_profile_sha256=_sha256("c"),
            baseline_resource_profile_sha256=_sha256("d"),
            parameter_count_disposition=ComparisonDisposition.COMPARABLE,
            resource_disposition=ComparisonDisposition.COMPARABLE,
            comparison_artifact_sha256=_sha256("e"),
        ),
        pretrained_resource_policy=PretrainedResourcePolicyEvidence(
            resources=(),
            inventory_artifact_sha256=_sha256("f"),
            contamination_status=PretrainedContaminationStatus.NOT_APPLICABLE,
            contamination_assessment_artifact_sha256=None,
        ),
    )


def clean_medical() -> MedicalImagingValidityEvidence:
    return MedicalImagingValidityEvidence(
        observations=(
            MedicalImageObservation(
                "image-train",
                SplitRole.TRAIN,
                "patient-1",
                "subject-1",
                "session-1",
                "scan-1",
                "site-a",
            ),
            MedicalImageObservation(
                "image-test",
                SplitRole.TEST,
                "patient-2",
                "subject-2",
                "session-2",
                "scan-2",
                "site-b",
            ),
        ),
        task=MedicalTask.CLASSIFICATION,
        analysis_unit=MedicalAnalysisUnit.SLICE,
        resampling_unit=MedicalAnalysisUnit.PATIENT,
        site_disjoint_evaluation_required=True,
        modality_documented=True,
        acquisition_metadata_documented=True,
        preprocessing_frozen=True,
        calibration_evaluated=True,
        uncertainty_evaluated=True,
        subgroup_dimensions_evaluated=("site", "sex"),
        required_subgroup_dimensions=("site", "sex"),
        sensitive_data_controls_documented=True,
        external_validation_claimed=False,
        external_validation_performed=None,
        task_semantics=MedicalClassificationSemantics(
            input_representation=MedicalImageRepresentation.IMAGE_2D,
            target=MedicalClassificationTarget.BINARY,
            primary_metric=MedicalMetric.CLASSIFICATION_AUROC,
            metric_direction=MetricDirection.HIGHER_IS_BETTER,
            protocol_artifact_sha256=_sha256("1"),
        ),
        clinical_interpretation=MedicalClinicalInterpretationEvidence(
            intended_use=MedicalClinicalUse.SCREENING,
            target_population="Adults referred for screening",
            interpretation=(
                "Scores at or above the frozen operating point trigger clinician review."
            ),
            threshold_basis=MedicalThresholdBasis.MODEL_SCORE,
            threshold_value=0.70,
            threshold_unit=MedicalThresholdUnit.PROBABILITY,
            threshold_relation=MedicalThresholdRelation.AT_LEAST,
            context_artifact_sha256=_sha256("2"),
        ),
    )


def clean_time_series() -> TimeSeriesValidityEvidence:
    return TimeSeriesValidityEvidence(
        windows=(
            TimeSeriesWindow("series-1", "fold-1", SplitRole.TRAIN, 0, 9),
            TimeSeriesWindow("series-1", "fold-1", SplitRole.VALIDATION, 10, 19),
            TimeSeriesWindow("series-1", "fold-1", SplitRole.TEST, 20, 29),
        ),
        forecast_horizon_steps=5,
        evaluated_horizon_steps=5,
        label_horizon_steps=2,
        embargo_steps=2,
        feature_cutoff_verified=True,
        drift_assessed=True,
        rolling_origin_evaluated=True,
        horizon_metrics_reported=True,
        evaluator_window_frozen_before_results=True,
    )


def clean_recommender() -> RecommenderValidityEvidence:
    return RecommenderValidityEvidence(
        interactions=(
            RecommenderInteraction(
                "i-1", "user-1", "item-1", "session-1", SplitRole.TRAIN, 1
            ),
            RecommenderInteraction(
                "i-2", "user-1", "item-2", "session-2", SplitRole.TEST, 2
            ),
            RecommenderInteraction(
                "i-3", "user-2", "item-1", "session-3", SplitRole.TRAIN, 3
            ),
            RecommenderInteraction(
                "i-4", "user-2", "item-3", "session-4", SplitRole.TEST, 4
            ),
        ),
        split_strategy=RecommenderSplitStrategy.TEMPORAL,
        ranking_metrics_verified=True,
        candidate_generation_documented=True,
        negative_sampling_documented=True,
        catalog_coverage_reported=True,
        user_coverage_reported=True,
        cold_start_evaluated=True,
        off_policy_claimed=True,
        propensity_scores_available=True,
        support_overlap_verified=True,
        heldout_labels_used_for_candidate_generation=False,
        evaluator_candidate_set_changed_after_results=False,
    )


def clean_optimization() -> OperationsResearchValidityEvidence:
    return OperationsResearchValidityEvidence(
        instances=(
            OptimizationInstanceResult("instance-1", True, True, 9, 10, 9, True, True),
            OptimizationInstanceResult("instance-2", True, True, 8, 9, 8, True, True),
        ),
        objective_direction=ObjectiveDirection.MINIMIZE,
        objective_and_constraints_validated=True,
        paired_instances_verified=True,
        exact_baseline_required=True,
        exact_baseline_run=True,
        central_superiority_claimed=True,
        solver_version="solver-1.0",
        timeout_policy_equivalent=True,
        machine_specification_equivalent=True,
        random_instance_generator_frozen=True,
        scalability_evaluated=True,
        runtime_quality_tradeoff_reported=True,
        optimality_gap_reported=True,
    )


def clean_systems() -> SystemsValidityEvidence:
    return SystemsValidityEvidence(
        measurements=(
            SystemsMeasurement(
                "latency_ms",
                MetricScope.END_TO_END,
                MetricDirection.LOWER_IS_BETTER,
                (9.9, 10.0, 10.1),
                (11.9, 12.0, 12.1),
                True,
            ),
        ),
        claim_scope=SystemsClaimScope.SYSTEM_LEVEL,
        hardware_identity="host-cpu-v1",
        os_kernel_stack="os-kernel-v1",
        software_stack="runtime-v1",
        workload_manifest="workload-v1",
        workload_validated=True,
        warmup_completed=True,
        resource_isolation_verified=True,
        concurrency_documented=True,
        hardware_equivalent=True,
        runtime_environment_equivalent=True,
        tail_latency_reported=True,
        memory_reported=True,
        energy_relevant=True,
        energy_reported=True,
        evaluator_frozen_before_results=True,
        evaluator_observable_to_candidate=False,
        evaluator_specific_branching_detected=False,
    )


def _put_domain_support(
    registry: ArtifactRegistry,
    *,
    domain: DomainKind,
    source_id: str,
    role: Role,
    run_id: str,
    object_id: str,
    task_id: str,
):
    return register_domain_raw_fixture_source(
        registry,
        run_id=run_id,
        domain=domain,
        object_id=object_id,
        task_id=task_id,
        source_id=source_id,
        creator_role=role,
        payload={
            "source_id": source_id,
            "fixture_observation": f"bounded {domain.value} technical fixture",
        },
    )


def _registry_backed_evidence(
    registry: ArtifactRegistry,
    domain: DomainKind,
    *,
    run_id: str,
    object_id: str,
    task_id: str,
) -> tuple[object, tuple[str, ...]]:
    source_count = {
        DomainKind.GENERIC_ML: 6,
        DomainKind.MEDICAL_IMAGING: 2,
        DomainKind.TIME_SERIES: 2,
        DomainKind.RECOMMENDER_SYSTEMS: 2,
        DomainKind.OPERATIONS_RESEARCH: 2,
        DomainKind.SYSTEMS: 2,
    }[domain]
    records = tuple(
        _put_domain_support(
            registry,
            domain=domain,
            source_id=f"source-{index}",
            role=(Role.PROTOCOL_DESIGNER if index == 0 else Role.EXPERIMENT_RUNNER),
            run_id=run_id,
            object_id=object_id,
            task_id=task_id,
        )
        for index in range(source_count)
    )
    hashes = tuple(record.sha256 for record in records)
    if domain is DomainKind.GENERIC_ML:
        clean = clean_generic_ml()
        assert clean.early_stopping_policy is not None
        assert clean.augmentation_policy is not None
        assert clean.model_resource_comparison is not None
        assert clean.pretrained_resource_policy is not None
        evidence = replace(
            clean,
            early_stopping_policy=replace(
                clean.early_stopping_policy,
                policy_artifact_sha256=hashes[0],
            ),
            augmentation_policy=replace(
                clean.augmentation_policy,
                policy_artifact_sha256=hashes[1],
            ),
            model_resource_comparison=replace(
                clean.model_resource_comparison,
                candidate_resource_profile_sha256=hashes[2],
                baseline_resource_profile_sha256=hashes[3],
                comparison_artifact_sha256=hashes[4],
            ),
            pretrained_resource_policy=replace(
                clean.pretrained_resource_policy,
                inventory_artifact_sha256=hashes[5],
            ),
        )
    elif domain is DomainKind.MEDICAL_IMAGING:
        clean = clean_medical()
        assert clean.task_semantics is not None
        assert clean.clinical_interpretation is not None
        evidence = replace(
            clean,
            task_semantics=replace(
                clean.task_semantics,
                protocol_artifact_sha256=hashes[0],
            ),
            clinical_interpretation=replace(
                clean.clinical_interpretation,
                context_artifact_sha256=hashes[1],
            ),
        )
    elif domain is DomainKind.TIME_SERIES:
        evidence = clean_time_series()
    elif domain is DomainKind.RECOMMENDER_SYSTEMS:
        evidence = clean_recommender()
    elif domain is DomainKind.OPERATIONS_RESEARCH:
        evidence = clean_optimization()
    else:
        evidence = clean_systems()
    return evidence, hashes


def _support_descriptor(record: object) -> dict[str, object]:
    return {
        "artifact_sha256": record.sha256,  # type: ignore[attr-defined]
        "logical_type": record.logical_type,  # type: ignore[attr-defined]
        "schema_version": record.schema_version,  # type: ignore[attr-defined]
        "mime_type": record.mime_type,  # type: ignore[attr-defined]
        "origin": record.origin,  # type: ignore[attr-defined]
        "creator_role": record.creator_role.value,  # type: ignore[attr-defined]
        "creation_command": list(record.creation_command),  # type: ignore[attr-defined]
        "parent_artifacts": list(record.parent_artifacts),  # type: ignore[attr-defined]
        "validation_result": record.validation_result,  # type: ignore[attr-defined]
        "frozen": record.frozen,  # type: ignore[attr-defined]
    }


class DomainProtocolTests(unittest.TestCase):
    def test_registry_is_complete_provider_independent_and_structural(self) -> None:
        self.assertEqual(
            {adapter.domain for adapter in DOMAIN_ADAPTERS},
            set(DomainKind),
        )
        self.assertTrue(all(isinstance(adapter, DomainAdapter) for adapter in DOMAIN_ADAPTERS))
        self.assertIsInstance(get_domain_adapter(DomainKind.MEDICAL_IMAGING), MedicalImagingAdapter)

    def test_wrong_evidence_type_returns_typed_blocked_outcome(self) -> None:
        outcome = MedicalImagingAdapter().evaluate(clean_time_series())
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertEqual(outcome.machine_codes, ("MEDICAL_IMAGING_INPUT_TYPE_MISMATCH",))
        self.assertIn("typed:MedicalImagingValidityEvidence", outcome.evidence_requirements)

    def test_evidence_checks_and_outcomes_are_immutable_and_serializable(self) -> None:
        evidence = clean_medical()
        outcome = MedicalImagingAdapter().evaluate(evidence)
        with self.assertRaises(FrozenInstanceError):
            evidence.task = MedicalTask.SEGMENTATION  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            outcome.status = DomainValidityStatus.FAIL  # type: ignore[misc]
        payload = outcome.to_dict()
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(payload["machine_codes"], ["MEDICAL_IMAGING_VALIDITY_PASS"])


class GenericMLAdapterTests(unittest.TestCase):
    def test_clean_generic_ml_evidence_passes(self) -> None:
        outcome = GenericMLAdapter().evaluate(clean_generic_ml())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)
        self.assertEqual(outcome.machine_codes, ("GENERIC_ML_VALIDITY_PASS",))

    def test_split_preprocessing_checkpoint_and_budget_leakage_fail(self) -> None:
        clean = clean_generic_ml()
        adversarial = replace(
            clean,
            examples=(
                GenericMLExample("same", SplitRole.TRAIN),
                GenericMLExample("same", SplitRole.TEST),
            ),
            preprocessing_fit_splits=(SplitRole.TRAIN, SplitRole.TEST),
            checkpoint_selection_split=SplitRole.HOLDOUT,
            hyperparameter_budget_equivalent=False,
            compute_budget_equivalent=False,
            generalization_claimed=True,
            external_validation_performed=False,
        )
        outcome = GenericMLAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "ML_EXAMPLE_SPLIT_LEAKAGE",
                "ML_PREPROCESSING_LEAKAGE",
                "ML_CHECKPOINT_SELECTION_LEAKAGE",
                "ML_HYPERPARAMETER_BUDGET_UNFAIR",
                "ML_COMPUTE_BUDGET_UNFAIR",
                "ML_GENERALIZATION_OVERCLAIM",
            }.issubset(_codes(outcome))
        )

    def test_typed_policy_leakage_unfair_resources_and_contamination_fail(
        self,
    ) -> None:
        adversarial = replace(
            clean_generic_ml(),
            early_stopping_policy=EarlyStoppingPolicyEvidence(
                enabled=True,
                monitor_split=SplitRole.TEST,
                policy_artifact_sha256=_sha256("0"),
                timing=MLPolicyTiming.FROZEN_AFTER_RESULTS,
            ),
            augmentation_policy=AugmentationPolicyEvidence(
                mode=AugmentationMode.TRAINING_ONLY,
                fit_splits=(SplitRole.TRAIN, SplitRole.HOLDOUT),
                application_splits=(SplitRole.TRAIN, SplitRole.TEST),
                policy_artifact_sha256=_sha256("1"),
                timing=MLPolicyTiming.FROZEN_AFTER_RESULTS,
            ),
            model_resource_comparison=ModelResourceComparisonEvidence(
                candidate_parameter_count=10_000,
                baseline_parameter_count=100,
                candidate_resource_profile_sha256=_sha256("2"),
                baseline_resource_profile_sha256=_sha256("3"),
                parameter_count_disposition=ComparisonDisposition.UNFAIR,
                resource_disposition=ComparisonDisposition.UNFAIR,
                comparison_artifact_sha256=_sha256("4"),
            ),
            pretrained_resource_policy=PretrainedResourcePolicyEvidence(
                resources=(
                    PretrainedResourceEvidence(
                        resource_id="foundation-model",
                        version="v1",
                        artifact_sha256=_sha256("5"),
                        training_data_manifest_sha256=_sha256("6"),
                    ),
                ),
                inventory_artifact_sha256=_sha256("7"),
                contamination_status=PretrainedContaminationStatus.DETECTED,
                contamination_assessment_artifact_sha256=_sha256("8"),
            ),
        )
        outcome = GenericMLAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "ML_EARLY_STOPPING_POLICY_NOT_FROZEN",
                "ML_EARLY_STOPPING_SPLIT_LEAKAGE",
                "ML_AUGMENTATION_POLICY_NOT_FROZEN",
                "ML_AUGMENTATION_FIT_LEAKAGE",
                "ML_AUGMENTATION_APPLICATION_POLICY_INVALID",
                "ML_PARAMETER_COUNT_COMPARABILITY",
                "ML_RESOURCE_COMPARABILITY",
                "ML_PRETRAINED_CONTAMINATION_UNCHECKED",
            }.issubset(_codes(outcome))
        )

    def test_legacy_generic_ml_fields_without_typed_evidence_are_blocked(
        self,
    ) -> None:
        legacy = replace(
            clean_generic_ml(),
            early_stopping_policy=None,
            augmentation_policy=None,
            model_resource_comparison=None,
            pretrained_resource_policy=None,
        )
        outcome = GenericMLAdapter().evaluate(legacy)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertTrue(
            {
                "ML_EARLY_STOPPING_POLICY_NOT_FROZEN",
                "ML_EARLY_STOPPING_SPLIT_LEAKAGE",
                "ML_AUGMENTATION_POLICY_NOT_FROZEN",
                "ML_AUGMENTATION_FIT_LEAKAGE",
                "ML_AUGMENTATION_APPLICATION_POLICY_INVALID",
                "ML_PARAMETER_COUNT_COMPARABILITY",
                "ML_RESOURCE_COMPARABILITY",
                "ML_PRETRAINED_RESOURCE_IDENTITY_MISSING",
                "ML_PRETRAINED_CONTAMINATION_UNCHECKED",
            }.issubset(_codes(outcome))
        )

    def test_pretrained_resource_requires_training_data_identity(self) -> None:
        incomplete = replace(
            clean_generic_ml(),
            pretrained_resource_policy=PretrainedResourcePolicyEvidence(
                resources=(
                    PretrainedResourceEvidence(
                        resource_id="foundation-model",
                        version="v1",
                        artifact_sha256=_sha256("9"),
                        training_data_manifest_sha256=None,
                    ),
                ),
                inventory_artifact_sha256=_sha256("a"),
                contamination_status=PretrainedContaminationStatus.CLEAR,
                contamination_assessment_artifact_sha256=_sha256("b"),
            ),
        )
        outcome = GenericMLAdapter().evaluate(incomplete)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertIn("ML_PRETRAINED_RESOURCE_IDENTITY_MISSING", _codes(outcome))

    def test_identified_pretrained_resource_with_clear_assessment_passes(self) -> None:
        identified = replace(
            clean_generic_ml(),
            pretrained_resource_policy=PretrainedResourcePolicyEvidence(
                resources=(
                    PretrainedResourceEvidence(
                        resource_id="foundation-model",
                        version="v1",
                        artifact_sha256=_sha256("c"),
                        training_data_manifest_sha256=_sha256("d"),
                    ),
                ),
                inventory_artifact_sha256=_sha256("e"),
                contamination_status=PretrainedContaminationStatus.CLEAR,
                contamination_assessment_artifact_sha256=_sha256("f"),
            ),
        )
        outcome = GenericMLAdapter().evaluate(identified)
        self.assertIs(outcome.status, DomainValidityStatus.PASS)


class MedicalImagingAdapterTests(unittest.TestCase):
    def test_clean_patient_grouped_calibrated_study_passes(self) -> None:
        outcome = MedicalImagingAdapter().evaluate(clean_medical())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_three_dimensional_segmentation_semantics_pass(self) -> None:
        segmentation = replace(
            clean_medical(),
            task=MedicalTask.SEGMENTATION,
            analysis_unit=MedicalAnalysisUnit.VOLUME,
            task_semantics=MedicalSegmentationSemantics(
                image_representation=MedicalImageRepresentation.VOLUME_3D,
                mask_representation=MedicalImageRepresentation.VOLUME_3D,
                target=MedicalSegmentationTarget.MULTICLASS_MASK,
                primary_metric=MedicalMetric.SEGMENTATION_DICE,
                metric_direction=MetricDirection.HIGHER_IS_BETTER,
                protocol_artifact_sha256=_sha256("3"),
            ),
            clinical_interpretation=MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.TREATMENT_PLANNING,
                target_population="Adults receiving volumetric treatment planning",
                interpretation=(
                    "Volumes meeting the frozen Dice criterion may enter clinician review."
                ),
                threshold_basis=MedicalThresholdBasis.PRIMARY_METRIC,
                threshold_value=0.85,
                threshold_unit=MedicalThresholdUnit.FRACTION,
                threshold_relation=MedicalThresholdRelation.AT_LEAST,
                context_artifact_sha256=_sha256("4"),
            ),
        )
        outcome = MedicalImagingAdapter().evaluate(segmentation)
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_three_dimensional_registration_semantics_pass(self) -> None:
        registration = replace(
            clean_medical(),
            task=MedicalTask.REGISTRATION,
            analysis_unit=MedicalAnalysisUnit.VOLUME,
            task_semantics=MedicalRegistrationSemantics(
                moving_representation=MedicalImageRepresentation.VOLUME_3D,
                fixed_representation=MedicalImageRepresentation.VOLUME_3D,
                transform=MedicalRegistrationTransform.DEFORMABLE_3D,
                reference=MedicalRegistrationReference.LANDMARKS,
                primary_metric=(
                    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM
                ),
                metric_direction=MetricDirection.LOWER_IS_BETTER,
                protocol_artifact_sha256=_sha256("5"),
            ),
            clinical_interpretation=MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.PROCEDURAL_GUIDANCE,
                target_population="Adults undergoing image-guided intervention",
                interpretation=(
                    "Registrations at or below the frozen error tolerance require clinician review."
                ),
                threshold_basis=MedicalThresholdBasis.PRIMARY_METRIC,
                threshold_value=2.0,
                threshold_unit=MedicalThresholdUnit.MILLIMETERS,
                threshold_relation=MedicalThresholdRelation.AT_MOST,
                context_artifact_sha256=_sha256("6"),
            ),
        )
        outcome = MedicalImagingAdapter().evaluate(registration)
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_legacy_evidence_without_typed_semantics_blocks(self) -> None:
        legacy = replace(
            clean_medical(),
            task_semantics=None,
            clinical_interpretation=None,
        )
        outcome = MedicalImagingAdapter().evaluate(legacy)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertTrue(
            {
                "MED_TASK_SEMANTICS_INVALID",
                "MED_REPRESENTATION_TASK_INCOMPATIBLE",
                "MED_TASK_METRIC_INVALID",
                "MED_METRIC_DIRECTION_INVALID",
                "MED_CLINICAL_INTERPRETATION_MISSING",
                "MED_CLINICAL_USE_TASK_MISMATCH",
                "MED_CLINICAL_THRESHOLD_INVALID",
            }.issubset(_codes(outcome))
        )

    def test_declared_task_and_semantics_type_mismatch_fails(self) -> None:
        mismatched = replace(clean_medical(), task=MedicalTask.SEGMENTATION)
        outcome = MedicalImagingAdapter().evaluate(mismatched)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertIn("MED_TASK_SEMANTICS_INVALID", _codes(outcome))

    def test_classification_rejects_segmentation_metric_direction_and_threshold(
        self,
    ) -> None:
        adversarial = replace(
            clean_medical(),
            task_semantics=MedicalClassificationSemantics(
                input_representation=MedicalImageRepresentation.IMAGE_2D,
                target=MedicalClassificationTarget.BINARY,
                primary_metric=MedicalMetric.SEGMENTATION_DICE,
                metric_direction=MetricDirection.LOWER_IS_BETTER,
                protocol_artifact_sha256=_sha256("7"),
            ),
            clinical_interpretation=MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.SCREENING,
                target_population="Adults referred for screening",
                interpretation="An invalid operating threshold is supplied.",
                threshold_basis=MedicalThresholdBasis.PRIMARY_METRIC,
                threshold_value=1.5,
                threshold_unit=MedicalThresholdUnit.FRACTION,
                threshold_relation=MedicalThresholdRelation.AT_MOST,
                context_artifact_sha256=_sha256("8"),
            ),
        )
        outcome = MedicalImagingAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "MED_TASK_METRIC_INVALID",
                "MED_METRIC_DIRECTION_INVALID",
                "MED_CLINICAL_THRESHOLD_INVALID",
            }.issubset(_codes(outcome))
        )

    def test_segmentation_rejects_mismatched_mask_representation_and_metric(
        self,
    ) -> None:
        adversarial = replace(
            clean_medical(),
            task=MedicalTask.SEGMENTATION,
            analysis_unit=MedicalAnalysisUnit.VOLUME,
            task_semantics=MedicalSegmentationSemantics(
                image_representation=MedicalImageRepresentation.VOLUME_3D,
                mask_representation=MedicalImageRepresentation.IMAGE_2D,
                target=MedicalSegmentationTarget.BINARY_MASK,
                primary_metric=(
                    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM
                ),
                metric_direction=MetricDirection.LOWER_IS_BETTER,
                protocol_artifact_sha256=_sha256("9"),
            ),
            clinical_interpretation=MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.TREATMENT_PLANNING,
                target_population="Adults receiving volumetric treatment planning",
                interpretation="The supplied mask dimensionality is inconsistent.",
                threshold_basis=MedicalThresholdBasis.PRIMARY_METRIC,
                threshold_value=2.0,
                threshold_unit=MedicalThresholdUnit.MILLIMETERS,
                threshold_relation=MedicalThresholdRelation.AT_MOST,
                context_artifact_sha256=_sha256("a"),
            ),
        )
        outcome = MedicalImagingAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "MED_REPRESENTATION_TASK_INCOMPATIBLE",
                "MED_TASK_METRIC_INVALID",
            }.issubset(_codes(outcome))
        )

    def test_registration_rejects_dimension_reference_use_and_threshold_mismatch(
        self,
    ) -> None:
        adversarial = replace(
            clean_medical(),
            task=MedicalTask.REGISTRATION,
            analysis_unit=MedicalAnalysisUnit.VOLUME,
            task_semantics=MedicalRegistrationSemantics(
                moving_representation=MedicalImageRepresentation.VOLUME_3D,
                fixed_representation=MedicalImageRepresentation.IMAGE_2D,
                transform=MedicalRegistrationTransform.RIGID_2D,
                reference=MedicalRegistrationReference.ANATOMICAL_LABELS,
                primary_metric=(
                    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM
                ),
                metric_direction=MetricDirection.HIGHER_IS_BETTER,
                protocol_artifact_sha256=_sha256("b"),
            ),
            clinical_interpretation=MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.SCREENING,
                target_population="Adults undergoing image-guided intervention",
                interpretation="The supplied clinical tolerance is inconsistent.",
                threshold_basis=MedicalThresholdBasis.MODEL_SCORE,
                threshold_value=-1.0,
                threshold_unit=MedicalThresholdUnit.PROBABILITY,
                threshold_relation=MedicalThresholdRelation.AT_LEAST,
                context_artifact_sha256=_sha256("c"),
            ),
        )
        outcome = MedicalImagingAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "MED_REPRESENTATION_TASK_INCOMPATIBLE",
                "MED_TASK_METRIC_INVALID",
                "MED_METRIC_DIRECTION_INVALID",
                "MED_CLINICAL_USE_TASK_MISMATCH",
                "MED_CLINICAL_THRESHOLD_INVALID",
            }.issubset(_codes(outcome))
        )

    def test_unsupported_untyped_semantics_are_rejected_at_construction(self) -> None:
        with self.assertRaises(DomainInputError):
            MedicalClassificationSemantics(
                input_representation="IMAGE_2D",  # type: ignore[arg-type]
                target=MedicalClassificationTarget.BINARY,
                primary_metric=MedicalMetric.CLASSIFICATION_AUROC,
                metric_direction=MetricDirection.HIGHER_IS_BETTER,
                protocol_artifact_sha256=_sha256("d"),
            )
        with self.assertRaises(DomainInputError):
            MedicalClinicalInterpretationEvidence(
                intended_use=MedicalClinicalUse.SCREENING,
                target_population="Adults referred for screening",
                interpretation="Untyped threshold units are not accepted.",
                threshold_basis=MedicalThresholdBasis.MODEL_SCORE,
                threshold_value=0.7,
                threshold_unit="PROBABILITY",  # type: ignore[arg-type]
                threshold_relation=MedicalThresholdRelation.AT_LEAST,
                context_artifact_sha256=_sha256("e"),
            )
        context = clean_medical().clinical_interpretation
        self.assertIsNotNone(context)
        with self.assertRaises(DomainInputError):
            replace(context, threshold_value=None)  # type: ignore[arg-type]

    def test_patient_session_scan_site_leakage_and_slice_pseudoreplication_fail(self) -> None:
        clean = clean_medical()
        leaked = replace(
            clean,
            observations=(
                clean.observations[0],
                MedicalImageObservation(
                    "image-test",
                    SplitRole.TEST,
                    "patient-2",
                    "subject-1",
                    "session-1",
                    "scan-1",
                    "site-a",
                ),
            ),
            resampling_unit=MedicalAnalysisUnit.SLICE,
            external_validation_claimed=True,
            external_validation_performed=False,
        )
        outcome = MedicalImagingAdapter().evaluate(leaked)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "MED_PATIENT_SUBJECT_SPLIT_LEAKAGE",
                "MED_PATIENT_SUBJECT_LINKAGE_INCONSISTENT",
                "MED_SESSION_SPLIT_LEAKAGE",
                "MED_SCAN_SPLIT_LEAKAGE",
                "MED_SITE_SPLIT_LEAKAGE",
                "MED_SLICE_PSEUDOREPLICATION",
                "MED_EXTERNAL_VALIDATION_OVERCLAIM",
            }.issubset(_codes(outcome))
        )

    def test_missing_calibration_subgroups_and_external_evidence_block(self) -> None:
        incomplete = replace(
            clean_medical(),
            calibration_evaluated=None,
            subgroup_dimensions_evaluated=("site",),
            external_validation_claimed=True,
            external_validation_performed=None,
        )
        outcome = MedicalImagingAdapter().evaluate(incomplete)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertTrue(
            {
                "MED_CALIBRATION_EVIDENCE_MISSING",
                "MED_SUBGROUP_EVALUATION_MISSING",
                "MED_EXTERNAL_VALIDATION_OVERCLAIM",
            }.issubset(_codes(outcome))
        )
        self.assertIn("evaluation.calibration_results", outcome.unresolved_evidence_requirements)


class TimeSeriesAdapterTests(unittest.TestCase):
    def test_clean_temporally_ordered_horizon_and_drift_evidence_passes(self) -> None:
        outcome = TimeSeriesAdapter().evaluate(clean_time_series())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_overlap_future_leakage_horizon_mismatch_and_evaluator_gaming_fail(self) -> None:
        adversarial = replace(
            clean_time_series(),
            windows=(
                TimeSeriesWindow("series-1", "fold-1", SplitRole.TRAIN, 0, 12),
                TimeSeriesWindow("series-1", "fold-1", SplitRole.TEST, 10, 20),
            ),
            evaluated_horizon_steps=3,
            label_horizon_steps=5,
            embargo_steps=1,
            feature_cutoff_verified=False,
            evaluator_window_frozen_before_results=False,
        )
        outcome = TimeSeriesAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "TS_TEMPORAL_SPLIT_OVERLAP",
                "TS_EVALUATION_HORIZON_MISMATCH",
                "TS_LABEL_HORIZON_LEAKAGE",
                "TS_FUTURE_FEATURE_LEAKAGE",
                "TS_EVALUATOR_WINDOW_GAMING",
            }.issubset(_codes(outcome))
        )

    def test_unavailable_horizon_drift_and_rolling_origin_evidence_blocks(self) -> None:
        incomplete = replace(
            clean_time_series(),
            forecast_horizon_steps=None,
            evaluated_horizon_steps=None,
            label_horizon_steps=None,
            embargo_steps=None,
            drift_assessed=None,
            rolling_origin_evaluated=None,
        )
        outcome = TimeSeriesAdapter().evaluate(incomplete)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertIn("TS_DRIFT_EVIDENCE_MISSING", outcome.machine_codes)


class RecommenderSystemsAdapterTests(unittest.TestCase):
    def test_clean_temporal_ranking_off_policy_and_coverage_evidence_passes(self) -> None:
        outcome = RecommenderSystemsAdapter().evaluate(clean_recommender())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_interaction_session_temporal_leakage_and_evaluator_exploitation_fail(self) -> None:
        clean = clean_recommender()
        adversarial = replace(
            clean,
            interactions=(
                RecommenderInteraction(
                    "same", "user-1", "item-1", "same-session", SplitRole.TRAIN, 10
                ),
                RecommenderInteraction(
                    "same", "user-1", "item-2", "same-session", SplitRole.TEST, 5
                ),
            ),
            heldout_labels_used_for_candidate_generation=True,
            evaluator_candidate_set_changed_after_results=True,
        )
        outcome = RecommenderSystemsAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "REC_INTERACTION_SPLIT_LEAKAGE",
                "REC_SESSION_SPLIT_LEAKAGE",
                "REC_TEMPORAL_ORDER_LEAKAGE",
                "REC_HELDOUT_LABEL_LEAKAGE",
                "REC_EVALUATOR_EXPLOITATION",
            }.issubset(_codes(outcome))
        )

    def test_user_disjoint_strategy_rejects_cross_split_user(self) -> None:
        interactions = (
            RecommenderInteraction("a", "same-user", "x", "s1", SplitRole.TRAIN, 1),
            RecommenderInteraction("b", "same-user", "y", "s2", SplitRole.TEST, 2),
        )
        outcome = RecommenderSystemsAdapter().evaluate(
            replace(
                clean_recommender(),
                interactions=interactions,
                split_strategy=RecommenderSplitStrategy.USER_DISJOINT,
            )
        )
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertIn("REC_USER_SPLIT_LEAKAGE", outcome.machine_codes)

    def test_missing_off_policy_support_evidence_blocks(self) -> None:
        outcome = RecommenderSystemsAdapter().evaluate(
            replace(
                clean_recommender(),
                propensity_scores_available=None,
                support_overlap_verified=None,
            )
        )
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertIn("REC_OFF_POLICY_PROPENSITY_MISSING", outcome.machine_codes)
        self.assertIn("REC_OFF_POLICY_SUPPORT_MISSING", outcome.machine_codes)


class OperationsResearchAdapterTests(unittest.TestCase):
    def test_clean_paired_feasible_bounded_optimization_evidence_passes(self) -> None:
        outcome = OperationsResearchAdapter().evaluate(clean_optimization())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_infeasibility_wrong_direction_unfair_compute_and_objective_gaming_fail(self) -> None:
        adversarial = replace(
            clean_optimization(),
            instances=(
                OptimizationInstanceResult(
                    "instance-1", False, True, 11, 10, 9, True, True
                ),
            ),
            paired_instances_verified=False,
            exact_baseline_run=False,
            timeout_policy_equivalent=False,
            machine_specification_equivalent=False,
            excluded_failures=2,
            failure_exclusion_justified=False,
            evaluator_objective_changed_after_results=True,
        )
        outcome = OperationsResearchAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "OR_INFEASIBLE_RESULT_PROMOTED",
                "OR_OBJECTIVE_DIRECTION_MISMATCH",
                "OR_OPTIMALITY_CLAIM_UNSUPPORTED",
                "OR_PAIRED_INSTANCE_COMPARISON_INVALID",
                "OR_REQUIRED_EXACT_BASELINE_OMITTED",
                "OR_TIMEOUT_POLICY_UNFAIR",
                "OR_MACHINE_SPEC_UNFAIR",
                "OR_SELECTIVE_FAILURE_REPORTING",
                "OR_EVALUATOR_OBJECTIVE_GAMING",
            }.issubset(_codes(outcome))
        )

    def test_missing_solver_baseline_scalability_and_gap_evidence_blocks(self) -> None:
        incomplete = replace(
            clean_optimization(),
            objective_and_constraints_validated=None,
            paired_instances_verified=None,
            exact_baseline_run=None,
            solver_version=None,
            scalability_evaluated=None,
            optimality_gap_reported=None,
        )
        outcome = OperationsResearchAdapter().evaluate(incomplete)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertIn("OR_SOLVER_VERSION_MISSING", outcome.machine_codes)


class SystemsAdapterTests(unittest.TestCase):
    def test_clean_end_to_end_repeated_system_measurements_pass(self) -> None:
        outcome = SystemsAdapter().evaluate(clean_systems())
        self.assertIs(outcome.status, DomainValidityStatus.PASS)

    def test_proxy_promotion_unfair_runtime_metric_direction_and_evaluator_gaming_fail(self) -> None:
        adversarial = replace(
            clean_systems(),
            measurements=(
                SystemsMeasurement(
                    "micro_ops",
                    MetricScope.PROXY,
                    MetricDirection.LOWER_IS_BETTER,
                    (12.0, 12.1, 11.9),
                    (10.0, 10.1, 9.9),
                    True,
                ),
            ),
            workload_validated=False,
            warmup_completed=False,
            resource_isolation_verified=False,
            hardware_equivalent=False,
            runtime_environment_equivalent=False,
            evaluator_frozen_before_results=False,
            evaluator_observable_to_candidate=True,
            evaluator_specific_branching_detected=True,
            excluded_runs=3,
            exclusion_justified=False,
        )
        outcome = SystemsAdapter().evaluate(adversarial)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertTrue(
            {
                "SYS_WORKLOAD_INVALID",
                "SYS_PROXY_PROMOTED_TO_SYSTEM_CLAIM",
                "SYS_METRIC_DIRECTION_MISMATCH",
                "SYS_WARMUP_MISSING",
                "SYS_RESOURCE_ISOLATION_MISSING",
                "SYS_HARDWARE_COMPARISON_UNFAIR",
                "SYS_RUNTIME_COMPARISON_UNFAIR",
                "SYS_EVALUATOR_NOT_FROZEN",
                "SYS_EVALUATOR_EXPLOITATION",
                "SYS_SELECTIVE_RUN_REPORTING",
            }.issubset(_codes(outcome))
        )

    def test_excessive_runtime_variance_blocks_claim(self) -> None:
        noisy = replace(
            clean_systems(),
            measurements=(
                SystemsMeasurement(
                    "latency_ms",
                    MetricScope.END_TO_END,
                    MetricDirection.LOWER_IS_BETTER,
                    (1.0, 10.0, 100.0),
                    (2.0, 20.0, 200.0),
                    True,
                ),
            ),
        )
        outcome = SystemsAdapter().evaluate(noisy)
        self.assertIs(outcome.status, DomainValidityStatus.BLOCKED)
        self.assertIn("SYS_RUNTIME_VARIANCE_EXCESSIVE", outcome.machine_codes)

    def test_fail_outcome_outranks_simultaneous_missing_evidence(self) -> None:
        mixed = replace(
            clean_systems(),
            workload_validated=False,
            hardware_identity=None,
            tail_latency_reported=None,
        )
        outcome = SystemsAdapter().evaluate(mixed)
        self.assertIs(outcome.status, DomainValidityStatus.FAIL)
        self.assertIn("SYS_WORKLOAD_INVALID", outcome.machine_codes)
        self.assertIn("SYS_HARDWARE_IDENTITY_MISSING", outcome.machine_codes)


class RegistryResolvedDomainValidityTests(unittest.TestCase):
    def test_all_domain_receipts_rehydrate_and_replay_at_fixture_scope(self) -> None:
        for domain in DomainKind:
            with self.subTest(domain=domain), TemporaryDirectory() as root:
                registry = ArtifactRegistry(root, "runs/domain/registry")
                run_id = "run-domain-fixture"
                object_id = f"{domain.value.lower()}-object"
                task_id = f"{domain.value.lower()}-task"
                evidence, supporting_hashes = _registry_backed_evidence(
                    registry,
                    domain,
                    run_id=run_id,
                    object_id=object_id,
                    task_id=task_id,
                )
                source = register_domain_evidence_source(
                    registry,
                    run_id=run_id,
                    domain=domain,
                    object_id=object_id,
                    task_id=task_id,
                    evidence=evidence,
                    supporting_artifact_hashes=supporting_hashes,
                )
                receipt = materialize_domain_validity(
                    registry,
                    source_artifact_sha256=source.sha256,
                    expected_run_id=run_id,
                    expected_domain=domain,
                    expected_object_id=object_id,
                    expected_task_id=task_id,
                )
                resolved = resolve_domain_validity(
                    registry,
                    receipt.sha256,
                    expected_run_id=run_id,
                    expected_domain=domain,
                    expected_object_id=object_id,
                    expected_task_id=task_id,
                )
                self.assertIs(resolved.outcome.status, DomainValidityStatus.PASS)
                self.assertIs(
                    resolved.scope,
                    DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE,
                )
                self.assertEqual(
                    resolved.source_artifact_hashes,
                    (source.sha256, *supporting_hashes),
                )
                self.assertIn(
                    DomainValidityLimitation.REAL_WORKLOAD_UNTESTED,
                    resolved.limitations,
                )
                self.assertIn(
                    DomainValidityLimitation.SCIENTIFIC_PROMOTION_PROHIBITED,
                    resolved.limitations,
                )
                if domain is DomainKind.MEDICAL_IMAGING:
                    self.assertIn(
                        DomainValidityLimitation.CLINICAL_VALIDATION_UNTESTED,
                        resolved.limitations,
                    )
                receipt_metadata = registry.get_metadata(receipt.sha256)
                manifest_metadata = registry.get_metadata(
                    resolved.manifest_artifact_sha256
                )
                self.assertEqual(
                    receipt_metadata.logical_type,
                    f"domain_validity.{domain.value.lower()}",
                )
                self.assertIs(
                    receipt_metadata.creator_role, Role.SCIENTIFIC_REVIEWER
                )
                self.assertEqual(
                    receipt_metadata.parent_artifacts,
                    (resolved.manifest_artifact_sha256, source.sha256),
                )
                self.assertIs(
                    manifest_metadata.creator_role, Role.EVIDENCE_CURATOR
                )
                self.assertEqual(manifest_metadata.parent_artifacts, (source.sha256,))

    def test_generic_fixture_pass_cannot_authorize_scientific_gate(self) -> None:
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            evidence, hashes = _registry_backed_evidence(
                registry,
                DomainKind.GENERIC_ML,
                run_id="run-generic",
                object_id="generic-object",
                task_id="generic-task",
            )
            with self.assertRaisesRegex(
                DomainInputError, "caller-selected scope cannot grant authority"
            ):
                register_domain_evidence_source(
                    registry,
                    run_id="run-generic",
                    domain=DomainKind.GENERIC_ML,
                    object_id="generic-object",
                    task_id="generic-task",
                    evidence=evidence,
                    supporting_artifact_hashes=hashes,
                    scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
                )
            source = register_domain_evidence_source(
                registry,
                run_id="run-generic",
                domain=DomainKind.GENERIC_ML,
                object_id="generic-object",
                task_id="generic-task",
                evidence=evidence,
                supporting_artifact_hashes=hashes,
            )
            forged_payload = safe_json_loads(registry.get_bytes(source.sha256))
            self.assertIsInstance(forged_payload, dict)
            forged_payload["scope"] = DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value
            forged_source = registry.put_json(
                forged_payload,
                logical_type="domain_evidence_source.generic_ml",
                origin=(
                    "non-evidentiary registry-bound GENERIC_ML evidence source "
                    "for generic-object"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "register-domain-evidence-source",
                ),
                parent_artifacts=hashes,
                schema_version=DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(
                DomainInputError, "no implemented raw-source resolver"
            ):
                materialize_domain_validity(
                    registry,
                    source_artifact_sha256=forged_source.sha256,
                    expected_run_id="run-generic",
                    expected_domain=DomainKind.GENERIC_ML,
                    expected_object_id="generic-object",
                    expected_task_id="generic-task",
                )
            receipt = materialize_domain_validity(
                registry,
                source_artifact_sha256=source.sha256,
                expected_run_id="run-generic",
                expected_domain=DomainKind.GENERIC_ML,
                expected_object_id="generic-object",
                expected_task_id="generic-task",
            )
            with self.assertRaisesRegex(
                DomainInputError, "cannot authorize a scientific gate"
            ):
                require_scientific_domain_validity(
                    registry,
                    receipt.sha256,
                    expected_run_id="run-generic",
                    expected_domain=DomainKind.GENERIC_ML,
                    expected_object_id="generic-object",
                    expected_task_id="generic-task",
                )

    def test_generic_embedded_hashes_must_resolve_as_declared_parents(self) -> None:
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            support = _put_domain_support(
                registry,
                domain=DomainKind.GENERIC_ML,
                source_id="only-source",
                role=Role.PROTOCOL_DESIGNER,
                run_id="run-generic",
                object_id="generic-object",
                task_id="generic-task",
            )
            with self.assertRaisesRegex(
                DomainInputError, "undeclared supporting artifact"
            ):
                register_domain_evidence_source(
                    registry,
                    run_id="run-generic",
                    domain=DomainKind.GENERIC_ML,
                    object_id="generic-object",
                    task_id="generic-task",
                    evidence=clean_generic_ml(),
                    supporting_artifact_hashes=(support.sha256,),
                )

    def test_or_source_substitution_parent_omission_and_role_tamper_fail(self) -> None:
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            evidence, hashes = _registry_backed_evidence(
                registry,
                DomainKind.OPERATIONS_RESEARCH,
                run_id="run-or",
                object_id="or-object",
                task_id="or-task",
            )
            source = register_domain_evidence_source(
                registry,
                run_id="run-or",
                domain=DomainKind.OPERATIONS_RESEARCH,
                object_id="or-object",
                task_id="or-task",
                evidence=evidence,
                supporting_artifact_hashes=hashes,
            )
            original = safe_json_loads(registry.get_bytes(source.sha256))
            self.assertIsInstance(original, dict)

            raw_payload = safe_json_loads(registry.get_bytes(hashes[0]))
            self.assertIsInstance(raw_payload, dict)
            raw_payload["task_id"] = "or-task-unsupported-role"
            raw_payload["source_id"] = "wrong-role-source"
            wrong_role_raw = registry.put_json(
                raw_payload,
                logical_type=(
                    "domain_raw_fixture.operations_research.wrong-role-source"
                ),
                origin=(
                    "typed non-evidentiary OPERATIONS_RESEARCH raw source "
                    "wrong-role-source for or-object"
                ),
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=(
                    "scientist-one",
                    "register-domain-raw-fixture-source",
                ),
                schema_version=registry.get_metadata(hashes[0]).schema_version,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            valid_second = _put_domain_support(
                registry,
                domain=DomainKind.OPERATIONS_RESEARCH,
                source_id="valid-second",
                role=Role.EXPERIMENT_RUNNER,
                run_id="run-or",
                object_id="or-object",
                task_id="or-task-unsupported-role",
            )
            with self.assertRaisesRegex(DomainInputError, "metadata differs"):
                register_domain_evidence_source(
                    registry,
                    run_id="run-or",
                    domain=DomainKind.OPERATIONS_RESEARCH,
                    object_id="or-object",
                    task_id="or-task-unsupported-role",
                    evidence=evidence,
                    supporting_artifact_hashes=(
                        wrong_role_raw.sha256,
                        valid_second.sha256,
                    ),
                )

            omitted = dict(original)
            omitted["task_id"] = "or-task-omitted"
            omitted_source = registry.put_json(
                omitted,
                logical_type="domain_evidence_source.operations_research",
                origin=(
                    "non-evidentiary registry-bound OPERATIONS_RESEARCH "
                    "evidence source for or-object"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "register-domain-evidence-source",
                ),
                parent_artifacts=hashes[:-1],
                schema_version=DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(DomainInputError):
                materialize_domain_validity(
                    registry,
                    source_artifact_sha256=omitted_source.sha256,
                    expected_run_id="run-or",
                    expected_domain=DomainKind.OPERATIONS_RESEARCH,
                    expected_object_id="or-object",
                    expected_task_id="or-task-omitted",
                )

            role_tampered = dict(original)
            role_tampered["task_id"] = "or-task-role-tampered"
            descriptors = [dict(value) for value in original["supporting_sources"]]
            descriptors[0]["creator_role"] = Role.EXPERIMENT_RUNNER.value
            role_tampered["supporting_sources"] = descriptors
            role_tampered_source = registry.put_json(
                role_tampered,
                logical_type="domain_evidence_source.operations_research",
                origin=(
                    "non-evidentiary registry-bound OPERATIONS_RESEARCH "
                    "evidence source for or-object"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "register-domain-evidence-source",
                ),
                parent_artifacts=hashes,
                schema_version=DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(DomainInputError):
                materialize_domain_validity(
                    registry,
                    source_artifact_sha256=role_tampered_source.sha256,
                    expected_run_id="run-or",
                    expected_domain=DomainKind.OPERATIONS_RESEARCH,
                    expected_object_id="or-object",
                    expected_task_id="or-task-role-tampered",
                )

            unrelated = _put_domain_support(
                registry,
                domain=DomainKind.OPERATIONS_RESEARCH,
                source_id="unrelated",
                role=Role.EXPERIMENT_RUNNER,
                run_id="run-or",
                object_id="other-object",
                task_id="other-task",
            )
            substituted = dict(original)
            substituted["task_id"] = "or-task-substituted"
            descriptors = [dict(value) for value in original["supporting_sources"]]
            descriptors[1] = _support_descriptor(unrelated)
            substituted["supporting_sources"] = descriptors
            substituted_source = registry.put_json(
                substituted,
                logical_type="domain_evidence_source.operations_research",
                origin=(
                    "non-evidentiary registry-bound OPERATIONS_RESEARCH "
                    "evidence source for or-object"
                ),
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=(
                    "scientist-one",
                    "register-domain-evidence-source",
                ),
                parent_artifacts=hashes,
                schema_version=DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(DomainInputError):
                materialize_domain_validity(
                    registry,
                    source_artifact_sha256=substituted_source.sha256,
                    expected_run_id="run-or",
                    expected_domain=DomainKind.OPERATIONS_RESEARCH,
                    expected_object_id="or-object",
                    expected_task_id="or-task-substituted",
                )

    def test_systems_receipt_binds_run_object_task_type_role_and_status(self) -> None:
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            evidence, hashes = _registry_backed_evidence(
                registry,
                DomainKind.SYSTEMS,
                run_id="run-systems",
                object_id="systems-object",
                task_id="systems-task",
            )
            source = register_domain_evidence_source(
                registry,
                run_id="run-systems",
                domain=DomainKind.SYSTEMS,
                object_id="systems-object",
                task_id="systems-task",
                evidence=evidence,
                supporting_artifact_hashes=hashes,
            )
            receipt = materialize_domain_validity(
                registry,
                source_artifact_sha256=source.sha256,
                expected_run_id="run-systems",
                expected_domain=DomainKind.SYSTEMS,
                expected_object_id="systems-object",
                expected_task_id="systems-task",
            )
            for changes in (
                {"expected_run_id": "other-run"},
                {"expected_object_id": "other-object"},
                {"expected_task_id": "other-task"},
                {"expected_domain": DomainKind.OPERATIONS_RESEARCH},
            ):
                expected = {
                    "expected_run_id": "run-systems",
                    "expected_domain": DomainKind.SYSTEMS,
                    "expected_object_id": "systems-object",
                    "expected_task_id": "systems-task",
                }
                expected.update(changes)
                with self.subTest(changes=changes), self.assertRaises(DomainInputError):
                    resolve_domain_validity(registry, receipt.sha256, **expected)

            payload = safe_json_loads(registry.get_bytes(receipt.sha256))
            self.assertIsInstance(payload, dict)
            manifest_hash = payload["manifest_artifact_sha256"]
            variants = (
                ("wrong-role", "domain_validity.systems", Role.STATISTICIAN, "PASS", True),
                ("wrong-type", "generic_json", Role.SCIENTIFIC_REVIEWER, "PASS", True),
                ("wrong-status", "domain_validity.systems", Role.SCIENTIFIC_REVIEWER, "FAIL", False),
            )
            for object_id, logical_type, role, status, frozen in variants:
                forged_payload = dict(payload)
                forged_payload["object_id"] = object_id
                forged = registry.put_json(
                    forged_payload,
                    logical_type=logical_type,
                    origin=f"deterministically replayed SYSTEMS validity receipt for {object_id}",
                    creator_role=role,
                    creation_command=(
                        "scientist-one",
                        "materialize-domain-validity-receipt",
                    ),
                    parent_artifacts=(manifest_hash, source.sha256),
                    schema_version=DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
                    mime_type="application/json",
                    validation_result=status,
                    frozen=frozen,
                )
                with self.subTest(object_id=object_id), self.assertRaises(
                    DomainInputError
                ):
                    resolve_domain_validity(
                        registry,
                        forged.sha256,
                        expected_run_id="run-systems",
                        expected_domain=DomainKind.SYSTEMS,
                        expected_object_id=object_id,
                        expected_task_id="systems-task",
                    )

    def test_systems_outcome_and_source_substitution_cannot_reuse_pass_label(self) -> None:
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            evidence_a, hashes_a = _registry_backed_evidence(
                registry,
                DomainKind.SYSTEMS,
                run_id="run-systems",
                object_id="systems-a",
                task_id="systems-task",
            )
            source_a = register_domain_evidence_source(
                registry,
                run_id="run-systems",
                domain=DomainKind.SYSTEMS,
                object_id="systems-a",
                task_id="systems-task",
                evidence=evidence_a,
                supporting_artifact_hashes=hashes_a,
            )
            receipt_a = materialize_domain_validity(
                registry,
                source_artifact_sha256=source_a.sha256,
                expected_run_id="run-systems",
                expected_domain=DomainKind.SYSTEMS,
                expected_object_id="systems-a",
                expected_task_id="systems-task",
            )
            evidence_b, hashes_b = _registry_backed_evidence(
                registry,
                DomainKind.SYSTEMS,
                run_id="run-systems",
                object_id="systems-b",
                task_id="systems-task",
            )
            source_b = register_domain_evidence_source(
                registry,
                run_id="run-systems",
                domain=DomainKind.SYSTEMS,
                object_id="systems-b",
                task_id="systems-task",
                evidence=evidence_b,
                supporting_artifact_hashes=hashes_b,
            )
            payload = safe_json_loads(registry.get_bytes(receipt_a.sha256))
            self.assertIsInstance(payload, dict)

            tampered = dict(payload)
            tampered_outcome = dict(payload["outcome"])
            tampered_outcome["status"] = DomainValidityStatus.FAIL.value
            tampered["outcome"] = tampered_outcome
            tampered_receipt = registry.put_json(
                tampered,
                logical_type="domain_validity.systems",
                origin="deterministically replayed SYSTEMS validity receipt for systems-a",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=(
                    "scientist-one",
                    "materialize-domain-validity-receipt",
                ),
                parent_artifacts=registry.get_metadata(
                    receipt_a.sha256
                ).parent_artifacts,
                schema_version=DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaisesRegex(DomainInputError, "freshly replayed"):
                resolve_domain_validity(
                    registry,
                    tampered_receipt.sha256,
                    expected_run_id="run-systems",
                    expected_domain=DomainKind.SYSTEMS,
                    expected_object_id="systems-a",
                    expected_task_id="systems-task",
                )

            substituted = dict(payload)
            substituted["source_artifact_hashes"] = [source_b.sha256, *hashes_b]
            substituted_receipt = registry.put_json(
                substituted,
                logical_type="domain_validity.systems",
                origin="deterministically replayed SYSTEMS validity receipt for systems-a",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=(
                    "scientist-one",
                    "materialize-domain-validity-receipt",
                ),
                parent_artifacts=(payload["manifest_artifact_sha256"], source_b.sha256),
                schema_version=DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(DomainInputError):
                resolve_domain_validity(
                    registry,
                    substituted_receipt.sha256,
                    expected_run_id="run-systems",
                    expected_domain=DomainKind.SYSTEMS,
                    expected_object_id="systems-a",
                    expected_task_id="systems-task",
                )


if __name__ == "__main__":
    unittest.main()
