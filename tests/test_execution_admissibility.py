"""Non-evidentiary checks for the closed execution-admissibility owner.

These tests exercise canonical DTOs, pure deterministic derivation, publication
shape, and fail-closed zero-write boundaries.  They do not install a backend
verifier, assert independent custody, or issue scientific authority.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.execution_admissibility import (
    FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
    SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND,
    SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN,
    SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA,
    SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE,
    ScientificDecisionStoppingStatus,
    ScientificEvaluatorIntegrityStatus,
    ScientificExecutionAdmissibilityAuthority,
    ScientificExecutionAdmissibilityError,
    ScientificExecutionAdmissibilityPolicy,
    ScientificExecutionAdmissibilityResolutionStatus,
    ScientificExecutionAdmissibilityStatus,
    _AdmissibilitySources,
    _build_publication_event,
    _derive_determination,
    _validate_publication_event,
    register_scientific_execution_admissibility_authority,
    resolve_scientific_execution_admissibility,
)
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


STAMP = "2026-09-04T00:00:00Z"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _changed(value: SimpleNamespace, **changes: object) -> SimpleNamespace:
    fields = vars(value).copy()
    fields.update(changes)
    return SimpleNamespace(**fields)


def _binding(label: str) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_sha256=_digest(label),
        artifact_record_hash=_digest(f"{label}-record"),
    )


class ScientificExecutionAdmissibilityTests(unittest.TestCase):
    """The supported fixed procedure is outcome-neutral and fail closed."""

    def _authority(self) -> ScientificExecutionAdmissibilityAuthority:
        direct_hashes = tuple(
            _digest(label)
            for label in ("freeze", "execution", "domain", "projection", "timeline")
        )
        direct_records = tuple(
            _digest(f"{label}-record")
            for label in ("freeze", "execution", "domain", "projection", "timeline")
        )
        return ScientificExecutionAdmissibilityAuthority(
            authority_id="execution-admissibility-fixture",
            ledger_run_id="admissibility-ledger",
            execution_run_id="admissibility-execution",
            scientific_binding_sha256=_digest("scientific-binding"),
            policy=ScientificExecutionAdmissibilityPolicy(),
            status=ScientificExecutionAdmissibilityStatus.ADMISSIBLE,
            decision_stopping_status=ScientificDecisionStoppingStatus.MET,
            evaluator_integrity_status=ScientificEvaluatorIntegrityStatus.PASS,
            reason_codes=("FIXED_COMPLETE_GENERIC_ML_ADMISSIBLE",),
            evaluation_contract_freeze_receipt_artifact_sha256=direct_hashes[0],
            evaluation_contract_freeze_receipt_record_hash=direct_records[0],
            contract_artifact_sha256=_digest("contract"),
            contract_record_hash=_digest("contract-record"),
            scientific_execution_preparation_artifact_sha256=_digest("preparation"),
            scientific_execution_preparation_record_hash=_digest(
                "preparation-record"
            ),
            scientific_execution_authority_artifact_sha256=direct_hashes[1],
            scientific_execution_authority_record_hash=direct_records[1],
            scientific_execution_activity_artifact_sha256=_digest("activity"),
            scientific_execution_activity_record_hash=_digest("activity-record"),
            frozen_run_spec_artifact_sha256=_digest("spec"),
            frozen_run_spec_record_hash=_digest("spec-record"),
            output_manifest_artifact_sha256=_digest("manifest"),
            output_manifest_record_hash=_digest("manifest-record"),
            scientific_domain_evidence_source_artifact_sha256=direct_hashes[2],
            scientific_domain_evidence_source_record_hash=direct_records[2],
            generic_ml_paired_metric_projection_authority_artifact_sha256=(
                direct_hashes[3]
            ),
            generic_ml_paired_metric_projection_authority_record_hash=(
                direct_records[3]
            ),
            scientific_confirmatory_timeline_receipt_artifact_sha256=(
                direct_hashes[4]
            ),
            scientific_confirmatory_timeline_receipt_record_hash=direct_records[4],
            source_artifact_sha256s=direct_hashes,
            source_artifact_record_hashes=direct_records,
            source_ledger_prefix_head_hash=_digest("source-ledger-prefix"),
        )

    def _sources(self) -> _AdmissibilitySources:
        seeds = (11, 29)
        dataset = _digest("dataset")
        splits = tuple(_digest(f"split-{index}") for index in range(4))
        unit_ids = ("confirmatory-unit-a", "confirmatory-unit-b")
        unit_hashes = tuple(_digest(item) for item in unit_ids)
        labels = (0, 1)
        rows: list[SimpleNamespace] = [
            SimpleNamespace(
                sequence=0,
                kind="DATASET_READ",
                seed=None,
                condition_id=None,
                ablation_id=None,
                input_artifact_bindings=(),
                output_artifact_bindings=(),
                dataset_artifact_binding=SimpleNamespace(
                    artifact_sha256=dataset
                ),
                split_artifact_binding=SimpleNamespace(
                    artifact_sha256=splits[-1]
                ),
                dataset_access_purpose="CONFIRMATORY_FEATURES",
            )
        ]
        seed_projections: list[SimpleNamespace] = []
        domain_outputs: list[str] = []
        for seed in seeds:
            candidate_model = _binding(f"candidate-model-{seed}")
            baseline_model = _binding(f"baseline-model-{seed}")
            predictions = _binding(f"paired-predictions-{seed}")
            robustness = _binding(f"robustness-{seed}")
            candidate_condition = "candidate-condition"
            baseline_condition = "baseline-condition"
            productions = (
                (
                    "MODEL_INVOCATION",
                    candidate_condition,
                    (),
                    (candidate_model,),
                ),
                (
                    "MODEL_INVOCATION",
                    baseline_condition,
                    (),
                    (baseline_model,),
                ),
                (
                    "PREDICTION_GENERATION",
                    candidate_condition,
                    (candidate_model, baseline_model),
                    (predictions,),
                ),
                (
                    "OUTPUT_COMMIT",
                    candidate_condition,
                    (predictions,),
                    (robustness,),
                ),
            )
            for kind, condition, inputs, outputs in productions:
                rows.append(
                    SimpleNamespace(
                        sequence=len(rows),
                        kind=kind,
                        seed=seed,
                        condition_id=condition,
                        ablation_id=None,
                        input_artifact_bindings=inputs,
                        output_artifact_bindings=outputs,
                        dataset_artifact_binding=None,
                        split_artifact_binding=None,
                        dataset_access_purpose=None,
                    )
                )
            domain_outputs.extend(
                (
                    candidate_model.artifact_sha256,
                    baseline_model.artifact_sha256,
                    predictions.artifact_sha256,
                    robustness.artifact_sha256,
                )
            )
            seed_projections.append(
                SimpleNamespace(
                    seed=seed,
                    candidate_condition_id=candidate_condition,
                    baseline_condition_id=baseline_condition,
                    candidate_model_artifact_sha256=(
                        candidate_model.artifact_sha256
                    ),
                    candidate_model_record_hash=(
                        candidate_model.artifact_record_hash
                    ),
                    baseline_model_artifact_sha256=(
                        baseline_model.artifact_sha256
                    ),
                    baseline_model_record_hash=(
                        baseline_model.artifact_record_hash
                    ),
                    paired_predictions_artifact_sha256=(
                        predictions.artifact_sha256
                    ),
                    paired_predictions_record_hash=(
                        predictions.artifact_record_hash
                    ),
                    robustness_artifact_sha256=robustness.artifact_sha256,
                    robustness_record_hash=robustness.artifact_record_hash,
                    paired_unit_ids=unit_ids,
                    paired_unit_hashes=unit_hashes,
                    reference_labels=labels,
                    # Deliberately worse candidate values: this is a valid
                    # negative result, not a procedure-integrity failure.
                    candidate_values=(0.0, 0.0),
                    baseline_values=(1.0, 1.0),
                    candidate_mean=0.0,
                    baseline_mean=1.0,
                )
            )
        ablation_hash = _digest("ablation-core-output")
        ablation_record_hash = _digest("ablation-core-output-record")
        rows.append(
            SimpleNamespace(
                sequence=len(rows),
                kind="ABLATION_EXECUTION",
                seed=None,
                condition_id=None,
                ablation_id="ablation-core",
                input_artifact_bindings=(),
                output_artifact_bindings=(
                    SimpleNamespace(
                        artifact_sha256=ablation_hash,
                        artifact_record_hash=ablation_record_hash,
                    ),
                ),
                dataset_artifact_binding=None,
                split_artifact_binding=None,
                dataset_access_purpose=None,
            )
        )
        contract = SimpleNamespace(
            scientific_execution_admissibility_policy=(
                ScientificExecutionAdmissibilityPolicy()
            ),
            stopping_criteria=FIXED_COMPLETE_GENERIC_ML_STOPPING_CRITERIA,
            seed_reporting=SimpleNamespace(seeds=seeds),
            ablations=(
                SimpleNamespace(ablation_id="ablation-core", required=True),
            ),
            compute_budget=SimpleNamespace(max_wall_seconds=30.0),
            dataset=SimpleNamespace(dataset_id="fixture-dataset"),
            candidate_conditions=SimpleNamespace(
                tuning_trials=0,
                hyperparameter_search="none",
            ),
            baseline_registry=SimpleNamespace(
                entries=(
                    SimpleNamespace(
                        status="MUST_RUN",
                        conditions=SimpleNamespace(
                            tuning_trials=0,
                            hyperparameter_search="none",
                        ),
                    ),
                ),
            ),
        )
        spec = SimpleNamespace(
            seeds=seeds,
            required_ablations=("ablation-core",),
            attempt=1,
            retry_of_run_id=None,
            phase="CONFIRMATORY",
            seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
            termination_conditions=(
                "wall_clock_timeout",
                "all_planned_seeds_reported",
            ),
            timeout_seconds=30.0,
            metadata={
                "scientific_domain_policy": {
                    "comparison_scope": (
                        "FROZEN_MODEL_CONFIRMATORY_INFERENCE_ONLY"
                    )
                }
            },
        )
        execution = SimpleNamespace(
            outcome="COMPLETED",
            attested_started_at=STAMP,
            attested_completed_at="2026-09-04T00:00:01Z",
        )
        activity = SimpleNamespace(
            activity_rows=tuple(rows),
            terminal=SimpleNamespace(
                kind="ALL_PLANNED_WORK_COMPLETED",
                occurred_at=execution.attested_completed_at,
            ),
        )
        projection = SimpleNamespace(
            comparison_scope="FROZEN_MODEL_CONFIRMATORY_INFERENCE_ONLY",
            dataset_authority_artifact_sha256=dataset,
            split_authority_artifact_sha256s=splits,
            seed_order=seeds,
            paired_unit_ids=unit_ids,
            paired_unit_hashes=unit_hashes,
            reference_labels=labels,
            seed_projections=tuple(seed_projections),
            domain_consumed_output_artifact_sha256s=tuple(domain_outputs),
            ablation_output_artifact_sha256s=(ablation_hash,),
            ablation_output_record_hashes=(ablation_record_hash,),
        )
        manifest = SimpleNamespace(
            artifacts=tuple(
                SimpleNamespace(sha256=digest)
                for digest in (*domain_outputs, ablation_hash)
            ),
            ablations=(
                SimpleNamespace(
                    ablation_id="ablation-core",
                    artifact_sha256=ablation_hash,
                    status="PASS",
                ),
            ),
        )
        return _AdmissibilitySources(
            freeze_record=None,
            freeze=None,
            contract_record=None,
            contract=contract,
            preparation_record=None,
            preparation=None,
            execution_record=None,
            execution=execution,
            activity_record=None,
            activity=activity,
            spec_record=None,
            spec=spec,
            manifest_record=None,
            manifest=manifest,
            domain_source_record=None,
            domain_source=None,
            projection_record=None,
            projection=projection,
            timeline_record=None,
            timeline=None,
            timeline_publication_head_hash=_digest("timeline-publication"),
            determination=None,
            registry_snapshot=None,
            ledger_snapshot=None,
        )

    def test_policy_and_authority_round_trip_exactly(self) -> None:
        policy = ScientificExecutionAdmissibilityPolicy()
        value = policy.to_dict()
        self.assertEqual(
            value["schema_version"],
            SCIENTIFIC_EXECUTION_ADMISSIBILITY_POLICY_SCHEMA,
        )
        self.assertEqual(
            ScientificExecutionAdmissibilityPolicy.from_mapping(value),
            policy,
        )
        with self.assertRaisesRegex(
            ScientificExecutionAdmissibilityError,
            "schema is invalid",
        ):
            ScientificExecutionAdmissibilityPolicy.from_mapping(
                {**value, "caller_pass": True}
            )

        authority = self._authority()
        serialized = authority.to_dict()
        self.assertEqual(
            ScientificExecutionAdmissibilityAuthority.from_mapping(serialized),
            authority,
        )
        self.assertNotIn("candidate_value", serialized)
        self.assertNotIn("baseline_value", serialized)
        self.assertNotIn("success", serialized)
        self.assertNotIn("release_readiness_authorized", serialized)
        self.assertEqual(
            serialized["authority_scope"],
            SCIENTIFIC_EXECUTION_ADMISSIBILITY_SCOPE,
        )

    def test_authority_rejects_cherry_picked_sources_and_false_admissible_status(self) -> None:
        authority = self._authority()
        with self.assertRaisesRegex(
            ScientificExecutionAdmissibilityError,
            "substituted source closure",
        ):
            replace(
                authority,
                source_artifact_sha256s=tuple(
                    reversed(authority.source_artifact_sha256s)
                ),
            )
        with self.assertRaisesRegex(
            ScientificExecutionAdmissibilityError,
            "lacks stopping and evaluator closure",
        ):
            replace(
                authority,
                evaluator_integrity_status=ScientificEvaluatorIntegrityStatus.FAIL,
            )

    def test_complete_grid_is_admissible_even_for_negative_result(self) -> None:
        determination = _derive_determination(self._sources())

        self.assertIs(
            determination.status,
            ScientificExecutionAdmissibilityStatus.ADMISSIBLE,
        )
        self.assertIs(
            determination.stopping,
            ScientificDecisionStoppingStatus.MET,
        )
        self.assertIs(
            determination.evaluator,
            ScientificEvaluatorIntegrityStatus.PASS,
        )

    def test_missing_grid_work_is_inadmissible_not_met(self) -> None:
        sources = self._sources()
        activity = _changed(
            sources.activity,
            activity_rows=tuple(
                row
                for row in sources.activity.activity_rows
                if not (
                    row.kind == "ABLATION_EXECUTION"
                    or row.seed == sources.spec.seeds[-1]
                )
            ),
        )
        determination = _derive_determination(
            replace(sources, activity=activity)
        )

        self.assertIs(
            determination.status,
            ScientificExecutionAdmissibilityStatus.INADMISSIBLE,
        )
        self.assertIs(
            determination.stopping,
            ScientificDecisionStoppingStatus.NOT_MET,
        )
        self.assertIn("MODEL_ACTIVITY_GRID_INCOMPLETE", determination.reason_codes)
        self.assertIn("ABLATION_ACTIVITY_GRID_MISMATCH", determination.reason_codes)

        over_budget_execution = _changed(
            sources.execution,
            attested_completed_at="2026-09-04T00:00:31Z",
        )
        over_budget_activity = _changed(
            sources.activity,
            terminal=_changed(
                sources.activity.terminal,
                occurred_at=over_budget_execution.attested_completed_at,
            ),
        )
        over_budget = _derive_determination(
            replace(
                sources,
                execution=over_budget_execution,
                activity=over_budget_activity,
            )
        )
        self.assertIs(over_budget.stopping, ScientificDecisionStoppingStatus.NOT_MET)
        self.assertIn(
            "EXECUTION_EXCEEDED_FROZEN_WALL_LIMIT",
            over_budget.reason_codes,
        )

    def test_adaptive_or_protected_access_fails_evaluator_integrity(self) -> None:
        sources = self._sources()
        adaptive = SimpleNamespace(
            sequence=len(sources.activity.activity_rows),
            kind="EVALUATOR_QUERY",
            seed=None,
            condition_id=None,
            ablation_id=None,
            input_artifact_bindings=(),
            output_artifact_bindings=(),
            dataset_artifact_binding=None,
            split_artifact_binding=None,
            dataset_access_purpose=None,
        )
        cases = {
            "adaptive": (
                *sources.activity.activity_rows,
                adaptive,
            ),
            "protected-labels": (
                _changed(
                    sources.activity.activity_rows[0],
                    dataset_access_purpose="CONFIRMATORY_LABELS",
                ),
                *sources.activity.activity_rows[1:],
            ),
        }
        for name, rows in cases.items():
            with self.subTest(name=name):
                activity = _changed(sources.activity, activity_rows=tuple(rows))
                determination = _derive_determination(
                    replace(sources, activity=activity)
                )
                self.assertIs(
                    determination.evaluator,
                    ScientificEvaluatorIntegrityStatus.FAIL,
                )
                self.assertIs(
                    determination.status,
                    ScientificExecutionAdmissibilityStatus.INADMISSIBLE,
                )

        wrong_scope = _changed(
            sources.projection,
            comparison_scope="TRAINING_EFFICIENCY",
        )
        determination = _derive_determination(
            replace(sources, projection=wrong_scope)
        )
        self.assertIn(
            "UNSUPPORTED_COMPARISON_OR_TUNING_SCOPE",
            determination.reason_codes,
        )

        tuned_contract = _changed(
            sources.contract,
            candidate_conditions=_changed(
                sources.contract.candidate_conditions,
                tuning_trials=1,
            ),
        )
        determination = _derive_determination(
            replace(sources, contract=tuned_contract)
        )
        self.assertIn(
            "UNSUPPORTED_COMPARISON_OR_TUNING_SCOPE",
            determination.reason_codes,
        )

    def test_unit_grid_activity_order_and_manifest_order_are_exact(self) -> None:
        sources = self._sources()
        first_seed = sources.projection.seed_projections[0]
        changed_seed = _changed(
            first_seed,
            paired_unit_ids=tuple(reversed(first_seed.paired_unit_ids)),
        )
        projection = _changed(
            sources.projection,
            seed_projections=(
                changed_seed,
                *sources.projection.seed_projections[1:],
            ),
        )
        determination = _derive_determination(
            replace(sources, projection=projection)
        )
        self.assertIn("PROJECTION_UNIT_GRID_MISMATCH", determination.reason_codes)

        rows = list(sources.activity.activity_rows)
        prediction_index = next(
            index for index, row in enumerate(rows)
            if row.kind == "PREDICTION_GENERATION"
        )
        rows[prediction_index] = _changed(
            rows[prediction_index],
            input_artifact_bindings=tuple(
                reversed(rows[prediction_index].input_artifact_bindings)
            ),
        )
        determination = _derive_determination(
            replace(
                sources,
                activity=_changed(sources.activity, activity_rows=tuple(rows)),
            )
        )
        self.assertIn(
            "MODEL_PREDICTION_ACTIVITY_GRID_MISMATCH",
            determination.reason_codes,
        )

        domain_outputs = sources.projection.domain_consumed_output_artifact_sha256s
        projection = _changed(
            sources.projection,
            domain_consumed_output_artifact_sha256s=(
                domain_outputs[1],
                domain_outputs[0],
                *domain_outputs[2:],
            ),
        )
        determination = _derive_determination(
            replace(sources, projection=projection)
        )
        self.assertIn(
            "MANIFEST_OUTPUT_CONSUMPTION_INCOMPLETE",
            determination.reason_codes,
        )

    def test_publication_is_single_artifact_and_correction_invalidates_it(self) -> None:
        authority = self._authority()
        prior = LedgerEvent.create(
            run_id=authority.ledger_run_id,
            event_id="fixture-prior",
            timestamp=STAMP,
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.PREFLIGHT,
            requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=(),
            code_version="non-evidentiary-test",
            configuration_hash=_digest("configuration"),
            reason="initialize non-evidentiary publication fixture",
            prior_event_hash=None,
            event_type="CHECKPOINT",
        )
        assert prior.event_hash is not None
        authority = replace(
            authority,
            source_ledger_prefix_head_hash=prior.event_hash,
        )
        data = canonical_json_bytes(authority.to_dict()) + b"\n"
        record = ArtifactRecord(
            sha256=hashlib.sha256(data).hexdigest(),
            path="objects/admissibility.json",
            relative_path="objects/admissibility.json",
            metadata_path="metadata/admissibility.json",
            logical_type=SCIENTIFIC_EXECUTION_ADMISSIBILITY_LOGICAL_TYPE,
            schema_version="1.0",
            mime_type="application/json",
            size=len(data),
            origin=SCIENTIFIC_EXECUTION_ADMISSIBILITY_ORIGIN,
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=SCIENTIFIC_EXECUTION_ADMISSIBILITY_COMMAND,
            parent_artifacts=authority.source_artifact_sha256s,
            validation_result="PASS",
            frozen=True,
            created_at=STAMP,
        )
        snapshot = SimpleNamespace(valid=True, events=(prior,), head_hash=prior.event_hash)
        contract = SimpleNamespace(dataset=SimpleNamespace(dataset_id="fixture-dataset"))
        spec = SimpleNamespace(seeds=(11, 29))
        publication = _build_publication_event(
            snapshot,
            timestamp=STAMP,
            record=record,
            authority=authority,
            contract=contract,
            spec=spec,
        )
        _validate_publication_event(
            publication,
            1,
            (prior, publication),
            record=record,
            authority=authority,
            contract=contract,
            spec=spec,
        )
        self.assertEqual(publication.artifact_hashes, (record.sha256,))
        # Pure chronology contract: a dependent publication cannot use a
        # source publication that has not yet appeared in its prefix. No
        # event or authority in this test is appended to a real runtime.
        absent_source = replace(
            authority,
            source_ledger_prefix_head_hash=_digest("future-timeline-publication"),
        )
        premature = _build_publication_event(
            snapshot, timestamp=STAMP, record=record, authority=absent_source,
            contract=contract, spec=spec,
        )
        with self.assertRaisesRegex(ScientificExecutionAdmissibilityError, "stale or substituted"):
            _validate_publication_event(
                premature, 1, (prior, premature), record=record,
                authority=absent_source, contract=contract, spec=spec,
            )
        correction = LedgerEvent.create(
            run_id=authority.ledger_run_id,
            event_id="fixture-correction",
            timestamp=STAMP,
            actor_role=Role.CLAIM_VERIFIER,
            state_before=MacroState.PREFLIGHT,
            requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=(),
            code_version=publication.code_version,
            configuration_hash=publication.configuration_hash,
            reason="invalidate non-evidentiary publication fixture",
            prior_event_hash=publication.event_hash,
            event_type="CORRECTION",
            supersedes_event_id=publication.event_id,
        )
        with self.assertRaisesRegex(
            ScientificExecutionAdmissibilityError,
            "stale or substituted",
        ):
            _validate_publication_event(
                publication,
                1,
                (prior, publication, correction),
                record=record,
                authority=authority,
                contract=contract,
                spec=spec,
            )

    def test_missing_source_diagnosis_rejects_mid_read_registry_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/admissibility-ledger/registry")
            ledger = EventLedger(root, "runs/admissibility-ledger/events.jsonl")
            selectors = {
                "expected_ledger_run_id": "admissibility-ledger",
                "expected_execution_run_id": "admissibility-execution",
                **{
                    name: _digest(name)
                    for name in (
                        "evaluation_contract_freeze_receipt_artifact_sha256",
                        "scientific_execution_authority_artifact_sha256",
                        "scientific_confirmatory_timeline_receipt_artifact_sha256",
                        "scientific_domain_evidence_source_artifact_sha256",
                        "generic_ml_paired_metric_projection_authority_artifact_sha256",
                    )
                },
            }
            original = registry.get_metadata
            changed = False

            def read_then_append(digest):
                nonlocal changed
                try:
                    return original(digest)
                finally:
                    if not changed:
                        changed = True
                        registry.put_json(
                            {"diagnostic_only": True},
                            logical_type="ordinary_admissibility_observation",
                            origin="non-evidentiary read consistency test",
                            creator_role=Role.ORCHESTRATOR,
                            creation_command=("scientist-one", "test-read-consistency"),
                            schema_version="1.0", mime_type="application/json",
                            validation_result="PASS", frozen=True,
                        )

            with (
                patch.object(registry, "get_metadata", side_effect=read_then_append),
                self.assertRaisesRegex(ScientificExecutionAdmissibilityError, "sources changed during fresh replay"),
            ):
                resolve_scientific_execution_admissibility(registry, ledger, **selectors)
            self.assertTrue(changed)
            self.assertEqual(ledger.events(), ())
            self.assertEqual(
                tuple(record.logical_type for record in registry.list_records()),
                ("ordinary_admissibility_observation",),
            )

    def test_missing_sources_are_blocked_local_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/admissibility-ledger/registry")
            ledger = EventLedger(root, "runs/admissibility-ledger/events.jsonl")
            selectors = {
                "expected_ledger_run_id": "admissibility-ledger",
                "expected_execution_run_id": "admissibility-execution",
                "evaluation_contract_freeze_receipt_artifact_sha256": _digest(
                    "absent-freeze"
                ),
                "scientific_execution_authority_artifact_sha256": _digest(
                    "absent-execution"
                ),
                "scientific_confirmatory_timeline_receipt_artifact_sha256": (
                    _digest("absent-timeline")
                ),
                "scientific_domain_evidence_source_artifact_sha256": _digest(
                    "absent-domain"
                ),
                "generic_ml_paired_metric_projection_authority_artifact_sha256": (
                    _digest("absent-projection")
                ),
            }
            before_records = registry.list_records()
            before_events = ledger.events()

            resolution = resolve_scientific_execution_admissibility(
                registry,
                ledger,
                **selectors,
            )
            self.assertIs(
                resolution.status,
                ScientificExecutionAdmissibilityResolutionStatus.BLOCKED_LOCAL,
            )
            self.assertEqual(resolution.reason_code, "LOCAL_SOURCE_AUTHORITY_ABSENT")
            with self.assertRaisesRegex(
                ScientificExecutionAdmissibilityError,
                "unavailable: LOCAL_SOURCE_AUTHORITY_ABSENT",
            ):
                register_scientific_execution_admissibility_authority(
                    registry,
                    ledger,
                    **selectors,
                )
            self.assertEqual(registry.list_records(), before_records)
            self.assertEqual(ledger.events(), before_events)


if __name__ == "__main__":
    unittest.main()
