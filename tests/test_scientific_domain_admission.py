"""Finite boundary tests for production scientific-domain admission.

These tests do not provision a trust root, authenticate observations, create a
scientific execution, or issue scientific authority.  They exercise only the
closed availability/fail-closed boundary and the unchanged fixture-v1 bytes.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import scientist_one.domains as domain_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.domains import (
    DOMAIN_RAW_FIXTURE_SCHEMA_VERSION,
    SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
    SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
    SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
    DomainEvidenceScope,
    DomainInputError,
    DomainKind,
    ScientificDomainAdmissionResolution,
    ScientificDomainAdmissionStatus,
    register_domain_evidence_source,
    register_domain_raw_fixture_source,
    register_scientific_domain_evidence_source,
    resolve_domain_validity,
    resolve_scientific_domain_admission_profile,
    revoke_scientific_domain_trust_root,
)
from scientist_one.ledger import LedgerEvent
from scientist_one.models import MacroState
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


class ScientificDomainAdmissionBoundaryTests(unittest.TestCase):
    def test_unknown_format_is_local_unsupported_not_external(self) -> None:
        result = resolve_scientific_domain_admission_profile(
            domain=DomainKind.GENERIC_ML,
            source_format_id="unimplemented-local-format",
            source_format_version="1.0",
        )
        self.assertIs(result.status, ScientificDomainAdmissionStatus.UNSUPPORTED)
        self.assertEqual(
            result.reason_code,
            "SCIENTIFIC_DOMAIN_SOURCE_FORMAT_UNSUPPORTED",
        )

    def test_installed_profile_and_missing_external_root_are_distinct(self) -> None:
        without_runtime = resolve_scientific_domain_admission_profile(
            domain=DomainKind.GENERIC_ML,
            source_format_id=(SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID),
            source_format_version=(
                SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
            ),
        )
        self.assertIs(
            without_runtime.status,
            ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
        )
        self.assertEqual(
            without_runtime.reason_code,
            "SCIENTIFIC_DOMAIN_SOURCE_REQUIRES_BOUND_CANDIDATE",
        )
        with TemporaryDirectory() as directory:
            registry = ArtifactRegistry(
                directory,
                "runs/domain-admission/registry",
            )
            before_records = registry.list_records()
            before_paths = tuple(
                sorted(
                    path.relative_to(directory).as_posix()
                    for path in Path(directory).rglob("*")
                )
            )
            unavailable = resolve_scientific_domain_admission_profile(
                domain=DomainKind.GENERIC_ML,
                source_format_id=(SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID),
                source_format_version=(
                    SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
                ),
                registry=registry,
            )
            after_paths = tuple(
                sorted(
                    path.relative_to(directory).as_posix()
                    for path in Path(directory).rglob("*")
                )
            )
            self.assertIs(
                unavailable.status,
                ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL,
            )
            self.assertEqual(
                unavailable.reason_code,
                "GENERIC_ML_OBSERVATION_TRUST_ROOT_UNAVAILABLE",
            )
            self.assertEqual(registry.list_records(), before_records)
            self.assertEqual(after_paths, before_paths)

    def test_malformed_root_files_fail_as_local_safety_errors(self) -> None:
        for shape in ("empty", "symlink", "hardlink"):
            with self.subTest(shape=shape), TemporaryDirectory() as directory:
                registry = ArtifactRegistry(
                    directory,
                    "runs/domain-admission/registry",
                )
                root_path = (
                    Path(directory)
                    / "runs/domain-admission/registry"
                    / SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
                )
                target = Path(directory) / "malformed-not-a-key"
                target.write_bytes(b"")
                target.chmod(0o600)
                if shape == "empty":
                    root_path.write_bytes(b"")
                    root_path.chmod(0o600)
                elif shape == "symlink":
                    root_path.symlink_to(target)
                else:
                    os.link(target, root_path)
                before = registry.list_records()
                unavailable = resolve_scientific_domain_admission_profile(
                    domain=DomainKind.GENERIC_ML,
                    source_format_id=(
                        SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID
                    ),
                    source_format_version=(
                        SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
                    ),
                    registry=registry,
                )
                self.assertIs(
                    unavailable.status,
                    ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
                )
                self.assertIn(
                    unavailable.reason_code,
                    {
                        "GENERIC_ML_TRUST_ROOT_UNSAFE",
                        "GENERIC_ML_TRUST_ROOT_READ_FAILED",
                    },
                )
                self.assertEqual(registry.list_records(), before)

    def test_unavailable_resolution_cannot_carry_claimed_authority(self) -> None:
        with self.assertRaisesRegex(
            DomainInputError,
            "unavailable scientific domain admission cannot carry authority",
        ):
            ScientificDomainAdmissionResolution(
                status=ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL,
                reason_code="TRUST_SOURCE_UNAVAILABLE",
                reason="the required external trust source is unavailable",
                source_artifact_sha256="a" * 64,
                evidence={"caller_claim": True},
            )

    def test_scientific_issuance_api_has_no_scope_or_evidence_injection(self) -> None:
        parameters = inspect.signature(
            register_scientific_domain_evidence_source
        ).parameters
        self.assertNotIn("scope", parameters)
        self.assertNotIn("evidence", parameters)
        self.assertIn("raw_source_artifact_sha256", parameters)
        self.assertIn(
            "scientific_execution_authority_artifact_sha256",
            parameters,
        )
        self.assertIn("canonical_run_artifact_sha256", parameters)

    def test_v2_replay_requires_ledger_but_fixture_v1_does_not(self) -> None:
        self.assertIn(
            "ledger",
            inspect.signature(resolve_domain_validity).parameters,
        )
        self.assertEqual(
            inspect.signature(resolve_domain_validity).parameters["ledger"].default,
            None,
        )

    def test_caller_selected_scientific_scope_still_fails_without_writes(self) -> None:
        with TemporaryDirectory() as directory:
            registry = ArtifactRegistry(
                directory,
                "runs/domain-admission/registry",
            )
            before = registry.list_records()
            with self.assertRaisesRegex(
                DomainInputError,
                "caller-selected scope cannot grant authority",
            ):
                register_domain_evidence_source(
                    registry,
                    run_id="domain-admission",
                    domain=DomainKind.GENERIC_ML,
                    object_id="candidate-object",
                    task_id="candidate-task",
                    evidence={"caller_claim": "PASS"},
                    supporting_artifact_hashes=(),
                    scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
                )
            self.assertEqual(registry.list_records(), before)

    def test_fixture_v1_wrapper_bytes_remain_exact_and_disjoint(self) -> None:
        with TemporaryDirectory() as directory:
            registry = ArtifactRegistry(
                directory,
                "runs/domain-admission/registry",
            )
            record = register_domain_raw_fixture_source(
                registry,
                run_id="domain-admission",
                domain=DomainKind.GENERIC_ML,
                object_id="candidate-object",
                task_id="candidate-task",
                source_id="deterministic-fixture",
                payload={"observed": [1, 2, 3]},
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            expected = (
                canonical_json_bytes(
                    {
                        "schema_version": DOMAIN_RAW_FIXTURE_SCHEMA_VERSION,
                        "run_id": "domain-admission",
                        "domain": DomainKind.GENERIC_ML.value,
                        "object_id": "candidate-object",
                        "task_id": "candidate-task",
                        "source_id": "deterministic-fixture",
                        "fixture": True,
                        "real_workload_validation": "UNTESTED",
                        "payload": {"observed": [1, 2, 3]},
                    }
                )
                + b"\n"
            )
            self.assertEqual(registry.get_bytes(record.sha256), expected)
            self.assertEqual(record.schema_version, DOMAIN_RAW_FIXTURE_SCHEMA_VERSION)

    def test_private_root_basename_is_assembled_and_not_an_api(self) -> None:
        expected = ".scientific-domain-generic-ml-observations-" + "authority.key"
        self.assertEqual(
            SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
            expected,
        )
        parameters = inspect.signature(
            register_scientific_domain_evidence_source
        ).parameters
        self.assertNotIn("authentication_key", parameters)
        self.assertNotIn("signing_key", parameters)
        revocation_parameters = inspect.signature(
            revoke_scientific_domain_trust_root
        ).parameters
        self.assertNotIn("authentication_key", revocation_parameters)
        self.assertNotIn("signing_key", revocation_parameters)

    def test_closed_output_parsers_recompute_and_reject_semantic_splices(self) -> None:
        execution_run_id = "execution-run"
        model_sha256 = "1" * 64
        evaluator_sha256 = "2" * 64
        split_sha256 = "3" * 64
        example_ids = ("example-1", "example-2")
        example_hashes = ("4" * 64, "5" * 64)
        metric_policy = {
            "schema_version": "trusted-kernel-reference-accuracy/v1",
            "metric_id": "primary-accuracy",
            "semantics": "EXACT_INTEGER_LABEL_MATCH",
            "aggregation": "MICRO_EXAMPLE_MEAN",
            "unit": "FRACTION",
            "direction": "HIGHER_IS_BETTER",
        }
        prediction_payload = {
            "schema_version": "trusted-kernel-generic-ml-predictions/v1",
            "execution_run_id": execution_run_id,
            "model_artifact_sha256": model_sha256,
            "evaluator_artifact_sha256": evaluator_sha256,
            "confirmatory_split_authority_artifact_sha256": split_sha256,
            "metric_policy": metric_policy,
            "reported_accuracy": 0.5,
            "rows": [
                {
                    "example_id": example_ids[0],
                    "example_sha256": example_hashes[0],
                    "expected_label": 0,
                    "prediction": 0,
                },
                {
                    "example_id": example_ids[1],
                    "example_sha256": example_hashes[1],
                    "expected_label": 0,
                    "prediction": 1,
                },
            ],
        }
        labels, predictions, accuracy = (
            domain_module._parse_trusted_kernel_generic_ml_prediction_bytes(
                canonical_json_bytes(prediction_payload) + b"\n",
                execution_run_id=execution_run_id,
                model_artifact_sha256=model_sha256,
                evaluator_artifact_sha256=evaluator_sha256,
                confirmatory_split_authority_artifact_sha256=split_sha256,
                metric_policy=metric_policy,
                expected_example_ids=example_ids,
                expected_example_hashes=example_hashes,
            )
        )
        self.assertEqual(labels, (0, 0))
        self.assertEqual(predictions, (0, 1))
        self.assertEqual(accuracy, 0.5)

        wrong_accuracy = dict(prediction_payload)
        wrong_accuracy["reported_accuracy"] = 1.0
        with self.assertRaisesRegex(DomainInputError, "reference accuracy"):
            domain_module._parse_trusted_kernel_generic_ml_prediction_bytes(
                canonical_json_bytes(wrong_accuracy) + b"\n",
                execution_run_id=execution_run_id,
                model_artifact_sha256=model_sha256,
                evaluator_artifact_sha256=evaluator_sha256,
                confirmatory_split_authority_artifact_sha256=split_sha256,
                metric_policy=metric_policy,
                expected_example_ids=example_ids,
                expected_example_hashes=example_hashes,
            )

        robustness = {
            "schema_version": "trusted-kernel-generic-ml-robustness/v1",
            "execution_run_id": execution_run_id,
            "robustness_test_id": "distribution-shift",
            "candidate_model_artifact_sha256": model_sha256,
            "evaluator_artifact_sha256": evaluator_sha256,
            "confirmatory_split_authority_artifact_sha256": split_sha256,
            "status": "COMPLETED",
        }
        domain_module._validate_trusted_kernel_generic_ml_robustness_bytes(
            canonical_json_bytes(robustness) + b"\n",
            execution_run_id=execution_run_id,
            robustness_test_id="distribution-shift",
            candidate_model_artifact_sha256=model_sha256,
            evaluator_artifact_sha256=evaluator_sha256,
            confirmatory_split_authority_artifact_sha256=split_sha256,
        )
        with self.assertRaisesRegex(DomainInputError, "source-owned schema"):
            domain_module._validate_trusted_kernel_generic_ml_robustness_bytes(
                canonical_json_bytes(robustness) + b"\n",
                execution_run_id=execution_run_id,
                robustness_test_id="different-test",
                candidate_model_artifact_sha256=model_sha256,
                evaluator_artifact_sha256=evaluator_sha256,
                confirmatory_split_authority_artifact_sha256=split_sha256,
            )
        caller_pass = dict(robustness)
        caller_pass["status"] = "PASS"
        with self.assertRaisesRegex(DomainInputError, "source-owned schema"):
            domain_module._validate_trusted_kernel_generic_ml_robustness_bytes(
                canonical_json_bytes(caller_pass) + b"\n",
                execution_run_id=execution_run_id,
                robustness_test_id="distribution-shift",
                candidate_model_artifact_sha256=model_sha256,
                evaluator_artifact_sha256=evaluator_sha256,
                confirmatory_split_authority_artifact_sha256=split_sha256,
            )

    def test_causal_time_uses_run_raw_and_source_order(self) -> None:
        domain_module._require_scientific_domain_causal_time(
            earlier="2026-01-01T00:00:00Z",
            earlier_label="canonical Run",
            later="2026-01-01T00:00:01Z",
            later_label="raw source",
            failure="raw source precedes Run",
        )
        with self.assertRaisesRegex(DomainInputError, "raw source precedes Run"):
            domain_module._require_scientific_domain_causal_time(
                earlier="2026-01-01T00:00:01Z",
                earlier_label="canonical Run",
                later="2026-01-01T00:00:00Z",
                later_label="raw source",
                failure="raw source precedes Run",
            )
        with self.assertRaisesRegex(DomainInputError, "UTC timestamp"):
            domain_module._require_scientific_domain_causal_time(
                earlier="2026-01-01T00:00:00",
                earlier_label="raw source",
                later="2026-01-01T00:00:01Z",
                later_label="evidence source",
                failure="source precedes raw source",
            )

    def test_revocation_marker_remains_denying_after_later_events(self) -> None:
        trust_root_id = "b" * 64
        marker = LedgerEvent.create(
            run_id="domain-admission",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.PREFLIGHT,
            requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=("a" * 64,),
            code_version="test-tree",
            configuration_hash="c" * 64,
            reason="deny-only trust-root revocation fixture",
            prior_event_hash=None,
            event_id=(
                domain_module._scientific_domain_trust_revocation_event_id(
                    trust_root_id
                )
            ),
            timestamp="2026-01-01T00:00:00Z",
            event_type="CHECKPOINT",
        )
        later = LedgerEvent.create(
            run_id="domain-admission",
            actor_role=Role.ORCHESTRATOR,
            state_before=MacroState.PREFLIGHT,
            requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=(),
            code_version="test-tree",
            configuration_hash="c" * 64,
            reason="later correction cannot restore a revoked root",
            prior_event_hash=marker.event_hash,
            event_id="evt-later-correction",
            timestamp="2026-01-01T00:00:01Z",
            event_type="CORRECTION",
            supersedes_event_id=marker.event_id,
        )
        with self.assertRaisesRegex(DomainInputError, "irreversibly revoked"):
            domain_module._reject_revoked_scientific_domain_trust_root(
                (marker, later),
                trust_root_id=trust_root_id,
                plan_artifact_sha256="a" * 64,
            )

    def test_observation_shape_rejects_claimed_status_and_incomplete_facts(self) -> None:
        digest = "a" * 64
        observations = {
            "schema_version": "trusted-kernel-generic-ml-observations/v1",
            "actual_domain_policy": {"preprocessing_fit_split_ids": ["train"]},
            "loaded_pretrained_resource_inventory": {
                "schema_version": "trusted-kernel-loaded-pretrained-inventory/v1",
                "completeness": "EXHAUSTIVE",
                "artifact_sha256s": [],
            },
            "models": {
                "baseline_id": "baseline-1",
                "candidate_model_artifact_sha256": digest,
                "candidate_model_record_hash": digest,
                "baseline_model_artifact_sha256": digest,
                "baseline_model_record_hash": digest,
                "candidate_parameter_count": 10,
                "baseline_parameter_count": 10,
            },
            "metric_evaluation": {
                "metric_id": "primary-accuracy",
                "evaluator_artifact_sha256": digest,
                "evaluator_record_hash": digest,
                "confirmatory_split_authority_artifact_sha256": digest,
                "confirmatory_split_authority_record_hash": digest,
                "candidate_model_artifact_sha256": digest,
                "baseline_model_artifact_sha256": digest,
                "candidate_predictions_artifact_sha256": digest,
                "candidate_predictions_record_hash": digest,
                "baseline_predictions_artifact_sha256": digest,
                "baseline_predictions_record_hash": digest,
                "candidate_accuracy": 0.5,
                "baseline_accuracy": 0.5,
            },
            "robustness_outputs": [
                {
                    "robustness_test_id": "distribution-shift",
                    "artifact_sha256": digest,
                    "artifact_record_hash": digest,
                }
            ],
        }
        self.assertEqual(
            domain_module._validate_trusted_kernel_generic_ml_observation_shape(
                observations
            ),
            observations,
        )
        for label, mutate in (
            (
                "missing-count",
                lambda value: value["models"].pop("candidate_parameter_count"),
            ),
            (
                "claimed-pass",
                lambda value: value.update(validation_status="PASS"),
            ),
            (
                "claimed-seed-fact",
                lambda value: value.update(seed_policy_pass=True),
            ),
            (
                "incomplete-inventory",
                lambda value: value["loaded_pretrained_resource_inventory"].update(
                    completeness="PARTIAL"
                ),
            ),
            (
                "missing-output-record",
                lambda value: value["metric_evaluation"].pop(
                    "candidate_predictions_record_hash"
                ),
            ),
        ):
            candidate = {
                key: dict(value) if isinstance(value, dict) else list(value)
                if isinstance(value, list)
                else value
                for key, value in observations.items()
            }
            mutate(candidate)
            with self.subTest(label=label), self.assertRaises(DomainInputError):
                domain_module._validate_trusted_kernel_generic_ml_observation_shape(
                    candidate
                )

        prospective = {"preprocessing_fit_split_ids": ["train"]}
        observed = {"preprocessing_fit_split_ids": ["confirmatory"]}
        with self.assertRaisesRegex(DomainInputError, "prospective policy"):
            domain_module._require_trusted_kernel_observed_domain_policy(
                observed,
                prospective,
            )


if __name__ == "__main__":
    unittest.main()
