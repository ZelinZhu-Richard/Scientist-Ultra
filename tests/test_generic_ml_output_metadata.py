"""Actual bounded metadata construction, never scientific owner admission.

The registry's schema bound is exercised by native ArtifactRecord construction.
Long content schema IDs remain exact payload formats, not registry schema IDs.
No keys, source-owner mocks, issuers or positive scientific lifecycle are used.
"""

import ast
from dataclasses import replace
import inspect
import unittest

from scientist_one import domains, generic_ml_projection as projection
from scientist_one.artifacts import ArtifactRecord
from scientist_one.errors import ValidationError
from scientist_one.models import Role


class GenericMLOutputMetadataTests(unittest.TestCase):
    def test_domain_plan_metadata_is_constructible_without_changing_its_payload_schema(self):
        metadata_schema = domains.SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION
        content_schema = domains.SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION
        self.assertEqual(content_schema, "scientific-domain-evidence-plan/v1")
        self.assertEqual(metadata_schema, "domain-evidence-plan/v1")
        record = ArtifactRecord(
            sha256="a" * 64, path="objects/inert-plan", relative_path="objects/inert-plan",
            metadata_path="metadata/inert-plan.json", logical_type="scientific_domain_evidence_plan.generic_ml",
            schema_version=metadata_schema, mime_type="application/json", size=1,
            origin="inert unregistered domain-plan metadata", creator_role=Role.PROTOCOL_DESIGNER,
            creation_command=("inert-metadata-check",), parent_artifacts=(),
            validation_result="PENDING", frozen=False, created_at="2026-09-06T00:00:00Z",
        )
        self.assertEqual(ArtifactRecord.from_dict(record.to_dict()), record)
        with self.assertRaisesRegex(ValidationError, "schema version"):
            replace(record, schema_version=content_schema, record_hash=None)
        register_tree = ast.parse(inspect.getsource(domains.register_scientific_domain_evidence_plan))
        plans = [node for node in ast.walk(register_tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "_scientific_domain_artifact_plan"]
        self.assertEqual(len(plans), 1)
        metadata_arg = next(keyword.value for keyword in plans[0].keywords if keyword.arg == "schema_version")
        self.assertEqual(ast.unparse(metadata_arg), "SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION")
        replay_tree = ast.parse(inspect.getsource(domains._require_scientific_domain_evidence_plan))
        comparisons = {ast.unparse(node) for node in ast.walk(replay_tree) if isinstance(node, ast.Compare)}
        self.assertIn("record.schema_version != SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION", comparisons)
        self.assertIn("value['schema_version'] != SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION", comparisons)

    def test_actual_output_metadata_schema_ids_fit_the_unchanged_registry_bound(self):
        profiles = (
            (projection.GENERIC_ML_MODEL_ARTIFACT_SCHEMA, projection.GENERIC_ML_MODEL_SCHEMA, "generic_ml_model"),
            (projection.GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA, projection.GENERIC_ML_PREDICTIONS_SCHEMA, "generic_ml_paired_predictions"),
            (projection.GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA, projection.GENERIC_ML_ROBUSTNESS_SCHEMA, "generic_ml_robustness"),
            (domains._SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA,
             domains._SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_SCHEMA, "generic_ml_predictions"),
            (domains._SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA,
             domains._SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_SCHEMA, "generic_ml_robustness"),
        )
        for metadata_schema, content_schema, logical_type in profiles:
            with self.subTest(metadata_schema=metadata_schema):
                record = ArtifactRecord(
                    sha256="a" * 64, path="objects/inert", relative_path="objects/inert",
                    metadata_path="metadata/inert.json", logical_type=f"experiment_output.{logical_type}",
                    schema_version=metadata_schema, mime_type="application/json", size=1,
                    origin="inert metadata shape test, not authority", creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("inert-metadata-check",), parent_artifacts=("b" * 64, "c" * 64),
                    validation_result="PASS", frozen=True, created_at="2026-09-06T00:00:00Z",
                )
                self.assertEqual(ArtifactRecord.from_dict(record.to_dict()), record)
                self.assertLessEqual(len(metadata_schema), 32)
                self.assertGreater(len(content_schema), 32)
                with self.assertRaisesRegex(ValidationError, "schema version"):
                    replace(record, schema_version=content_schema, record_hash=None)

    def test_native_output_reader_calls_use_metadata_not_content_schema_ids(self):
        calls = [node for node in ast.walk(ast.parse(inspect.getsource(projection.derive_generic_ml_projection_facts)))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "_execution_output_record"]
        self.assertEqual(len(calls), 4)
        schemas = [next(keyword.value.id for keyword in node.keywords if keyword.arg == "schema_version")
                   for node in calls]
        self.assertEqual(schemas, ["GENERIC_ML_MODEL_ARTIFACT_SCHEMA", "GENERIC_ML_MODEL_ARTIFACT_SCHEMA",
                                   "GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA", "GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA"])

    def test_content_format_identifiers_are_unchanged_and_not_metadata_aliases(self):
        self.assertEqual(projection.GENERIC_ML_MODEL_SCHEMA, "trusted-kernel-integer-linear-classifier/v2")
        self.assertEqual(projection.GENERIC_ML_PREDICTIONS_SCHEMA, "trusted-kernel-generic-ml-predictions/v2")
        self.assertEqual(projection.GENERIC_ML_ROBUSTNESS_SCHEMA, "trusted-kernel-generic-ml-robustness/v2")
        self.assertEqual(domains._SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_SCHEMA, "trusted-kernel-generic-ml-predictions/v1")
        self.assertEqual(domains._SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_SCHEMA, "trusted-kernel-generic-ml-robustness/v1")
        # The legacy source verifier still parses the same content IDs, while
        # its actual metadata predicates use the separate short schema IDs.
        source = inspect.getsource(domains)
        self.assertIn("record.schema_version\n            != _SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA", source)
        self.assertIn("output.schema_version\n            != _SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA", source)


if __name__ == "__main__":
    unittest.main()
