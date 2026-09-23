"""Inert format tests, not scientific or source-owner acceptance tests."""

from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import BOUNDED_MEAN_PROFILE_ID
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    CHECKED_RESULT_ASSESSMENT_SCHEMA_V3,
    CheckedResultAssessment,
    require_checked_result_assessment,
)
from scientist_one.security import canonical_json_bytes
from tests import test_projection_checked_result_assessment as projection_fixtures


class BoundedMeanAssessmentCodecTests(unittest.TestCase):
    def setUp(self):
        self.fixture = projection_fixtures.ProjectionCheckedResultAssessmentTests()
        self.projection = self.fixture._assessment(projection_backed=True)
        self.new = replace(
            self.projection,
            adjusted_p_value=None,
            statistical_use_authority_artifact_sha256="a" * 64,
            statistical_use_authority_record_hash="b" * 64,
            inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
            mean_zero_p_upper=0.5,
        )

    def test_legacy_byte_hashes_are_unchanged(self):
        for projection, expected in (
            (False, "3920a8b8193f7189e2b38510b057f97e27ba3b7f9dfa0d08dd48b971f23dbe3a"),
            (True, "a7f9943b45f02d03f0a1e2d42a8927d1ab031003177e479999c2aa1d7662eb33"),
        ):
            value = self.fixture._assessment(projection_backed=projection).to_dict()
            self.assertEqual(
                hashlib.sha256(canonical_json_bytes(value)).hexdigest(), expected
            )
            self.assertEqual(CheckedResultAssessment.from_dict(value).to_dict(), value)
            self.assertNotIn("inference_profile_id", value)

    def test_new_roundtrip_has_explicit_mean_bound_and_statistical_source(self):
        value = self.new.to_dict()
        self.assertEqual(value["schema_version"], CHECKED_RESULT_ASSESSMENT_SCHEMA_V3)
        self.assertNotIn("adjusted_p_value", value)
        self.assertEqual(value["mean_zero_p_upper"], 0.5)
        self.assertTrue(self.new.is_projection_backed)
        self.assertTrue(self.new.is_bounded_mean)
        self.assertEqual(self.new.source_artifact_hashes[5], "a" * 64)
        self.assertEqual(
            self.new.source_artifact_hashes[:5],
            self.projection.source_artifact_hashes[:5],
        )
        self.assertEqual(
            self.new.source_artifact_hashes[6:],
            self.projection.source_artifact_hashes[5:],
        )
        self.assertEqual(CheckedResultAssessment.from_dict(value), self.new)

    def test_missing_null_or_wrong_profile_cannot_be_read_as_a_legacy_version(self):
        value = self.new.to_dict()
        fields = (
            "statistical_use_authority_artifact_sha256",
            "statistical_use_authority_record_hash",
            "inference_profile_id",
            "mean_zero_p_upper",
        )
        for field in fields:
            missing = dict(value)
            missing.pop(field)
            for changed in (missing, {**value, field: None}):
                with self.subTest(field=field, changed=changed):
                    with self.assertRaises(ValidationError):
                        CheckedResultAssessment.from_dict(changed)
        for changed in (
            {**value, **{field: None for field in fields}},
            {**value, "inference_profile_id": "legacy-sign-bootstrap"},
            {**value, "schema_version": "checked-result-assessment/v2"},
            {**value, "adjusted_p_value": 0.5},
        ):
            with self.assertRaises(ValidationError):
                CheckedResultAssessment.from_dict(changed)

    def test_new_constructor_rejects_mixed_sources_aliases_and_generic_p(self):
        for change in (
            {"adjusted_p_value": 0.5},
            {
                "statistical_use_authority_artifact_sha256": self.new.aggregate_result_sha256
            },
            {
                "evaluator_assessment_sha256": "c" * 64,
                "evaluator_record_hash": "d" * 64,
            },
            {"inference_profile_id": None},
            {"sample_size": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValidationError):
                    replace(self.new, **change)

    def test_positive_mean_bound_underflow_is_retained_not_zero(self):
        self.assertEqual(
            replace(self.new, mean_zero_p_upper=5e-324).mean_zero_p_upper, 5e-324
        )
        for value in (0.0, -0.1, 1.1, True, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    replace(self.new, mean_zero_p_upper=value)

    def test_codec_alone_cannot_enable_public_scientific_replay(self):
        with TemporaryDirectory(prefix="bounded-codec-inert-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(
                root, base_path="runs/non-evidentiary-ledger/registry"
            )
            ledger = EventLedger(
                root, path="runs/non-evidentiary-ledger/events.jsonl"
            )
            record = registry.put_json(
                self.new.to_dict(),
                logical_type="checked_result_assessment",
                origin="non-evidentiary codec-only test",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("test", "inert-codec"),
                parent_artifacts=(),
                schema_version="3.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with self.assertRaises(ValidationError):
                require_checked_result_assessment(
                    registry,
                    ledger,
                    assessment_artifact_sha256=record.sha256,
                    expected_ledger_run_id=self.new.ledger_run_id,
                    expected_execution_run_id=self.new.execution_run_id,
                )


if __name__ == "__main__":
    unittest.main()
