"""Non-authoritative numeric artifact slots; no scientific owner is mocked."""

from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import BOUNDED_MEAN_PROFILE_ID
from scientist_one.errors import ValidationError
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    _CHECKED_RESULT_ASSESSMENT_COMMAND,
    _CHECKED_RESULT_ASSESSMENT_ORIGIN,
    _preflight_projection_checked_result_slots,
    _projection_checked_material_metadata,
    _projection_checked_material_record,
)
from tests import test_projection_checked_result_assessment as projection_fixtures


class BoundedMeanMaterialSlotTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="inert-numeric-slots-")
        self.addCleanup(self.directory.cleanup)
        self.registry = ArtifactRegistry(self.directory.name)
        self.selector = self.registry.put_json(
            {"scope": "NON_EVIDENTIARY_SELECTOR_ONLY"},
            logical_type="non_evidentiary_selector",
            origin="inert slot fixture",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("test", "inert-slot"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _arguments(self, bounded, kind="aggregate"):
        schema, origin, command = _projection_checked_material_metadata(
            bounded_mean=bounded,
            material_kind=kind,
        )
        return {
            "value": {
                "schema_version": f"checked-result-{kind}/v{3 if bounded else 2}",
                "scope": "NON_EVIDENTIARY_SLOT_CONTROL",
                "scientific_authority": False,
            },
            "logical_type": (
                "aggregate_experiment_result" if kind == "aggregate"
                else "statistical_analysis"
            ),
            "origin": origin,
            "creation_command": command,
            "schema_version": schema,
            "parent_artifacts": (self.selector.sha256,),
            "slot_parent_artifact_sha256": self.selector.sha256,
        }

    def _put(self, bounded, kind="aggregate", extra_parents=()):
        args = self._arguments(bounded, kind)
        return self.registry.put_json(
            args["value"],
            logical_type=args["logical_type"],
            origin=args["origin"],
            creator_role=Role.STATISTICIAN,
            creation_command=args["creation_command"],
            parent_artifacts=(*args["parent_artifacts"], *extra_parents),
            schema_version=args["schema_version"],
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _read(self, bounded, **overrides):
        return _projection_checked_material_record(
            self.registry,
            self.registry.verify_all(raise_on_error=True),
            **{**self._arguments(bounded), **overrides},
        )

    def test_new_slot_matches_exact_inert_material_without_issuing_authority(self):
        before = self.registry.verify_all(raise_on_error=True)
        record, encoded, digest = self._read(True)
        self.assertIsNone(record)
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)
        expected = self._put(True)
        actual, replayed_bytes, replayed_digest = self._read(True)
        self.assertEqual(actual, expected)
        self.assertEqual((replayed_bytes, replayed_digest), (encoded, digest))
        self.assertEqual(self.registry.get_bytes(expected.sha256), encoded)

    def test_a_legacy_material_occupies_the_same_projection_slot(self):
        legacy = self._put(False)
        self.assertEqual(self._read(False)[0], legacy)
        with self.assertRaisesRegex(ValidationError, "substituted"):
            self._read(True)
        self._put(True)
        for bounded in (False, True):
            with self.assertRaisesRegex(ValidationError, "ambiguous"):
                self._read(bounded)

    def test_new_record_cannot_be_read_with_legacy_metadata_or_changed_parents(self):
        self._put(True)
        _, legacy_origin, legacy_command = _projection_checked_material_metadata(
            bounded_mean=False,
            material_kind="aggregate",
        )
        for overrides in (
            {"origin": legacy_origin},
            {"creation_command": legacy_command},
            {"schema_version": "2.0"},
            {"parent_artifacts": ()},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ValidationError, "substituted"):
                    self._read(True, **overrides)

    def test_material_format_selection_is_closed(self):
        for bounded, kind in ((1, "aggregate"), (True, "caller-profile")):
            with self.assertRaises(ValidationError):
                _projection_checked_material_metadata(
                    bounded_mean=bounded, material_kind=kind
                )
        with self.assertRaises(ValidationError):
            self._read(True, schema_version="4.0")

    def _preflight(self, registry=None, **overrides):
        registry = registry or self.registry
        return _preflight_projection_checked_result_slots(
            registry,
            registry.verify_all(raise_on_error=True),
            **{
                "assessment_id": "inert-new-assessment",
                "execution_run_id": "inert-new-execution",
                "execution_authority_artifact_sha256": "f" * 64,
                "projection_artifact_sha256": self.selector.sha256,
                "aggregate_record": None,
                "statistics_record": None,
                **overrides,
            },
        )

    def test_empty_and_ordered_material_prefixes_remain_extendable(self):
        before = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(self._preflight(), ())
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)
        aggregate = self._put(True)
        before = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(self._preflight(aggregate_record=aggregate), ())
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)
        statistics = self._put(True, "statistics", (aggregate.sha256,))
        before = self.registry.verify_all(raise_on_error=True)
        self.assertEqual(
            self._preflight(aggregate_record=aggregate, statistics_record=statistics),
            (),
        )
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_statistics_without_aggregate_is_rejected_without_writes(self):
        self._put(True, "statistics")
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaisesRegex(ValidationError, "extendable material prefix"):
            self._preflight()
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_legacy_statistics_without_aggregate_also_occupies_slot(self):
        self._put(False, "statistics")
        before = self.registry.verify_all(raise_on_error=True)
        with self.assertRaisesRegex(ValidationError, "extendable material prefix"):
            self._preflight()
        self.assertEqual(self.registry.verify_all(raise_on_error=True), before)

    def test_every_assessment_version_and_identity_is_checked_before_new_materials(self):
        # These canonical-shaped assessment DTOs have only NON_EVIDENTIARY
        # supports. Only the mechanical slot inventory is called, never an
        # execution, source, inference or publication authority owner.
        fixture = projection_fixtures.ProjectionCheckedResultAssessmentTests()
        for version in (1, 2, 3):
            with self.subTest(version=version), TemporaryDirectory(
                prefix="inert-preflight-assessment-"
            ) as directory:
                registry = ArtifactRegistry(directory)
                supports = tuple(
                    registry.put_json(
                        {"scope": "NON_EVIDENTIARY", "index": index},
                        logical_type="non_evidentiary_slot_support",
                        origin="inert preflight fixture",
                        creator_role=Role.ORCHESTRATOR,
                        creation_command=("test", "inert-preflight"),
                        parent_artifacts=(),
                        schema_version="1.0",
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    ) for index in range(8)
                )
                assessment = fixture._assessment(
                    projection_backed=version != 1,
                    support_records=supports,
                )
                if version == 3:
                    assessment = replace(
                        assessment,
                        adjusted_p_value=None,
                        statistical_use_authority_artifact_sha256=supports[7].sha256,
                        statistical_use_authority_record_hash=supports[7].record_hash,
                        inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
                        mean_zero_p_upper=0.5,
                    )
                if version == 1:
                    schema, origin, command = (
                        "1.0", _CHECKED_RESULT_ASSESSMENT_ORIGIN,
                        _CHECKED_RESULT_ASSESSMENT_COMMAND,
                    )
                else:
                    schema, origin, command = _projection_checked_material_metadata(
                        bounded_mean=version == 3, material_kind="assessment",
                    )
                registry.put_json(
                    assessment.to_dict(),
                    logical_type="checked_result_assessment",
                    origin=origin,
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=command,
                    parent_artifacts=assessment.source_artifact_hashes,
                    schema_version=schema,
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                before = registry.verify_all(raise_on_error=True)
                self.assertFalse(any(
                    record.logical_type in {"aggregate_experiment_result", "statistical_analysis"}
                    for record in before.records
                ))
                for identity in (
                    {"assessment_id": assessment.assessment_id},
                    {"execution_run_id": assessment.execution_run_id},
                    {"execution_authority_artifact_sha256": supports[1].sha256},
                ):
                    # Also cover aggregate-only crash prefixes with no stats.
                    for aggregate in (None, supports[2]):
                        with self.subTest(identity=identity, aggregate=aggregate):
                            with self.assertRaisesRegex(ValidationError, "slot is occupied"):
                                self._preflight(
                                    registry, aggregate_record=aggregate, **identity,
                                )
                            self.assertEqual(registry.verify_all(raise_on_error=True), before)


if __name__ == "__main__":
    unittest.main()
