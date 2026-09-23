"""Inert native projections and publication mechanics; never scientific PASS mocks."""

from dataclasses import MISSING, fields, replace
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import BOUNDED_MEAN_PROFILE_ID
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.research_state import (
    HypothesisEvaluationAuthority,
    HypothesisStatus,
    RecordStatus,
    ResearchStateRepository,
    StatisticalTest,
    _bounded_hypothesis_projection_outcome,
    _hypothesis_evaluation_facts,
    _locked_research_state_source_snapshot,
    _matching_hypothesis_evaluation_authority_slots,
    _preflight_bounded_hypothesis_evaluation_publication,
    require_hypothesis_evaluation_authority,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes, sha256_bytes
from tests import test_bounded_mean_canonical_projection as bounded
from tests import test_scientific_canonical_state as canonical


def _legacy_authority():
    values = {}
    for item in fields(HypothesisEvaluationAuthority):
        if item.default is not MISSING:
            continue
        name = item.name
        if name == "evidence_scope":
            values[name] = "NON_EVIDENTIARY_MECHANICAL"
        elif name == "outcome":
            values[name] = "INCONCLUSIVE"
        elif name == "scientific_evidence_eligible":
            values[name] = False
        elif name == "blocker_codes":
            values[name] = ("INERT_DTO_ONLY",)
        elif name.endswith("_hashes"):
            values[name] = ("a" * 64,)
        elif "hash" in name or name.endswith("sha256"):
            values[name] = None if "None" in item.type else "b" * 64
        elif name == "sample_size":
            values[name] = 20
        elif name == "evaluation_event_index":
            values[name] = 0
        elif name == "adjusted_p_value":
            values[name] = None
        elif name == "improvement_effect":
            values[name] = 0.0
        elif name == "confidence_low":
            values[name] = -0.3
        elif name == "confidence_high":
            values[name] = 0.3
        else:
            values[name] = name.replace("_", "-")
    return HypothesisEvaluationAuthority(**values)


def _bounded_authority():
    return replace(
        _legacy_authority(),
        inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
        mean_zero_p_upper=1.0,
        checked_result_assessment_artifact_hash="c" * 64,
        checked_result_assessment_record_hash="d" * 64,
        paired_metric_projection_authority_artifact_hash="e" * 64,
        paired_metric_projection_authority_record_hash="f" * 64,
        statistical_use_authority_artifact_hash="1" * 64,
        statistical_use_authority_record_hash="2" * 64,
    )


def _pair(projection):
    result = replace(
        canonical._result(),
        value=projection.state_value,
        uncertainty=projection.state_uncertainty,
        metadata=projection.state_metadata,
        content_hash=None,
    )
    test = StatisticalTest(
        object_id="inert-native-test",
        producer=Role.STATISTICIAN,
        status=RecordStatus.COMPLETE,
        created_at="2026-09-04T12:00:03Z",
        code_version=projection.canonical_state_code_version,
        result_ids=(projection.result_id,),
        test_name=projection.contract_primary_test,
        null_hypothesis=projection.null_hypothesis,
        alternative=projection.alternative,
        method_configuration=projection.statistical_state_method_configuration,
        outcome=projection.statistical_state_outcome,
        metadata=projection.statistical_state_metadata,
        source_artifact_hashes=projection.statistical_state_source_artifact_hashes,
    )
    return result, test


def _inert_publication_prefix(directory):
    """Only ledger/registry mechanics: these objects deliberately lack scientific owners."""
    registry = ArtifactRegistry(directory, "runs/ledger-run/registry")
    ledger = EventLedger(directory, "runs/ledger-run/events.jsonl")
    projection = bounded._projection()
    result, test = _pair(projection)
    repository = ResearchStateRepository(
        registry,
        ledger,
        run_id="ledger-run",
        code_version=projection.canonical_state_code_version,
        configuration_hash="b" * 64,
        state=MacroState.CONFIRM,
    )
    base = registry.put_json(
        {"scope": "INERT_PUBLICATION_MECHANICS_ONLY"},
        logical_type="inert_fixture",
        origin="inert fixture",
        creator_role=Role.ORCHESTRATOR,
        creation_command=("test", "inert"),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
        created_at="2026-09-04T12:00:00Z",
    )
    ledger.record(
        run_id=repository.run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=repository.state,
        requested_state_after=repository.state,
        artifact_hashes=(base.sha256,),
        code_version=repository.code_version,
        configuration_hash=repository.configuration_hash,
        reason="inert publication mechanics",
        event_type="CHECKPOINT",
        timestamp="2026-09-04T12:00:00Z",
    )
    stored = []
    for obj in (result, test):
        record = registry.put_bytes(
            obj.canonical_bytes(),
            logical_type=obj.logical_type,
            origin="inert unpublished scientific view",
            creator_role=obj.producer,
            creation_command=("test", "inert"),
            schema_version=obj.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=obj.created_at,
        )
        ledger.record(
            run_id=repository.run_id,
            actor_role=obj.producer,
            state_before=repository.state,
            requested_state_after=repository.state,
            artifact_hashes=(record.sha256,),
            code_version=repository.code_version,
            configuration_hash=repository.configuration_hash,
            reason="inert materialization-shaped event, not source authority",
            event_type="CHECKPOINT",
            event_id=f"rs-{record.sha256[:48]}",
            timestamp=obj.created_at,
            metadata={
                "research_state_operation": "MATERIALIZED",
                "object_type": obj.object_type,
                "object_id": obj.object_id,
                "revision": 1,
                "content_hash": obj.content_hash,
                "artifact_hash": record.sha256,
                "schema_version": obj.schema_version,
                "supersedes_content_hash": None,
            },
        )
        stored.append(record)
    # Supply inert structs only to the private read-only preflight boundary.
    # No production source resolver is called or replaced with success.
    source = {
        "repository": repository,
        "prior": replace(result, object_id=projection.hypothesis_id, content_hash=None),
        "prior_record": base,
        "result": result,
        "result_record": stored[0],
        "statistical_test": test,
        "statistical_record": stored[1],
        "contract": type("InertContract", (), {"sha256": "b" * 64})(),
        "contract_record": base,
        "policy": projection.hypothesis_policy,
        "facts": projection,
        "outcome": HypothesisStatus(projection.hypothesis_status.value),
        "result_records": (base,),
        "statistical_records": (base,),
        **{
            key: None
            for key in (
                "promotion_hash",
                "backend_hash",
                "timeline_hash",
                "confirmation_hash",
                "domain_hash",
                "statistics_hash",
                "evaluator_hash",
                "obligations_hash",
            )
        },
        "blockers": ("INERT_DTO_ONLY",),
        "scientific_evidence_eligible": False,
        "evidence_scope": _legacy_authority().evidence_scope,
        "bounded_fields": {
            "inference_profile_id": BOUNDED_MEAN_PROFILE_ID,
            "mean_zero_p_upper": projection.mean_zero_p_upper,
            **{
                key: (base.record_hash if key.endswith("record_hash") else base.sha256)
                for key in (
                    "checked_result_assessment_artifact_hash",
                    "checked_result_assessment_record_hash",
                    "paired_metric_projection_authority_artifact_hash",
                    "paired_metric_projection_authority_record_hash",
                    "statistical_use_authority_artifact_hash",
                    "statistical_use_authority_record_hash",
                )
            },
        },
        "source_hashes": tuple(
            sorted((base.sha256, stored[0].sha256, stored[1].sha256))
        ),
    }
    source["source_snapshot"] = _locked_research_state_source_snapshot(
        registry, ledger, run_id=repository.run_id
    )
    return registry, ledger, source


class BoundedHypothesisCodecTests(unittest.TestCase):
    def test_legacy_bytes_remain_exact_and_omit_all_new_fields(self):
        old = _legacy_authority()
        self.assertEqual(
            sha256_bytes(canonical_json_bytes(old.to_dict())),
            "249227af194c31a6ed2b8226382723b6475556ae9526f686b29da6a7df59bfe4",
        )
        self.assertEqual(HypothesisEvaluationAuthority.from_dict(old.to_dict()), old)
        self.assertEqual(old.artifact_schema_version, "1.0")
        self.assertNotIn("mean_zero_p_upper", old.evaluation_binding["facts"])

    def test_native_fields_and_source_closure_are_distinct(self):
        value = _bounded_authority()
        self.assertEqual(value.artifact_schema_version, "2.0")
        self.assertEqual(
            HypothesisEvaluationAuthority.from_dict(value.to_dict()), value
        )
        for key in (
            "adjusted_p_value",
            "evaluator_authority_artifact_hash",
            "scientific_obligations_authority_artifact_hash",
        ):
            self.assertNotIn(key, value.to_dict())
            self.assertIsNone(getattr(value, key))
        self.assertNotIn("adjusted_p_value", value.evaluation_binding["facts"])
        self.assertEqual(
            value.evaluation_binding["schema_version"], "hypothesis-evaluated-event/v2"
        )
        for key in (
            "checked_result_assessment_artifact_hash",
            "paired_metric_projection_authority_artifact_hash",
            "statistical_use_authority_artifact_hash",
        ):
            self.assertIn(getattr(value, key), value.source_artifact_hashes)
        self.assertFalse(value.scientific_evidence_eligible)

    def test_closed_versions_reject_missing_mixed_and_unknown_fields(self):
        base = _bounded_authority().to_dict()
        changes = [
            {"schema_version": "hypothesis-evaluation-authority/v1"},
            {"schema_version": "hypothesis-evaluation-authority/v3"},
            {"inference_profile_id": None},
            {"inference_profile_id": "legacy"},
            {"adjusted_p_value": None},
            {"mean_zero_p_upper": None},
            {"evaluator_authority_artifact_hash": None},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                HypothesisEvaluationAuthority.from_dict({**base, **change})
        for key in base:
            with self.subTest(missing=key), self.assertRaises(ValidationError):
                HypothesisEvaluationAuthority.from_dict(
                    {k: v for k, v in base.items() if k != key}
                )

    def test_finite_native_numbers_and_positive_underflow_are_required(self):
        class Integer(int):
            pass

        class Floating(float):
            pass

        base = _bounded_authority()
        for change in (
            {"mean_zero_p_upper": 0.0},
            {"mean_zero_p_upper": float("nan")},
            {"mean_zero_p_upper": True},
            {"mean_zero_p_upper": Floating(1.0)},
            {"confidence_low": float("-inf")},
            {"sample_size": Integer(20)},
            {"sample_size": True},
            {"sample_size": 4097},
            {"adjusted_p_value": 0.5},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                replace(base, **change)
        underflow = replace(base, mean_zero_p_upper=5e-324)
        self.assertEqual(
            HypothesisEvaluationAuthority.from_dict(
                underflow.to_dict()
            ).mean_zero_p_upper,
            5e-324,
        )


class BoundedHypothesisProjectionTests(unittest.TestCase):
    def test_all_native_mean_outcomes_follow_exact_policy_not_generic_p(self):
        for changes in (
            {},
            {"meaningful_effect": 0.02},
            {"candidate": 2, "reference": 3},
            {"candidate": 2, "reference": 3, "falsification_effect": 0.02},
            {"candidate": 2, "reference": 2},
            {"n": 20, "candidate": 2, "reference": 2},
        ):
            projection = bounded._projection(**changes)
            result, test = _pair(projection)
            with self.subTest(changes=changes):
                self.assertEqual(
                    _bounded_hypothesis_projection_outcome(
                        projection, projection.hypothesis_policy, result, test
                    ).value,
                    projection.hypothesis_status.value,
                )
                with self.assertRaisesRegex(ValidationError, "native source replay"):
                    _hypothesis_evaluation_facts(result, test)

    def test_mixed_policy_view_numeric_type_and_generic_p_fail_closed(self):
        projection = bounded._projection()
        result, test = _pair(projection)
        for changed in (
            replace(
                test,
                outcome={
                    **projection.statistical_state_outcome,
                    "adjusted_p_value": 0.01,
                },
                content_hash=None,
            ),
            replace(
                test,
                outcome={**projection.statistical_state_outcome, "sample_size": True},
                content_hash=None,
            ),
            replace(
                test,
                metadata={
                    **projection.statistical_state_metadata,
                    "inference_profile_id": "wrong",
                },
                content_hash=None,
            ),
        ):
            with self.assertRaises(ValidationError):
                _bounded_hypothesis_projection_outcome(
                    projection, projection.hypothesis_policy, result, changed
                )
        with self.assertRaises(ValidationError):
            _bounded_hypothesis_projection_outcome(
                projection,
                replace(projection.hypothesis_policy, policy_id="other"),
                result,
                test,
            )


class BoundedHypothesisPublicationTests(unittest.TestCase):
    def test_read_only_candidate_and_event_only_recovery_preserve_timestamp(self):
        with TemporaryDirectory() as directory:
            registry, ledger, source = _inert_publication_prefix(directory)
            before = source["source_snapshot"]
            candidate = _preflight_bounded_hypothesis_evaluation_publication(
                registry,
                ledger,
                source=source,
                authority_id="inert-evaluation",
                evaluated_at="2026-09-04T12:00:04Z",
            )
            authority, record, event, event_missing, artifact_missing = candidate
            self.assertFalse(authority.scientific_evidence_eligible)
            self.assertTrue(event_missing and artifact_missing)
            self.assertEqual(
                _locked_research_state_source_snapshot(
                    registry, ledger, run_id="ledger-run"
                ),
                before,
            )
            ledger.append(event)
            source["source_snapshot"] = _locked_research_state_source_snapshot(
                registry, ledger, run_id="ledger-run"
            )
            retry = _preflight_bounded_hypothesis_evaluation_publication(
                registry,
                ledger,
                source=source,
                authority_id="inert-evaluation",
                evaluated_at=event.timestamp,
            )
            self.assertEqual(retry[:3], (authority, record, event))
            self.assertEqual(retry[3:], (False, True))
            with self.assertRaisesRegex(ValidationError, "prefix differs"):
                _preflight_bounded_hypothesis_evaluation_publication(
                    registry,
                    ledger,
                    source=source,
                    authority_id="inert-evaluation",
                    evaluated_at="2026-09-04T12:00:05Z",
                )
            self.assertEqual(
                _locked_research_state_source_snapshot(
                    registry, ledger, run_id="ledger-run"
                ),
                source["source_snapshot"],
            )

    def test_backdated_publication_rejects_before_any_write(self):
        with TemporaryDirectory() as directory:
            registry, ledger, source = _inert_publication_prefix(directory)
            before = source["source_snapshot"]
            with self.assertRaisesRegex(ValidationError, "backdated"):
                _preflight_bounded_hypothesis_evaluation_publication(
                    registry,
                    ledger,
                    source=source,
                    authority_id="inert-evaluation",
                    evaluated_at="2026-09-04T12:00:01Z",
                )
            self.assertEqual(
                _locked_research_state_source_snapshot(
                    registry, ledger, run_id="ledger-run"
                ),
                before,
            )

    def test_shared_slots_cover_both_versions_and_all_identity_dimensions(self):
        for old_version in (False, True):
            for same_id in (False, True):
                with (
                    self.subTest(old_version=old_version, same_id=same_id),
                    TemporaryDirectory() as directory,
                ):
                    registry = ArtifactRegistry(directory)
                    target = _bounded_authority()
                    other = _legacy_authority() if old_version else target
                    other = replace(
                        other,
                        **(
                            {"hypothesis_id": "other"}
                            if same_id
                            else {"authority_id": "other"}
                        ),
                    )
                    record = registry.put_json(
                        other.to_dict(),
                        logical_type="hypothesis_evaluation_authority",
                        origin="inert slot fixture",
                        creator_role=Role.SCIENTIFIC_REVIEWER,
                        creation_command=("test", "inert"),
                        schema_version=other.artifact_schema_version,
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )
                    self.assertEqual(
                        _matching_hypothesis_evaluation_authority_slots(
                            registry, (record,), target
                        ),
                        (record,),
                    )

    def test_inert_dto_never_substitutes_for_full_hypothesis_source_owner(self):
        with TemporaryDirectory() as directory:
            registry = ArtifactRegistry(directory, "runs/run-id/registry")
            ledger = EventLedger(directory, "runs/run-id/events.jsonl")
            ledger.validate(raise_on_error=True)
            value = _bounded_authority()
            record = registry.put_json(
                value.to_dict(),
                logical_type="hypothesis_evaluation_authority",
                origin="inert codec fixture",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("test", "inert"),
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before = _locked_research_state_source_snapshot(
                registry, ledger, run_id="run-id"
            )
            with self.assertRaises((ArtifactError, ValidationError)):
                require_hypothesis_evaluation_authority(
                    registry,
                    ledger,
                    authority_artifact_hash=record.sha256,
                    expected_run_id="run-id",
                )
            self.assertEqual(
                _locked_research_state_source_snapshot(
                    registry, ledger, run_id="run-id"
                ),
                before,
            )
