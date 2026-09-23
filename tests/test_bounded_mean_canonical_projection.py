"""Pure bounded canonical views; no scientific source authority is fabricated."""

from dataclasses import fields, replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_PROFILE_ID,
    BoundedMeanInferenceResult,
    PairedRowCorrectnessCounts,
)
from scientist_one.errors import ValidationError
from scientist_one.ledger import EventLedger
from scientist_one.research_state import (
    MAX_CANONICAL_OBJECT_BYTES,
    CanonicalResearchObject,
    RecordStatus,
    StatisticalTest,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    HypothesisStatus,
    ScientificResultCanonicalProjectionV4,
    ScientificResultOutcome,
    derive_bounded_mean_result_assessment,
    require_scientific_result_canonical_projection_v3,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from scientist_one.scientific_r_checks import _canonical_v3_selected
from tests import test_bounded_mean_policy as numeric_fixtures
from tests import test_scientific_canonical_state as canonical_fixtures


def _projection(*, n=1000, candidate=3, reference=2, seeds=5, **policy_changes):
    legacy = canonical_fixtures._projection()
    policy = numeric_fixtures._policy(
        metric_id=legacy.metric_id,
        hypothesis_id=legacy.hypothesis_id,
        **policy_changes,
    )
    numeric = numeric_fixtures._result(
        policy, n=n, candidate=candidate, reference=reference, seeds=seeds,
    )
    decision = derive_bounded_mean_result_assessment(policy, numeric)
    # Reuse only method-neutral inert fixture identities, never legacy
    # bootstrap or generic p fields. No source owner is called or replaced.
    values = {
        field.name: getattr(legacy, field.name)
        for field in fields(ScientificResultCanonicalProjectionV4)
        if hasattr(legacy, field.name)
        and field.name not in {"null_hypothesis", "alternative"}
    }
    values.update(
        candidate_value=candidate / seeds,
        baseline_value=reference / seeds,
        improvement_effect=numeric.mean_estimate,
        confidence_low=numeric.confidence_low,
        confidence_high=numeric.confidence_high,
        mean_zero_p_upper=numeric.mean_zero_p_upper,
        sample_size=n,
        hypothesis_status=decision.hypothesis_status,
        outcome=decision.outcome,
        seed_order=numeric.plan.seed_order,
        numeric_result=numeric,
        hypothesis_policy=policy,
        statistical_use_authority_artifact_sha256=canonical_fixtures._hash("statistical-use"),
        statistical_use_authority_record_hash=canonical_fixtures._hash("statistical-use-record"),
    )
    return ScientificResultCanonicalProjectionV4(**values)


class BoundedMeanCanonicalProjectionTests(unittest.TestCase):
    def test_legacy_view_bytes_and_common_run_identity_are_preserved(self):
        legacy = canonical_fixtures._projection()
        views = {name: getattr(legacy, name) for name in (
            "state_value", "state_uncertainty", "state_metadata",
            "statistical_state_method_configuration", "statistical_state_outcome",
            "statistical_state_metadata", "run_metadata",
        )}
        self.assertEqual(
            hashlib.sha256(canonical_json_bytes(views)).hexdigest(),
            "998d2cbb7669e17040ac969567322ef129d5ca6665749b14e84f55015b534c02",
        )
        self.assertEqual(legacy.run_id, legacy.execution_run_id)

    def test_new_views_have_explicit_native_mean_sources_without_legacy_placeholders(self):
        projection = _projection()
        legacy = canonical_fixtures._projection()
        self.assertEqual(projection.run_id, projection.execution_run_id)
        self.assertFalse(projection.scientific_authority)
        self.assertEqual(projection.state_metadata["schema_version"], "scientific-result-canonical-state/v4")
        self.assertEqual(projection.statistical_state_metadata["schema_version"], "scientific-statistical-canonical-state/v4")
        for value in (
            projection.state_metadata, projection.statistical_state_metadata,
            projection.statistical_state_method_configuration,
        ):
            self.assertEqual(value["inference_profile_id"], BOUNDED_MEAN_PROFILE_ID)
            self.assertEqual(value["statistical_use_authority_artifact_sha256"], projection.statistical_use_authority_artifact_sha256)
            self.assertEqual(value["statistical_use_authority_record_hash"], projection.statistical_use_authority_record_hash)
        field_names = {field.name for field in fields(projection)}
        for key in ("bootstrap_seed", "bootstrap_resamples", "raw_p_value", "adjusted_p_value", "resampling_unit"):
            self.assertNotIn(key, field_names)
            self.assertNotIn(key, projection.statistical_state_method_configuration)
            self.assertNotIn(key, projection.statistical_state_outcome)
            self.assertNotIn(key, projection.state_uncertainty)
        for name in (
            "state_source_artifact_hashes", "state_evaluation_artifact_hashes",
            "state_authority_artifact_hashes", "statistical_state_source_artifact_hashes",
            "run_output_artifact_hashes", "run_authority_artifact_hashes", "run_metadata",
        ):
            self.assertEqual(getattr(projection, name), getattr(legacy, name))

    def test_native_outcomes_remain_distinct_in_result_and_test_views(self):
        for arguments, expected, status in (
            ({"meaningful_effect": 0.02}, ScientificResultOutcome.POSITIVE, HypothesisStatus.SUPPORTED),
            ({}, ScientificResultOutcome.POSITIVE, HypothesisStatus.PARTIALLY_SUPPORTED),
            ({"candidate": 2, "reference": 3}, ScientificResultOutcome.NEGATIVE, HypothesisStatus.NOT_SUPPORTED),
            ({"candidate": 2, "reference": 3, "falsification_effect": 0.02}, ScientificResultOutcome.FALSIFIED, HypothesisStatus.FALSIFIED),
            ({"candidate": 2, "reference": 2}, ScientificResultOutcome.NULL, HypothesisStatus.NOT_SUPPORTED),
            ({"n": 20, "candidate": 2, "reference": 2}, ScientificResultOutcome.INCONCLUSIVE, HypothesisStatus.INCONCLUSIVE),
        ):
            with self.subTest(arguments=arguments):
                projection = _projection(**arguments)
                self.assertIs(projection.outcome, expected)
                self.assertIs(projection.hypothesis_status, status)
                self.assertEqual(projection.state_metadata["scientific_result_outcome"], expected.value)
                self.assertEqual(projection.statistical_state_outcome["scientific_result_outcome"], expected.value)

    def test_mixed_policy_numeric_identity_or_interval_is_rejected(self):
        projection = _projection()
        for change in (
            {"hypothesis_id": "another-hypothesis"},
            {"metric_id": "another-metric"},
            {"seed_order": (False, 1, 2, 3, 4)},
            {"seed_order": tuple(reversed(projection.seed_order))},
            {"sample_size": True},
            {"mean_zero_p_upper": 0.0},
            {"candidate_value": 0.61},
            {"confidence_low": projection.confidence_low + 0.001},
            {"hypothesis_policy": replace(projection.hypothesis_policy, alpha=0.1)},
            {"outcome": ScientificResultOutcome.NEGATIVE},
            {"null_hypothesis": "median difference is zero"},
            {"scientific_authority": True},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                replace(projection, **change)
        forged = replace(projection.numeric_result)
        object.__setattr__(forged, "mean_zero_p_upper", 0.0)
        with self.assertRaises(ValidationError):
            replace(projection, numeric_result=forged)

    def test_maximum_grid_views_fit_canonical_capacity_and_retain_underflow(self):
        projection = _projection(n=4096, candidate=24, reference=0, seeds=24)
        self.assertGreater(projection.mean_zero_p_upper, 0.0)
        self.assertTrue(projection.statistical_state_outcome["mean_zero_p_binary64_underflow_limited"])
        views = {
            "method_configuration": projection.statistical_state_method_configuration,
            "outcome": projection.statistical_state_outcome,
            "metadata": projection.statistical_state_metadata,
        }
        self.assertLess(len(canonical_json_bytes(views)), MAX_CANONICAL_OBJECT_BYTES // 10)
        self.assertNotIn("unit_ids", views["method_configuration"])
        self.assertEqual(len(views["method_configuration"]["ordered_numeric_plan_sha256"]), 64)
        # Roundtrip the actual canonical codecs, still without materializing
        # or authorizing these caller-reproducible numerical fixture values.
        result = replace(
            canonical_fixtures._result(),
            value=projection.state_value,
            uncertainty=projection.state_uncertainty,
            metadata=projection.state_metadata,
            source_artifact_hashes=projection.state_source_artifact_hashes,
            evaluation_artifact_hashes=projection.state_evaluation_artifact_hashes,
            authority_artifact_hashes=projection.state_authority_artifact_hashes,
            content_hash=None,
        )
        test = StatisticalTest(
            object_id="inert-maximum-native-test",
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
            source_artifact_hashes=projection.statistical_state_source_artifact_hashes,
            authority_artifact_hashes=tuple(sorted(projection.statistical_state_source_artifact_hashes)),
            metadata=projection.statistical_state_metadata,
        )
        for value in (result, test):
            encoded = value.canonical_bytes()
            self.assertLess(len(encoded), MAX_CANONICAL_OBJECT_BYTES // 10)
            roundtrip = CanonicalResearchObject.from_dict(safe_json_loads(encoded))
            self.assertEqual(roundtrip, value)
            self.assertEqual(roundtrip.canonical_bytes(), encoded)

    def test_opposing_sign_balance_cannot_change_the_native_mean_decision(self):
        projection = _projection(
            n=4096, candidate=24, reference=0, seeds=24, meaningful_effect=0.1,
        )
        plan = projection.numeric_result.plan
        rows = tuple(
            PairedRowCorrectnessCounts(unit, 24, 0, 1)
            if index < 3200 else PairedRowCorrectnessCounts(unit, 24, 24, 0)
            for index, unit in enumerate(plan.unit_ids)
        )
        numeric = BoundedMeanInferenceResult(plan=plan, rows=rows)
        decision = derive_bounded_mean_result_assessment(projection.hypothesis_policy, numeric)
        changed = replace(
            projection,
            numeric_result=numeric,
            candidate_value=896 / 4096,
            baseline_value=3200 / (24 * 4096),
            improvement_effect=numeric.mean_estimate,
            confidence_low=numeric.confidence_low,
            confidence_high=numeric.confidence_high,
            mean_zero_p_upper=numeric.mean_zero_p_upper,
            hypothesis_status=decision.hypothesis_status,
            outcome=decision.outcome,
        )
        self.assertIs(changed.outcome, ScientificResultOutcome.POSITIVE)
        self.assertIs(changed.hypothesis_status, HypothesisStatus.SUPPORTED)
        self.assertEqual(numeric.auxiliary_sign.positive_count, 896)
        self.assertEqual(numeric.auxiliary_sign.negative_count, 3200)
        self.assertGreater(changed.confidence_low, 0.1)
        self.assertEqual(changed.statistical_state_outcome["scientific_result_outcome"], "POSITIVE")

    def test_inert_view_cannot_replace_full_promotion_source_replay(self):
        projection = _projection()
        with TemporaryDirectory(prefix="inert-bounded-canonical-") as directory:
            registry = ArtifactRegistry(Path(directory), "runs/ledger-run/registry")
            ledger = EventLedger(Path(directory), "runs/ledger-run/events.jsonl")
            record = registry.put_json(
                {"scope": "NON_EVIDENTIARY", "view": projection.state_metadata},
                logical_type="scientific_result_promotion_authority_v3",
                origin="inert canonical rejection fixture",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("test", "inert-canonical"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before = registry.verify_all(raise_on_error=True)
            with self.assertRaises(ValidationError):
                require_scientific_result_canonical_projection_v3(
                    registry, ledger,
                    promotion_receipt_artifact_sha256=record.sha256,
                    expected_ledger_run_id=projection.ledger_run_id,
                    expected_execution_run_id=projection.execution_run_id,
                    expected_result_id=projection.result_id,
                    canonical_state_code_version=projection.canonical_state_code_version,
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), before)

    def test_r_check_dispatch_selects_only_matching_new_or_historical_profiles(self):
        # Real canonical codecs and registry bytes, but selector-only: none of
        # these objects is materialized or admitted by a scientific owner.
        for result_version, statistics_version, expected in (
            (3, 3, True), (4, 4, True), (None, None, False),
            (3, 4, None), (4, 3, None), (4, None, None),
            (None, 4, None), (5, 5, None),
        ):
            with self.subTest(result=result_version, test=statistics_version), TemporaryDirectory(
                prefix="inert-canonical-profile-pair-"
            ) as directory:
                registry = ArtifactRegistry(Path(directory))
                result = replace(
                    canonical_fixtures._result(),
                    metadata=(
                        {"schema_version": f"scientific-result-canonical-state/v{result_version}"}
                        if result_version is not None else {}
                    ),
                    content_hash=None,
                )
                statistical_test = StatisticalTest(
                    object_id="inert-test-profile",
                    producer=Role.STATISTICIAN,
                    status=RecordStatus.COMPLETE,
                    created_at="2026-09-04T12:00:03Z",
                    code_version="inert-profile-selector",
                    result_ids=(result.object_id,),
                    test_name="NON_EVIDENTIARY_SELECTOR",
                    null_hypothesis="No statistical claim.",
                    alternative="No statistical claim.",
                    source_artifact_hashes=(canonical_fixtures._hash("inert-source"),),
                    metadata=(
                        {"schema_version": f"scientific-statistical-canonical-state/v{statistics_version}"}
                        if statistics_version is not None else {}
                    ),
                )
                records = tuple(registry.put_bytes(
                    value.canonical_bytes(),
                    logical_type=value.logical_type,
                    origin="NON_EVIDENTIARY canonical selector only",
                    creator_role=Role.STATISTICIAN,
                    creation_command=("test", "inert-canonical-selector"),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                ) for value in (result, statistical_test))
                before = registry.verify_all(raise_on_error=True)
                if expected is None:
                    with self.assertRaisesRegex(ValueError, "profiles disagree"):
                        _canonical_v3_selected(registry, records)
                else:
                    self.assertIs(_canonical_v3_selected(registry, records), expected)
                self.assertEqual(registry.verify_all(raise_on_error=True), before)


if __name__ == "__main__":
    unittest.main()
