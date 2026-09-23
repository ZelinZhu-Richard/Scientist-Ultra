"""Non-evidentiary clean-repeat codecs, complete grids, and failing prefixes.

No source owner is patched to PASS; no scientific authority is registered.
Pure DTO equality and mechanical metadata probes are not scientific evidence.
"""

from dataclasses import fields, replace
import hashlib
import inspect
import math
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_PROFILE_ID, BoundedMeanInferencePlan, PairedRowCorrectnessCounts,
    analyze_fixed_complete_bounded_mean,
)
from scientist_one.generic_ml_projection import (
    GenericMLPairedMetricProjectionAuthority, GenericMLSeedPairedProjection,
)
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
import scientist_one.reproduction as reproduction
from scientist_one.reproduction import (
    BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID,
    BoundedMeanCleanRerunComparison,
    BoundedMeanCleanRerunDifference,
    BoundedMeanCleanRerunGridComparison,
    ReproductionError,
    ScientificCleanRerunAuthority,
    ScientificCleanRerunOutcome,
    ScientificCleanRerunPlan,
    derive_bounded_mean_clean_rerun_comparison,
    derive_scientific_clean_rerun_comparison,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import HypothesisStatus, ScientificResultOutcome
from scientist_one.security import canonical_json_bytes
from tests import test_projection_checked_result_assessment as fixtures
from tests.test_experiments import spec as inert_spec
from tests import test_scientific_clean_rerun as legacy_fixtures


def _hash(label):
    return hashlib.sha256(label.encode()).hexdigest()


def _profile():
    return dict(
        comparison_profile_id=BOUNDED_MEAN_CLEAN_RERUN_COMPARISON_PROFILE_ID,
        inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
        statistical_use_authority_artifact_sha256="a" * 64,
        statistical_use_authority_record_hash="b" * 64,
    )


def _projection(execution, *, n=3, seeds=(5, 17), candidate_rows=None):
    """Unregistered shape fixture; all hash strings are inert identifiers."""
    units = tuple(f"unit-{i}" for i in range(n))
    hashes = tuple(_hash(unit) for unit in units)
    candidate_rows = candidate_rows or tuple(tuple((i + seed) % 2 for i in range(n)) for seed in seeds)
    seed_rows = []
    for seed, candidate in zip(seeds, candidate_rows, strict=True):
        values = {
            field.name: _hash(f"{execution}-{seed}-{field.name}")
            for field in fields(GenericMLSeedPairedProjection)
            if "sha256" in field.name or "record_hash" in field.name
        }
        seed_rows.append(GenericMLSeedPairedProjection(
            **values, seed=seed, candidate_condition_id="candidate", baseline_condition_id="baseline",
            paired_unit_ids=units, paired_unit_hashes=hashes, reference_labels=(0,) * n,
            candidate_values=candidate, baseline_values=(0,) * n,
            candidate_mean=sum(candidate) / n, baseline_mean=0.0,
            candidate_parameter_count=2, baseline_parameter_count=2,
        ))
    values = {
        field.name: _hash(field.name)
        for field in fields(GenericMLPairedMetricProjectionAuthority)
        if "sha256" in field.name or "record_hash" in field.name or "content_hash" in field.name
    }
    for name in (
        "projection_artifact_sha256", "projection_record_hash", "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_record_hash", "scientific_execution_authority_artifact_sha256",
        "scientific_execution_authority_record_hash", "output_manifest_artifact_sha256",
        "output_manifest_record_hash", "canonical_run_artifact_sha256", "canonical_run_record_hash",
        "canonical_run_content_hash", "plan_artifact_sha256", "plan_record_hash",
    ):
        values[name] = _hash(execution + name)
    for name, length in (
        ("split_authority_artifact_sha256s", 4), ("split_authority_record_hashes", 4),
        ("paired_projection_artifact_sha256s", len(seeds)), ("paired_projection_record_hashes", len(seeds)),
        ("domain_consumed_output_artifact_sha256s", 1), ("domain_consumed_output_record_hashes", 1),
        ("ablation_output_artifact_sha256s", 1), ("ablation_output_record_hashes", 1),
    ):
        values[name] = tuple(_hash(f"{name}-{i}") for i in range(length))
    return GenericMLPairedMetricProjectionAuthority(
        **values, run_id="non-evidentiary-ledger", execution_run_id=execution,
        object_id=f"result-{execution}", task_id=f"task-{execution}", comparison_scope="FIXTURE_ONLY",
        seed_order=seeds, paired_unit_ids=units, paired_unit_hashes=hashes,
        reference_labels=(0,) * n, seed_projections=tuple(seed_rows),
        ledger_event_id=f"event-{execution}", ledger_event_hash=_hash(execution), ledger_event_index=10,
    )


def _assessment(projection):
    base = fixtures.ProjectionCheckedResultAssessmentTests()._assessment(projection_backed=True)
    profile = _profile()
    del profile["comparison_profile_id"]
    candidate = sum(sum(row.candidate_values) for row in projection.seed_projections) / (
        len(projection.paired_unit_ids) * len(projection.seed_order)
    )
    return replace(
        base, **profile, assessment_id=f"assessment-{projection.execution_run_id}",
        execution_run_id=projection.execution_run_id, ledger_run_id=projection.run_id,
        contract_artifact_sha256=projection.evaluation_contract_artifact_sha256,
        contract_record_hash=projection.evaluation_contract_record_hash,
        generic_ml_paired_metric_projection_authority_artifact_sha256=projection.projection_artifact_sha256,
        generic_ml_paired_metric_projection_authority_record_hash=projection.projection_record_hash,
        adjusted_p_value=None, mean_zero_p_upper=0.5, sample_size=len(projection.paired_unit_ids),
        candidate_value=candidate, baseline_value=0.0, improvement_effect=candidate,
        confidence_low=-1.0, confidence_high=1.0,
        hypothesis_status=HypothesisStatus.INCONCLUSIVE, outcome=ScientificResultOutcome.INCONCLUSIVE,
    )


def _comparison(left=None, right=None, *, tolerance=0.0, left_assessment=None, right_assessment=None):
    left = left or _projection("original-execution")
    right = right or _projection("rerun-execution")
    return derive_bounded_mean_clean_rerun_comparison(
        left_assessment or _assessment(left), right_assessment or _assessment(right),
        original_projection=left, rerun_projection=right, comparison_tolerance=tolerance,
    )


def _plan():
    return replace(
        legacy_fixtures.ScientificCleanRerunTests()._plan(), **_profile(),
        rerun_domain="GENERIC_ML",
        exact_match_fields=reproduction._BOUNDED_MEAN_CLEAN_RERUN_EXACT_FIELDS,
        numeric_comparison_fields=reproduction._BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS,
        grid_comparison_fields=reproduction._BOUNDED_MEAN_CLEAN_RERUN_GRID_FIELDS,
    )


def _authority(comparison=None):
    comparison = comparison or _comparison()
    return replace(
        legacy_fixtures.ScientificCleanRerunTests()._authority(), **_profile(),
        rerun_domain="GENERIC_ML",
        exact_mismatches=comparison.exact_mismatches, differences=comparison.differences,
        grid_comparisons=comparison.grid_comparisons, outcome=comparison.outcome,
    )


class BoundedMeanCleanRerunProfileTests(unittest.TestCase):
    def test_v1_payload_goldens_remain_exact(self):
        legacy = legacy_fixtures.ScientificCleanRerunTests()
        for value, expected in (
            (legacy._plan(), "2161573b3b6b45dbe15f5941ee1291df4ed203d989ada0cee7982bd297eab625"),
            (legacy._authority(), "608f648292e8403681d4ed3bbf52ef49f5731271d63dba8d450993f36de20a56"),
        ):
            raw = canonical_json_bytes(value.to_dict()) + b"\n"
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
            self.assertEqual(type(value).from_mapping(value.to_dict()), value)

    def test_v2_codecs_round_trip_exact_closed_profiles(self):
        for value, schema, parent_count in (
            (_plan(), reproduction.SCIENTIFIC_CLEAN_RERUN_PLAN_V2_SCHEMA, 5),
            (_authority(), reproduction.SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_SCHEMA, 12),
        ):
            self.assertEqual(value.to_dict()["schema_version"], schema)
            self.assertEqual(type(value).from_mapping(value.to_dict()), value)
            self.assertEqual(len(value.source_artifact_hashes), parent_count)
            self.assertNotIn(b"adjusted_p_value", canonical_json_bytes(value.to_dict()))
            self.assertIn(b"mean_zero_p_upper", canonical_json_bytes(value.to_dict()))

    def test_v2_closed_codecs_reject_missing_extra_null_and_mixed_version(self):
        for value in (_plan(), _authority()):
            wire = value.to_dict()
            for name in wire:
                with self.subTest(kind=type(value).__name__, missing=name):
                    candidate = dict(wire)
                    del candidate[name]
                    with self.assertRaises(ReproductionError):
                        type(value).from_mapping(candidate)
            for changes in (
                {"unknown": 1}, {"comparison_profile_id": None},
                {"inference_profile_id": None}, {"statistical_use_authority_record_hash": None},
                {"schema_version": wire["schema_version"].replace("/v2", "/v1")},
                {"comparison_profile_id": "unsupported/v1"},
            ):
                with self.subTest(changes=changes):
                    with self.assertRaises(ReproductionError):
                        type(value).from_mapping({**wire, **changes})

    def test_legacy_codecs_do_not_accept_v2_fields(self):
        legacy = legacy_fixtures.ScientificCleanRerunTests()
        for value in (legacy._plan(), legacy._authority()):
            with self.assertRaises(ReproductionError):
                type(value).from_mapping({**value.to_dict(), **_profile()})
        with self.assertRaises(ReproductionError):
            reproduction.ScientificCleanRerunDifference.from_mapping(_comparison().differences[-1].to_dict())

    def test_v2_arrays_and_native_tolerance_are_closed(self):
        for value, names in (
            (_plan(), ("exact_match_fields", "numeric_comparison_fields", "grid_comparison_fields")),
            (_authority(), ("exact_mismatches", "differences", "grid_comparisons")),
        ):
            for name in names:
                candidate = value.to_dict()
                candidate[name] = tuple(candidate[name])
                with self.assertRaises(ReproductionError):
                    type(value).from_mapping(candidate)
        class FloatSubclass(float):
            pass
        for value in (None, True, "0", math.nan, math.inf, -1.0, FloatSubclass(0)):
            with self.subTest(value=value):
                with self.assertRaises(ReproductionError):
                    replace(_plan(), comparison_tolerance=value)

    def test_all_required_primary_numbers_and_derived_differences_are_checked(self):
        for difference in _comparison().differences:
            for field in ("original_value", "rerun_value", "absolute_difference", "tolerance"):
                for bad in (None, True, "0", math.nan, math.inf):
                    with self.subTest(field=difference.field_name, component=field, bad=bad):
                        with self.assertRaises(ReproductionError):
                            replace(difference, **{field: bad})
            for changes in ({"absolute_difference": 0.125}, {"within_tolerance": 1}, {"within_tolerance": False}):
                with self.assertRaises(ReproductionError):
                    replace(difference, **changes)
        for probability in (0.0, -0.1, 1.1):
            with self.assertRaises(ReproductionError):
                BoundedMeanCleanRerunDifference("mean_zero_p_upper", probability, probability, 0, 0, True)

    def test_identical_grids_are_only_a_non_evidentiary_mechanical_pass(self):
        comparison = _comparison()
        self.assertIs(comparison.outcome, ScientificCleanRerunOutcome.PASS)
        self.assertFalse(comparison.scientific_evidence)
        self.assertEqual(comparison.authority_scope, "NON_EVIDENTIARY_MECHANICAL_COMPARISON")
        self.assertEqual(tuple(item.compared_value_count for item in comparison.grid_comparisons), (6, 6))
        self.assertEqual(comparison.differences[-1].field_name, "mean_zero_p_upper")

    def test_mean_probability_is_compared_at_precommitted_tolerance(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        changed = replace(_assessment(right), mean_zero_p_upper=0.75)
        self.assertIs(_comparison(left, right, right_assessment=changed).outcome,
                      ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE)
        self.assertIs(_comparison(left, right, right_assessment=changed, tolerance=0.25).outcome,
                      ScientificCleanRerunOutcome.PASS)

    def test_seed_cell_swaps_with_identical_marginal_counts_are_detected(self):
        left = _projection("original-execution", candidate_rows=((1, 0, 1), (0, 1, 1)))
        right = _projection("rerun-execution", candidate_rows=((0, 1, 1), (1, 0, 1)))
        comparison = _comparison(left, right)
        self.assertTrue(all(item.within_tolerance for item in comparison.differences))
        self.assertEqual(comparison.grid_comparisons[0].outside_tolerance_count, 4)
        self.assertIs(comparison.outcome, ScientificCleanRerunOutcome.OUTSIDE_TOLERANCE)
        self.assertIs(_comparison(left, right, tolerance=1.0).outcome, ScientificCleanRerunOutcome.PASS)

    def test_every_shared_source_and_record_join_is_exact(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        for name in (
            "run_id", "comparison_scope", "evaluation_contract_artifact_sha256", "evaluation_contract_record_hash",
            "dataset_authority_artifact_sha256", "dataset_authority_record_hash",
            "dataset_raw_artifact_sha256", "dataset_raw_record_hash",
            "frozen_model_configuration_artifact_sha256", "frozen_model_configuration_record_hash",
            "evaluator_artifact_sha256", "evaluator_record_hash",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ReproductionError):
                    _comparison(left, replace(right, **{name: _hash("other")}))
        for name in ("split_authority_artifact_sha256s", "split_authority_record_hashes"):
            for index in range(4):
                changed = list(getattr(right, name))
                changed[index] = _hash("other")
                with self.assertRaises(ReproductionError):
                    _comparison(left, replace(right, **{name: tuple(changed)}))

    def test_ordered_units_seeds_labels_conditions_and_dimensions_cannot_drift(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        for name in ("seed_order", "paired_unit_ids", "paired_unit_hashes", "reference_labels", "seed_projections"):
            for changed in ((), getattr(right, name)[:-1], getattr(right, name) + getattr(right, name)[:1]):
                with self.subTest(name=name):
                    with self.assertRaises(ReproductionError):
                        _comparison(left, replace(right, **{name: changed}), right_assessment=_assessment(right))
        for name, changed in (
            ("seed", 999), ("candidate_condition_id", "other"), ("baseline_condition_id", "other"),
            ("paired_unit_ids", left.paired_unit_ids[::-1]),
            ("paired_unit_hashes", left.paired_unit_hashes[::-1]), ("reference_labels", (1, 0, 0)),
            ("candidate_values", ()), ("baseline_values", (0,)),
        ):
            row = replace(right.seed_projections[0], **{name: changed})
            with self.assertRaises(ReproductionError):
                    _comparison(left, replace(right, seed_projections=(row, *right.seed_projections[1:])),
                                right_assessment=_assessment(right))

    def test_correctness_cells_reject_rounded_nonfinite_boolean_and_subclass_values(self):
        class IntSubclass(int):
            pass
        left, right = _projection("original-execution"), _projection("rerun-execution")
        for value in (True, False, math.nan, math.inf, -1, 2, 0.5, math.nextafter(1.0, 0), "1", IntSubclass(1)):
            for field in ("candidate_values", "baseline_values"):
                row = replace(right.seed_projections[0], **{field: (value, 0, 1)})
                with self.subTest(value=value, field=field):
                    with self.assertRaises(ReproductionError):
                        _comparison(left, replace(right, seed_projections=(row, *right.seed_projections[1:])),
                                    right_assessment=_assessment(right))

    @staticmethod
    def _hostile_types(calls):
        def tripwire(*args, **kwargs):
            calls.append("hostile scalar hook executed")
            raise AssertionError("native prevalidation must reject without calling scalar hooks")

        class HostileFloat(float):
            __float__ = __eq__ = __ne__ = __sub__ = __rsub__ = __lt__ = __le__ = __hash__ = tripwire

        class HostileString(str):
            __eq__ = __ne__ = __hash__ = tripwire

        class HostileInt(int):
            __eq__ = __ne__ = __hash__ = __sub__ = __rsub__ = tripwire

        class HostileTuple(tuple):
            __eq__ = __ne__ = __len__ = __iter__ = __getitem__ = tripwire

        return HostileFloat, HostileString, HostileInt, HostileTuple

    def test_mutated_assessment_dtos_reject_hostile_scalars_before_coercion_or_arithmetic(self):
        calls = []
        hostile_float, hostile_string, hostile_int, hostile_tuple = self._hostile_types(calls)
        left, right = _projection("original-execution"), _projection("rerun-execution")
        replacements = tuple((field, hostile_float(0.5)) for field in reproduction._BOUNDED_MEAN_CLEAN_RERUN_NUMERIC_FIELDS)
        replacements += tuple((field, hostile_string("hostile")) for field in (
            "ledger_run_id", "execution_run_id", "hypothesis_id", "contract_sha256", "contract_record_hash",
            "inference_profile_id", "statistical_use_authority_artifact_sha256", "statistical_use_authority_record_hash",
            "metric_id", "metric_unit", "metric_scope", "outcome", "hypothesis_status",
        ))
        replacements += (("sample_size", hostile_int(3)), ("baseline_exclusion_receipt_sha256s", hostile_tuple(())))
        for name, value in replacements:
            assessment = _assessment(right)
            object.__setattr__(assessment, name, value)
            with self.subTest(field=name), self.assertRaises(ReproductionError):
                _comparison(left, right, right_assessment=assessment)
        self.assertEqual(calls, [])
        for name, value in (("mean_zero_p_upper", None), ("confidence_low", math.nan), ("sample_size", True)):
            assessment = _assessment(right)
            object.__setattr__(assessment, name, value)
            with self.assertRaises(ReproductionError):
                _comparison(left, right, right_assessment=assessment)

    def test_projection_and_seed_identities_reject_hostile_values_before_equality(self):
        calls = []
        hostile_float, hostile_string, hostile_int, hostile_tuple = self._hostile_types(calls)
        left, right = _projection("original-execution"), _projection("rerun-execution")
        assessment = _assessment(right)
        for field in fields(right):
            value = getattr(right, field.name)
            if type(value) is str:
                changed = hostile_string(value)
            elif type(value) is tuple:
                changed = hostile_tuple(value)
            elif type(value) is int:
                changed = hostile_int(value)
            else:
                continue
            with self.subTest(field=field.name), self.assertRaises(ReproductionError):
                _comparison(left, replace(right, **{field.name: changed}), right_assessment=assessment)
        for name, value in (
            ("seed", hostile_int(5)), ("candidate_condition_id", hostile_string("candidate")),
            ("baseline_condition_id", hostile_string("baseline")), ("candidate_mean", hostile_float(0.5)),
            ("candidate_values", (hostile_float(1), 0, 1)),
            ("baseline_values", (hostile_int(0), 0, 0)),
            ("paired_unit_ids", (hostile_string("unit-0"), "unit-1", "unit-2")),
            ("reference_labels", (hostile_int(0), 0, 0)),
            ("candidate_model_artifact_sha256", hostile_string("a" * 64)),
        ):
            row = replace(right.seed_projections[0], **{name: value})
            with self.subTest(seed_field=name), self.assertRaises(ReproductionError):
                _comparison(left, replace(right, seed_projections=(row, *right.seed_projections[1:])),
                            right_assessment=assessment)
        self.assertEqual(calls, [])

    def test_distinct_run_output_and_projection_hashes_are_not_equality_fields(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        self.assertNotEqual(left.projection_artifact_sha256, right.projection_artifact_sha256)
        self.assertNotEqual(left.frozen_run_spec_artifact_sha256, right.frozen_run_spec_artifact_sha256)
        self.assertNotEqual(left.output_manifest_artifact_sha256, right.output_manifest_artifact_sha256)
        self.assertIs(_comparison(left, right).outcome, ScientificCleanRerunOutcome.PASS)

    def test_negative_null_falsified_and_inconclusive_repeat_without_becoming_positive(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        for outcome, status in (
            (ScientificResultOutcome.NEGATIVE, HypothesisStatus.NOT_SUPPORTED),
            (ScientificResultOutcome.NULL, HypothesisStatus.NOT_SUPPORTED),
            (ScientificResultOutcome.FALSIFIED, HypothesisStatus.FALSIFIED),
            (ScientificResultOutcome.INCONCLUSIVE, HypothesisStatus.INCONCLUSIVE),
        ):
            a, b = (replace(_assessment(item), outcome=outcome, hypothesis_status=status) for item in (left, right))
            self.assertIs(_comparison(left, right, left_assessment=a, right_assessment=b).outcome,
                          ScientificCleanRerunOutcome.PASS)
            changed = replace(b, outcome=ScientificResultOutcome.POSITIVE, hypothesis_status=HypothesisStatus.SUPPORTED)
            self.assertIs(_comparison(left, right, left_assessment=a, right_assessment=changed).outcome,
                          ScientificCleanRerunOutcome.FAIL)

    def test_compact_maximum_grid_fits_64k_without_dropping_cells(self):
        left, right = (_projection(item, n=4096, seeds=tuple(range(24)))
                       for item in ("original-execution", "rerun-execution"))
        comparison = _comparison(left, right)
        self.assertEqual(sum(item.compared_value_count for item in comparison.grid_comparisons), 196608)
        authority = _authority(comparison)
        self.assertLess(len(canonical_json_bytes(authority.to_dict())), 16 * 1024)
        event = self._event(metadata={"synthetic_non_evidentiary_comparison_codec": authority.to_dict()})
        reproduction._require_clean_rerun_event_bound(event)
        self.assertNotIn("paired_unit_ids", authority.to_dict())

    def test_grid_summaries_cannot_lie_about_counts_tolerance_or_outcome(self):
        summary = _comparison().grid_comparisons[0]
        for changes in (
            {"compared_value_count": 0}, {"compared_value_count": True},
            {"compared_value_count": 4096 * 24 + 1}, {"outside_tolerance_count": -1},
            {"outside_tolerance_count": 1}, {"maximum_absolute_difference": 0.5},
            {"within_tolerance": 1}, {"tolerance": math.nan},
        ):
            with self.assertRaises(ReproductionError):
                replace(summary, **changes)
        comparison = _comparison()
        for changes in ({"grid_comparisons": ()}, {"differences": comparison.differences[::-1]},
                        {"outcome": ScientificCleanRerunOutcome.FAIL}, {"scientific_evidence": True}):
            with self.assertRaises(ReproductionError):
                replace(comparison, **changes)

    def test_auxiliary_sign_and_underflow_log_are_not_primary_comparison_fields(self):
        plan = BoundedMeanInferencePlan(
            alpha=0.05, benefit_margin=0.1, harm_margin=0.1, minimum_unit_count=2,
            unit_ids=tuple(f"unit-{i}" for i in range(4096)), seed_order=tuple(range(24)),
        )
        values = tuple(analyze_fixed_complete_bounded_mean(
            plan=plan, rows=tuple(PairedRowCorrectnessCounts(unit, 24, count, 0) for unit in plan.unit_ids),
        ) for count in (23, 24))
        self.assertEqual(values[0].mean_zero_p_upper, values[1].mean_zero_p_upper)
        self.assertNotEqual(values[0].mean_zero_log_p_upper, values[1].mean_zero_log_p_upper)
        fields = _plan().numeric_comparison_fields
        self.assertNotIn("mean_zero_log_p_upper", fields)
        self.assertNotIn("auxiliary_sign", fields)
        self.assertNotIn("adjusted_p_value", fields)

    def test_same_host_is_allowed_without_new_data_or_seed_generalization(self):
        value = _authority()
        self.assertEqual(value.original_host_instance_id, value.rerun_host_instance_id)
        self.assertEqual(value.original_boot_session_id, value.rerun_boot_session_id)
        self.assertFalse(value.new_data_replication_claimed)
        self.assertFalse(value.training_randomness_generalization_claimed)
        self.assertTrue(value.original_cache_used)
        for changes in ({"new_data_replication_claimed": True}, {"training_randomness_generalization_claimed": True},
                        {"rerun_cache_used": True}, {"rerun_writable_storage_id": value.original_writable_storage_id},
                        {"rerun_challenge_nonce": value.original_challenge_nonce}):
            with self.assertRaises(ReproductionError):
                replace(value, **changes)

    def test_new_comparison_cannot_accept_legacy_or_optional_inputs(self):
        left, right = _projection("original-execution"), _projection("rerun-execution")
        legacy = fixtures.ProjectionCheckedResultAssessmentTests()._assessment(projection_backed=True)
        for a, b in ((legacy, _assessment(right)), (_assessment(left), legacy), (legacy, legacy)):
            with self.assertRaises(ReproductionError):
                _comparison(left, right, left_assessment=a, right_assessment=b)
        self.assertIsInstance(_comparison(), BoundedMeanCleanRerunComparison)
        self.assertIsInstance(_comparison().grid_comparisons[0], BoundedMeanCleanRerunGridComparison)
        self.assertIsInstance(_plan(), ScientificCleanRerunPlan)
        self.assertIsInstance(_authority(), ScientificCleanRerunAuthority)

    def test_slots_are_global_across_v1_v2_and_unknown_schemas(self):
        plan = _plan()
        for schema in ("v1", "v2", "unsupported"):
            for field, expected in (
                ("plan_artifact_sha256", _hash("plan")), ("rerun_result_id", plan.rerun_result_id),
                ("rerun_assessment_id", plan.rerun_assessment_id),
                ("rerun_execution_run_id", plan.rerun_execution_run_id),
            ):
                self.assertTrue(reproduction._clean_rerun_authority_slot_matches(
                    {"schema_version": schema, field: expected}, plan_artifact_sha256=_hash("plan"),
                    rerun_result_id=plan.rerun_result_id, rerun_assessment_id=plan.rerun_assessment_id,
                    rerun_execution_run_id=plan.rerun_execution_run_id,
                ))
        with TemporaryDirectory(prefix="non-evidentiary-clean-slot-") as directory:
            registry = ArtifactRegistry(Path(directory), "runs/fixture/registry")
            records = tuple(registry.put_json(
                {"schema_version": schema, "rerun_execution_run_id": plan.rerun_execution_run_id,
                 "scientific_evidence": False, "purpose": "invalid slot inventory fixture"},
                logical_type=reproduction.SCIENTIFIC_CLEAN_RERUN_AUTHORITY_LOGICAL_TYPE,
                creator_role=Role.IMPLEMENTER, origin="NON_EVIDENTIARY_SLOT_FIXTURE",
                creation_command=("fixture-only",), schema_version="0.0", validation_result="PASS", frozen=True,
            ) for schema in ("v1", "v2"))
            self.assertEqual(set(reproduction._matching_clean_rerun_authority_records(
                registry, registry.verify_all(raise_on_error=True).records,
                plan_artifact_sha256=_hash("plan"), plan=plan,
            )), set(records))

    def _prefix_sources(self, registry, *, bounded):
        records = tuple(registry.put_json(
            {"fixture_index": index, "scientific_evidence": False},
            logical_type="non_evidentiary_clean_prefix", creator_role=Role.IMPLEMENTER,
            origin="NON_EVIDENTIARY_PREFIX_FIXTURE", creation_command=("fixture-only",),
            schema_version="0.0", validation_result="PASS", frozen=True,
            created_at="2026-09-04T00:00:00Z",
        ) for index in range(5 if bounded else 4))
        return reproduction._CleanRerunPlanSources(
            result_promotion_record=records[0], result_resolution=None,
            assessment_record=records[1], original_execution_record=records[2],
            # Deliberately not a ScientificExecutionAuthority and no PASS outcome.
            original_execution=SimpleNamespace(execution_run_id="original-execution", ledger_event_index=0),
            rerun_spec_record=records[3], rerun_spec=inert_spec("rerun-execution"),
            original_promotion_event_index=0,  # Inert prefix topology only.
            original_domain_event_index=0,
            statistical_use_record=records[4] if bounded else None,
        )

    def _prefix_plan_event(self, sources, *, prior, event_id="plan-probe"):
        binding = reproduction._scientific_clean_rerun_plan_binding(
            plan_id="plan-probe", ledger_run_id="clean-rerun-ledger", original_result_id="original-result",
            rerun_result_id="rerun-result", rerun_assessment_id="rerun-assessment",
            rerun_domain="GENERIC_ML", rerun_domain_task_id="rerun-task", sources=sources,
        )
        event = LedgerEvent.create(
            run_id="clean-rerun-ledger", actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.PREFLIGHT, requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=tuple(item.sha256 for item in sources.source_records),
            code_version=f"sha256:{sources.rerun_spec.code_sha256}",
            configuration_hash=sources.rerun_spec.configuration_sha256,
            dataset_identifiers=(sources.rerun_spec.data_sha256,), random_seeds=sources.rerun_spec.seeds,
            evaluator_outputs=(), reason="froze a distinct scientific clean-rerun comparison before preparation",
            prior_event_hash=prior, event_type="CHECKPOINT", metadata={"scientific_clean_rerun_plan": binding},
            event_id=event_id, timestamp="2026-09-05T12:00:00Z",
        )
        return event, binding

    def test_late_plan_prefix_rejected_without_registry_or_ledger_writes_both_versions(self):
        for bounded in (False, True):
            with self.subTest(bounded=bounded), TemporaryDirectory(prefix="non-evidentiary-late-plan-") as directory:
                root = Path(directory)
                registry = ArtifactRegistry(root, "runs/fixture/registry")
                ledger = EventLedger(root, "runs/fixture/events.jsonl")
                sources = self._prefix_sources(registry, bounded=bounded)
                original = self._event(metadata={"non_evidentiary_prefix": True}, event_id="original-probe")
                preparation = self._event(metadata={"scientific_execution_preparation": {
                    "execution_run_id": sources.rerun_spec.run_id, "scientific_evidence": False,
                }}, prior=original.event_hash, event_id="preparation-probe")
                event, binding = self._prefix_plan_event(sources, prior=preparation.event_hash)
                before = reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger")
                with self.assertRaisesRegex(ReproductionError, "post hoc"):
                    reproduction._validate_scientific_clean_rerun_plan_event(
                        event, 2, (original, preparation, event), binding=binding, sources=sources,
                    )
                self.assertEqual(reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger"), before)
                self.assertEqual(ledger.read_events(), ())
                self.assertFalse(any(record.logical_type == reproduction.SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE
                                     for record in registry.list_records()))

    def test_exact_partial_plan_prefix_is_version_bound_and_correctable_not_upgradable(self):
        with TemporaryDirectory(prefix="non-evidentiary-plan-prefix-") as directory:
            registry = ArtifactRegistry(Path(directory), "runs/fixture/registry")
            legacy_sources = self._prefix_sources(registry, bounded=False)
            bounded_sources = self._prefix_sources(registry, bounded=True)
            original = self._event(metadata={}, event_id="original-probe")
            legacy_event, legacy_binding = self._prefix_plan_event(legacy_sources, prior=original.event_hash)
            _, bounded_binding = self._prefix_plan_event(bounded_sources, prior=original.event_hash)
            # Pure validation of an inert prefix is not source-owned admission.
            reproduction._validate_scientific_clean_rerun_plan_event(
                legacy_event, 1, (original, legacy_event), binding=legacy_binding, sources=legacy_sources,
            )
            later_preparation = self._event(metadata={"scientific_execution_preparation": {
                "execution_run_id": legacy_sources.rerun_spec.run_id, "scientific_evidence": False,
            }}, prior=legacy_event.event_hash, event_id="later-preparation")
            reproduction._validate_scientific_clean_rerun_plan_event(
                legacy_event, 1, (original, legacy_event, later_preparation), binding=legacy_binding, sources=legacy_sources,
            )
            with self.assertRaises(ReproductionError):
                reproduction._validate_scientific_clean_rerun_plan_event(
                    legacy_event, 1, (original, legacy_event), binding=bounded_binding, sources=bounded_sources,
                )
            correction = SimpleNamespace(event_type="CORRECTION", supersedes_event_id=legacy_event.event_id, metadata={})
            with self.assertRaises(ReproductionError):
                reproduction._validate_scientific_clean_rerun_plan_event(
                    legacy_event, 1, (original, legacy_event, correction), binding=legacy_binding, sources=legacy_sources,
                )

    def test_prospective_metadata_conflicts_are_inert_and_existing_timestamp_is_preserved(self):
        with TemporaryDirectory(prefix="non-evidentiary-clean-metadata-") as directory:
            registry = ArtifactRegistry(Path(directory), "runs/fixture/registry")
            sources = self._prefix_sources(registry, bounded=True)
            snapshot = registry.verify_all(raise_on_error=True)
            raw = b'{"scientific_evidence":false}\n'
            metadata = dict(
                logical_type="non_evidentiary_clean_prefix", creator_role=Role.IMPLEMENTER,
                origin="NON_EVIDENTIARY_METADATA_PROBE", creation_command=("fixture-only",),
                parent_artifacts=tuple(item.sha256 for item in sources.source_records),
                schema_version="0.0", created_at="2026-09-05T12:00:00Z",
            )
            prospective = reproduction._preflight_clean_rerun_record(registry, snapshot, raw, **metadata)
            self.assertEqual(registry.verify_all(raise_on_error=True), snapshot)
            record = registry.put_bytes(raw, **metadata, mime_type="application/json", validation_result="PASS", frozen=True)
            self.assertEqual(record, prospective)
            snapshot = registry.verify_all(raise_on_error=True)
            reused = reproduction._preflight_clean_rerun_record(
                registry, snapshot, raw, **{**metadata, "created_at": "2026-09-06T12:00:00Z"},
            )
            self.assertEqual(reused, record)
            with self.assertRaises(ReproductionError):
                reproduction._preflight_clean_rerun_record(registry, snapshot, raw, **{**metadata, "schema_version": "2.0"})
            with self.assertRaises(ReproductionError):
                reproduction._preflight_clean_rerun_record(
                    registry, snapshot, raw, **{**metadata, "parent_artifacts": (_hash("absent-parent"),)},
                )
            self.assertEqual(registry.verify_all(raise_on_error=True), snapshot)

    def test_stale_or_wrong_version_publication_prefix_is_rejected_without_writes(self):
        with TemporaryDirectory(prefix="non-evidentiary-publication-prefix-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/fixture/registry")
            ledger = EventLedger(root, "runs/fixture/events.jsonl")
            source = self._prefix_sources(registry, bounded=True)
            # Only the existing non-evidentiary fixture record is used. No
            # clean authority or publication is admitted to either store.
            record = source.source_records[0]
            authority = replace(_authority(), verification_event_index=0)
            prior = self._event(metadata={"scientific_evidence": False}, event_id="prior-probe")
            before = reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger")
            for schema, record_hash in (
                (reproduction.SCIENTIFIC_CLEAN_RERUN_AUTHORITY_EVENT_SCHEMA, record.record_hash),
                (reproduction.SCIENTIFIC_CLEAN_RERUN_AUTHORITY_V2_EVENT_SCHEMA, _hash("wrong-record")),
            ):
                metadata = reproduction._scientific_clean_rerun_publication_metadata(record, authority)
                metadata["scientific_clean_rerun_authority_publication"]["schema_version"] = schema
                metadata["artifact_record_hashes"] = [record_hash]
                event = LedgerEvent.create(
                    run_id="clean-rerun-ledger", actor_role=Role.REPRODUCTION_VERIFIER,
                    state_before=MacroState.PREFLIGHT, requested_state_after=MacroState.PREFLIGHT,
                    artifact_hashes=(record.sha256,), code_version=f"sha256:{source.rerun_spec.code_sha256}",
                    configuration_hash=source.rerun_spec.configuration_sha256,
                    dataset_identifiers=(source.rerun_spec.data_sha256,), random_seeds=source.rerun_spec.seeds,
                    evaluator_outputs=(), reason="admitted source-owned scientific clean-rerun authority",
                    prior_event_hash=prior.event_hash, event_type="CHECKPOINT", metadata=metadata,
                )
                with self.assertRaises(ReproductionError):
                    reproduction._validate_scientific_clean_rerun_publication_event(
                        event, 1, (prior, event), record=record, authority=authority, rerun_spec=source.rerun_spec,
                    )
                self.assertEqual(reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger"), before)

    def test_paired_snapshot_rejects_real_non_evidentiary_ledger_mutation(self):
        with TemporaryDirectory(prefix="non-evidentiary-clean-cas-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/fixture/registry")
            ledger = EventLedger(root, "runs/fixture/events.jsonl")
            before = reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger")
            ledger.append(self._event(metadata={"scientific_evidence": False}))
            with self.assertRaises(ReproductionError):
                reproduction._require_clean_rerun_snapshot_unchanged(
                    registry, ledger, "clean-rerun-ledger", *before,
                )
            self.assertFalse(registry.list_records())

    def test_source_owned_public_entrypoints_reject_forged_v2_without_mutation(self):
        with TemporaryDirectory(prefix="non-evidentiary-clean-owner-") as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "runs/fixture/registry")
            ledger = EventLedger(root, "runs/fixture/events.jsonl")
            record = registry.put_json(
                {**_plan().to_dict(), "scientific_evidence": False},
                logical_type=reproduction.SCIENTIFIC_CLEAN_RERUN_PLAN_LOGICAL_TYPE,
                creator_role=Role.IMPLEMENTER, origin="NON_EVIDENTIARY_FORGED_PLAN_REJECTION_FIXTURE",
                creation_command=("fixture-only",), schema_version="2.0", validation_result="PASS", frozen=True,
            )
            before = reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger")
            arguments = dict(
                plan_artifact_sha256=record.sha256, expected_ledger_run_id="clean-rerun-ledger",
                expected_original_execution_run_id="original-execution", expected_rerun_execution_run_id="rerun-execution",
            )
            for owner in (reproduction.require_scientific_clean_rerun_plan, reproduction.resolve_scientific_clean_rerun_authority):
                with self.assertRaises(ReproductionError):
                    owner(registry, ledger, **arguments)
                self.assertEqual(reproduction._locked_clean_rerun_snapshot(registry, ledger, "clean-rerun-ledger"), before)

    def test_prewrite_order_and_acyclic_owner_routing_are_explicit(self):
        # Structural guard complements inert negative probes; it is not an
        # end-to-end positive scientific issuance test.
        source = inspect.getsource(reproduction.register_scientific_clean_rerun_plan)
        self.assertLess(source.index("_validate_scientific_clean_rerun_plan_event("), source.index("ledger._append_locked("))
        self.assertLess(source.index("_preflight_clean_rerun_record("), source.index("ledger._append_locked("))
        source = inspect.getsource(reproduction.register_scientific_clean_rerun_authority)
        self.assertLess(source.index("_validate_scientific_clean_rerun_publication_event("), source.index("ledger._append_locked("))
        source = inspect.getsource(reproduction._replay_bounded_clean_rerun_evidence)
        self.assertIn("_derive_projection_checked_result_evidence(", source)
        self.assertNotIn("require_canonical", source)
        source = inspect.getsource(reproduction._resolve_clean_rerun_plan_sources)
        self.assertIn("use.run_id != ledger_run_id", source)
        self.assertNotIn("use.run_id != original_execution_run_id", source)

    @staticmethod
    def _event(*, metadata, prior=None, event_id="fixture-event", timestamp="2026-09-05T12:00:00Z"):
        return LedgerEvent.create(
            run_id="clean-rerun-ledger", actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.PREFLIGHT, requested_state_after=MacroState.PREFLIGHT,
            artifact_hashes=(), code_version="fixture-only", configuration_hash=_hash("config"),
            dataset_identifiers=(), random_seeds=(), evaluator_outputs=(),
            reason="synthetic non-evidentiary prefix probe", prior_event_hash=prior,
            event_type="CHECKPOINT", metadata=metadata, event_id=event_id, timestamp=timestamp,
        )

    def test_legacy_comparison_keeps_its_original_field_contract(self):
        for projection in (False, True):
            value = fixtures.ProjectionCheckedResultAssessmentTests()._assessment(
                projection_backed=projection,
            )
            result = derive_scientific_clean_rerun_comparison(
                value, value, comparison_tolerance=0.0,
            )
            self.assertIs(result.outcome, ScientificCleanRerunOutcome.PASS)
            self.assertEqual(result.differences[-1].field_name, "adjusted_p_value")
            self.assertFalse(result.scientific_evidence)

    def test_new_or_mixed_profiles_cannot_use_legacy_comparison(self):
        legacy = fixtures.ProjectionCheckedResultAssessmentTests()._assessment(
            projection_backed=True,
        )
        bounded = replace(
            legacy,
            adjusted_p_value=None,
            inference_profile_id=BOUNDED_MEAN_PROFILE_ID,
            statistical_use_authority_artifact_sha256="a" * 64,
            statistical_use_authority_record_hash="b" * 64,
            mean_zero_p_upper=0.5,
        )
        other_bound = replace(bounded, mean_zero_p_upper=0.75)
        for index, (original, rerun) in enumerate((
            (bounded, bounded), (bounded, other_bound),
            (bounded, legacy), (legacy, bounded),
        )):
            with self.subTest(case=index):
                with self.assertRaisesRegex(ReproductionError, "legacy clean-rerun comparison"):
                    derive_scientific_clean_rerun_comparison(
                        original, rerun, comparison_tolerance=0.0,
                    )


if __name__ == "__main__":
    unittest.main()
