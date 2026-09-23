"""Inert D-065 DTO/adapter/codec vectors, never positive source authority.

These caller-constructed facts may yield a pure adapter PASS. They do not
authenticate activity, Dataset units, model grids, resources, or any execution.
No scientific source owner is mocked into PASS or admitted by this test file.
"""

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import math
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.domains import (
    DOMAIN_ADAPTERS,
    AugmentationMode,
    ComparisonDisposition,
    DomainEvidenceScope,
    DomainInputError,
    DomainKind,
    DomainValidityLimitation,
    DomainValidityStatus,
    GenericMLAdapter,
    GenericMLExample,
    GenericMLFixedModelAdapter,
    GenericMLFixedModelValidityEvidence,
    GenericMLValidityEvidence,
    MLPolicyTiming,
    PretrainedContaminationStatus,
    PretrainedResourceEvidence,
    ResolvedDomainValidity,
    SplitRole,
    _decode_domain_value,
    _domain_evidence_type,
    _embedded_artifact_hashes,
    _encode_domain_value,
    get_domain_adapter,
    register_domain_evidence_source,
)
from scientist_one.generic_ml_projection import (
    GenericMLReferenceWork,
    GenericMLReferenceWorkPolicy,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.test_domains import clean_generic_ml


_REPLACED_CODES = {
    "ML_CHECKPOINT_SELECTION_LEAKAGE": "ML_FIXED_MODEL_NO_RECORDED_SELECTION",
    "ML_RESOURCE_COMPARABILITY": "ML_FIXED_MODEL_PRIMARY_REFERENCE_WORK_EQUAL",
    "ML_COMPUTE_BUDGET_UNFAIR": "ML_FIXED_MODEL_DECLARED_RUN_CAP",
}


def _inert_evidence() -> GenericMLFixedModelValidityEvidence:
    """Synthetic pure input; its hashes do not name registered authority."""
    old = clean_generic_ml()
    return GenericMLFixedModelValidityEvidence(
        legacy_evidence=replace(
            old,
            preprocessing_fit_splits=(),
            checkpoint_selection_split=None,
            compute_budget_equivalent=None,
            early_stopping_policy=replace(
                old.early_stopping_policy, enabled=False, monitor_split=None,
            ),
            augmentation_policy=replace(
                old.augmentation_policy, mode=AugmentationMode.NONE,
                fit_splits=(), application_splits=(),
            ),
            model_resource_comparison=replace(
                old.model_resource_comparison,
                candidate_parameter_count=24, baseline_parameter_count=24,
                resource_disposition=ComparisonDisposition.UNAVAILABLE,
            ),
        ),
        reference_work_policy=GenericMLReferenceWorkPolicy(),
        reference_work=GenericMLReferenceWork(7, 3, 4, 5),
        statistical_use_authority_artifact_sha256="1" * 64,
        statistical_use_authority_record_hash="2" * 64,
        no_recorded_selection_or_protected_label_access=True,
        requested_timeout_seconds=30.0,
        contract_wall_cap_seconds=60.0,
    )


def _check_status(evidence: GenericMLFixedModelValidityEvidence, code: str):
    return next(
        item.status for item in GenericMLFixedModelAdapter().evaluate(evidence).checks
        if item.machine_code == code
    )


def _hostile(*args, **kwargs):
    raise AssertionError("hostile scalar/container operation must not execute")


class _HostileInt(int):
    __eq__ = __lt__ = __le__ = __gt__ = __ge__ = _hostile
    __mul__ = __add__ = __float__ = __int__ = __hash__ = _hostile


class _HostileFloat(float):
    __eq__ = __lt__ = __le__ = __gt__ = __ge__ = _hostile
    __float__ = __hash__ = _hostile


class _HostileText(str):
    __eq__ = __hash__ = strip = encode = _hostile


class _HostileTuple(tuple):
    __iter__ = __len__ = _hostile


class FixedModelDomainProfileTests(unittest.TestCase):
    def assert_retained_checks_unchanged(self, evidence):
        old = GenericMLAdapter().evaluate(evidence.legacy_evidence)
        new = GenericMLFixedModelAdapter().evaluate(evidence)
        self.assertEqual(
            tuple(item for item in old.checks if item.machine_code not in _REPLACED_CODES),
            tuple(item for item in new.checks if item.machine_code not in _REPLACED_CODES.values()),
        )
        self.assertEqual(
            tuple(_REPLACED_CODES.get(item.machine_code, item.machine_code) for item in old.checks),
            tuple(item.machine_code for item in new.checks),
        )

    def test_pure_pass_is_non_evidentiary_and_legacy_facts_stay_unavailable(self):
        value = _inert_evidence()
        self.assertIs(GenericMLFixedModelAdapter().evaluate(value).status, DomainValidityStatus.PASS)
        self.assertIs(GenericMLAdapter().evaluate(value.legacy_evidence).status, DomainValidityStatus.BLOCKED)
        self.assertIsNone(value.legacy_evidence.checkpoint_selection_split)
        self.assertIsNone(value.legacy_evidence.compute_budget_equivalent)
        self.assertIs(value.legacy_evidence.model_resource_comparison.resource_disposition,
                      ComparisonDisposition.UNAVAILABLE)
        self.assert_retained_checks_unchanged(value)

    def test_closed_evidence_fields_have_no_duplicate_count_table(self):
        self.assertEqual(tuple(item.name for item in fields(_inert_evidence())), (
            "legacy_evidence", "reference_work_policy", "reference_work",
            "statistical_use_authority_artifact_sha256", "statistical_use_authority_record_hash",
            "no_recorded_selection_or_protected_label_access",
            "requested_timeout_seconds", "contract_wall_cap_seconds",
        ))
        self.assertEqual(tuple(item.name for item in fields(GenericMLReferenceWork)),
                         ("unit_count", "seed_count", "class_count", "feature_count"))

    def test_no_selection_fact_does_not_replace_cumulative_seed_evidence(self):
        value = _inert_evidence()
        absent = replace(value, no_recorded_selection_or_protected_label_access=False)
        self.assertIs(_check_status(absent, "ML_FIXED_MODEL_NO_RECORDED_SELECTION"), DomainValidityStatus.FAIL)
        cumulative_failed = replace(value, legacy_evidence=replace(
            value.legacy_evidence, seed_policy_frozen=False, hyperparameter_budget_equivalent=False,
        ))
        self.assertIs(_check_status(cumulative_failed, "ML_FIXED_MODEL_NO_RECORDED_SELECTION"),
                      DomainValidityStatus.PASS)
        self.assertIs(_check_status(cumulative_failed, "ML_SEED_POLICY_MISSING"), DomainValidityStatus.BLOCKED)
        self.assertIs(_check_status(cumulative_failed, "ML_HYPERPARAMETER_BUDGET_UNFAIR"), DomainValidityStatus.FAIL)
        self.assert_retained_checks_unchanged(cumulative_failed)

    def test_missing_nonresource_facts_retain_each_legacy_blocker(self):
        value = _inert_evidence()
        cases = (
            ("benchmark_version", "ML_BENCHMARK_VERSION_MISSING"),
            ("seed_policy_frozen", "ML_SEED_POLICY_MISSING"),
            ("metric_implementation_verified", "ML_METRIC_IMPLEMENTATION_UNVERIFIED"),
            ("hyperparameter_budget_equivalent", "ML_HYPERPARAMETER_BUDGET_UNFAIR"),
            ("robustness_evaluated", "ML_ROBUSTNESS_EVIDENCE_MISSING"),
            ("early_stopping_policy", "ML_EARLY_STOPPING_POLICY_NOT_FROZEN"),
            ("early_stopping_policy", "ML_EARLY_STOPPING_SPLIT_LEAKAGE"),
            ("augmentation_policy", "ML_AUGMENTATION_POLICY_NOT_FROZEN"),
            ("augmentation_policy", "ML_AUGMENTATION_FIT_LEAKAGE"),
            ("augmentation_policy", "ML_AUGMENTATION_APPLICATION_POLICY_INVALID"),
            ("model_resource_comparison", "ML_PARAMETER_COUNT_COMPARABILITY"),
            ("pretrained_resource_policy", "ML_PRETRAINED_RESOURCE_IDENTITY_MISSING"),
            ("pretrained_resource_policy", "ML_PRETRAINED_CONTAMINATION_UNCHECKED"),
        )
        for name, code in cases:
            with self.subTest(name=name, code=code):
                current = replace(value, legacy_evidence=replace(value.legacy_evidence, **{name: None}))
                self.assertIs(_check_status(current, code), DomainValidityStatus.BLOCKED)
                self.assert_retained_checks_unchanged(current)

    def test_adverse_nonresource_facts_retain_exact_old_checks(self):
        value = _inert_evidence()
        old = value.legacy_evidence
        cases = (
            (dict(examples=(GenericMLExample("same", SplitRole.TRAIN), GenericMLExample("same", SplitRole.TEST))),
             "ML_EXAMPLE_SPLIT_LEAKAGE", DomainValidityStatus.FAIL),
            (dict(early_stopping_policy=replace(old.early_stopping_policy, timing=MLPolicyTiming.FROZEN_AFTER_RESULTS)),
             "ML_EARLY_STOPPING_POLICY_NOT_FROZEN", DomainValidityStatus.FAIL),
            (dict(augmentation_policy=replace(old.augmentation_policy, timing=MLPolicyTiming.FROZEN_AFTER_RESULTS)),
             "ML_AUGMENTATION_POLICY_NOT_FROZEN", DomainValidityStatus.FAIL),
            (dict(pretrained_resource_policy=replace(old.pretrained_resource_policy,
                                                   contamination_status=PretrainedContaminationStatus.DETECTED)),
             "ML_PRETRAINED_CONTAMINATION_UNCHECKED", DomainValidityStatus.FAIL),
            (dict(model_resource_comparison=replace(old.model_resource_comparison,
                                                   parameter_count_disposition=ComparisonDisposition.UNFAIR)),
             "ML_PARAMETER_COUNT_COMPARABILITY", DomainValidityStatus.FAIL),
            (dict(model_resource_comparison=replace(old.model_resource_comparison, comparison_artifact_sha256=None)),
             "ML_PARAMETER_COUNT_COMPARABILITY", DomainValidityStatus.BLOCKED),
            (dict(model_resource_comparison=replace(old.model_resource_comparison,
                                                   parameter_count_disposition=ComparisonDisposition.JUSTIFIED_DIFFERENCE)),
             "ML_PARAMETER_COUNT_COMPARABILITY", DomainValidityStatus.BLOCKED),
            (dict(hyperparameter_budget_equivalent=False), "ML_HYPERPARAMETER_BUDGET_UNFAIR", DomainValidityStatus.FAIL),
            (dict(seed_policy_frozen=False), "ML_SEED_POLICY_MISSING", DomainValidityStatus.BLOCKED),
            (dict(metric_implementation_verified=False), "ML_METRIC_IMPLEMENTATION_UNVERIFIED", DomainValidityStatus.BLOCKED),
            (dict(robustness_evaluated=False), "ML_ROBUSTNESS_EVIDENCE_MISSING", DomainValidityStatus.BLOCKED),
        )
        for updates, code, expected in cases:
            with self.subTest(code=code, updates=updates):
                current = replace(value, legacy_evidence=replace(old, **updates))
                self.assertIs(_check_status(current, code), expected)
                self.assert_retained_checks_unchanged(current)

    def test_contradictory_fixed_profile_facts_are_rejected(self):
        value = _inert_evidence()
        old = value.legacy_evidence
        cases = [
            dict(preprocessing_fit_splits=(SplitRole.TRAIN,)),
            dict(preprocessing_fit_splits=(SplitRole.HOLDOUT,)),
            dict(checkpoint_selection_split=SplitRole.VALIDATION),
            dict(checkpoint_selection_split=SplitRole.TEST),
            dict(compute_budget_equivalent=True), dict(compute_budget_equivalent=False),
            dict(generalization_claimed=True),
            dict(external_validation_performed=True), dict(external_validation_performed=False),
            dict(early_stopping_policy=replace(old.early_stopping_policy, enabled=True)),
            dict(augmentation_policy=replace(old.augmentation_policy, mode=AugmentationMode.TRAINING_ONLY)),
            dict(augmentation_policy=replace(old.augmentation_policy, fit_splits=(SplitRole.TRAIN,))),
            dict(augmentation_policy=replace(old.augmentation_policy, application_splits=(SplitRole.TEST,))),
            dict(pretrained_resource_policy=replace(old.pretrained_resource_policy, resources=(
                PretrainedResourceEvidence("external-model", "v1", "3" * 64, None),
            ))),
        ]
        for disposition in (ComparisonDisposition.COMPARABLE, ComparisonDisposition.UNFAIR,
                            ComparisonDisposition.JUSTIFIED_DIFFERENCE):
            cases.append(dict(model_resource_comparison=replace(
                old.model_resource_comparison, resource_disposition=disposition,
            )))
        for updates in cases:
            with self.subTest(updates=updates), self.assertRaises(DomainInputError):
                replace(value, legacy_evidence=replace(old, **updates))

    def test_parameter_counts_must_match_both_complete_frozen_model_shapes(self):
        value = _inert_evidence()
        for name in ("candidate_parameter_count", "baseline_parameter_count"):
            for count in (0, 23, 25):
                with self.subTest(name=name, count=count), self.assertRaises(DomainInputError):
                    replace(value, legacy_evidence=replace(value.legacy_evidence,
                        model_resource_comparison=replace(value.legacy_evidence.model_resource_comparison, **{name: count})))

    def test_reference_work_boundaries_and_robustness_remain_separate(self):
        value = _inert_evidence()
        for work in (GenericMLReferenceWork(1, 1, 2, 1), GenericMLReferenceWork(10000, 2, 64, 1023)):
            parameters = work.class_count * (work.feature_count + 1)
            current = replace(value, reference_work=work, legacy_evidence=replace(value.legacy_evidence,
                model_resource_comparison=replace(value.legacy_evidence.model_resource_comparison,
                    candidate_parameter_count=parameters, baseline_parameter_count=parameters)))
            self.assertIs(_check_status(current, "ML_FIXED_MODEL_PRIMARY_REFERENCE_WORK_EQUAL"), DomainValidityStatus.PASS)
            counts = current.reference_work.to_dict()
            self.assertEqual(counts["candidate_primary_metric"], counts["baseline_primary_metric"])
            self.assertEqual(counts["candidate_robustness_overhead"],
                             {key: 2 * count for key, count in counts["candidate_primary_metric"].items()})

    def test_mutated_reference_work_bounds_are_revalidated(self):
        for name, values in (
            ("unit_count", (0, 10001)), ("seed_count", (0, 25)),
            ("class_count", (1, 1025)), ("feature_count", (0, 1025)),
        ):
            for bad in (*values, True, 1.0, _HostileInt(1)):
                value = _inert_evidence()
                object.__setattr__(value.reference_work, name, bad)
                with self.subTest(name=name, bad=bad), self.assertRaises(DomainInputError):
                    GenericMLFixedModelAdapter().evaluate(value)

    def test_declared_cap_accepts_equality_and_reports_excess_as_fail(self):
        value = _inert_evidence()
        for request, cap, expected in (
            (1, 1, DomainValidityStatus.PASS), (0.5, 1.0, DomainValidityStatus.PASS),
            (math.nextafter(1.0, math.inf), 1.0, DomainValidityStatus.FAIL),
            (2**53 + 1, 2**53, DomainValidityStatus.FAIL),
            (2**53 + 1, float(2**53), DomainValidityStatus.FAIL),
            (2**53, 2**53 + 1, DomainValidityStatus.PASS),
        ):
            with self.subTest(request=request, cap=cap):
                current = replace(value, requested_timeout_seconds=request, contract_wall_cap_seconds=cap)
                self.assertIs(_check_status(current, "ML_FIXED_MODEL_DECLARED_RUN_CAP"), expected)
                self.assertIs(type(current.requested_timeout_seconds), type(request))

    def test_durations_require_positive_finite_native_values(self):
        for name in ("requested_timeout_seconds", "contract_wall_cap_seconds"):
            for bad in (None, True, "1", 0, -1, math.inf, -math.inf, math.nan,
                        10**400, _HostileInt(1), _HostileFloat(1)):
                with self.subTest(name=name, bad=bad), self.assertRaises(DomainInputError):
                    replace(_inert_evidence(), **{name: bad})

    def test_mutated_wrapper_scalars_are_checked_before_operations(self):
        cases = (
            ("statistical_use_authority_artifact_sha256", _HostileText("1" * 64)),
            ("statistical_use_authority_record_hash", _HostileText("2" * 64)),
            ("no_recorded_selection_or_protected_label_access", _HostileInt(1)),
            ("requested_timeout_seconds", _HostileFloat(30)),
            ("contract_wall_cap_seconds", _HostileInt(60)),
        )
        for name, bad in cases:
            value = _inert_evidence()
            object.__setattr__(value, name, bad)
            with self.subTest(name=name), self.assertRaises(DomainInputError):
                GenericMLFixedModelAdapter().evaluate(value)

    def test_mutated_nested_legacy_values_are_checked_before_old_adapter(self):
        for name, bad in (
            ("examples", _HostileTuple(())),
            ("preprocessing_fit_splits", _HostileTuple(())),
            ("benchmark_version", _HostileText("v1")),
            ("seed_policy_frozen", 1), ("checkpoint_selection_split", "TEST"),
            ("generalization_claimed", _HostileInt(1)),
        ):
            value = _inert_evidence()
            object.__setattr__(value.legacy_evidence, name, bad)
            with self.subTest(name=name), self.assertRaises(DomainInputError):
                GenericMLFixedModelAdapter().evaluate(value)
        value = _inert_evidence()
        object.__setattr__(value.legacy_evidence.model_resource_comparison, "candidate_parameter_count", _HostileInt(24))
        with self.assertRaises(DomainInputError):
            GenericMLFixedModelAdapter().evaluate(value)

    def test_total_node_budget_rejects_repeated_nested_tuple_expansion(self):
        value = _inert_evidence()
        repeated = (None,) * 10000
        object.__setattr__(value.legacy_evidence, "examples", (repeated,) * 10000)
        with self.assertRaisesRegex(DomainInputError, "total node budget"):
            GenericMLFixedModelAdapter().evaluate(value)

    def test_cycles_and_excess_tuple_width_are_bounded(self):
        value = _inert_evidence()
        object.__setattr__(value.legacy_evidence, "examples", (value.legacy_evidence,))
        with self.assertRaisesRegex(DomainInputError, "nesting"):
            GenericMLFixedModelAdapter().evaluate(value)
        value = _inert_evidence()
        object.__setattr__(value.legacy_evidence, "examples", (None,) * 10001)
        with self.assertRaisesRegex(DomainInputError, "tuple exceeds"):
            GenericMLFixedModelAdapter().evaluate(value)

    def test_total_node_budget_allows_maximum_legitimate_example_tuple(self):
        value = _inert_evidence()
        examples = tuple(GenericMLExample(f"inert-row-{index}", SplitRole.TRAIN) for index in range(10000))
        current = replace(value, legacy_evidence=replace(value.legacy_evidence, examples=examples))
        self.assertEqual(current.legacy_evidence.examples, examples)

    def test_policy_and_record_types_are_closed_even_after_mutation(self):
        class WorkSubclass(GenericMLReferenceWork):
            pass

        class PolicySubclass(GenericMLReferenceWorkPolicy):
            pass

        class LegacySubclass(GenericMLValidityEvidence):
            pass

        value = _inert_evidence()
        for name, bad in (
            ("reference_work", WorkSubclass(7, 3, 4, 5)),
            ("reference_work_policy", PolicySubclass()),
            ("legacy_evidence", LegacySubclass(**{item.name: getattr(value.legacy_evidence, item.name)
                                                 for item in fields(value.legacy_evidence)})),
        ):
            with self.subTest(name=name), self.assertRaises(DomainInputError):
                replace(value, **{name: bad})
        for field in fields(GenericMLReferenceWorkPolicy):
            for bad in ("unsupported", _HostileText("unsupported"), None):
                current = _inert_evidence()
                object.__setattr__(current.reference_work_policy, field.name, bad)
                with self.subTest(field=field.name), self.assertRaises(DomainInputError):
                    GenericMLFixedModelAdapter().evaluate(current)

    def test_hashes_and_activity_flag_require_exact_closed_scalars(self):
        for name in ("statistical_use_authority_artifact_sha256", "statistical_use_authority_record_hash"):
            for bad in (None, "x" * 64, "A" * 64, "a" * 63, 1):
                with self.subTest(name=name, bad=bad), self.assertRaises(DomainInputError):
                    replace(_inert_evidence(), **{name: bad})
        for bad in (None, 0, 1, "true", 1.0):
            with self.subTest(bad=bad), self.assertRaises(DomainInputError):
                replace(_inert_evidence(), no_recorded_selection_or_protected_label_access=bad)

    def test_new_value_is_frozen_and_reconstructs_mutable_frozen_inputs(self):
        value = _inert_evidence()
        with self.assertRaises(FrozenInstanceError):
            value.requested_timeout_seconds = 0
        previous = value.legacy_evidence
        current = replace(value)
        self.assertIsNot(current.legacy_evidence, previous)
        object.__setattr__(previous, "benchmark_version", "mutated-after-copy")
        self.assertNotEqual(previous.benchmark_version, current.legacy_evidence.benchmark_version)

    def test_new_typed_codec_roundtrip_is_closed_and_contains_only_input_dimensions(self):
        value = _inert_evidence()
        encoded = _encode_domain_value(value)
        self.assertEqual(_decode_domain_value(safe_json_loads(canonical_json_bytes(encoded))), value)
        self.assertEqual(encoded["type"], "GenericMLFixedModelValidityEvidence")
        self.assertEqual(set(encoded["fields"]["reference_work"]["fields"]),
                         {"unit_count", "seed_count", "class_count", "feature_count"})
        for extra in (True, False):
            changed = _encode_domain_value(value)
            if extra:
                changed["fields"]["actual_compute_equivalent"] = True
            else:
                del changed["fields"]["reference_work_policy"]
            with self.subTest(extra=extra), self.assertRaises(DomainInputError):
                _decode_domain_value(changed)
        for name, bad in (("unit_count", True), ("seed_count", 25)):
            changed = _encode_domain_value(value)
            changed["fields"]["reference_work"]["fields"][name] = bad
            with self.assertRaises(DomainInputError):
                _decode_domain_value(changed)

    def test_record_hash_and_embedded_policy_do_not_become_artifact_references(self):
        value = _inert_evidence()
        hashes = _embedded_artifact_hashes(value)
        self.assertIn(value.statistical_use_authority_artifact_sha256, hashes)
        self.assertNotIn(value.statistical_use_authority_record_hash, hashes)
        self.assertEqual(hashes, (*_embedded_artifact_hashes(value.legacy_evidence),
                                 value.statistical_use_authority_artifact_sha256))

    def test_legacy_evidence_and_outcome_goldens_remain_byte_exact(self):
        value = clean_generic_ml()
        self.assertEqual(hashlib.sha256(canonical_json_bytes(_encode_domain_value(value))).hexdigest(),
                         "23acb49265469f7bc7f18d9a416e423cfc6b9e92be64b9ba9e06e579b34187f6")
        self.assertEqual(hashlib.sha256(canonical_json_bytes(GenericMLAdapter().evaluate(value).to_dict())).hexdigest(),
                         "80f7f7b52f8285612c42d3908a95b19bc577e13043fa76198633cadba2fa51ce")
        self.assertEqual(_decode_domain_value(_encode_domain_value(value)), value)

    def test_default_fixture_and_cross_adapter_dispatch_stay_closed(self):
        value = _inert_evidence()
        self.assertIs(type(get_domain_adapter(DomainKind.GENERIC_ML)), GenericMLAdapter)
        self.assertEqual(get_domain_adapter(DomainKind.GENERIC_ML).version, "2.0")
        self.assertIs(_domain_evidence_type(DomainKind.GENERIC_ML), GenericMLValidityEvidence)
        self.assertEqual(sum(item.domain is DomainKind.GENERIC_ML for item in DOMAIN_ADAPTERS), 1)
        for adapter, invalid in ((GenericMLAdapter(), value), (GenericMLFixedModelAdapter(), value.legacy_evidence)):
            self.assertIs(adapter.evaluate(invalid).status, DomainValidityStatus.BLOCKED)
        with TemporaryDirectory() as root:
            registry = ArtifactRegistry(root, "runs/domain/registry")
            before = registry.verify_all(raise_on_error=True)
            for scope in DomainEvidenceScope:
                with self.subTest(scope=scope), self.assertRaises(DomainInputError):
                    register_domain_evidence_source(registry, run_id="run-fixture", domain=DomainKind.GENERIC_ML,
                        object_id="result-fixture", task_id="task-fixture", evidence=value,
                        supporting_artifact_hashes=(), scope=scope)
                self.assertEqual(registry.verify_all(raise_on_error=True), before)

    def test_new_adapter_rejects_evidence_subclasses(self):
        class EvidenceSubclass(GenericMLFixedModelValidityEvidence):
            pass

        value = _inert_evidence()
        subclass = EvidenceSubclass(**{item.name: getattr(value, item.name) for item in fields(value)})
        self.assertIs(GenericMLFixedModelAdapter().evaluate(subclass).status, DomainValidityStatus.BLOCKED)

    def test_resolved_dto_new_shape_requires_exact_scope_projection_and_adapter(self):
        # This unregistered shape is deliberately NOT source-owner authority.
        value = _inert_evidence()
        resolved = ResolvedDomainValidity(
            receipt_artifact_sha256="3" * 64, manifest_artifact_sha256="4" * 64,
            source_artifact_hashes=("5" * 64,), run_id="inert-run", domain=DomainKind.GENERIC_ML,
            object_id="inert-result", task_id="inert-task", scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
            limitations=(), evidence=value, outcome=GenericMLFixedModelAdapter().evaluate(value),
            projection_artifact_sha256="6" * 64,
        )
        for updates in (
            dict(domain=DomainKind.SYSTEMS), dict(projection_artifact_sha256=None),
            dict(outcome=GenericMLAdapter().evaluate(value.legacy_evidence)),
            dict(scope=DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE,
                 limitations=(DomainValidityLimitation.NON_EVIDENTIARY_FIXTURE,)),
        ):
            with self.subTest(updates=updates), self.assertRaises(DomainInputError):
                replace(resolved, **updates)

    def test_new_check_messages_state_narrow_limits(self):
        checks = {item.machine_code: item for item in GenericMLFixedModelAdapter().evaluate(_inert_evidence()).checks}
        activity = checks["ML_FIXED_MODEL_NO_RECORDED_SELECTION"].message
        self.assertIn("does not establish absence of training", activity)
        self.assertNotIn("complete", activity)
        self.assertIn("not equal actual instructions, total work, time, memory, or energy",
                      checks["ML_FIXED_MODEL_PRIMARY_REFERENCE_WORK_EQUAL"].message)
        self.assertIn("not observed or per-condition", checks["ML_FIXED_MODEL_DECLARED_RUN_CAP"].message)


if __name__ == "__main__":
    unittest.main()
