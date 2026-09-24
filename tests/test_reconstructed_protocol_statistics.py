"""SEMANTIC_RECONSTRUCTION: frozen pre-vNext protocol/statistics/custody.

Authored 2026-09-19 from hash-recovered source and baseline B-06/B-07/B-08.
These are new executable specifications, NOT recovered historical364 tests.
All observations, protocol identities and custody payloads are synthetic.
Simulated custody is never independent human review or E4 authority.
"""

from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import random
import tempfile
import unittest

from scientist_one import protocol as p
from scientist_one import statistics as s
from scientist_one.holdout import (
    AccessOutcome,
    CustodyIndependence,
    HoldoutAccessViolation,
    HoldoutAlreadyRevealed,
    HoldoutCustodyError,
    HoldoutPreconditionError,
    RevealPreconditions,
    SimulatedHoldoutCustody,
)


STAMP = "2026-09-19T12:00:00Z"


def protocol_fixture():
    conditions = p.ExecutionConditions("fixed", "same split", 2, "fixed", 10.0, "same")
    return p.ResearchProtocol(
        study_id="synthetic-reconstruction", study_version=1,
        primary_hypothesis="synthetic treatment mean differs",
        primary_estimand="mean difference", primary_metric="score", secondary_metrics=(),
        unit_of_analysis="subject", resampling_unit="subject", data_exclusions=(),
        data_roles=p.DataRoles(("train",), ("dev",), ("validation",), ("holdout",)),
        candidate_conditions=conditions, baseline_set=(p.BaselineSpec("control", conditions),),
        ablation_set=("remove treatment",), negative_controls=("null treatment",),
        domain_nulls=(p.DomainNullSpec("exchangeable", "label permutation", "subject",
                                     ("subject",), ("independent subjects",), True),),
        statistical_tests=(p.StatisticalTestSpec("primary", "permutation", "exchangeable", "two-sided"),),
        confidence_intervals=(p.ConfidenceIntervalSpec("bootstrap", 0.95, "subject"),),
        multiple_comparison_correction="holm",
        seed_policy=p.SeedPolicy((11, 23), "use all", "technical failure before reveal only"),
        compute_budget=p.ProtocolComputeBudget(4, 60.0, 1, 0),
        stopping_rules=("fixed sample",), decision_ladder=("evaluate", "retain null"),
        claim_scope_contract="synthetic subjects only",
        interpretation_rules=p.InterpretationRules("bounded support", "retain null",
                                                 "retain contradiction", "inconclusive"),
    )


def unit_fixture():
    return s.StatisticalUnitDesign("subject", "subject", (
        s.UnitObservation(1, "a", "a"), s.UnitObservation(2, "b", "b"),
    ), "distinct synthetic subjects")


def null_fixture():
    return s.DomainNullDesign("synthetic null", s.NullMethod.LABEL_PERMUTATION,
                             "subject", ("subject",), ("subject",),
                             "synthetic randomized labels", True)


class ReconstructedProtocolTests(unittest.TestCase):
    def test_freeze_is_immutable_and_hash_is_stable(self):
        protocol = protocol_fixture()
        study = p.freeze_protocol(protocol)
        self.assertEqual(study.protocol_hash, protocol_fixture().sha256)
        with self.assertRaises(FrozenInstanceError):
            protocol.primary_metric = "changed"
        detached = protocol.canonical_dict
        detached["primary_metric"] = "changed"
        self.assertEqual(protocol.primary_metric, "score")
        self.assertFalse(study.confirmatory_revealed)

    def test_data_roles_reject_overlap(self):
        with self.assertRaises(p.ProtocolValidationError):
            p.DataRoles(("patient",), ("dev",), ("validation",), ("patient",))

    def test_reserve_bounds_are_inclusive_and_reject_invalid_numbers(self):
        for value in (0.30, 0.40, 0.50):
            self.assertEqual(replace(protocol_fixture(), validity_reserve_fraction=value).validity_reserve_fraction, value)
        for value in (0.29, 0.51, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(p.ProtocolValidationError):
                replace(protocol_fixture(), validity_reserve_fraction=value)

    def test_reveal_preserves_parent_and_is_one_shot(self):
        original = p.freeze_protocol(protocol_fixture())
        revealed = p.record_confirmatory_reveal(original, release_hash="1" * 64, revealed_at=STAMP)
        self.assertFalse(original.confirmatory_revealed)
        self.assertTrue(revealed.confirmatory_revealed)
        self.assertEqual(original.protocol_hash, revealed.protocol_hash)
        with self.assertRaises(p.ProtocolStateError):
            p.record_confirmatory_reveal(revealed, release_hash="2" * 64, revealed_at=STAMP)

    def test_pre_reveal_revision_preserves_explicit_lineage(self):
        parent = p.freeze_protocol(protocol_fixture())
        child = p.revise_study_version(parent, revision_reason="prospective refinement",
                                       changes={"primary_hypothesis": "refined prediction"})
        p.validate_study_lineage(parent, child)
        self.assertEqual(child.version, 2)
        self.assertEqual(child.protocol.parent_protocol_hash, parent.protocol_hash)
        self.assertNotEqual(child.protocol_hash, parent.protocol_hash)
        self.assertFalse(child.requires_fresh_confirmatory_reserve)

    def test_post_reveal_revision_requires_fresh_reserve(self):
        parent = p.record_confirmatory_reveal(p.freeze_protocol(protocol_fixture()),
                                             release_hash="1" * 64, revealed_at=STAMP)
        child = p.revise_study_version(parent, revision_reason="post-hoc question",
                                       changes={"primary_hypothesis": "new question"})
        self.assertTrue(child.requires_fresh_confirmatory_reserve)
        self.assertFalse(child.confirmatory_revealed)
        p.validate_study_lineage(parent, child)
        with self.assertRaises(p.ProtocolStateError):
            p.validate_study_lineage(parent, replace(child, requires_fresh_confirmatory_reserve=False))

    def test_lineage_rejects_skips_wrong_parent_and_controller_field_edits(self):
        parent = p.freeze_protocol(protocol_fixture())
        child = p.revise_study_version(parent, revision_reason="refinement",
                                       changes={"primary_metric": "new score"})
        for field, value in (("study_version", 3), ("parent_protocol_hash", "f" * 64), ("study_id", "other")):
            with self.subTest(field=field), self.assertRaises(p.ProtocolStateError):
                p.validate_study_lineage(parent, replace(child, protocol=replace(child.protocol, **{field: value})))
        with self.assertRaises(p.ProtocolStateError):
            p.revise_study_version(parent, revision_reason="illegal", changes={"study_id": "other"})

    def test_protocol_rejects_pseudo_units_and_unjustified_null(self):
        base = protocol_fixture()
        for unit in ("seed", "folds", "time-point", "checkpoint"):
            with self.subTest(unit=unit), self.assertRaises(p.ProtocolValidationError):
                replace(base, resampling_unit=unit,
                        confidence_intervals=(p.ConfidenceIntervalSpec("bootstrap", 0.95, unit),))
        with self.assertRaises(p.ProtocolValidationError):
            replace(base, domain_nulls=(replace(base.domain_nulls[0], exchangeability_justified=False),))

    def test_protocol_rejects_missing_null_multiplicity_and_interval_mismatch(self):
        base = protocol_fixture()
        changes = (
            {"statistical_tests": (replace(base.statistical_tests[0], null_name="missing"),)},
            {"secondary_metrics": ("secondary",), "multiple_comparison_correction": "none"},
            {"confidence_intervals": (p.ConfidenceIntervalSpec("bootstrap", 0.95, "site"),)},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(p.ProtocolValidationError):
                replace(base, **change)

    def test_baseline_equivalence_covers_all_declared_conditions(self):
        base = protocol_fixture()
        self.assertTrue(p.validate_protocol(base)[0].equivalent)
        alternatives = {"preprocessing": "other", "data_access": "extra", "tuning_budget": 3,
                        "early_stopping": "adaptive", "compute_budget": 11.0,
                        "feature_set": "extra", "implementation_verified": False}
        for name, value in alternatives.items():
            with self.subTest(field=name):
                baseline = p.BaselineSpec("changed", replace(base.candidate_conditions, **{name: value}))
                report = p.baseline_equivalence(base.candidate_conditions, baseline)
                self.assertEqual(report.mismatches, (name,))
                with self.assertRaises(p.ProtocolValidationError):
                    replace(base, baseline_set=(baseline,))


class ReconstructedStatisticsTests(unittest.TestCase):
    def test_independent_units_are_counted_separately_from_repeated_observations(self):
        design = s.StatisticalUnitDesign("subject", "subject", (
            s.UnitObservation(1, "a", "a", "a"), s.UnitObservation(2, "a", "a", "a"),
            s.UnitObservation(3, "b", "b", "b"), s.UnitObservation(4, "b", "b", "b"),
        ), "two subjects; repeats kept together", repeated_measures=True)
        report = s.validate_statistical_units(design)
        self.assertEqual((report.independent_unit_count, report.observation_count), (2, 4))
        self.assertTrue(report.valid)

    def test_pseudoreplication_unit_names_fail_without_justification(self):
        for unit in ("seeds", "fold", "time points", "checkpoint", "correlated-tasks"):
            with self.subTest(unit=unit), self.assertRaises(s.StatisticalValidationError):
                s.validate_statistical_units(replace(unit_fixture(), resampling_unit=unit))

    def test_analysis_unit_cannot_be_split_across_resampling_units(self):
        design = replace(unit_fixture(), observations=(s.UnitObservation(1, "a", "x", "a"),
                         s.UnitObservation(2, "a", "y", "a")), repeated_measures=True)
        report = s.validate_statistical_units(design, raise_on_failure=False)
        self.assertFalse(report.valid)
        self.assertTrue(any("same analysis unit" in issue for issue in report.issues))
        with self.assertRaises(s.StatisticalValidationError):
            s.validate_statistical_units(design)

    def test_dependency_groups_cannot_be_split(self):
        design = replace(unit_fixture(), observations=(s.UnitObservation(1, "a", "a", "site"),
                         s.UnitObservation(2, "b", "b", "site")))
        with self.assertRaisesRegex(s.StatisticalValidationError, "dependent observations"):
            s.validate_statistical_units(design)

    def test_repeated_measure_declaration_and_group_ids_are_required(self):
        design = replace(unit_fixture(), observations=unit_fixture().observations + (s.UnitObservation(3, "a", "a"),))
        with self.assertRaisesRegex(s.StatisticalValidationError, "repeated_measures is false"):
            s.validate_statistical_units(design)
        with self.assertRaisesRegex(s.StatisticalValidationError, "dependency_group_id"):
            s.validate_statistical_units(replace(design, repeated_measures=True))

    def test_one_independent_unit_is_insufficient(self):
        with self.assertRaisesRegex(s.StatisticalValidationError, "at least two"):
            s.validate_statistical_units(replace(unit_fixture(), observations=(s.UnitObservation(1, "a", "a"),)))

    def test_domain_null_requires_exchangeable_labels(self):
        self.assertTrue(s.validate_domain_null(null_fixture(), unit_fixture()).valid)
        with self.assertRaisesRegex(s.StatisticalValidationError, "not exchangeable"):
            s.validate_domain_null(replace(null_fixture(), labels_exchangeable=False))

    def test_domain_null_requires_structures_and_matching_units(self):
        changes = ({"preserved_structures": ()}, {"exchangeability_unit": "site"},
                   {"method": s.NullMethod.BLOCK_PERMUTATION,
                    "required_preserved_structures": (), "preserved_structures": ()})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(s.StatisticalValidationError):
                s.validate_domain_null(replace(null_fixture(), **change), unit_fixture())

    def test_numeric_inputs_reject_boolean_nonfinite_and_empty(self):
        for bad in (True, float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=bad):
                with self.assertRaises(s.StatisticalValidationError):
                    s.UnitObservation(bad, "a", "a")
                with self.assertRaises(s.StatisticalValidationError):
                    s.mean_difference((bad, 1), (0, 1))
                with self.assertRaises(s.StatisticalValidationError):
                    s.adjust_pvalues((bad,), method="holm")
        with self.assertRaises(s.StatisticalValidationError):
            s.mean_difference((), (1,))

    def test_mean_effect_and_zero_variance_remain_honest(self):
        self.assertEqual(s.mean_difference((3, 5), (1, 3)), 2)
        self.assertEqual(s.mean_difference((1, 3), (3, 5)), -2)
        self.assertIsNone(s.hedges_g((2, 2), (1, 1)))
        self.assertEqual(s.hedges_g((1, 2, 3), (1, 2, 3)), 0)

    def test_exact_permutation_has_hand_enumerated_tail_probabilities(self):
        # Of six assignments of two of [3, 4, 1, 2], one reaches +2 and two reach |2|.
        self.assertAlmostEqual(s.permutation_test_mean_difference((3, 4), (1, 2), alternative="greater"), 1 / 6)
        self.assertAlmostEqual(s.permutation_test_mean_difference((3, 4), (1, 2)), 2 / 6)
        self.assertEqual(s.permutation_test_mean_difference((2, 2), (2, 2)), 1)

    def test_seeded_bootstrap_and_monte_carlo_are_repeatable_without_global_rng_mutation(self):
        before = random.getstate()
        bounds = s.bootstrap_mean_difference_ci((3, 4, 5), (0, 1, 2), resamples=100, seed=19)
        self.assertEqual(bounds, s.bootstrap_mean_difference_ci((3, 4, 5), (0, 1, 2), resamples=100, seed=19))
        self.assertLessEqual(bounds[0], bounds[1])
        kwargs = {"resamples": 100, "seed": 19, "exact_limit": 1}
        value = s.permutation_test_mean_difference((3, 4, 5), (0, 1, 2), **kwargs)
        self.assertEqual(value, s.permutation_test_mean_difference((3, 4, 5), (0, 1, 2), **kwargs))
        self.assertGreaterEqual(value, 1 / 101)
        self.assertLessEqual(value, 1)
        self.assertEqual(random.getstate(), before)

    def test_two_group_analysis_reports_null_and_uncertainty(self):
        result = s.analyze_two_group((1, 2, 3), (1, 2, 3), bootstrap_resamples=100,
                                     permutation_resamples=100, seed=4)
        self.assertEqual(result.estimate, 0)
        self.assertEqual(result.p_value, 1)
        self.assertGreater(result.standard_error, 0)
        self.assertLessEqual(result.ci_lower, 0)
        self.assertGreaterEqual(result.ci_upper, 0)
        self.assertEqual((result.treatment_independent_units, result.control_independent_units), (3, 3))

    def test_multiplicity_methods_have_known_adjusted_values_and_keep_identity(self):
        expected = {"bonferroni": (0.12, 0.03, 0.09), "holm": (0.06, 0.03, 0.06),
                    "benjamini-hochberg": (0.04, 0.03, 0.04)}
        for method, adjusted in expected.items():
            with self.subTest(method=method):
                results = s.adjust_pvalues((0.04, 0.01, 0.03), method=method,
                                           hypothesis_ids=("c", "a", "b"))
                self.assertEqual(tuple(r.hypothesis_id for r in results), ("c", "a", "b"))
                for result, value in zip(results, adjusted):
                    self.assertAlmostEqual(result.adjusted_p_value, value)
                    self.assertEqual(result.rejected, value <= 0.05)
                    self.assertEqual(result.family_size, 3)

    def test_multiplicity_plan_and_hypothesis_identity_fail_closed(self):
        self.assertIsNone(s.validate_multiplicity_plan(family_size=1, method=None))
        for method in (None, "none", "unadjusted", "invented"):
            with self.subTest(method=method), self.assertRaises(s.StatisticalValidationError):
                s.validate_multiplicity_plan(family_size=2, method=method)
        for ids in (("same", "same"), ("one",)):
            with self.subTest(ids=ids), self.assertRaises(s.StatisticalValidationError):
                s.adjust_pvalues((0.01, 0.02), method="holm", hypothesis_ids=ids)


class ReconstructedSimulatedCustodyTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"synthetic reconstruction holdout; no real subjects"
        self.hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in (
            "protocol_hash", "code_hash", "configuration_hash", "split_manifest_hash",
            "pre_unblinding_interpretation_hash")}
        self.preconditions = RevealPreconditions(True, True, True, True, True, True)
        self.custody = SimulatedHoldoutCustody(("synthetic-evaluator",))

    def seal(self, custody=None):
        return (custody or self.custody).seal(self.payload, **self.hashes, sealed_at=STAMP)

    def request(self, **changes):
        return {"requester": "synthetic-evaluator", "reason": "synthetic unit test",
                "preconditions": self.preconditions, "requested_at": STAMP,
                **self.hashes, **changes}

    def test_simulated_custody_is_explicitly_non_independent(self):
        seal = self.seal()
        self.assertIs(seal.custody_independence, CustodyIndependence.NON_INDEPENDENT)
        self.assertEqual(self.custody.custody_label, "SIMULATED_NON_INDEPENDENT")
        self.assertFalse(self.custody.status.confirmatory_claims_valid)
        self.custody.request_reveal(**self.request())
        self.assertIs(self.custody.status.custody_independence, CustodyIndependence.NON_INDEPENDENT)

    def test_reveal_requires_seal(self):
        with self.assertRaises(HoldoutPreconditionError):
            self.custody.request_reveal(**self.request())
        self.assertEqual(self.custody.status.authorized_access_count, 0)

    def test_each_missing_precondition_denies_without_consuming_reveal(self):
        self.seal()
        for name in self.preconditions.__dataclass_fields__:
            with self.subTest(field=name):
                with self.assertRaises(HoldoutPreconditionError):
                    self.custody.request_reveal(**self.request(preconditions=replace(self.preconditions, **{name: False})))
                self.assertEqual(self.custody.status.authorized_access_count, 0)
                self.assertFalse(self.custody.status.invalidated)
                self.assertIs(self.custody.access_records[-1].outcome, AccessOutcome.DENIED_PRECONDITION)
        self.assertEqual(self.custody.request_reveal(**self.request()).content, self.payload)

    def test_reveal_binds_seal_content_and_can_happen_only_once(self):
        seal = self.seal()
        released = self.custody.request_reveal(**self.request())
        self.assertEqual(released.content, self.payload)
        self.assertEqual(released.release.seal_hash, seal.seal_hash)
        self.assertEqual(released.release.holdout_identity_hash, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.custody.status.authorized_access_count, 1)
        with self.assertRaises(HoldoutAlreadyRevealed):
            self.custody.request_reveal(**self.request())

    def test_unauthorized_request_permanently_invalidates_confirmation(self):
        self.seal()
        with self.assertRaises(HoldoutAccessViolation):
            self.custody.request_reveal(**self.request(requester="unapproved-synthetic-actor"))
        self.assertTrue(self.custody.status.invalidated)
        self.assertFalse(self.custody.status.confirmatory_claims_valid)
        with self.assertRaises(HoldoutAccessViolation):
            self.custody.request_reveal(**self.request())

    def test_each_frozen_identity_mismatch_invalidates_confirmation(self):
        for name in self.hashes:
            with self.subTest(field=name):
                custody = SimulatedHoldoutCustody(("synthetic-evaluator",))
                self.seal(custody)
                with self.assertRaises(HoldoutAccessViolation):
                    custody.request_reveal(**self.request(**{name: "f" * 64}))
                self.assertTrue(custody.status.invalidated)
                self.assertEqual(custody.status.authorized_access_count, 0)

    def test_reseal_is_idempotent_only_for_the_same_payload_and_identities(self):
        seal = self.seal()
        self.assertEqual(self.seal(), seal)
        with self.assertRaises(HoldoutCustodyError):
            self.custody.seal(b"other synthetic payload", **self.hashes, sealed_at=STAMP)
        with self.assertRaises(HoldoutCustodyError):
            self.custody.seal(self.payload, **{**self.hashes, "code_hash": "f" * 64}, sealed_at=STAMP)
        self.assertEqual(self.custody.seal_record, seal)

    def test_reported_accidental_access_invalidates_even_after_release(self):
        self.seal()
        self.custody.request_reveal(**self.request())
        self.custody.assert_confirmatory_claims_valid()
        self.custody.record_violation(requester="synthetic-evaluator", reason="synthetic accidental access", occurred_at=STAMP)
        self.assertTrue(self.custody.status.invalidated)
        with self.assertRaises(HoldoutAccessViolation):
            self.custody.assert_confirmatory_claims_valid()

    def test_evaluator_failure_after_reveal_cannot_be_retried(self):
        self.seal()
        calls = []

        def fail_after_access(content):
            calls.append(content)
            raise RuntimeError("synthetic evaluator failure")

        with self.assertRaises(HoldoutCustodyError):
            self.custody.run_confirmatory(fail_after_access, **self.request())
        self.assertEqual(calls, [self.payload])
        self.assertTrue(self.custody.status.revealed)
        self.assertTrue(self.custody.status.invalidated)
        with self.assertRaises(HoldoutAlreadyRevealed):
            self.custody.run_confirmatory(fail_after_access, **self.request())
        self.assertEqual(len(calls), 1)

    def test_durable_restart_retains_consumed_reveal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            custody = SimulatedHoldoutCustody(("synthetic-evaluator",), journal_root=root, journal_path="custody.jsonl")
            self.seal(custody)
            released = custody.request_reveal(**self.request())
            head = custody.verify_journal()
            restored = SimulatedHoldoutCustody(("synthetic-evaluator",), journal_root=root, journal_path="custody.jsonl")
            self.assertEqual(restored.verify_journal(), head)
            self.assertTrue(restored.status.durable_journal)
            self.assertEqual(restored.status.release_event, released.release)
            self.assertEqual(restored.status.authorized_access_count, 1)
            self.seal(restored)
            with self.assertRaises(HoldoutAlreadyRevealed):
                restored.request_reveal(**self.request())


if __name__ == "__main__":
    unittest.main()
