"""Pure policy/protocol controls, never scientific or external authority."""

from dataclasses import replace
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_DECISION_RULE_ID,
    BoundedMeanDecision,
    BoundedMeanInferencePlan,
    BoundedMeanInferenceResult,
    PairedRowCorrectnessCounts,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    HypothesisEvaluationFacts,
    HypothesisEvaluationPolicy,
    HypothesisStatus,
    ScientificDesignError,
    ScientificResultOutcome,
    derive_bounded_mean_result_assessment,
    derive_scientific_result_assessment,
    evaluate_bounded_mean_hypothesis_policy,
    evaluate_hypothesis_policy,
    register_frozen_evaluation_contract,
    require_frozen_evaluation_contract,
)
from tests.test_hypothesis_evaluation_and_rejections import _policies
from tests.test_scientific_design import make_contract


def _policy(**changes):
    values = dict(
        policy_id="bounded-mean-policy",
        hypothesis_id="hypothesis-primary",
        metric_id="accuracy",
        meaningful_effect=0.2,
        falsification_effect=0.2,
        alpha=0.05,
        minimum_sample_size=20,
        rule_id=BOUNDED_MEAN_DECISION_RULE_ID,
        outcome_order=BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER,
    )
    values.update(changes)
    return HypothesisEvaluationPolicy(**values)


def _result(policy, *, n=1000, candidate=3, reference=2, seeds=5):
    plan = BoundedMeanInferencePlan(
        alpha=policy.alpha,
        benefit_margin=policy.meaningful_effect,
        harm_margin=policy.falsification_effect,
        minimum_unit_count=policy.minimum_sample_size,
        unit_ids=tuple(f"unit-{i}" for i in range(n)),
        seed_order=tuple(range(seeds)),
    )
    return BoundedMeanInferenceResult(
        plan=plan,
        rows=tuple(
            PairedRowCorrectnessCounts(unit, seeds, candidate, reference)
            for unit in plan.unit_ids
        ),
    )


class BoundedMeanPolicyTests(unittest.TestCase):
    def test_exact_numeric_branches_preserve_distinct_scientific_outcomes(self):
        cases = (
            (
                _policy(meaningful_effect=0.02),
                3,
                2,
                HypothesisStatus.SUPPORTED,
                ScientificResultOutcome.POSITIVE,
            ),
            (
                _policy(falsification_effect=0.02),
                2,
                3,
                HypothesisStatus.FALSIFIED,
                ScientificResultOutcome.FALSIFIED,
            ),
            (
                _policy(),
                3,
                2,
                HypothesisStatus.PARTIALLY_SUPPORTED,
                ScientificResultOutcome.POSITIVE,
            ),
            (
                _policy(),
                2,
                3,
                HypothesisStatus.NOT_SUPPORTED,
                ScientificResultOutcome.NEGATIVE,
            ),
            (
                _policy(),
                2,
                2,
                HypothesisStatus.NOT_SUPPORTED,
                ScientificResultOutcome.NULL,
            ),
        )
        for policy, candidate, reference, status, outcome in cases:
            with self.subTest(outcome=outcome, status=status):
                result = _result(policy, candidate=candidate, reference=reference)
                self.assertIs(
                    evaluate_bounded_mean_hypothesis_policy(policy, result), status
                )
                decision = derive_bounded_mean_result_assessment(policy, result)
                self.assertIs(decision.hypothesis_status, status)
                self.assertIs(decision.outcome, outcome)

    def test_equivalence_precedes_smaller_directional_support(self):
        policy = _policy()
        result = _result(policy, seeds=10, candidate=3, reference=2)
        self.assertGreater(result.confidence_low, 0)
        self.assertIs(result.decision, BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS)
        self.assertIs(
            derive_bounded_mean_result_assessment(policy, result).outcome,
            ScientificResultOutcome.NULL,
        )

    def test_twenty_ties_and_unmet_frozen_minimum_stay_inconclusive(self):
        for policy, n, candidate, reference in (
            (_policy(), 20, 2, 2),
            (_policy(minimum_sample_size=1001), 1000, 5, 0),
        ):
            result = _result(policy, n=n, candidate=candidate, reference=reference)
            self.assertIs(
                evaluate_bounded_mean_hypothesis_policy(policy, result),
                HypothesisStatus.INCONCLUSIVE,
            )
            self.assertIs(
                derive_bounded_mean_result_assessment(policy, result).outcome,
                ScientificResultOutcome.INCONCLUSIVE,
            )

    def test_generic_legacy_facts_cannot_interpret_new_rule(self):
        policy = _policy()
        facts = HypothesisEvaluationFacts(0.3, 0.2, 0.4, 0.001, 1000)
        for consumer in (
            evaluate_hypothesis_policy,
            derive_scientific_result_assessment,
        ):
            with self.subTest(consumer=consumer.__name__):
                with self.assertRaisesRegex(ScientificDesignError, "not generic facts"):
                    consumer(policy, facts)

    def test_bounded_mean_output_cannot_silently_replace_legacy_policy(self):
        policy = _policy()
        result = _result(policy)
        legacy = _policies(make_contract())[0]
        with self.assertRaisesRegex(ScientificDesignError, "prospective rule"):
            evaluate_bounded_mean_hypothesis_policy(legacy, result)

    def test_all_frozen_numeric_policy_parameters_require_exact_agreement(self):
        policy = _policy()
        result = _result(policy)
        for name, value in (
            ("alpha", math.nextafter(policy.alpha, 1.0)),
            ("meaningful_effect", math.nextafter(policy.meaningful_effect, 1.0)),
            ("falsification_effect", math.nextafter(policy.falsification_effect, 1.0)),
            ("minimum_sample_size", policy.minimum_sample_size + 1),
        ):
            with self.subTest(field=name):
                with self.assertRaisesRegex(
                    ScientificDesignError, "differs from the prospective"
                ):
                    evaluate_bounded_mean_hypothesis_policy(
                        replace(policy, **{name: value}), result
                    )

    def test_derived_result_substitution_fails_recomputation(self):
        policy = _policy()
        for name, value in (
            ("decision", BoundedMeanDecision.SUPPORTED),
            ("mean_zero_p_upper", 0.0),
            ("confidence_low", 0.99),
            ("mean_denominator", 1),
        ):
            with self.subTest(field=name):
                result = _result(policy)
                object.__setattr__(result, name, value)
                with self.assertRaisesRegex(
                    ScientificDesignError, "differs from recomputation"
                ):
                    evaluate_bounded_mean_hypothesis_policy(policy, result)

    def test_new_order_and_numeric_scope_are_explicit(self):
        legacy_order = _policies(make_contract())[0].outcome_order
        for changes in (
            {"outcome_order": legacy_order},
            {"outcome_order": tuple(reversed(BOUNDED_MEAN_HYPOTHESIS_OUTCOME_ORDER))},
            {"alpha": 1.0},
            {"meaningful_effect": 1.01},
            {"falsification_effect": 1.01},
            {"minimum_sample_size": 4097},
            {"rule_id": "unreviewed-rule"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ScientificDesignError):
                    _policy(**changes)

    def test_new_rule_rejects_integer_subclass_with_substituted_equality(self):
        class FalseEquality(int):
            def __ne__(self, other):
                return False

        with self.assertRaises(ScientificDesignError):
            _policy(minimum_sample_size=FalseEquality(1001))
        policy = _policy()
        result = _result(policy)
        object.__setattr__(policy, "minimum_sample_size", FalseEquality(1001))
        with self.assertRaises(ScientificDesignError):
            evaluate_bounded_mean_hypothesis_policy(policy, result)

    def test_new_rule_rejects_untyped_or_overridden_outcome_order(self):
        class DifferentOrder(tuple):
            def __ne__(self, other):
                return False

        class AlwaysEqualStatus(str):
            def __eq__(self, other):
                return True

        for order in (
            DifferentOrder((HypothesisStatus.SUPPORTED,)),
            tuple(AlwaysEqualStatus("UNREVIEWED") for _ in range(7)),
        ):
            with self.subTest(order=order):
                with self.assertRaises(ScientificDesignError):
                    _policy(outcome_order=order)

    def test_policy_mapping_rejects_overridden_rule_identity(self):
        class FalseInequality(str):
            def __ne__(self, other):
                return False

        policy = _policy()
        result = _result(policy)
        object.__setattr__(policy, "rule_id", FalseInequality("UNREVIEWED"))
        with self.assertRaises(ScientificDesignError):
            evaluate_bounded_mean_hypothesis_policy(policy, result)

    def test_policy_roundtrip_does_not_issue_numeric_or_execution_authority(self):
        contract = make_contract()
        policies = tuple(
            _policy(
                policy_id=f"bounded-{old.policy_id}",
                hypothesis_id=old.hypothesis_id,
                metric_id=old.metric_id,
            )
            for old in _policies(contract)
        )
        contract = replace(contract, hypothesis_evaluation_policies=policies)
        with TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory))
            inert = registry.put_json(
                {"kind": "non-evidentiary bounded-policy test"},
                logical_type="frozen_scientific_inputs",
                origin="pure policy fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("test", "bounded-policy"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            record = register_frozen_evaluation_contract(
                registry,
                contract=contract,
                parent_artifact_sha256s=(inert.sha256,),
            )
            self.assertEqual(
                require_frozen_evaluation_contract(
                    registry, contract_artifact_sha256=record.sha256
                ),
                contract,
            )
            self.assertEqual(
                {row.logical_type for row in registry.verify_all().records},
                {"frozen_scientific_inputs", "evaluation_contract"},
            )

    def test_legacy_policy_and_contract_hashes_remain_exact(self):
        contract = make_contract()
        policies = _policies(contract)
        self.assertEqual(
            contract.sha256,
            "3e91f26235e92bf39b32aca3a7d3dcf617326c625bab60220e90c48c9b54fe11",
        )
        self.assertEqual(
            replace(contract, hypothesis_evaluation_policies=policies).sha256,
            "bfbca392277fff47da83919cce9226a0ff96c64c3eb1e976cdf2339ae6a06132",
        )
        self.assertEqual(
            policies[0].sha256,
            "a65d69e48497e0c5079b2e79ab281b0a42929b3d8732285e160c95d93dbf2ff3",
        )


if __name__ == "__main__":
    unittest.main()
