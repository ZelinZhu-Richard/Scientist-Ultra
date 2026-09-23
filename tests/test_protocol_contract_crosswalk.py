"""Pure compatibility checks; no scientific source or authority is issued."""

from dataclasses import replace
import unittest

from scientist_one.protocol import BaselineSpec, DataRoles, ProtocolComputeBudget
from scientist_one.scientific_design import (
    BaselineRegistry,
    BaselineStatus,
    ScientificPromotionError,
    _require_scientific_protocol_contract_crosswalk,
)
from tests.test_scientific_core import conditions, make_protocol
from tests.test_scientific_design import make_contract


def matching_protocol(contract):
    candidate = conditions(
        preprocessing=contract.candidate_conditions.preprocessing,
        tuning_budget=contract.candidate_conditions.tuning_trials,
        compute_budget=contract.candidate_conditions.compute_budget,
    )
    template = make_protocol()
    return replace(
        template,
        primary_hypothesis=contract.hypothesis_register.primary.statement,
        primary_metric=contract.primary_metric.metric_id,
        data_exclusions=contract.dataset.exclusions,
        data_roles=DataRoles(
            train=(contract.dataset.train_split_id,),
            development=(contract.dataset.development_split_id,),
            validation=(contract.dataset.validation_split_id,),
            holdout=(contract.dataset.confirmatory_split_id,),
        ),
        candidate_conditions=candidate,
        baseline_set=tuple(
            BaselineSpec(item.name, candidate)
            for item in contract.baseline_registry.entries
        ),
        ablation_set=tuple(item.ablation_id for item in contract.ablations if item.required),
        seed_policy=replace(template.seed_policy, seeds=contract.seed_reporting.seeds),
        compute_budget=ProtocolComputeBudget(
            contract.compute_budget.max_runs,
            contract.compute_budget.max_wall_seconds,
            contract.compute_budget.max_cpu_workers,
            contract.compute_budget.max_gpu_jobs,
        ),
        stopping_rules=contract.stopping_criteria,
        statistical_tests=(replace(
            template.statistical_tests[0],
            name=contract.statistical_plan.primary_test,
            alpha=contract.statistical_plan.alpha,
        ),),
        multiple_comparison_correction=contract.statistical_plan.multiplicity_correction,
    )


class ProtocolContractCrosswalkTests(unittest.TestCase):
    def setUp(self):
        self.contract = make_contract()
        self.protocol = matching_protocol(self.contract)

    def refuse(self, protocol, contract=None, *, baseline=False):
        with self.assertRaisesRegex(
            ScientificPromotionError,
            "baseline semantics are substituted" if baseline else "not the exact vNext",
        ):
            _require_scientific_protocol_contract_crosswalk(
                protocol, self.contract if contract is None else contract,
            )

    def test_exact_match_is_nonissuing_and_preserves_hashes(self):
        before = self.protocol.sha256, self.contract.sha256
        self.assertIsNone(_require_scientific_protocol_contract_crosswalk(
            self.protocol, self.contract,
        ))
        self.assertEqual(before, (self.protocol.sha256, self.contract.sha256))

    def test_primary_fields_and_exclusions_must_match(self):
        for field, value in (
            ("primary_hypothesis", "Different hypothesis."),
            ("primary_metric", "different_metric"),
            ("data_exclusions", ("Different prospective exclusions.",)),
            ("stopping_rules", ("Different stop rule.",)),
            ("ablation_set", ("different-ablation",)),
        ):
            with self.subTest(field=field):
                self.refuse(replace(self.protocol, **{field: value}))

    def test_each_data_role_must_match(self):
        for role in ("train", "development", "validation", "holdout"):
            with self.subTest(role=role):
                self.refuse(replace(
                    self.protocol,
                    data_roles=replace(self.protocol.data_roles, **{role: ("different-split",)}),
                ))

    def test_seed_order_and_each_compute_dimension_must_match(self):
        self.refuse(replace(
            self.protocol,
            seed_policy=replace(self.protocol.seed_policy, seeds=(19, 11, 7)),
        ))
        for field, value in (
            ("max_runs", 13), ("max_wall_seconds", 3601.0),
            ("max_cpu_workers", 3), ("max_gpu_jobs", 0),
        ):
            with self.subTest(field=field):
                self.refuse(replace(
                    self.protocol,
                    compute_budget=replace(self.protocol.compute_budget, **{field: value}),
                ))

    def test_statistical_name_alpha_resampling_and_correction_must_match(self):
        for field, value in (("name", "different-test"), ("alpha", 0.01)):
            with self.subTest(field=field):
                self.refuse(replace(self.protocol, statistical_tests=(replace(
                    self.protocol.statistical_tests[0], **{field: value},
                ),)))
        self.refuse(replace(self.protocol, multiple_comparison_correction="Bonferroni"))
        self.refuse(self.protocol, replace(
            self.contract,
            statistical_plan=replace(self.contract.statistical_plan, resampling_unit="patient"),
        ))
        # Preserve the existing case-insensitive correction comparison.
        self.assertIsNone(_require_scientific_protocol_contract_crosswalk(
            replace(self.protocol, multiple_comparison_correction="HOLM"), self.contract,
        ))

    def test_candidate_dimensions_cannot_change_together_with_baselines(self):
        for field, value in (
            ("preprocessing", "different-transform"),
            ("tuning_budget", 7), ("compute_budget", 99.0),
        ):
            with self.subTest(field=field):
                candidate = replace(self.protocol.candidate_conditions, **{field: value})
                self.refuse(replace(
                    self.protocol, candidate_conditions=candidate,
                    baseline_set=tuple(replace(item, conditions=candidate) for item in self.protocol.baseline_set),
                ))

    def test_baseline_name_and_context_only_semantics_are_retained(self):
        self.refuse(replace(self.protocol, baseline_set=(replace(
            self.protocol.baseline_set[0], name="Different baseline",
        ),)))
        original = self.contract.baseline_registry.entries[0]
        for field, value in (
            ("preprocessing", "context-transform"),
            ("tuning_trials", 7), ("compute_budget", 99.0),
        ):
            with self.subTest(field=field):
                # A context-only baseline may differ prospectively, but this
                # exact crosswalk cannot silently substitute its semantics.
                baseline = replace(
                    original, status=BaselineStatus.CONTEXT_ONLY,
                    baseline_id="context-baseline", name="Context baseline",
                    conditions=replace(original.conditions, **{field: value}),
                )
                protocol = replace(self.protocol, baseline_set=(
                    *self.protocol.baseline_set,
                    BaselineSpec(baseline.name, self.protocol.candidate_conditions),
                ))
                self.refuse(protocol, replace(
                    self.contract, baseline_registry=BaselineRegistry((original, baseline)),
                ), baseline=True)


if __name__ == "__main__":
    unittest.main()
