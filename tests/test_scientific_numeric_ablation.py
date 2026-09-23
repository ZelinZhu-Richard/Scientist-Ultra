"""Bounded prospective numeric-ablation policy controls.

These tests exercise only the closed native declaration, pure context/math and
source-closure helpers, plus real unavailable-owner boundaries.  They do not
mock a Method, statistical-use, reference-work or Dataset owner, issue an
authority, provision trust, execute a model, or claim scientific evidence.
"""

import ast
from dataclasses import FrozenInstanceError, replace
import inspect
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import textwrap
import unittest

from scientist_one import experiments
from scientist_one.experiments import EvidenceClass, ExperimentPhase
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.generic_ml_ablation import (
    MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS,
    GenericMLFeatureIntervention,
)
from scientist_one.generic_ml_projection import GenericMLReferenceWork
from scientist_one.security import canonical_json_bytes
from scientist_one.scientific_design import (
    _require_temporal_run_spec,
    register_frozen_run_spec,
)
from scientist_one.scientific_numeric_ablation import (
    GENERIC_ML_ABLATION_POLICY_SCHEMA,
    GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
    GenericMLAblationPolicy,
    ScientificNumericAblationBinding,
    ScientificNumericAblationError,
    _joint_reference_products,
    _require_policy_context,
    resolve_scientific_numeric_ablation_binding,
)
from tests.test_scientific_method_alignment import _prepared_canonical_timeline
from tests.test_statistical_use_spec_binding import _declaration as _statistical_declaration


def _intervention(
    *,
    ablation_id="ablation-core",
    component_id="component-core",
    intervention_condition_id="experiment-primary-ablation-core",
    feature_indices=(0,),
):
    return GenericMLFeatureIntervention(
        ablation_id=ablation_id,
        hypothesis_id="hypothesis-primary",
        component_id=component_id,
        candidate_condition_id="experiment-primary",
        baseline_condition_id="baseline-strong",
        intervention_condition_id=intervention_condition_id,
        feature_indices=feature_indices,
    )


def _policy(*interventions):
    return GenericMLAblationPolicy(
        method_id="method-primary",
        metric_id="accuracy",
        interventions=tuple(interventions or (_intervention(),)),
    )


def _valid_context(policy=None):
    value = _policy() if policy is None else policy
    return dict(
        policy=value,
        required_ablation_ids=tuple(item.ablation_id for item in value.interventions),
        hypothesis_id="hypothesis-primary",
        method_id="method-primary",
        method_component_ids=tuple(item.component_id for item in value.interventions),
        metric_id="accuracy",
        candidate_condition_id="experiment-primary",
        baseline_condition_id="baseline-strong",
    )


def _source(function):
    return textwrap.dedent(inspect.getsource(function))


def _call_lines(function):
    tree = ast.parse(_source(function))
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        else:
            continue
        result.setdefault(name, []).append(node.lineno)
    return {name: min(lines) for name, lines in result.items()}


def _snapshot(values):
    registry = values["registry"]
    ledger = values["ledger"]
    return registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)


class _TextSubclass(str):
    pass


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class NumericAblationPolicyTests(unittest.TestCase):
    def test_policy_codec_is_closed_with_exact_golden_bytes(self):
        value = _policy()
        self.assertEqual(GenericMLAblationPolicy.from_dict(value.to_dict()), value)
        self.assertEqual(
            canonical_json_bytes(value.to_dict()),
            b'{"interventions":[{"ablation_id":"ablation-core",'
            b'"baseline_condition_id":"baseline-strong",'
            b'"candidate_condition_id":"experiment-primary",'
            b'"component_id":"component-core","feature_indices":[0],'
            b'"hypothesis_id":"hypothesis-primary",'
            b'"intervention_condition_id":"experiment-primary-ablation-core",'
            b'"operator":"ZERO_DECLARED_INPUT_FEATURE_WEIGHTS_V1",'
            b'"schema_version":"generic-ml-feature-intervention/v1",'
            b'"scope":"DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY"}],'
            b'"method_id":"method-primary","metric_id":"accuracy",'
            b'"schema_version":"generic-ml-feature-intervention-policy/v1",'
            b'"scope":"DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY"}',
        )
        self.assertEqual(value.schema_version, GENERIC_ML_ABLATION_POLICY_SCHEMA)
        self.assertEqual(value.scope, GENERIC_ML_FEATURE_INTERVENTION_SCOPE)

    def test_policy_codec_rejects_absent_extra_null_and_non_native_fields(self):
        complete = _policy().to_dict()
        invalid = [None, {}, [], _DictSubclass(complete)]
        for key in complete:
            invalid.append({name: item for name, item in complete.items() if name != key})
        invalid.append({**complete, "unexpected": True})
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ScientificNumericAblationError):
                    GenericMLAblationPolicy.from_dict(value)
        for key, bad in (
            ("schema_version", None),
            ("scope", True),
            ("method_id", _TextSubclass("method-primary")),
            ("metric_id", None),
            ("interventions", _TupleSubclass(_policy().to_dict()["interventions"])),
            ("interventions", _ListSubclass(_policy().to_dict()["interventions"])),
        ):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ScientificNumericAblationError):
                    GenericMLAblationPolicy.from_dict({**complete, key: bad})

    def test_policy_constructor_rejects_duplicate_ids_and_exact_type_hooks(self):
        duplicate_id = _intervention(ablation_id="ablation-core", component_id="component-other")
        duplicate_condition = _intervention(
            ablation_id="ablation-other",
            component_id="component-other",
            intervention_condition_id="experiment-primary-ablation-core",
        )
        for interventions in ((_intervention(), duplicate_id), (_intervention(), duplicate_condition)):
            with self.subTest(interventions=interventions):
                with self.assertRaises(ScientificNumericAblationError):
                    _policy(*interventions)

        class PolicySubclass(GenericMLAblationPolicy):
            pass

        with self.assertRaises(ScientificNumericAblationError):
            PolicySubclass(
                method_id="method-primary",
                metric_id="accuracy",
                interventions=(_intervention(),),
            )
        with self.assertRaises(ScientificNumericAblationError):
            GenericMLAblationPolicy(
                method_id=_TextSubclass("method-primary"),
                metric_id="accuracy",
                interventions=(_intervention(),),
            )

    def test_policy_and_intervention_are_detached_from_later_caller_mutation(self):
        intervention = _intervention()
        value = _policy(intervention)
        before = value.to_dict()
        object.__setattr__(intervention, "component_id", "caller-mutated")
        object.__setattr__(intervention, "feature_indices", (1,))
        self.assertEqual(value.interventions[0].component_id, "component-core")
        self.assertEqual(value.interventions[0].feature_indices, (0,))
        wire = value.to_dict()
        wire["interventions"][0]["feature_indices"][0] = 7
        self.assertEqual(value.to_dict(), before)
        with self.assertRaises(FrozenInstanceError):
            value.method_id = "mutated"

    def test_policy_cap_and_complete_order_preserve_overlapping_component_groups(self):
        interventions = tuple(
            _intervention(ablation_id=f"ablation-{index}",
                          intervention_condition_id=f"intervention-{index}")
            for index in range(65)
        )
        policy = _policy(*interventions[:64])
        self.assertEqual(GenericMLAblationPolicy.from_dict(policy.to_dict()), policy)
        for values in ((), interventions, list(interventions[:1]), _TupleSubclass(interventions[:1])):
            with self.subTest(kind=type(values), count=len(values)), self.assertRaises(ScientificNumericAblationError):
                replace(policy, interventions=values)
        wire = policy.to_dict()
        wire["interventions"].append(interventions[-1].to_dict())
        with self.assertRaises(ScientificNumericAblationError):
            GenericMLAblationPolicy.from_dict(wire)
        context = {**_valid_context(policy), "method_component_ids": ("component-core",)}
        self.assertIsNone(_require_policy_context(**context))
        ids = context["required_ablation_ids"]
        for wrong in (ids[::-1], ids[:-1], (ids[0],) * len(ids), ()):
            with self.subTest(ids=wrong), self.assertRaises(ScientificNumericAblationError):
                _require_policy_context(**{**context, "required_ablation_ids": wrong})

    def test_policy_codec_refuses_subclass_before_attribute_hooks(self):
        calls = []

        class HostilePolicy(GenericMLAblationPolicy):
            def __getattribute__(self, name):
                calls.append(name)
                raise AssertionError("untrusted attribute hook ran")

        hostile = object.__new__(HostilePolicy)
        with self.assertRaises(ScientificNumericAblationError):
            GenericMLAblationPolicy.to_dict(hostile)
        with self.assertRaises(ScientificNumericAblationError):
            HostilePolicy.from_dict(_policy().to_dict())
        self.assertEqual(calls, [])

    def test_policy_context_requires_exact_ordered_method_metric_and_condition_joins(self):
        context = _valid_context()
        self.assertIsNone(_require_policy_context(**context))
        cases = (
            {"method_id": "method-other"},
            {"metric_id": "proxy-score"},
            {"hypothesis_id": "hypothesis-other"},
            {"method_component_ids": ("component-other",)},
            {"candidate_condition_id": "candidate-other"},
            {"baseline_condition_id": "baseline-other"},
            {"required_ablation_ids": ("ablation-other",)},
            {"required_ablation_ids": ["ablation-core"]},
            {"method_component_ids": _TupleSubclass(("component-core",))},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ScientificNumericAblationError):
                _require_policy_context(**{**context, **changes})

    def test_joint_reference_products_are_exact_and_bounded_across_all_declared_interventions(self):
        work = GenericMLReferenceWork(4096, 24, 2, 9)
        per_grid = 3 * 4096 * 24 * 2 * 9
        self.assertEqual(_joint_reference_products(work, 3), 3 * per_grid)
        self.assertEqual(3 * per_grid, 15_925_248)
        self.assertEqual(MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS, 16_777_216)
        self.assertEqual(4 * per_grid > MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS, True)
        with self.assertRaises(ScientificNumericAblationError):
            _joint_reference_products(work, 4)
        for count in (0, 65, True, 1.0, _TextSubclass("1")):
            with self.subTest(count=count), self.assertRaises(ScientificNumericAblationError):
                _joint_reference_products(work, count)
        with self.assertRaises(ValidationError):
            GenericMLReferenceWork(4096, 24, 256, 255)
        with self.assertRaises(ScientificNumericAblationError):
            _joint_reference_products(SimpleNamespace(unit_count=1), 1)

    def test_binding_source_records_deduplicate_exact_identity_and_reject_conflicts(self):
        record_a = SimpleNamespace(sha256="a" * 64, record_hash="b" * 64)
        record_b = SimpleNamespace(sha256="c" * 64, record_hash="d" * 64)
        binding = ScientificNumericAblationBinding(
            policy=_policy(),
            reference_binding=SimpleNamespace(source_records=(record_a, record_a, record_b)),
            method_binding=SimpleNamespace(),
            method_record=record_b,
            joint_reference_products=1,
            changed_coefficient_counts=((1,),),
        )
        self.assertEqual(binding.source_records, (record_a, record_b))
        conflict = SimpleNamespace(sha256=record_a.sha256, record_hash="e" * 64)
        conflicted = replace(
            binding,
            reference_binding=SimpleNamespace(source_records=(record_a, conflict)),
        )
        with self.assertRaises(ScientificNumericAblationError):
            conflicted.source_records

    def test_numeric_resolver_is_source_replay_only_and_never_predicts_before_freeze(self):
        calls = _call_lines(resolve_scientific_numeric_ablation_binding)
        self.assertTrue({"predict", "derive_generic_ml_ablation_grid"}.isdisjoint(calls))
        for name in (
            "_scientific_statistical_use_context",
            "resolve_scientific_reference_work_binding",
            "resolve_scientific_method_definition_binding",
            "require_frozen_evaluation_contract",
            "_require_policy_context",
            "_joint_reference_products",
            "parse_bounded_integer_classification_dataset",
            "parse_frozen_model_configuration",
            "_require_scientific_execution_snapshot_unchanged",
        ):
            self.assertIn(name, calls)
        self.assertLess(calls["_scientific_statistical_use_context"], calls["resolve_scientific_reference_work_binding"])
        self.assertLess(calls["resolve_scientific_reference_work_binding"], calls["resolve_scientific_method_definition_binding"])
        self.assertLess(calls["resolve_scientific_method_definition_binding"], calls["_require_policy_context"])
        self.assertLess(calls["_require_policy_context"], calls["_joint_reference_products"])
        self.assertLess(calls["_joint_reference_products"], calls["parse_bounded_integer_classification_dataset"])
        self.assertLess(calls["parse_bounded_integer_classification_dataset"], calls["parse_frozen_model_configuration"])
        self.assertLess(calls["parse_frozen_model_configuration"], calls["_require_scientific_execution_snapshot_unchanged"])


class NumericAblationIntegrationBoundaryTests(unittest.TestCase):
    def _values(self, directory):
        return _prepared_canonical_timeline(directory)

    def _with_metadata(self, spec, **entries):
        return replace(spec, metadata={**dict(spec.to_dict()["metadata"]), **entries})

    def test_absent_policy_preserves_legacy_none_when_required_set_is_empty(self):
        with TemporaryDirectory(prefix="numeric-ablation-legacy-") as directory:
            values = self._values(directory)
            spec = replace(values["spec"], required_ablations=())
            before = _snapshot(values)
            self.assertIsNone(
                resolve_scientific_numeric_ablation_binding(
                    values["registry"], spec=spec,
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                )
            )
            self.assertEqual(_snapshot(values), before)

    def test_malformed_present_policy_refuses_without_registry_or_ledger_delta(self):
        with TemporaryDirectory(prefix="numeric-ablation-malformed-") as directory:
            values = self._values(directory)
            key = "scientific_numeric_ablation_policy"
            spec = self._with_metadata(values["spec"], **{key: None})
            before = _snapshot(values)
            with self.assertRaises(ScientificNumericAblationError):
                resolve_scientific_numeric_ablation_binding(
                    values["registry"], spec=spec,
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                )
            self.assertEqual(_snapshot(values), before)

    def test_required_fixed_model_reference_without_numeric_policy_is_rejected(self):
        with TemporaryDirectory(prefix="numeric-ablation-absent-required-") as directory:
            values = self._values(directory)
            spec = self._with_metadata(
                values["spec"],
                **{
                    experiments.SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY:
                    {"schema_version": "scientist-one-fixed-model-reference-work-policy/v1",
                     "profile_id": "FIXED_DENSE_INTEGER_LINEAR_MICRO_ACCURACY_V1",
                     "scope": "FIXED_MODEL_REFERENCE_WORK_ONLY",
                     "wall_cap_scope": "RUN_WIDE_CONTRACT_WALL_SECONDS"},
                },
            )
            before = _snapshot(values)
            with self.assertRaisesRegex(ScientificNumericAblationError, "lack their prospective numeric policy"):
                resolve_scientific_numeric_ablation_binding(
                    values["registry"], spec=spec,
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                )
            self.assertEqual(_snapshot(values), before)

    def test_present_policy_without_statistical_use_refuses_without_owner_writes(self):
        with TemporaryDirectory(prefix="numeric-ablation-no-statistical-use-") as directory:
            values = self._values(directory)
            spec = self._with_metadata(
                values["spec"],
                scientific_numeric_ablation_policy=_policy().to_dict(),
            )
            before = _snapshot(values)
            with self.assertRaisesRegex(ScientificNumericAblationError, "prospective statistical use"):
                resolve_scientific_numeric_ablation_binding(
                    values["registry"], spec=spec,
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                )
            self.assertEqual(_snapshot(values), before)

    def test_actual_spec_registration_reaches_numeric_owner_before_writing(self):
        with TemporaryDirectory(prefix="numeric-ablation-spec-prewrite-") as directory:
            values = self._values(directory)
            spec = self._with_metadata(values["spec"], scientific_numeric_ablation_policy=_policy().to_dict())
            before = _snapshot(values)
            try:
                register_frozen_run_spec(
                    values["registry"], contract=values["contract"],
                    contract_artifact_sha256=values["contract_record"].sha256,
                    experiment_plan_artifact_sha256s=tuple(item.sha256 for item in values["plan_records"]),
                    spec=spec,
                )
            except ScientificNumericAblationError as refused:
                call_names = []
                trace = refused.__traceback__
                while trace is not None:
                    call_names.append(trace.tb_frame.f_code.co_name)
                    trace = trace.tb_next
                self.assertIn("resolve_scientific_numeric_ablation_binding", call_names)
                self.assertIn("prospective statistical use", str(refused))
            else:
                self.fail("spec registration accepted a numeric policy without statistical use")
            self.assertEqual(_snapshot(values), before)

    def test_declared_missing_statistical_authority_reaches_real_owner_and_stays_zero_write(self):
        with TemporaryDirectory(prefix="numeric-ablation-missing-statistical-owner-") as directory:
            values = self._values(directory)
            spec = self._with_metadata(
                values["spec"],
                scientific_numeric_ablation_policy=_policy().to_dict(),
                **{
                    experiments.SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY:
                    {"schema_version": "scientist-one-fixed-model-reference-work-policy/v1",
                     "profile_id": "FIXED_DENSE_INTEGER_LINEAR_MICRO_ACCURACY_V1",
                     "scope": "FIXED_MODEL_REFERENCE_WORK_ONLY",
                     "wall_cap_scope": "RUN_WIDE_CONTRACT_WALL_SECONDS"},
                    experiments.SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY:
                    _statistical_declaration(),
                },
            )
            spec = replace(
                spec,
                phase=ExperimentPhase.CONFIRMATORY,
                evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
                timeout_seconds=values["contract"].compute_budget.max_wall_seconds,
                metadata={
                    **dict(spec.to_dict()["metadata"]),
                    "evaluation_split": values["contract"].dataset.confirmatory_split_id,
                },
            )
            before = _snapshot(values)
            try:
                resolve_scientific_numeric_ablation_binding(
                    values["registry"], spec=spec,
                    expected_contract_artifact_sha256=values["contract_record"].sha256,
                )
            except (ArtifactError, ValidationError) as refused:
                call_names = []
                trace = refused.__traceback__
                while trace is not None:
                    call_names.append(trace.tb_frame.f_code.co_name)
                    trace = trace.tb_next
            else:
                self.fail("missing statistical authority was accepted")
            self.assertIn("resolve_scientific_statistical_use_binding", call_names)
            self.assertIn("require_dataset_statistical_use_authority", call_names)
            self.assertEqual(_snapshot(values), before)


class NumericAblationIntegrationStructureTests(unittest.TestCase):
    def test_run_spec_registration_replays_numeric_policy_before_parent_write(self):
        lines = _call_lines(register_frozen_run_spec)
        for name in (
            "_require_temporal_method_definition_binding",
            "resolve_scientific_statistical_use_binding",
            "resolve_scientific_reference_work_binding",
            "resolve_scientific_numeric_ablation_binding",
            "put_json",
        ):
            self.assertIn(name, lines)
        self.assertLess(lines["_require_temporal_method_definition_binding"], lines["resolve_scientific_statistical_use_binding"])
        self.assertLess(lines["resolve_scientific_statistical_use_binding"], lines["resolve_scientific_reference_work_binding"])
        self.assertLess(lines["resolve_scientific_reference_work_binding"], lines["resolve_scientific_numeric_ablation_binding"])
        self.assertLess(lines["resolve_scientific_numeric_ablation_binding"], lines["put_json"])

    def test_temporal_readback_and_execution_spec_replay_numeric_policy_after_existing_owners(self):
        readback = _call_lines(_require_temporal_run_spec)
        execution = _call_lines(experiments._require_scientific_execution_spec_and_inputs)
        for lines, method_name in ((readback, "_require_temporal_method_definition_binding"), (execution, "resolve_scientific_method_definition_binding")):
            for name in (
                method_name,
                "resolve_scientific_statistical_use_binding",
                "resolve_scientific_reference_work_binding",
                "resolve_scientific_numeric_ablation_binding",
            ):
                self.assertIn(name, lines)
            self.assertLess(lines[method_name], lines["resolve_scientific_statistical_use_binding"])
            self.assertLess(lines["resolve_scientific_statistical_use_binding"], lines["resolve_scientific_reference_work_binding"])
            self.assertLess(lines["resolve_scientific_reference_work_binding"], lines["resolve_scientific_numeric_ablation_binding"])
        self.assertLess(
            execution["_require_scientific_execution_input_records"],
            execution["resolve_scientific_method_definition_binding"],
        )


if __name__ == "__main__":
    unittest.main()
