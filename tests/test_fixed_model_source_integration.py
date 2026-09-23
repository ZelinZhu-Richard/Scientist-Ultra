"""Bounded D-065 Stage-B source-integration controls.

The static assertions below extract production predicates and call ordering;
they do not construct a scientific source owner or turn inert values into
authority. Dynamic tests use empty or ordinary non-evidentiary fixture
registries and verify actual owner refusal with zero admission delta. No
private issuer, positive owner patch, trust root, network call, or positive
scientific lifecycle is used here.
"""

import ast
import copy
from dataclasses import replace
import inspect
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import textwrap
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.domains import (
    GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
    GenericMLFixedModelAdapter,
    DomainKind,
    SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
    _scientific_domain_v3_plans,
    _verify_scientific_domain_source_candidate,
)
from scientist_one.generic_ml_projection import (
    GenericMLReferenceWorkPolicy,
    GenericMLProjectionError,
    derive_generic_ml_projection_facts,
)
from scientist_one.ledger import EventLedger
from scientist_one.experiments import ExperimentPhase
from scientist_one.reproduction import (
    _resolve_clean_rerun_authority_sources,
    _resolve_clean_rerun_plan_sources,
)
from scientist_one.scientific_design import (
    ScientificPromotionError,
    _derive_projection_checked_result_evidence,
    _require_projection_fixed_model_reference_work,
)
from tests import test_fixed_model_domain_profile as fixed_model_fixture
from tests.test_reference_work_spec_binding import _spec as _reference_spec
from tests.test_scientific_method_alignment import _prepared_canonical_timeline


def _source(function):
    return textwrap.dedent(inspect.getsource(function))


def _tree(function):
    return ast.parse(_source(function))


def _call_lines(function):
    found = {}
    for node in ast.walk(_tree(function)):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        else:
            continue
        found.setdefault(name, []).append(node.lineno)
    return {name: min(lines) for name, lines in found.items()}


def _normalized(function):
    return " ".join(_source(function).split())


def _raising_branch(function, marker):
    for node in ast.walk(_tree(function)):
        if not isinstance(node, ast.If):
            continue
        if any(
            isinstance(child, ast.Raise)
            and marker in ast.unparse(child)
            for child in node.body
        ):
            return node
    raise AssertionError(f"no production raising branch contains {marker!r}")


def _evaluate_guard(function, marker, context):
    branch = _raising_branch(function, marker)
    expression = compile(ast.Expression(branch.test), "<inert-fixed-model-guard>", "eval")
    globals_value = {
        "__builtins__": {},
        "GenericMLFixedModelAdapter": GenericMLFixedModelAdapter,
        "GenericMLFixedModelValidityEvidence": fixed_model_fixture.GenericMLFixedModelValidityEvidence,
        "len": len,
        "set": set,
        "tuple": tuple,
        "type": type,
    }
    return eval(expression, {**globals_value, **context}, {})


def _projection_join_context():
    rows = (SimpleNamespace(unit_id="unit-1", unit_hash="unit-hash-1"),)
    spec = SimpleNamespace(
        sha256="spec-sha",
        code_sha256="code-sha",
        data_sha256="data-sha",
        configuration_sha256="configuration-sha",
        evaluator_sha256="evaluator-sha",
    )
    plan = SimpleNamespace(
        run_id="ledger-run",
        execution_run_id="execution-run",
        evaluation_contract_artifact_sha256="contract-sha",
        evaluation_contract_record_hash="contract-record",
        dataset_authority_artifact_sha256="dataset-sha",
        dataset_authority_record_hash="dataset-record",
        split_authority_artifact_sha256s=("split-0", "split-1", "split-2", "split-3"),
        split_authority_record_hashes=("split-record-0", "split-record-1", "split-record-2", "split-record-3"),
    )
    dataset = SimpleNamespace(dataset_id="dataset")
    raw_record = SimpleNamespace(sha256="raw-sha", record_hash="raw-record")
    confirmatory = SimpleNamespace(
        member_unit_ids=(rows[0].unit_id,),
        member_unit_hashes=(rows[0].unit_hash,),
    )
    split_record = SimpleNamespace(sha256="split-3", record_hash="split-record-3")
    statistical_use = SimpleNamespace(
        member_unit_ids=(rows[0].unit_id,),
        member_unit_hashes=(rows[0].unit_hash,),
    )
    configuration_record = SimpleNamespace(
        sha256="configuration-sha", record_hash="configuration-record"
    )
    evaluator_record = SimpleNamespace(
        sha256="evaluator-sha", record_hash="evaluator-record"
    )
    observed_work = SimpleNamespace(class_count=2, feature_count=3)
    reference_binding = SimpleNamespace(
        run_id=plan.run_id,
        execution_run_id=plan.execution_run_id,
        frozen_run_spec_sha256=spec.sha256,
        contract_record=SimpleNamespace(
            sha256=plan.evaluation_contract_artifact_sha256,
            record_hash=plan.evaluation_contract_record_hash,
        ),
        dataset_authority=dataset,
        dataset_record=SimpleNamespace(
            sha256=plan.dataset_authority_artifact_sha256,
            record_hash=plan.dataset_authority_record_hash,
        ),
        raw_data_record=raw_record,
        confirmatory_split_authority=confirmatory,
        confirmatory_split_record=split_record,
        statistical_use_authority=statistical_use,
        input_records=(
            SimpleNamespace(sha256=spec.code_sha256),
            SimpleNamespace(sha256=spec.data_sha256),
            configuration_record,
            evaluator_record,
        ),
        reference_work=observed_work,
    )
    return {
        "reference_binding": reference_binding,
        "plan": plan,
        "spec": spec,
        "dataset": dataset,
        "raw_record": raw_record,
        "confirmatory": confirmatory,
        "confirmatory_rows": rows,
        "configuration_record": configuration_record,
        "evaluator_record": evaluator_record,
        "observed_work": observed_work,
        "candidate_count": 8,
        "baseline_count": 8,
    }


def _result_join_context():
    evidence = fixed_model_fixture._inert_evidence()
    unit_ids = tuple(f"unit-{index}" for index in range(evidence.reference_work.unit_count))
    unit_hashes = tuple(f"hash-{index}" for index in range(evidence.reference_work.unit_count))
    spec = SimpleNamespace(
        sha256="spec-sha",
        run_id="execution-run",
        code_sha256="code-sha",
        data_sha256="data-sha",
        configuration_sha256="configuration-sha",
        evaluator_sha256="evaluator-sha",
        seeds=(1, 2, 3),
    )
    contract_record = SimpleNamespace(sha256="contract-sha", record_hash="contract-record")
    statistical_use_record = SimpleNamespace(
        sha256=evidence.statistical_use_authority_artifact_sha256,
        record_hash=evidence.statistical_use_authority_record_hash,
    )
    projection = SimpleNamespace(
        run_id="ledger-run",
        execution_run_id=spec.run_id,
        evaluation_contract_record_hash=contract_record.record_hash,
        dataset_authority_artifact_sha256="dataset-sha",
        dataset_authority_record_hash="dataset-record",
        dataset_raw_artifact_sha256="raw-sha",
        dataset_raw_record_hash="raw-record",
        split_authority_artifact_sha256s=("split-0", "split-1", "split-2", "split-3"),
        split_authority_record_hashes=("split-record-0", "split-record-1", "split-record-2", "split-record-3"),
        frozen_model_configuration_record_hash="configuration-record",
        evaluator_record_hash="evaluator-record",
        seed_order=spec.seeds,
        paired_unit_ids=unit_ids,
        paired_unit_hashes=unit_hashes,
    )
    contract_input = SimpleNamespace(sha256=spec.configuration_sha256, record_hash="configuration-record")
    evaluator_input = SimpleNamespace(sha256=spec.evaluator_sha256, record_hash="evaluator-record")
    binding = SimpleNamespace(
        run_id=projection.run_id,
        execution_run_id=projection.execution_run_id,
        frozen_run_spec_sha256=spec.sha256,
        contract_record=contract_record,
        dataset_record=SimpleNamespace(sha256="dataset-sha", record_hash="dataset-record"),
        raw_data_record=SimpleNamespace(sha256="raw-sha", record_hash="raw-record"),
        confirmatory_split_record=SimpleNamespace(sha256="split-3", record_hash="split-record-3"),
        confirmatory_split_authority=SimpleNamespace(
            member_unit_ids=unit_ids, member_unit_hashes=unit_hashes
        ),
        input_records=(
            SimpleNamespace(sha256=spec.code_sha256),
            SimpleNamespace(sha256=spec.data_sha256),
            contract_input,
            evaluator_input,
        ),
        statistical_use_record=statistical_use_record,
        policy=evidence.reference_work_policy,
        reference_work=evidence.reference_work,
        timeout_seconds=evidence.requested_timeout_seconds,
        contract_wall_cap_seconds=evidence.contract_wall_cap_seconds,
        source_records=(contract_record, statistical_use_record, contract_input, evaluator_input),
    )
    domain = SimpleNamespace(
        evidence=evidence,
        outcome=SimpleNamespace(adapter_version=GenericMLFixedModelAdapter.version),
        source_artifact_hashes=frozenset(record.sha256 for record in binding.source_records),
    )
    return {
        "binding": binding,
        "projection": projection,
        "spec": spec,
        "contract_record": contract_record,
        "domain": domain,
        "statistical_use_record": statistical_use_record,
        "evidence": evidence,
    }


def _fixed_profile_view(value, **changes):
    names = (
        "reference_work_policy",
        "reference_work",
        "statistical_use_authority_artifact_sha256",
        "statistical_use_authority_record_hash",
        "requested_timeout_seconds",
        "contract_wall_cap_seconds",
    )
    return SimpleNamespace(
        **{name: changes.get(name, getattr(value, name)) for name in names}
    )


class FixedModelSourceIntegrationTests(unittest.TestCase):
    def test_projection_owner_replay_precedes_native_grid_and_binding(self):
        lines = _call_lines(derive_generic_ml_projection_facts)
        for name in (
            "_replay_scientific_domain_plan_sources",
            "require_scientific_execution_activity",
            "derive_paired_correctness",
            "validate_duplicate_inference_robustness",
            "resolve_scientific_reference_work_binding",
            "GenericMLFixedModelValidityEvidence",
        ):
            self.assertIn(name, lines)
        self.assertLess(
            lines["_replay_scientific_domain_plan_sources"],
            lines["require_scientific_execution_activity"],
        )
        self.assertLess(
            lines["require_scientific_execution_activity"],
            lines["derive_paired_correctness"],
        )
        self.assertLess(
            lines["derive_paired_correctness"],
            lines["validate_duplicate_inference_robustness"],
        )
        self.assertLess(
            lines["validate_duplicate_inference_robustness"],
            lines["resolve_scientific_reference_work_binding"],
        )
        self.assertLess(
            lines["resolve_scientific_reference_work_binding"],
            lines["GenericMLFixedModelValidityEvidence"],
        )

    def test_narrow_activity_fact_is_captured_before_cumulative_seed_refinement(self):
        source = _source(derive_generic_ml_projection_facts)
        narrow = source.index(
            "procedure_activity_eligible = no_recorded_selection_or_protected_label_access"
        )
        cumulative = source.index(
            "procedure_activity_eligible = (",
            narrow + 1,
        )
        loop = source.index("for seed, seed_value, robust_value, frozen_model_pair in zip(")
        self.assertLess(narrow, loop)
        self.assertLess(loop, cumulative)
        self.assertLess(
            narrow,
            source.index("no_recorded_selection_or_protected_label_access=", narrow),
        )

    def test_projection_fixed_model_join_contains_complete_cross_source_identity(self):
        source = _normalized(derive_generic_ml_projection_facts)
        predicates = (
            "reference_binding.run_id != plan.run_id",
            "reference_binding.execution_run_id != plan.execution_run_id",
            "reference_binding.frozen_run_spec_sha256 != spec.sha256",
            "reference_binding.contract_record.sha256 != plan.evaluation_contract_artifact_sha256",
            "reference_binding.contract_record.record_hash != plan.evaluation_contract_record_hash",
            "reference_binding.dataset_authority != dataset",
            "reference_binding.dataset_record.sha256 != plan.dataset_authority_artifact_sha256",
            "reference_binding.dataset_record.record_hash != plan.dataset_authority_record_hash",
            "reference_binding.raw_data_record != raw_record",
            "reference_binding.confirmatory_split_authority != confirmatory",
            "reference_binding.confirmatory_split_record.sha256 != plan.split_authority_artifact_sha256s[3]",
            "reference_binding.confirmatory_split_record.record_hash != plan.split_authority_record_hashes[3]",
            "reference_binding.statistical_use_authority.member_unit_ids != tuple(row.unit_id for row in confirmatory_rows)",
            "reference_binding.statistical_use_authority.member_unit_hashes != tuple(row.unit_hash for row in confirmatory_rows)",
            "tuple(record.sha256 for record in reference_binding.input_records) != (spec.code_sha256, spec.data_sha256, spec.configuration_sha256, spec.evaluator_sha256)",
            "reference_binding.input_records[2:] != (configuration_record, evaluator_record)",
            "reference_binding.reference_work != observed_work",
            "candidate_count != observed_work.class_count * (observed_work.feature_count + 1)",
            "baseline_count != candidate_count",
        )
        for predicate in predicates:
            with self.subTest(predicate=predicate):
                self.assertIn(" ".join(predicate.split()), source)
        self.assertIn(
            "semantic.extend(reference_binding.source_records)",
            source,
        )
        self.assertIn(
            "Generic-ML semantic closure contains conflicting source records",
            source,
        )

    def test_projection_join_guard_is_the_actual_raise_expression_with_independent_mutations(self):
        branch = _raising_branch(
            derive_generic_ml_projection_facts,
            "fixed-model reference-work sources differ",
        )
        self.assertIsInstance(branch.test, ast.BoolOp)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in branch.body))
        baseline = _projection_join_context()
        self.assertFalse(
            _evaluate_guard(
                derive_generic_ml_projection_facts,
                "fixed-model reference-work sources differ",
                baseline,
            )
        )
        mutations = {
            "run identity": lambda value: setattr(value["reference_binding"], "run_id", "other-run"),
            "execution identity": lambda value: setattr(value["reference_binding"], "execution_run_id", "other-execution"),
            "spec identity": lambda value: setattr(value["reference_binding"], "frozen_run_spec_sha256", "other-spec"),
            "contract artifact": lambda value: setattr(value["reference_binding"].contract_record, "sha256", "other-contract"),
            "contract record": lambda value: setattr(value["reference_binding"].contract_record, "record_hash", "other-contract-record"),
            "dataset artifact": lambda value: setattr(value["reference_binding"].dataset_record, "sha256", "other-dataset"),
            "dataset record": lambda value: setattr(value["reference_binding"].dataset_record, "record_hash", "other-dataset-record"),
            "raw identity": lambda value: setattr(
                value["reference_binding"],
                "raw_data_record",
                SimpleNamespace(sha256="other-raw", record_hash="raw-record"),
            ),
            "split authority": lambda value: setattr(
                value["reference_binding"],
                "confirmatory_split_authority",
                SimpleNamespace(member_unit_ids=("other-unit",), member_unit_hashes=("unit-hash-1",)),
            ),
            "split artifact": lambda value: setattr(value["reference_binding"].confirmatory_split_record, "sha256", "other-split"),
            "split record": lambda value: setattr(value["reference_binding"].confirmatory_split_record, "record_hash", "other-split-record"),
            "statistical-use unit IDs": lambda value: setattr(value["reference_binding"].statistical_use_authority, "member_unit_ids", ("other-unit",)),
            "statistical-use unit hashes": lambda value: setattr(value["reference_binding"].statistical_use_authority, "member_unit_hashes", ("other-hash",)),
            "input code": lambda value: setattr(value["reference_binding"].input_records[0], "sha256", "other-code"),
            "input model record": lambda value: setattr(
                value["reference_binding"],
                "input_records",
                (
                    value["reference_binding"].input_records[0],
                    value["reference_binding"].input_records[1],
                    SimpleNamespace(sha256="configuration-sha", record_hash="other-configuration-record"),
                    value["reference_binding"].input_records[3],
                ),
            ),
            "reference work": lambda value: setattr(
                value["reference_binding"],
                "reference_work",
                SimpleNamespace(class_count=3, feature_count=3),
            ),
            "candidate count": lambda value: value.__setitem__("candidate_count", 7),
            "baseline count": lambda value: value.__setitem__("baseline_count", 7),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(baseline)
                mutate(changed)
                self.assertTrue(
                    _evaluate_guard(
                        derive_generic_ml_projection_facts,
                        "fixed-model reference-work sources differ",
                        changed,
                    )
                )

    def test_domain_verifier_requires_exact_versioned_evidence_and_closed_records(self):
        source = _normalized(_verify_scientific_domain_source_candidate)
        required = (
            "expected_type = _domain_evidence_type(candidate.plan.domain)",
            "candidate.plan.domain is DomainKind.GENERIC_ML",
            "candidate.plan.source_format_id == SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID",
            "candidate.plan.source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION",
            "type(evidence) is GenericMLFixedModelValidityEvidence",
            "expected_type = GenericMLFixedModelValidityEvidence",
            "if type(evidence) is not expected_type",
            "embedded_hashes = _embedded_artifact_hashes(evidence)",
            "if not set(embedded_hashes).issubset(allowed_hashes)",
            "semantic_records = verified.semantic_source_records",
            "any(type(record) is not ArtifactRecord for record in semantic_records)",
            "semantic_by_hash = {record.sha256: record for record in semantic_records}",
            "record.validation_result != \"PASS\"",
            "record.frozen is not True",
            "record.creator_role is Role.HUMAN_RELEASE",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), source)

    def test_v3_dispatch_selects_fixed_adapter_only_from_replayed_exact_evidence(self):
        source = _normalized(_scientific_domain_v3_plans)
        for fragment in (
            "source.domain is DomainKind.GENERIC_ML",
            "type(source.evidence) is GenericMLFixedModelValidityEvidence",
            "GenericMLFixedModelAdapter()",
            "get_domain_adapter(source.domain)",
            "outcome = adapter.evaluate(source.evidence)",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), source)
        self.assertLess(
            source.index("type(source.evidence) is GenericMLFixedModelValidityEvidence"),
            source.index("outcome = adapter.evaluate(source.evidence)"),
        )

    def test_result_admission_joins_bounded_mean_before_fixed_model_profile(self):
        lines = _call_lines(_derive_projection_checked_result_evidence)
        self.assertIn("_require_bounded_mean_projection_source_join", lines)
        self.assertIn("_require_projection_fixed_model_reference_work", lines)
        return_lines = [
            node.lineno
            for node in ast.walk(_tree(_derive_projection_checked_result_evidence))
            if isinstance(node, ast.Return)
            and isinstance(node.value, ast.Call)
            and (
                (isinstance(node.value.func, ast.Name)
                 and node.value.func.id == "_ProjectionCheckedResultEvidence")
                or (isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == "_ProjectionCheckedResultEvidence")
            )
        ]
        self.assertTrue(return_lines)
        self.assertLess(
            lines["_require_bounded_mean_projection_source_join"],
            lines["_require_projection_fixed_model_reference_work"],
        )
        self.assertLess(lines["_require_projection_fixed_model_reference_work"], min(return_lines))

    def test_fixed_model_reference_helper_replays_binding_and_requires_complete_join(self):
        source = _normalized(_require_projection_fixed_model_reference_work)
        required = (
            "resolve_scientific_reference_work_binding(",
            "if binding is None:",
            "type(evidence) is GenericMLFixedModelValidityEvidence",
            "domain.outcome.adapter_version == GenericMLFixedModelAdapter.version",
            "statistical_use_record is None",
            "binding.run_id != projection.run_id",
            "binding.execution_run_id != spec.run_id",
            "binding.contract_record != contract_record",
            "binding.raw_data_record.record_hash != projection.dataset_raw_record_hash",
            "binding.confirmatory_split_authority.member_unit_hashes != projection.paired_unit_hashes",
            "binding.statistical_use_record != statistical_use_record",
            "evidence.reference_work != binding.reference_work",
            "evidence.no_recorded_selection_or_protected_label_access is not True",
            "not {record.sha256 for record in binding.source_records}.issubset(domain.source_artifact_hashes)",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), source)

    def test_required_ablations_mandate_fresh_numeric_source_replay_without_a_boolean_bypass(self):
        function = _tree(_require_projection_fixed_model_reference_work).body[0]
        branch = next(
            node
            for node in ast.walk(function)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "spec.required_ablations"
        )
        returns = [node for node in branch.body if isinstance(node, ast.Return)]
        self.assertFalse(returns)
        self.assertEqual(branch.orelse, [])
        calls = [node for node in ast.walk(branch) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "require_scientific_numeric_ablation_execution"]
        self.assertEqual(len(calls), 1)
        self.assertEqual([ast.unparse(argument) for argument in calls[0].args], ["registry", "ledger"])
        signature = inspect.signature(_require_projection_fixed_model_reference_work)
        self.assertEqual(signature.parameters["ledger"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(signature.parameters["ledger"].default, inspect.Parameter.empty)
        self.assertFalse({"numeric_ablations", "verified", "passed"} & set(signature.parameters))
        actual_predicate = compile(ast.Expression(branch.test), "<required-obligations-selector>", "eval")
        for required in ((), ("required-ablation",)):
            with self.subTest(required=required):
                self.assertEqual(
                    eval(actual_predicate, {"__builtins__": {}}, {"spec": SimpleNamespace(required_ablations=required)}),
                    required,
                )
        self.assertIn("numeric_ablations.prospective_binding.reference_binding != binding", ast.unparse(branch))
        self.assertIn("numeric_ablations.projection != projection", ast.unparse(branch))
        self.assertIn("numeric_ablations.spec != spec", ast.unparse(branch))
        self.assertNotIn("candidate_minus_ablated", ast.unparse(branch))

    def test_numeric_result_handoff_rejects_each_changed_source_without_running_an_owner(self):
        reference = SimpleNamespace(contract_record="inert-contract", statistical_use_record="inert-use")
        context = {
            "binding": reference, "projection": "inert-projection", "spec": "inert-spec",
            "contract_record": reference.contract_record, "statistical_use_record": reference.statistical_use_record,
            "numeric_ablations": SimpleNamespace(
                prospective_binding=SimpleNamespace(reference_binding=reference),
                projection="inert-projection", spec="inert-spec",
            ),
        }
        marker = "numeric ablation Result replay differs"
        self.assertFalse(_evaluate_guard(_require_projection_fixed_model_reference_work, marker, context))
        changes = (
            lambda value: setattr(value["numeric_ablations"].prospective_binding, "reference_binding", "other-reference"),
            lambda value: setattr(value["numeric_ablations"], "projection", "other-projection"),
            lambda value: setattr(value["numeric_ablations"], "spec", "other-spec"),
            lambda value: value.update(contract_record="other-contract"),
            lambda value: value.update(statistical_use_record="other-use"),
        )
        for change in changes:
            altered = copy.deepcopy(context)
            change(altered)
            with self.subTest(change=change):
                self.assertTrue(_evaluate_guard(_require_projection_fixed_model_reference_work, marker, altered))
        function = _tree(_require_projection_fixed_model_reference_work)
        loop, = [node for node in ast.walk(function) if isinstance(node, ast.For)
                 and ast.unparse(node.target) == "(record, digest, record_hash)"]
        entries = loop.iter.elts
        self.assertEqual([ast.unparse(entry.elts[0]) for entry in entries], [
            "numeric_ablations.execution_record", "numeric_ablations.projection_record", "numeric_ablations.spec_record",
            "numeric_ablations.manifest_record", "numeric_ablations.activity_record",
        ])
        self.assertEqual(ast.unparse(loop.body[0].test),
                         "record.sha256 != digest or record.record_hash != record_hash or registry.get_metadata(digest) != record")

    def test_result_join_guard_is_the_actual_raise_expression_with_profile_mutations(self):
        branch = _raising_branch(
            _require_projection_fixed_model_reference_work,
            "fixed-model Result profile differs",
        )
        self.assertIsInstance(branch.test, ast.BoolOp)
        baseline = _result_join_context()
        self.assertFalse(
            _evaluate_guard(
                _require_projection_fixed_model_reference_work,
                "fixed-model Result profile differs",
                baseline,
            )
        )
        mutations = {
            "run identity": lambda value: setattr(value["binding"], "run_id", "other-run"),
            "execution identity": lambda value: setattr(value["binding"], "execution_run_id", "other-execution"),
            "spec identity": lambda value: setattr(value["binding"], "frozen_run_spec_sha256", "other-spec"),
            "contract artifact": lambda value: setattr(value["binding"], "contract_record", SimpleNamespace(sha256="other-contract", record_hash="contract-record")),
            "contract record": lambda value: setattr(value["binding"], "contract_record", SimpleNamespace(sha256="contract-sha", record_hash="other-contract-record")),
            "dataset artifact": lambda value: setattr(value["binding"].dataset_record, "sha256", "other-dataset"),
            "dataset record": lambda value: setattr(value["binding"].dataset_record, "record_hash", "other-dataset-record"),
            "raw artifact": lambda value: setattr(value["binding"].raw_data_record, "sha256", "other-raw"),
            "raw record": lambda value: setattr(value["binding"].raw_data_record, "record_hash", "other-raw-record"),
            "split artifact": lambda value: setattr(value["binding"].confirmatory_split_record, "sha256", "other-split"),
            "split record": lambda value: setattr(value["binding"].confirmatory_split_record, "record_hash", "other-split-record"),
            "split unit grid": lambda value: setattr(value["binding"].confirmatory_split_authority, "member_unit_ids", ("other-unit",)),
            "input model record": lambda value: setattr(value["binding"].input_records[2], "record_hash", "other-model-record"),
            "input evaluator record": lambda value: setattr(value["binding"].input_records[3], "record_hash", "other-evaluator-record"),
            "statistical-use record": lambda value: setattr(value["binding"], "statistical_use_record", SimpleNamespace(sha256="other-statistical-use", record_hash="other-record")),
            "evidence statistical-use artifact": lambda value: value.__setitem__("evidence", replace(value["evidence"], statistical_use_authority_artifact_sha256="a" * 64)),
            "evidence statistical-use record": lambda value: value.__setitem__("evidence", replace(value["evidence"], statistical_use_authority_record_hash="b" * 64)),
            "policy": lambda value: setattr(value["binding"], "policy", SimpleNamespace()),
            "reference work": lambda value: setattr(value["binding"], "reference_work", replace(value["evidence"].reference_work, class_count=5)),
            "timeout": lambda value: setattr(value["binding"], "timeout_seconds", value["binding"].timeout_seconds + 1.0),
            "wall cap": lambda value: setattr(value["binding"], "contract_wall_cap_seconds", value["binding"].contract_wall_cap_seconds + 1.0),
            "seed grid": lambda value: setattr(value["projection"], "seed_order", (1, 2)),
            "unit grid": lambda value: setattr(value["binding"].confirmatory_split_authority, "member_unit_hashes", ("other-hash",) + tuple(value["binding"].confirmatory_split_authority.member_unit_hashes[1:])),
            "closure": lambda value: setattr(value["binding"], "source_records", (SimpleNamespace(sha256="outside-domain"),)),
            "omitted domain source": lambda value: setattr(value["domain"], "source_artifact_hashes", value["domain"].source_artifact_hashes - {value["contract_record"].sha256}),
            "narrow activity": lambda value: value.__setitem__("evidence", replace(value["evidence"], no_recorded_selection_or_protected_label_access=False)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(baseline)
                mutate(changed)
                self.assertTrue(
                    _evaluate_guard(
                        _require_projection_fixed_model_reference_work,
                        "fixed-model Result profile differs",
                        changed,
                    )
                )

    def test_clean_rerun_plan_replays_both_prospective_fixed_model_bindings(self):
        source = _normalized(_resolve_clean_rerun_plan_sources)
        required = (
            "reference_bindings = tuple(",
            "resolve_scientific_reference_work_binding(",
            "for spec in (original_spec, rerun_spec)",
            "if any(binding is not None for binding in reference_bindings):",
            "if any(binding is None for binding in reference_bindings):",
            "original_reference.execution_run_id != original_execution_run_id",
            "rerun_reference.execution_run_id != rerun_spec.run_id",
            "any(binding.statistical_use_record != statistical_use_record for binding in reference_bindings)",
            "original_reference.policy != rerun_reference.policy",
            "original_reference.reference_work != rerun_reference.reference_work",
            "original_reference.timeout_seconds != rerun_reference.timeout_seconds",
            "original_reference.contract_wall_cap_seconds != rerun_reference.contract_wall_cap_seconds",
            "original_reference.source_records != rerun_reference.source_records",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), source)
        self.assertIn(
            "clean rerun cannot mix legacy and fixed-model reference-work profiles",
            source,
        )

    def test_clean_rerun_authority_compares_common_fixed_profile_facts_only(self):
        source = _normalized(_resolve_clean_rerun_authority_sources)
        required = (
            "fixed_profiles = tuple(item.domain.evidence for item in evidence)",
            "if any(type(profile) is GenericMLFixedModelValidityEvidence for profile in fixed_profiles):",
            "any(type(profile) is not GenericMLFixedModelValidityEvidence for profile in fixed_profiles)",
            "any(item.domain.outcome.adapter_version != GenericMLFixedModelAdapter.version for item in evidence)",
            "reference_work_policy",
            "reference_work",
            "statistical_use_authority_artifact_sha256",
            "statistical_use_authority_record_hash",
            "requested_timeout_seconds",
            "contract_wall_cap_seconds",
            "clean rerun changes the full-owned fixed-model domain facts",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(" ".join(fragment.split()), source)
        profile_branch = source[
            source.index("fixed_profiles = tuple(") : source.index(
                "comparison = derive_bounded_mean_clean_rerun_comparison"
            )
        ]
        for forbidden in (
            "original_result_promotion_artifact_sha256",
            "rerun_domain_validity_receipt_artifact_sha256",
            "frozen_run_spec_artifact_sha256",
            "projection_artifact_sha256",
        ):
            self.assertNotIn(forbidden, profile_branch)

    def test_clean_rerun_common_profile_guard_rejects_each_fact_but_ignores_run_identity(self):
        branch = _raising_branch(
            _resolve_clean_rerun_authority_sources,
            "clean rerun changes the full-owned fixed-model domain facts",
        )
        self.assertIsInstance(branch.test, ast.Call)
        expression = compile(ast.Expression(branch.test), "<inert-clean-profile-guard>", "eval")
        left = fixed_model_fixture._inert_evidence()
        right = replace(
            left,
            legacy_evidence=replace(
                left.legacy_evidence,
                benchmark_version="rerun-only-legacy-fact",
            ),
        )
        globals_value = {"__builtins__": {}, "any": any, "getattr": getattr}
        per_run_identity = {
            "original_result_promotion_artifact_sha256": "original-receipt",
            "rerun_domain_validity_receipt_artifact_sha256": "rerun-receipt",
            "frozen_run_spec_artifact_sha256": "original-spec",
            "projection_artifact_sha256": "rerun-projection",
        }
        self.assertNotEqual(
            per_run_identity["original_result_promotion_artifact_sha256"],
            per_run_identity["rerun_domain_validity_receipt_artifact_sha256"],
        )
        self.assertFalse(
            eval(
                expression,
                {**globals_value, **per_run_identity, "fixed_profiles": (left, right)},
                {},
            )
        )
        mutations = {
            "policy": _fixed_profile_view(
                right,
                reference_work_policy=SimpleNamespace(profile_id="other"),
            ),
            "work": _fixed_profile_view(
                right,
                reference_work=SimpleNamespace(class_count=5, feature_count=5),
            ),
            "statistical-use artifact": replace(right, statistical_use_authority_artifact_sha256="a" * 64),
            "statistical-use record": replace(right, statistical_use_authority_record_hash="b" * 64),
            "timeout": replace(right, requested_timeout_seconds=right.requested_timeout_seconds + 1.0),
            "wall cap": replace(right, contract_wall_cap_seconds=right.contract_wall_cap_seconds + 1.0),
        }
        for name, changed_right in mutations.items():
            with self.subTest(name=name):
                self.assertTrue(
                    eval(
                        expression,
                        {**globals_value, **per_run_identity, "fixed_profiles": (left, changed_right)},
                        {},
                    )
                )

    def test_actual_owner_refuses_missing_plan_sources_without_registry_or_ledger_admission(self):
        with TemporaryDirectory(prefix="fixed-model-owner-refusal-") as directory:
            registry = ArtifactRegistry(directory, "runs/fixed-model/registry")
            ledger = EventLedger(directory, "runs/fixed-model/events.jsonl")
            before_records = registry.list_records()
            before_ledger = ledger.validate(raise_on_error=True)
            plan = SimpleNamespace(
                run_id="inert-fixed-model",
                domain=DomainKind.GENERIC_ML,
                object_id="inert-object",
                task_id="inert-task",
                source_format_id=SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
                source_format_version=GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
                evaluation_contract_artifact_sha256="1" * 64,
                dataset_authority_artifact_sha256="2" * 64,
                split_authority_artifact_sha256s=(
                    "3" * 64,
                    "4" * 64,
                    "5" * 64,
                    "6" * 64,
                ),
                frozen_run_spec_artifact_sha256="7" * 64,
            )
            with self.assertRaises(GenericMLProjectionError):
                derive_generic_ml_projection_facts(
                    registry,
                    ledger,
                    SimpleNamespace(plan=plan),
                )
            self.assertEqual(registry.list_records(), before_records)
            self.assertEqual(ledger.validate(raise_on_error=True), before_ledger)

    def test_actual_result_profile_refuses_new_domain_without_prospective_policy(self):
        with TemporaryDirectory(prefix="fixed-model-no-policy-") as directory:
            values = _prepared_canonical_timeline(directory)
            registry, ledger = values["registry"], values["ledger"]
            before = registry.verify_all(raise_on_error=True), ledger.assert_valid()
            inert_domain = SimpleNamespace(
                evidence=fixed_model_fixture._inert_evidence(),
                outcome=SimpleNamespace(adapter_version="3.0"),
            )
            with self.assertRaisesRegex(ScientificPromotionError, "no prospective reference-work policy"):
                _require_projection_fixed_model_reference_work(
                    registry, ledger=ledger, spec=values["spec"], contract_record=values["contract_record"],
                    projection=None, domain=inert_domain, statistical_use_record=None,
                )
            self.assertEqual((registry.verify_all(raise_on_error=True), ledger.assert_valid()), before)

    def test_actual_result_profile_reaches_missing_statistical_owner_without_writes(self):
        with TemporaryDirectory(prefix="fixed-model-missing-use-") as directory:
            values = _prepared_canonical_timeline(directory)
            registry, ledger = values["registry"], values["ledger"]
            spec = _reference_spec(
                values["spec"], GenericMLReferenceWorkPolicy().to_dict(),
                statistical_use=True, scientific=True,
            )
            spec = replace(
                spec, phase=ExperimentPhase.CONFIRMATORY,
                timeout_seconds=values["contract"].compute_budget.max_wall_seconds,
                metadata={**dict(spec.to_dict()["metadata"]),
                          "evaluation_split": values["contract"].dataset.confirmatory_split_id},
            )
            before = registry.verify_all(raise_on_error=True), ledger.assert_valid()
            try:
                _require_projection_fixed_model_reference_work(
                    registry, ledger=ledger, spec=spec, contract_record=values["contract_record"],
                    projection=None, domain=None, statistical_use_record=None,
                )
            except (ArtifactError, ValidationError) as error:
                names = []
                trace = error.__traceback__
                while trace is not None:
                    names.append(trace.tb_frame.f_code.co_name)
                    trace = trace.tb_next
                self.assertIn("resolve_scientific_reference_work_binding", names)
                self.assertIn("resolve_scientific_statistical_use_binding", names)
                self.assertIn("require_dataset_statistical_use_authority", names)
            else:
                self.fail("missing statistical authority reached Result profile admission")
            self.assertEqual((registry.verify_all(raise_on_error=True), ledger.assert_valid()), before)


if __name__ == "__main__":
    unittest.main()
