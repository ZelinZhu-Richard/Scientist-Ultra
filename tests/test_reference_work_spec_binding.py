"""Mechanical reference-work policy/grid and real owner-refusal controls.

No test replaces a scientific owner with a positive verdict, issues source
authority, provisions a trust root, or claims a real scientific execution.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import inspect
from tempfile import TemporaryDirectory
import unittest

from scientist_one import experiments, scientific_design
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.experiments import (
    EvidenceClass,
    ExperimentPhase,
    ExperimentError,
    SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY,
    _require_scientific_execution_input_records,
    _require_scientific_reference_work_source_chronology,
    _require_reference_work_statistical_use_before_spec,
    require_scientific_execution_run_spec,
    resolve_scientific_reference_work_binding,
)
from scientist_one.generic_ml_projection import (
    GENERIC_ML_DATASET_ROW_SCHEMA,
    GenericMLProjectionError,
    GenericMLReferenceWorkPolicy,
    derive_frozen_model_reference_work,
    parse_bounded_integer_classification_dataset,
    parse_generic_ml_reference_work_policy,
    require_generic_ml_reference_work_wall_cap,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    record_scientific_design_freeze,
    register_frozen_run_spec,
)
from scientist_one.security import canonical_json_bytes, safe_json_loads
from tests.test_generic_ml_projection import H, H2, _dataset_bytes, _frozen_configuration
from tests.test_scientific_method_alignment import _prepared_canonical_timeline
from tests.test_statistical_use_spec_binding import _declaration as _statistical_declaration


def _spec(spec, declaration, *, statistical_use=False, scientific=False):
    metadata = dict(spec.to_dict()["metadata"])
    metadata[SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY] = declaration
    if statistical_use:
        metadata[experiments.SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY] = _statistical_declaration()
    return replace(
        spec,
        metadata=metadata,
        evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE if scientific else spec.evidence_class,
    )


class ReferenceWorkPureBindingTests(unittest.TestCase):
    def test_closed_policy_roundtrip_is_inert_and_frozen(self):
        policy = GenericMLReferenceWorkPolicy()
        self.assertEqual(parse_generic_ml_reference_work_policy(policy.to_dict()), policy)
        with self.assertRaises(FrozenInstanceError):
            policy.scope = "ACTUAL_RESOURCE_EQUIVALENCE"
        value = policy.to_dict()
        self.assertEqual(value["wall_cap_scope"], "RUN_WIDE_CONTRACT_WALL_SECONDS")
        self.assertNotIn("passed", value)
        self.assertNotIn("compute_budget_equivalent", value)
        self.assertNotIn("scientific_evidence", value)

    def test_policy_unknown_extra_missing_null_and_nonnative_values_reject(self):
        class Text(str):
            pass

        complete = GenericMLReferenceWorkPolicy().to_dict()
        invalid = [None, {}, True, {**complete, "equal_runtime": True}]
        for key in complete:
            invalid.append({name: value for name, value in complete.items() if name != key})
            invalid.extend({**complete, key: value} for value in (None, True, "unreviewed/v2", Text(complete[key])))
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(GenericMLProjectionError):
                    parse_generic_ml_reference_work_policy(value)

    def test_run_wall_cap_is_exact_and_never_a_per_condition_measurement(self):
        self.assertEqual(require_generic_ml_reference_work_wall_cap(3, 4.0), (3.0, 4.0))
        self.assertEqual(require_generic_ml_reference_work_wall_cap(4, 4), (4.0, 4.0))
        for timeout, cap in ((5, 4), (2**53 + 1, 2**53)):
            with self.subTest(timeout=timeout, cap=cap):
                with self.assertRaisesRegex(GenericMLProjectionError, "exceeds"):
                    require_generic_ml_reference_work_wall_cap(timeout, cap)

    def test_wall_limits_reject_nonnative_nonfinite_and_nonpositive_values(self):
        class Number(float):
            def __gt__(self, other):
                raise AssertionError("comparison hook must not execute")

        for value in (None, "3", True, False, 0, -1, float("nan"), float("inf"), 10**400, Number(3)):
            for args in ((value, 5), (3, value)):
                with self.subTest(args=args):
                    with self.assertRaises(GenericMLProjectionError):
                        require_generic_ml_reference_work_wall_cap(*args)

    def _grid(self):
        dataset = safe_json_loads(_dataset_bytes())
        dataset["data"].append({
            "schema_version": GENERIC_ML_DATASET_ROW_SCHEMA,
            "unit_id": "unit-c", "features": [0, 1], "label": 2,
        })
        raw = canonical_json_bytes(dataset)
        rows = parse_bounded_integer_classification_dataset(raw)
        configuration = _frozen_configuration(seeds=(7, 11))
        configuration["metric_scope"] = "END_TO_END"
        for seed in configuration["seed_model_definitions"]:
            for role in ("candidate_model", "baseline_model"):
                seed[role]["class_labels"].append(2)
                seed[role]["weights"].append([0, 1])
                seed[role]["bias"].append(0)
        arguments = dict(
            member_unit_ids=(rows[0].unit_id,),
            member_unit_hashes=(rows[0].unit_hash,),
            seed_order=(7, 11),
            contract_artifact_sha256=H,
            contract_sha256=H2,
            dataset_id="bounded-classification",
            dataset_split_id="confirmatory",
            evaluator_id="reference-evaluator",
            metric_id="accuracy",
            metric_unit="FRACTION",
            metric_scope="END_TO_END",
            candidate_condition_id="candidate-condition",
            baseline_condition_id="baseline-condition",
        )
        return raw, configuration, arguments

    def test_grid_counts_confirmatory_members_but_all_dataset_classes(self):
        raw, configuration, arguments = self._grid()
        work = derive_frozen_model_reference_work(raw, canonical_json_bytes(configuration), **arguments)
        self.assertEqual((work.unit_count, work.seed_count, work.class_count, work.feature_count), (1, 2, 3, 2))
        self.assertEqual(work.to_dict()["candidate_primary_metric"], {
            "predictions": 2, "integer_multiplications": 12,
            "dot_reduction_additions": 6, "bias_additions": 6,
            "argmax_score_comparisons": 4,
        })
        self.assertEqual(work.to_dict()["candidate_robustness_overhead"]["predictions"], 4)

    def test_grid_rejects_omitted_reordered_or_substituted_sources(self):
        raw, configuration, arguments = self._grid()
        for changes in (
            {"member_unit_hashes": ("f" * 64,)},
            {"member_unit_ids": ("absent-unit",)},
            {"member_unit_ids": ("unit-a", "unit-a"), "member_unit_hashes": arguments["member_unit_hashes"] * 2},
            {"seed_order": (11, 7)},
            {"seed_order": (7, 7)},
            {"seed_order": (7.0, 11)},
            {"dataset_id": "another-dataset"},
            {"contract_sha256": "f" * 64},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(GenericMLProjectionError):
                    derive_frozen_model_reference_work(raw, canonical_json_bytes(configuration), **{**arguments, **changes})
        malformed = []
        omitted = deepcopy(configuration)
        omitted["seed_model_definitions"].pop()
        malformed.append(omitted)
        nonnative = deepcopy(configuration)
        nonnative["seed_model_definitions"][0]["seed"] = 7.0
        malformed.append(nonnative)
        wrong_model = deepcopy(configuration)
        wrong_model["seed_model_definitions"][1]["baseline_model"]["weights"][0].append(0)
        malformed.append(wrong_model)
        for value in malformed:
            with self.subTest(value=value):
                with self.assertRaises(GenericMLProjectionError):
                    derive_frozen_model_reference_work(raw, canonical_json_bytes(value), **arguments)


class ReferenceWorkSpecBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.values = _prepared_canonical_timeline(temporary.name)
        self.registry = self.values["registry"]
        self.ledger = self.values["ledger"]
        self.spec = self.values["spec"]

    def _snapshot(self):
        return self.registry.verify_all(raise_on_error=True), self.ledger.validate(raise_on_error=True)

    def _resolve(self, spec):
        return resolve_scientific_reference_work_binding(
            self.registry, spec=spec,
            expected_contract_artifact_sha256=self.values["contract_record"].sha256,
        )

    def _register(self, spec):
        return register_frozen_run_spec(
            self.registry,
            contract=self.values["contract"],
            contract_artifact_sha256=self.values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(record.sha256 for record in self.values["plan_records"]),
            spec=spec,
        )

    def test_absent_declaration_preserves_legacy_bytes_parents_and_registry(self):
        before = self._snapshot()
        raw = self.registry.get_bytes(self.values["spec_record"].sha256)
        self.assertIsNone(self._resolve(self.spec))
        self.assertEqual(self._register(self.spec), self.values["spec_record"])
        self.assertEqual(self.registry.get_bytes(self.values["spec_record"].sha256), raw)
        self.assertEqual(self.values["spec_record"].parent_artifacts[-4:], (
            self.spec.code_sha256, self.spec.data_sha256,
            self.spec.configuration_sha256, self.spec.evaluator_sha256,
        ))
        self.assertEqual(self._snapshot(), before)

    def test_present_null_and_unknown_declarations_fail_before_registration(self):
        for declaration in (None, {}, {**GenericMLReferenceWorkPolicy().to_dict(), "profile_id": "unreviewed"}):
            spec = _spec(self.spec, declaration)
            before = self._snapshot()
            with self.subTest(declaration=declaration):
                with self.assertRaises(GenericMLProjectionError):
                    self._register(spec)
                self.assertEqual(self._snapshot(), before)

    def test_complete_declaration_cannot_replace_missing_statistical_use(self):
        spec = _spec(self.spec, GenericMLReferenceWorkPolicy().to_dict())
        before = self._snapshot()
        with self.assertRaisesRegex(ExperimentError, "requires its prospective statistical-use"):
            self._resolve(spec)
        with self.assertRaisesRegex(ExperimentError, "requires its prospective statistical-use"):
            self._register(spec)
        self.assertEqual(self._snapshot(), before)

    def test_declared_missing_authority_never_becomes_positive_source_evidence(self):
        spec = _spec(self.spec, GenericMLReferenceWorkPolicy().to_dict(), statistical_use=True, scientific=True)
        spec = replace(
            spec, phase=ExperimentPhase.CONFIRMATORY,
            timeout_seconds=self.values["contract"].compute_budget.max_wall_seconds,
            metadata={
                **dict(spec.to_dict()["metadata"]),
                "evaluation_split": self.values["contract"].dataset.confirmatory_split_id,
            },
        )
        before = self._snapshot()
        with self.assertRaises((ArtifactError, ValidationError)) as refused:
            self._resolve(spec)
        self.assertNotIn("native confirmatory", str(refused.exception))
        self.assertNotIn("wall cap", str(refused.exception))
        # The negative boundary must actually reach the complete statistical
        # source owner, not pass on an unrelated earlier validation error.
        # unittest clears exception tracebacks, so retain this second real
        # read-only refusal's call chain before leaving the except block.
        try:
            self._resolve(spec)
        except (ArtifactError, ValidationError) as error:
            call_names = []
            trace = error.__traceback__
            while trace is not None:
                call_names.append(trace.tb_frame.f_code.co_name)
                trace = trace.tb_next
            self.assertIn("resolve_scientific_statistical_use_binding", call_names)
            self.assertIn("require_dataset_statistical_use_authority", call_names)
        else:
            self.fail("missing statistical source was accepted")
        with self.assertRaises((ArtifactError, ValidationError)):
            self._register(spec)
        self.assertEqual(self._snapshot(), before)

    def test_fixture_cannot_enter_declared_scientific_profile(self):
        spec = _spec(self.spec, GenericMLReferenceWorkPolicy().to_dict(), statistical_use=True)
        before = self._snapshot()
        with self.assertRaisesRegex(ExperimentError, "native confirmatory"):
            self._resolve(spec)
        self.assertEqual(self._snapshot(), before)

    def test_inert_descriptor_cannot_bypass_public_readback_or_design_gate(self):
        spec = _spec(self.spec, None, scientific=True)
        record = self.registry.put_json(
            spec.to_dict(),
            logical_type="frozen_run_spec",
            origin="run spec frozen after scientific-plan admission and before execution",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("scientist-one", "freeze-run-spec"),
            parent_artifacts=self.values["spec_record"].parent_artifacts,
            schema_version="1.0", mime_type="application/json",
            validation_result="PASS", frozen=True,
        )
        before = self._snapshot()
        with self.assertRaises(GenericMLProjectionError):
            require_scientific_execution_run_spec(self.registry, frozen_run_spec_artifact_sha256=record.sha256)
        adaptive_plan = experiments.plan_adaptive_execution(
            spec.compute_profile, spec.resource_estimate,
            observed_available_memory_bytes=spec.compute_profile.memory_limit_bytes,
            pending_tasks=len(spec.seeds), bytes_per_sample=spec.bytes_per_sample,
            worker_overhead_bytes=spec.worker_overhead_bytes,
        )
        with self.assertRaises(GenericMLProjectionError):
            experiments.register_scientific_execution_preparation(
                self.registry, self.ledger, ledger_run_id="timeline",
                frozen_run_spec_artifact_sha256=record.sha256,
                adaptive_execution_plan=adaptive_plan,
                backend_profile=experiments.ScientificBackendAttestationProfile(
                    backend_id="non-evidentiary-reference-work-fixture",
                    attestation_schema="non-evidentiary-reference-work-fixture/v1",
                    verifier_id="non-evidentiary-verifier",
                    trust_root_id="non-evidentiary-root-selector",
                ),
            )
        with self.assertRaises(GenericMLProjectionError):
            record_scientific_design_freeze(
                self.registry, self.ledger, run_id="timeline",
                contract=self.values["contract"],
                contract_artifact_sha256=self.values["contract_record"].sha256,
                experiment_plan_artifact_sha256s=tuple(item.sha256 for item in self.values["plan_records"]),
                frozen_run_spec_artifact_sha256=record.sha256,
            )
        self.assertEqual(self._snapshot(), before)

    def test_factored_input_reader_retains_all_four_real_fixture_records(self):
        records = _require_scientific_execution_input_records(self.registry, self.spec)
        self.assertEqual(tuple(record.sha256 for record in records), self.values["spec_record"].parent_artifacts[-4:])
        self.assertEqual(tuple(record.logical_type for record in records), (
            "experiment_code", "experiment_dataset", "experiment_configuration", "evaluator_implementation",
        ))
        with self.assertRaises(ExperimentError):
            _require_scientific_execution_input_records(self.registry, replace(self.spec, code_sha256=self.spec.evaluator_sha256))

    def test_source_creation_and_actual_design_timestamp_are_not_retroactive(self):
        # Inert ArtifactRecords exercise only the pure temporal relation.
        record = self.values["configuration"]
        early = replace(record, created_at="2000-01-01T00:00:00.000Z", record_hash=None)
        late = replace(record, created_at="2100-01-01T00:00:00.000Z", record_hash=None)
        _require_scientific_reference_work_source_chronology((early,), timestamp=early.created_at)
        _require_reference_work_statistical_use_before_spec(early, timestamp=late.created_at)
        for timestamp in (early.created_at, late.created_at):
            with self.assertRaisesRegex(ExperimentError, "strictly precede"):
                _require_reference_work_statistical_use_before_spec(late, timestamp=timestamp)
        for records in ((early, late), (late, early)):
            with self.assertRaisesRegex(ExperimentError, "creation follows"):
                _require_scientific_reference_work_source_chronology(records, timestamp=early.created_at)
        declared = _spec(self.spec, GenericMLReferenceWorkPolicy().to_dict())
        with self.assertRaisesRegex(ExperimentError, "creation follows"):
            scientific_design._require_reference_work_spec_before_design_timestamp(declared, late, timestamp=early.created_at)
        # The old profile does not acquire new timestamp semantics.
        scientific_design._require_reference_work_spec_before_design_timestamp(self.spec, late, timestamp=early.created_at)

    def test_actual_call_topology_keeps_full_replay_upstream_and_four_inputs(self):
        def calls(function):
            return [node for node in ast.walk(ast.parse(inspect.getsource(function))) if isinstance(node, ast.Call)]

        for function in (
            scientific_design.register_frozen_run_spec,
            scientific_design._require_temporal_run_spec,
            experiments._require_scientific_execution_spec_and_inputs,
        ):
            self.assertEqual(sum(isinstance(node.func, ast.Name) and node.func.id == "resolve_scientific_reference_work_binding" for node in calls(function)), 1)
        names = {node.func.id for node in calls(resolve_scientific_reference_work_binding) if isinstance(node.func, ast.Name)}
        self.assertTrue({
            "require_frozen_evaluation_contract", "resolve_scientific_statistical_use_binding",
            "require_scientific_dataset_authority", "require_scientific_dataset_split_authority",
            "require_scientific_dataset_acquisition_plan",
            "_require_scientific_execution_input_records", "derive_frozen_model_reference_work",
            "_require_scientific_execution_snapshot_unchanged",
        }.issubset(names))
        self.assertFalse(names.intersection({
            "require_scientific_execution_authority", "require_scientific_execution_preparation",
            "require_scientific_execution_admissibility_authority", "require_scientific_domain_validity",
            "require_generic_ml_paired_metric_projection_authority", "require_scientific_execution_run_spec",
        }))
        self.assertEqual(tuple(inspect.signature(resolve_scientific_reference_work_binding).parameters), (
            "registry", "spec", "expected_contract_artifact_sha256",
        ))

    def test_chronology_preflight_reuses_actual_timestamp_before_each_write(self):
        # Structural integration controls only; these do not construct a
        # positive reference-work source companion or authorize a new spec.
        registration = ast.parse(inspect.getsource(scientific_design.register_frozen_run_spec))
        expressions = {ast.unparse(node) for node in ast.walk(registration) if isinstance(node, ast.Assign)}
        self.assertIn(
            "reference_created_at = existing_spec.created_at if existing_spec is not None else utc_now()",
            expressions,
        )
        self.assertIn("existing_spec = snapshot_records.get(spec_digest)", expressions)
        calls = [node for node in ast.walk(registration) if isinstance(node, ast.Call)]
        chronology = next(node for node in calls if isinstance(node.func, ast.Name) and node.func.id == "_require_scientific_reference_work_source_chronology")
        commit = next(node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "_put_bytes_locked")
        self.assertLess(chronology.lineno, commit.lineno)
        strict_chronology = next(
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_require_reference_work_statistical_use_before_spec"
        )
        self.assertLess(strict_chronology.lineno, commit.lineno)
        self.assertEqual(ast.unparse(strict_chronology.args[0]), "reference_binding.statistical_use_record")
        self.assertEqual(next(ast.unparse(item.value) for item in strict_chronology.keywords if item.arg == "timestamp"), "reference_created_at")
        self.assertEqual(next(ast.unparse(item.value) for item in commit.keywords if item.arg == "created_at"), "reference_created_at")
        for function, expected in (
            (scientific_design._require_temporal_run_spec, "record.created_at"),
            (experiments._require_scientific_execution_spec_and_inputs, "spec_record.created_at"),
        ):
            tree = ast.parse(inspect.getsource(function))
            call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_require_scientific_reference_work_source_chronology")
            self.assertEqual(next(ast.unparse(item.value) for item in call.keywords if item.arg == "timestamp"), expected)
        freeze = inspect.getsource(scientific_design.record_scientific_design_freeze)
        self.assertIn('event_arguments["timestamp"] = freeze_timestamp', freeze)
        for function in (
            scientific_design._derive_evaluation_contract_freeze_gate_receipt,
            scientific_design._resolve_registered_scientific_visibility,
            scientific_design.record_scientific_result_observed,
        ):
            tree = ast.parse(inspect.getsource(function))
            call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_require_reference_work_spec_before_design_timestamp")
            self.assertEqual(next(ast.unparse(item.value) for item in call.keywords if item.arg == "timestamp"), "design_event.timestamp")
            if function is scientific_design.record_scientific_result_observed:
                append = next(
                    node for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and ast.unparse(node.func) == "ledger.record"
                )
                self.assertLess(call.lineno, append.lineno)


if __name__ == "__main__":
    unittest.main()
