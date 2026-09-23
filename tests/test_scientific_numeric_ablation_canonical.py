"""Inert descriptive shapes and real refusals, never scientific issuance."""

import ast
import copy
from dataclasses import replace
import hashlib
import inspect
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.generic_ml_ablation import GenericMLAblationUnitCounts, GenericMLFeatureIntervention
from scientist_one.research_state import Ablation, CanonicalResearchObject, ObjectReference, RecordStatus, ResearchStateRepository
from scientist_one.roles import Role
from scientist_one.scientific_numeric_ablation_authority import (
    _same_slot_selector,
    _require_primary_grid_join,
    _time,
    build_scientific_numeric_ablation_authority,
    register_scientific_numeric_ablation_authority,
    require_scientific_numeric_ablation_authority,
)
from scientist_one.scientific_numeric_ablation_canonical import (
    NUMERIC_ABLATION_CANONICAL_SCHEMA,
    _project_canonical,
    is_numeric_ablation_metadata,
    materialize_scientific_numeric_ablation,
    require_numeric_ablation_canonical,
    require_numeric_ablation_metadata_shape,
)
from scientist_one.scientific_numeric_ablation_execution import ScientificNumericAblationExecutionBinding
from scientist_one.security import safe_json_loads
from tests.test_scientific_method_alignment import _prepared_canonical_timeline
from tests.test_scientific_canonical_state import _experiment, _result
from tests.test_scientific_numeric_ablation_authority_value import _authority
from tests.test_bounded_mean_canonical_projection import _projection


def _metadata():
    return {
        "schema_version": NUMERIC_ABLATION_CANONICAL_SCHEMA,
        "authority_id": "numeric-ablation-authority:" + "a" * 64,
        "intervention": GenericMLFeatureIntervention(
            ablation_id="obligation-one", hypothesis_id="hypothesis-one", component_id="declared-component",
            candidate_condition_id="candidate", baseline_condition_id="baseline",
            intervention_condition_id="intervened", feature_indices=(0,),
        ).to_dict(),
        "metric_id": "accuracy", "unit_count": 3, "seed_order": [7, 11],
        "changed_coefficient_counts": [1, 0], "activity_sequence": 7,
        "candidate_correct_total": 2, "baseline_correct_total": 3, "ablated_correct_total": 4,
        "scope": "DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY",
        "replay_status": "DESCRIPTIVE_OUTPUT_VERIFIED", "scientific_evidence_eligible": False,
    }


def _canonical(**changes):
    values = dict(
        object_id="inert-canonical-numeric-ablation", producer=Role.STATISTICIAN, status=RecordStatus.COMPLETE,
        created_at="2026-09-06T12:00:00Z", code_version="non-evidentiary-fixture",
        hypothesis_id="hypothesis-one", experiment_ids=("experiment-one",), result_ids=("result-one",),
        removed_component_ids=(), authority_artifact_hashes=("b" * 64,), metadata=_metadata(),
    )
    return Ablation(**{**values, **changes})


class NumericCanonicalShapeTests(unittest.TestCase):
    def test_full_inert_projection_matches_closed_metadata_and_strict_source_time(self):
        result, experiment = _result(), _experiment()
        initial = _authority()
        bindings = list(initial.state_bindings)
        bindings[0] = replace(bindings[0], object_id=result.object_id, content_hash=result.content_hash)
        bindings[3] = replace(bindings[3], object_id=experiment.object_id, content_hash=experiment.content_hash)
        receipt = replace(initial, state_bindings=tuple(bindings))
        raw = receipt.canonical_bytes()
        # Unregistered PENDING record: this exercises only the pure projection.
        record = ArtifactRecord(
            sha256=hashlib.sha256(raw).hexdigest(), path="inert/authority.json", relative_path="inert/authority.json",
            metadata_path="inert/authority.metadata.json", logical_type="scientific_ablation_authority",
            schema_version="2.0", mime_type="application/json", size=len(raw), origin="inert projection fixture",
            creator_role=Role.SCIENTIFIC_REVIEWER, creation_command=("test", "inert"),
            parent_artifacts=receipt.source_artifact_hashes, validation_result="PENDING", frozen=False,
            created_at="2026-09-06T11:00:00Z",
        )
        arguments = dict(result=result, experiment=experiment, code_version=result.code_version,
                         created_at="2026-09-06T12:00:00Z")
        projected = _project_canonical(receipt, record, **arguments)
        self.assertEqual(projected.object_id, receipt.canonical_object_id)
        self.assertEqual(require_numeric_ablation_metadata_shape(projected.metadata), receipt.canonical_metadata())
        self.assertEqual(tuple(parent.relation for parent in projected.parents), ("ablates", "evaluates"))
        self.assertEqual(projected.removed_component_ids, ())
        self.assertEqual(projected.authority_artifact_hashes, (record.sha256,))
        for change in ({"created_at": record.created_at}, {"created_at": result.created_at},
                       {"code_version": "foreign"}, {"result": _result("different-result")},
                       {"experiment": _experiment("different-experiment")}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                _project_canonical(receipt, record, **{**arguments, **change})

    def test_roundtrip_retains_descriptive_empty_removal_and_negative_effect(self):
        value = _canonical()
        self.assertTrue(is_numeric_ablation_metadata(value.metadata))
        self.assertEqual(value.removed_component_ids, ())
        self.assertIs(value.metadata["scientific_evidence_eligible"], False)
        self.assertLess(value.metadata["candidate_correct_total"], value.metadata["ablated_correct_total"])
        self.assertEqual(CanonicalResearchObject.from_dict(safe_json_loads(value.canonical_bytes())), value)

    def test_old_shape_is_nonempty_and_native_profile_cannot_be_draft_or_assert_removal(self):
        for change in (
            {"metadata": {}}, {"metadata": {"schema_version": "unknown"}},
            {"status": RecordStatus.DRAFT}, {"producer": Role.ORCHESTRATOR},
            {"authority_artifact_hashes": ()}, {"authority_artifact_hashes": ("b" * 64, "c" * 64)},
            {"removed_component_ids": ("declared-component",)}, {"removed_component_ids": []},
            {"revision": 2, "supersedes_content_hash": "d" * 64},
        ):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                _canonical(**change)
        old = _canonical(metadata={}, removed_component_ids=("declared-component",))
        self.assertFalse(is_numeric_ablation_metadata(old.metadata))
        self.assertEqual(old.removed_component_ids, ("declared-component",))

    def test_closed_metadata_rejects_false_grants_foreign_grids_and_numeric_coercion(self):
        base = _metadata()
        for key, changed in (
            ("unknown", True), ("scientific_evidence_eligible", True), ("scientific_evidence_eligible", 0),
            ("scope", "MECHANISTIC_REMOVAL"), ("replay_status", "PASS"), ("unit_count", True),
            ("unit_count", 4097), ("seed_order", [7, 7]), ("seed_order", [True]),
            ("changed_coefficient_counts", [0, 0]), ("changed_coefficient_counts", [1]),
            ("activity_sequence", 10000), ("candidate_correct_total", 7), ("ablated_correct_total", -1),
        ):
            with self.subTest(key=key, changed=changed), self.assertRaises(ValidationError):
                _canonical(metadata={**base, key: changed})
        for key in base:
            changed = copy.deepcopy(base)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValidationError):
                require_numeric_ablation_metadata_shape(changed)
        largest = {**base, "unit_count": 4096, "seed_order": list(range(23)) + [2**53 - 1],
                   "changed_coefficient_counts": [65536] * 24, "activity_sequence": 9999,
                   "candidate_correct_total": 4096 * 24, "ablated_correct_total": 0}
        self.assertEqual(require_numeric_ablation_metadata_shape(largest), largest)

    def test_native_claim_branches_refuse_before_old_eligibility_or_experiment_checks(self):
        # Inspect the actual independent consumer guards without replacing
        # scientific owners or constructing a positive claim-evidence graph.
        from scientist_one import research_state

        first = inspect.getsource(research_state._require_scientific_state_evidence_source)
        robust = first[first.index("if evidence_kind is GraphEvidenceKind.ROBUSTNESS:"):]
        self.assertLess(robust.index("is_numeric_ablation_metadata"), robust.index("resolved.scientific_evidence_eligible"))
        self.assertIn("descriptive numeric intervention is not generic robustness evidence", robust)
        second = inspect.getsource(research_state._require_scientific_claim_evidence_coherence)
        ablation = second[second.index("if isinstance(robustness, Ablation):"):]
        self.assertLess(ablation.index("is_numeric_ablation_metadata"), ablation.index("set(robustness.experiment_ids)"))
        self.assertIn("descriptive numeric intervention cannot anchor", ablation)


class NumericAuthorityOwnerBoundaryTests(unittest.TestCase):
    def test_chronology_rejects_naive_date_only_and_non_utc_without_comparison_errors(self):
        self.assertIsNotNone(_time("2026-09-06T12:00:00Z").utcoffset())
        for value in ("2026-09-06Z", "2026-09-06", "2026-09-06T12:00:00", "2026-09-06T12:00:00+01:00", True):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                _time(value)

    def test_complete_primary_integer_join_retains_zero_or_reversed_interventions(self):
        # These are local inert field containers exercising only a pure join.
        # No callable source owner, registry lookup or scientific issuance is
        # replaced. The actual primary numeric plan/arithmetic is constructed.
        primary = _projection(n=20, candidate=2, reference=3, seeds=5)
        ids, seeds = primary.numeric_result.plan.unit_ids, primary.seed_order
        hashes = tuple(f"{index + 100:064x}" for index in range(len(ids)))
        projection = SimpleNamespace(seed_order=seeds, paired_unit_ids=ids, paired_unit_hashes=hashes)
        grids = tuple(SimpleNamespace(seed_order=seeds, unit_ids=ids, unit_hashes=hashes,
                                      unit_counts=tuple(GenericMLAblationUnitCounts(unit, digest, 5, 2, 3, ablated)
                                                        for unit, digest in zip(ids, hashes, strict=True)))
                      for ablated in (0, 2, 5))
        prospective = SimpleNamespace(
            policy=SimpleNamespace(metric_id=primary.metric_id,
                                   interventions=(SimpleNamespace(baseline_condition_id=primary.baseline_id),)),
            reference_binding=SimpleNamespace(contract_record=SimpleNamespace(sha256=primary.contract_artifact_sha256)),
        )
        binding = ScientificNumericAblationExecutionBinding(
            prospective_binding=prospective, execution=None, projection=projection,
            spec=SimpleNamespace(hypothesis_id=primary.hypothesis_id),
            execution_record=SimpleNamespace(sha256=primary.scientific_execution_authority_artifact_sha256),
            projection_record=None, spec_record=SimpleNamespace(sha256=primary.frozen_run_spec_artifact_sha256),
            manifest_record=SimpleNamespace(sha256=primary.output_manifest_artifact_sha256), activity_record=None,
            entries=tuple(SimpleNamespace(grid=grid) for grid in grids), source_records=(),
        )
        _require_primary_grid_join(binding, primary)
        for name in ("execution_record", "spec_record", "manifest_record"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                _require_primary_grid_join(replace(binding, **{name: SimpleNamespace(sha256="f" * 64)}), primary)
        for field, changed in (("unit_ids", ids[::-1]), ("unit_hashes", hashes[::-1]),
                               ("seed_order", seeds[::-1]), ("unit_counts", grids[-1].unit_counts[:-1])):
            bad = SimpleNamespace(**{**vars(grids[-1]), field: changed})
            with self.subTest(field=field), self.assertRaises(ValidationError):
                _require_primary_grid_join(replace(binding, entries=(*binding.entries[:-1], SimpleNamespace(grid=bad))), primary)
        bad_counts = (replace(grids[-1].unit_counts[0], candidate_correct_count=3), *grids[-1].unit_counts[1:])
        bad = SimpleNamespace(**{**vars(grids[-1]), "unit_counts": bad_counts})
        with self.assertRaises(ValidationError):
            _require_primary_grid_join(replace(binding, entries=(*binding.entries[:-1], SimpleNamespace(grid=bad))), primary)
        with self.assertRaises(ValidationError):
            _require_primary_grid_join(replace(binding, entries=()), primary)

    def test_shared_slot_detects_altered_outcome_malformed_peer_and_old_profile(self):
        expected = _authority()
        self.assertTrue(_same_slot_selector(expected.to_dict(), expected))
        other_outcome = replace(expected, ablated_correct_total=6)
        self.assertTrue(_same_slot_selector(other_outcome.to_dict(), expected))
        malformed = expected.to_dict()
        del malformed["candidate_correct_total"]
        self.assertTrue(_same_slot_selector(malformed, expected))
        legacy = expected.to_dict()
        legacy.update(schema_version="scientific-ablation-authority/v1", authority_id="legacy-authority",
                      ablation_id=expected.intervention.ablation_id, intervention="old prose")
        self.assertTrue(_same_slot_selector(legacy, expected))
        for key, value in (("ledger_run_id", "foreign"), ("execution_run_id", "foreign"),
                           ("contract_artifact_sha256", "e" * 64), ("ablation_id", "foreign")):
            with self.subTest(key=key):
                self.assertFalse(_same_slot_selector({**legacy, key: value}, expected))
        another_result = copy.deepcopy(legacy)
        another_result["state_bindings"][0]["artifact_sha256"] = "e" * 64
        self.assertFalse(_same_slot_selector(another_result, expected))
        # A colliding authority ID still occupies the slot even when its other
        # selectors were damaged; it must not be silently treated as unrelated.
        self.assertTrue(_same_slot_selector({"authority_id": expected.authority_id}, expected))

    def test_missing_current_result_refuses_all_public_admission_paths_without_delta(self):
        with TemporaryDirectory(prefix="numeric-authority-refusal-") as directory:
            values = _prepared_canonical_timeline(directory)
            registry, ledger = values["registry"], values["ledger"]
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            arguments = dict(expected_ledger_run_id="global-run-1", expected_execution_run_id="confirmatory-run-1",
                             expected_ablation_id="obligation-one", result_state_artifact_sha256="e" * 64,
                             run_state_artifact_sha256="d" * 64, method_state_artifact_sha256="c" * 64,
                             experiment_state_artifact_sha256="b" * 64)
            for owner in (build_scientific_numeric_ablation_authority, register_scientific_numeric_ablation_authority):
                with self.subTest(owner=owner.__name__), self.assertRaises(ValidationError):
                    owner(registry, ledger, **arguments)
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)
            with self.assertRaises((ArtifactError, ValidationError)):
                require_scientific_numeric_ablation_authority(
                    registry, ledger, expected_ledger_run_id=arguments["expected_ledger_run_id"],
                    expected_execution_run_id=arguments["expected_execution_run_id"],
                    expected_ablation_id=arguments["expected_ablation_id"], authority_artifact_sha256="f" * 64,
                )
            repository = ResearchStateRepository(registry, ledger, run_id="global-run-1", code_version="test",
                                                 configuration_hash=values["spec"].configuration_sha256)
            with self.assertRaises((ArtifactError, ValidationError)):
                materialize_scientific_numeric_ablation(repository, authority_artifact_sha256="f" * 64,
                                                        created_at="2026-09-06T12:00:00Z")
            self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)

    def test_native_shape_without_bound_parents_does_not_return_authority(self):
        with self.assertRaises(ValidationError):
            require_numeric_ablation_canonical(SimpleNamespace(), _canonical(), (), {})

    def test_wrong_parent_type_fails_closed_before_dereferencing_result_fields(self):
        value = _canonical(parents=(ObjectReference("Experiment", "experiment-one", "c" * 64, "ablates", True),
                                    ObjectReference("Result", "result-one", "d" * 64, "evaluates", True)))
        records = (SimpleNamespace(logical_type="scientific_ablation_authority", schema_version="2.0"),)
        by_content = {"c" * 64: SimpleNamespace(research_object=_experiment()),
                      "d" * 64: SimpleNamespace(research_object=_experiment("not-a-result"))}
        with self.assertRaisesRegex(ValidationError, "exact Result/Experiment"):
            require_numeric_ablation_canonical(SimpleNamespace(), value, records, by_content)

    def test_closed_outer_shape_is_checked_before_thawing_nested_values(self):
        class Untraversable(dict):
            def items(self):
                raise AssertionError("out-of-profile nested value was traversed")
        value = {**_metadata(), "unexpected": Untraversable()}
        with self.assertRaisesRegex(ValidationError, "not closed"):
            require_numeric_ablation_metadata_shape(value)

    def test_sources_are_replayed_before_selection_and_publication_retains_locked_cas(self):
        source = inspect.getsource(build_scientific_numeric_ablation_authority)
        required = ("resolve_current_research_state_bindings(", "require_scientific_result_promotion_authority_v3(",
                    "require_scientific_result_canonical_projection_v3(", "require_scientific_numeric_ablation_execution(",
                    "_require_primary_grid_join(", "entries = tuple(", "_scientific_ablation_custody_bindings(")
        positions = [source.index(name) for name in required]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("ScientificResultOutcome.POSITIVE", source)
        self.assertNotIn("build_checked_superiority", source)
        self.assertIn("for item in numeric.source_records", source)
        register = inspect.getsource(register_scientific_numeric_ablation_authority)
        self.assertLess(register.index("_preflight_publication("), register.index("_put_bytes_locked("))
        self.assertLess(register.index("(locked_registry, locked_ledger) != before"), register.index("_put_bytes_locked("))
        self.assertIn("record != planned", register)
        self.assertIn("after_ledger != before[1]", register)
        self.assertIn("require_scientific_numeric_ablation_authority(", register)
        self.assertNotIn("append_event", register)
        admission = inspect.getsource(ResearchStateRepository._resolve_object_authority)
        native = admission[admission.index("if isinstance(record, Ablation):"):]
        self.assertLess(native.index("require_numeric_ablation_canonical(self"), native.index("experiment_parents ="))
        self.assertIn("_ResolvedObjectAuthority(records, scientific_evidence_eligible=False)", native)

    def test_no_public_builder_parameter_accepts_an_authority_dto_or_boolean_grant(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(build_scientific_numeric_ablation_authority)))
        function = tree.body[0]
        names = [arg.arg for arg in (*function.args.args, *function.args.kwonlyargs)]
        self.assertEqual(names[:2], ["registry", "ledger"])
        self.assertEqual(set(names[2:]), {"expected_ledger_run_id", "expected_execution_run_id", "expected_ablation_id",
                                       "result_state_artifact_sha256", "run_state_artifact_sha256",
                                       "method_state_artifact_sha256", "experiment_state_artifact_sha256"})
        self.assertIsNone(function.args.kwarg)


if __name__ == "__main__":
    unittest.main()
