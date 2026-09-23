"""Pure/inert cohort controls and real owner refusals; no scientific issuance."""

import ast
from dataclasses import replace
import inspect
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one import research_state as rs
from scientist_one.roles import Role
from scientist_one import scientific_numeric_ablation_cohort as cohort
from scientist_one.scientific_numeric_ablation_authority_value import (
    ScientificNumericAblationAuthority, numeric_ablation_slot_hash,
)
from scientist_one.scientific_numeric_ablation_execution import ScientificNumericAblationExecutionBinding
from tests.test_scientific_audit_cohort import _member, _binding, _digest, _ref
from tests.test_scientific_numeric_ablation_canonical import _canonical
from tests.test_scientific_numeric_ablation_authority_value import _arguments
from tests.test_scientific_method_alignment import _prepared_canonical_timeline


def _state(entries):
    return rs.ResearchStateAuthoritySnapshot(
        run_id="ledger-a", snapshot_artifact_sha256=_digest("snapshot"),
        snapshot_artifact_record_hash=_digest("snapshot-record"),
        ledger_head_hash=_digest("head"), ledger_event_count=20,
        code_version="inert-cohort", configuration_hash=_digest("configuration"),
        entries=tuple(entries),
    )


def _record(index, logical_type):
    """Unregistered PENDING metadata, not a production source record."""
    return ArtifactRecord(
        sha256=f"{index:064x}", origin="inert cohort count probe", logical_type=logical_type,
        creator_role=Role.ORCHESTRATOR, creation_command=("inert",), parent_artifacts=(),
        schema_version="1.0", path=f"objects/{index:064x}", relative_path=f"objects/{index:064x}",
        metadata_path=f"metadata/{index:064x}.json", size=1,
        created_at="2026-09-06T00:00:00Z", mime_type="application/json",
        validation_result="PENDING", frozen=False,
    )


def _observation_case(ablated_total=2):
    """Inert native DTOs for pure joins only; no owner is replaced."""
    arguments = _arguments()
    entries = list(_member("a", "NEGATIVE", 4))
    state_bindings = []
    for stated in arguments["state_bindings"]:
        index = next(index for index, item in enumerate(entries)
                     if item.research_object.object_type == stated.object_type)
        item = entries[index]
        entries[index] = replace(item,
            artifact_sha256=stated.artifact_sha256, artifact_record_hash=stated.artifact_record_hash,
            materialization_event_id=stated.materialization_event_id,
            materialization_event_hash=stated.materialization_event_hash,
            materialization_event_index=stated.materialization_event_index,
        )
        state_bindings.append(replace(stated, object_id=item.research_object.object_id,
                                      content_hash=item.research_object.content_hash))
    state_bindings = tuple(state_bindings)
    arguments.update(
        execution_run_id="run-a", state_bindings=state_bindings,
        metric_id="metric-a", ablated_correct_total=ablated_total,
        authority_id="numeric-ablation-authority:" + numeric_ablation_slot_hash(
            ledger_run_id="ledger-a", execution_run_id="run-a",
            result_artifact_sha256=state_bindings[0].artifact_sha256,
            contract_artifact_sha256=arguments["contract_artifact_sha256"], ablation_id="ablation-a",
        ),
    )
    receipt = ScientificNumericAblationAuthority(**arguments)
    values = {item.research_object.object_type: item for item in entries}
    ablation = _canonical(
        object_id=receipt.canonical_object_id, metadata=receipt.canonical_metadata(),
        hypothesis_id=receipt.intervention.hypothesis_id,
        experiment_ids=("experiment-a",), result_ids=("result-a",),
        parents=(_ref(values["Experiment"].research_object, "ablates"),
                 _ref(values["Result"].research_object, "evaluates")),
    )
    member = cohort._cohort_inventory(_state((*entries, _binding(ablation))))[0]
    unit_values = tuple(SimpleNamespace(
        candidate_correct_count=value[0], baseline_correct_count=value[1],
        ablated_correct_count=min(2, max(0, ablated_total - 2 * index)),
    ) for index, value in enumerate(((2, 1), (1, 1), (1, 1))))
    grid = SimpleNamespace(
        intervention=receipt.intervention, unit_counts=unit_values, seed_order=receipt.seed_order,
        seed_results=tuple(SimpleNamespace(changed_coefficient_count=value)
                           for value in receipt.changed_coefficient_counts),
    )
    numeric = ScientificNumericAblationExecutionBinding(
        prospective_binding=SimpleNamespace(
            policy=SimpleNamespace(interventions=(receipt.intervention,)),
            reference_binding=SimpleNamespace(contract_record=SimpleNamespace(
                sha256=receipt.contract_artifact_sha256, record_hash=receipt.contract_record_hash)),
        ),
        execution=None, projection=None, spec=None,
        execution_record=SimpleNamespace(sha256=receipt.execution_artifact_sha256, record_hash=receipt.execution_record_hash),
        projection_record=SimpleNamespace(sha256=receipt.projection_artifact_sha256, record_hash=receipt.projection_record_hash),
        spec_record=None, manifest_record=None, activity_record=None,
        entries=(SimpleNamespace(grid=grid, activity_sequence=receipt.activity_sequence,
                                 output_record=SimpleNamespace(sha256=receipt.ablation_output_artifact_sha256,
                                                               record_hash=receipt.ablation_output_record_hash)),),
        source_records=(),
    )
    return member, numeric, receipt


class NumericAblationCohortTests(unittest.TestCase):
    def test_complete_inventory_retains_all_primary_outcomes_and_false_eligibility(self):
        outcomes = ("POSITIVE", "NEGATIVE", "NULL", "INCONCLUSIVE", "FALSIFIED")
        entries = tuple(item for index, outcome in enumerate(outcomes)
                        for item in _member(str(index), outcome, 4))
        members = cohort._cohort_inventory(_state(entries))
        self.assertEqual(len(members), 5)
        self.assertEqual({item.result.research_object.metadata["scientific_result_outcome"] for item in members}, set(outcomes))
        self.assertTrue(all(item.result.scientific_evidence_eligible is False for item in members))
        self.assertEqual(members, cohort._cohort_inventory(_state(entries[::-1])))

    def test_omitted_duplicate_and_unrelated_tests_refuse(self):
        entries = _member("a", "NULL", 4)
        test = entries[-1]
        cases = (entries[:-1], (*entries, _binding(replace(test.research_object,
                 object_id="second-test", content_hash=None))),
                 (*entries, *_member("b", "NEGATIVE", 4)[:-1]))
        for value in cases:
            with self.subTest(length=len(value)), self.assertRaises(ValidationError):
                cohort._cohort_inventory(_state(value))

    def test_foreign_parent_revision_relation_and_unevaluated_parent_refuse(self):
        entries = _member("a", "NULL", 4)
        test = entries[-1]
        for ref in (replace(test.research_object.parents[0], relation="describes"),
                    replace(test.research_object.parents[0], evaluated=False),
                    replace(test.research_object.parents[0], content_hash=_digest("foreign"))):
            altered = replace(test.research_object, parents=(ref,), content_hash=None)
            with self.assertRaises(ValidationError):
                cohort._cohort_inventory(_state((*entries[:-1], _binding(altered))))

    def test_mixed_or_historical_result_test_profile_is_not_dropped(self):
        for version in (3, 2):
            with self.assertRaisesRegex(ValidationError, "unsupported"):
                cohort._cohort_inventory(_state((*_member("a", "NULL", 4), *_member("b", "NEGATIVE", version))))

    def test_empty_snapshot_or_empty_result_population_refuses(self):
        for entries in ((), _member("a", "NULL", 4)[:2]):
            with self.assertRaises(ValidationError):
                cohort._cohort_inventory(_state(entries))

    def test_unrelated_run_does_not_replace_result_obligations(self):
        entries = _member("a", "NULL", 4)
        extra = replace(next(item.research_object for item in entries if isinstance(item.research_object, rs.Run)),
                        object_id="additional-resultless-run", content_hash=None)
        members = cohort._cohort_inventory(_state((*entries, _binding(extra))))
        self.assertEqual(len(members), 1)
        self.assertNotEqual(members[0].run.research_object.object_id, extra.object_id)
        # This owner covers Result-backed interventions, not all Run/design
        # obligations. R1-R4 complete execution coverage remains separate.

    def test_legacy_ablation_in_complete_population_refuses(self):
        entries = _member("a", "NULL", 4)
        legacy = rs.Ablation(
            object_id="legacy-ablation", producer=Role.STATISTICIAN,
            hypothesis_id="hypothesis-a", experiment_ids=("experiment-a",),
            removed_component_ids=("component-a",), result_ids=("result-a",),
        )
        with self.assertRaisesRegex(ValidationError, "unsupported Ablation"):
            cohort._cohort_inventory(_state((*entries, _binding(legacy))))

    def test_all_effect_directions_are_retained_in_exact_observation_join(self):
        for ablated_total in (0, 4, 6):
            member, numeric, receipt = _observation_case(ablated_total)
            cohort._require_complete_observations(member, numeric, (receipt,))
            self.assertFalse(member.ablations[0].scientific_evidence_eligible)
            self.assertFalse(receipt.scientific_evidence_eligible)

    def test_missing_duplicate_extra_and_empty_intervention_coverage_refuses(self):
        member, numeric, receipt = _observation_case()
        for receipts in ((), (receipt, receipt)):
            with self.assertRaisesRegex(ValidationError, "required interventions"):
                cohort._require_complete_observations(member, numeric, receipts)
        for entries in ((), (*numeric.entries, *numeric.entries)):
            with self.assertRaises(ValidationError):
                cohort._require_complete_observations(member, replace(numeric, entries=entries), (receipt,))
        empty = replace(numeric, prospective_binding=SimpleNamespace(policy=SimpleNamespace(interventions=())))
        with self.assertRaises(ValidationError):
            cohort._require_complete_observations(member, empty, ())

    def test_same_experiment_different_result_and_substituted_record_refuse(self):
        member, numeric, receipt = _observation_case()
        for result in (replace(member.result, artifact_record_hash=_digest("foreign-record")),
                       replace(member.result, materialization_event_hash=_digest("foreign-event"))):
            with self.assertRaisesRegex(ValidationError, "canonical revision"):
                cohort._require_complete_observations(replace(member, result=result), numeric, (receipt,))
        foreign = SimpleNamespace(sha256=receipt.execution_artifact_sha256, record_hash=_digest("foreign"))
        with self.assertRaises(ValidationError):
            cohort._require_complete_observations(member, replace(numeric, execution_record=foreign), (receipt,))

    def test_changed_counts_and_elevated_eligibility_refuse(self):
        member, numeric, receipt = _observation_case()
        altered = replace(receipt, ablated_correct_total=3)
        with self.assertRaises(ValidationError):
            cohort._require_complete_observations(member, numeric, (altered,))
        elevated = replace(member.ablations[0], scientific_evidence_eligible=True)
        with self.assertRaises(ValidationError):
            cohort._require_complete_observations(replace(member, ablations=(elevated,)), numeric, (receipt,))

    def test_history_preflight_counts_all_revisions_profiles_not_only_selected_S(self):
        for logical_type, limit in cohort._RETAINED_HISTORY_LIMITS:
            records = tuple(_record(index + 1, logical_type) for index in range(limit))
            cohort._preflight_cohort_history(records, (records[0].sha256,))
            with self.subTest(logical_type=logical_type), self.assertRaisesRegex(ValidationError, "computational scope"):
                cohort._preflight_cohort_history((*records, _record(limit + 1, logical_type)), (records[0].sha256,))
        # Unrelated small metadata remains allowed; it is never selected as
        # evidence or treated as a native profile by this rejection-only guard.
        record = _record(1, "unrelated")
        cohort._preflight_cohort_history((record,), (record.sha256,))

    def test_absent_ambiguous_or_malformed_snapshot_selectors_refuse(self):
        record = _record(1, "research_state.result")
        for records, hashes in (((record,), (_digest("absent"),)),
                                ((record, record), (record.sha256,)),
                                ((record,), (record.sha256, record.sha256)),
                                ((record,), ())):
            with self.assertRaises(ValidationError):
                cohort._preflight_cohort_history(records, hashes)

    def test_real_missing_snapshot_refuses_without_registry_or_ledger_delta(self):
        with TemporaryDirectory(prefix="numeric-cohort-refusal-") as directory:
            runtime = _prepared_canonical_timeline(directory)
            registry, ledger = runtime["registry"], runtime["ledger"]
            before = (registry.list_records(), ledger.validate(raise_on_error=True))
            for current in (False, True):
                with self.assertRaises((ValidationError, ArtifactError)):
                    cohort.require_scientific_numeric_ablation_cohort(
                        registry, ledger, expected_ledger_run_id="ledger-a",
                        snapshot_artifact_sha256=_digest("missing-snapshot"), require_whole_current=current,
                    )
                self.assertEqual((registry.list_records(), ledger.validate(raise_on_error=True)), before)

    def test_actual_source_replays_full_snapshot_before_complete_sources_without_audit_calls(self):
        source = inspect.getsource(cohort.require_scientific_numeric_ablation_cohort)
        calls = [node.func.id for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        for name in ("resolve_research_state_authority", "resolve_bound_research_state_authority",
                     "_require_research_state_snapshot_issuance", "_preflight_cohort_history",
                     "_require_bound_snapshot_no_post_snapshot_core_drift",
                     "require_scientific_result_promotion_authority_v3",
                     "require_scientific_result_canonical_projection_v3",
                     "require_scientific_numeric_ablation_execution",
                     "require_scientific_numeric_ablation_authority", "_require_complete_observations"):
            self.assertIn(name, calls)
        self.assertLess(source.index("    _preflight_cohort_history("), source.index("        state = resolve_research_state_authority("))
        self.assertEqual(calls.count("_locked_checked_result_authority_snapshot"), 3)
        self.assertFalse(any("semantic" in name or "assess_soundness" in name or "scientific_audit_cohort" in name for name in calls))
        self.assertNotIn("put_json", source)
        self.assertNotIn("DimensionStatus.PASS", inspect.getsource(cohort))


if __name__ == "__main__":
    unittest.main()
