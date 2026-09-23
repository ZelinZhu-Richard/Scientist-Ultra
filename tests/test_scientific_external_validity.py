"""Inert source joins and real refusals, never successful scientific issuance."""

import ast
from dataclasses import replace
import inspect
from tempfile import TemporaryDirectory
import traceback
from types import SimpleNamespace
import unittest

from scientist_one import scientific_external_validity as boundary
from scientist_one import scientific_external_validity_gate as gate
from scientist_one import gates, evaluators
from scientist_one import research_state as rs
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.scientific_design import (
    CheckedResultAssessment, ScientificResultCanonicalProjectionV3,
    ScientificResultCanonicalProjectionV4, ScientificResultPromotionResolutionV3,
)
from tests.test_scientific_audit_cohort import _member, _binding, _digest
from tests.test_scientific_numeric_ablation_cohort import _state, _record
from tests.test_scientific_method_alignment import _prepared_canonical_timeline
from tests import test_snapshot_reference_replay as snapshot_fixtures
from tests.test_numeric_ablation_round_join import _case as _inert_round_case


def _inert_boundary_round():
    """Unregistered structural outputs only, not source-owner substitutes."""
    cohort, audit, args = _inert_round_case()
    claims = tuple(_binding(rs.Claim(
        object_id=claim_id, producer=gates.Role.ORCHESTRATOR,
        claim_text="Inert shape only", scope="NONE", verification_method="NONE_NON_EVIDENTIARY",
    )) for claim_id in audit.central_claim_ids)
    state = replace(cohort.state, entries=(*cohort.state.entries, *claims))
    domain = _record(202, "domain_validity.generic_ml")
    value = boundary.ScientificExternalValidityBoundary(
        state, cohort.snapshot_record, args["claim_graph_record"], (domain,),
        cohort.result_test_bindings, (cohort.snapshot_record.sha256, domain.sha256), None,
    )
    return value, audit


class ScientificExternalValidityTests(unittest.TestCase):
    def test_complete_inert_inventory_keeps_all_outcomes_and_false_eligibility(self):
        outcomes = ("POSITIVE", "NEGATIVE", "NULL", "INCONCLUSIVE", "FALSIFIED")
        entries = tuple(item for index, outcome in enumerate(outcomes)
                        for item in _member(str(index), outcome, 3 if index == 0 else 4))
        members = boundary._result_test_members(_state(entries))
        self.assertEqual(len(members), len(outcomes))
        self.assertEqual({result.research_object.metadata["scientific_result_outcome"]
                          for result, _, _ in members}, set(outcomes))
        self.assertTrue(all(not item.scientific_evidence_eligible for member in members for item in member))
        self.assertEqual(members, boundary._result_test_members(_state(entries[::-1])))

    def test_inventory_refuses_missing_duplicate_and_unrelated_tests(self):
        entries = _member("a", "NULL", 4)
        test = entries[-1]
        cases = (entries[:-1], (*entries, _binding(replace(test.research_object,
                 object_id="duplicate-test", content_hash=None))),
                 (*entries, *_member("b", "NEGATIVE", 3)[:-1]))
        for case in cases:
            with self.subTest(count=len(case)), self.assertRaises(ValidationError):
                boundary._result_test_members(_state(case))

    def test_inventory_refuses_wrong_test_revision_relation_or_authority_flag(self):
        entries = _member("a", "NULL", 4)
        test = entries[-1].research_object
        for reference in (
            replace(test.parents[0], content_hash=_digest("foreign-revision")),
            replace(test.parents[0], relation="describes"),
            replace(test.parents[0], evaluated=False),
        ):
            with self.assertRaises(ValidationError):
                boundary._result_test_members(_state((*entries[:-1], _binding(
                    replace(test, parents=(reference,), content_hash=None),
                ))))

    def test_empty_results_and_empty_state_do_not_complete_inventory(self):
        for entries in ((), _member("a", "NULL", 4)[:2]):
            with self.assertRaises(ValidationError):
                boundary._result_test_members(_state(entries))

    def test_resultless_runs_cannot_replace_missing_result_tests(self):
        entries = _member("a", "NULL", 4)
        run = next(item.research_object for item in entries if type(item.research_object) is rs.Run)
        extra = _binding(replace(run, object_id="resultless-run", content_hash=None))
        self.assertEqual(len(boundary._result_test_members(_state((*entries, extra)))), 1)
        with self.assertRaises(ValidationError):
            boundary._result_test_members(_state((*entries[:-1], extra)))

    def test_selector_capacity_and_missing_roots_refuse_before_ownership(self):
        records = (_record(1, "research_state.result"), _record(2, "research_state.statistical_test"))
        hashes = tuple(record.sha256 for record in records)
        boundary._preflight_boundary_selectors(records, hashes)
        for candidates, selectors in (
            (records, ()), (records, (hashes[0],)), (records, (*hashes, hashes[0])),
            (records, (*hashes, _digest("absent"))), ((*records, records[0]), hashes),
        ):
            with self.assertRaises(ValidationError):
                boundary._preflight_boundary_selectors(candidates, selectors)
        records = tuple(_record(index + 1, "research_state.result" if index < 85
                                else "research_state.statistical_test") for index in range(170))
        with self.assertRaisesRegex(ValidationError, "capacity"):
            boundary._preflight_boundary_selectors(records, tuple(record.sha256 for record in records))

    def test_real_absent_snapshot_refuses_with_zero_delta_for_both_modes(self):
        with TemporaryDirectory(prefix="external-boundary-refusal-") as directory:
            runtime = _prepared_canonical_timeline(directory)
            registry, ledger = runtime["registry"], runtime["ledger"]
            before = (registry.list_records(), ledger.validate(raise_on_error=True))
            for current in (False, True):
                caught = None
                try:
                    boundary.require_scientific_external_validity_boundary(
                        registry, ledger, expected_ledger_run_id="ledger-a",
                        snapshot_artifact_sha256=_digest("missing-snapshot"),
                        claim_graph_artifact_sha256=_digest("missing-graph"),
                        central_claim_ids=("claim-a",), require_whole_current=current,
                    )
                except (ValidationError, ArtifactError) as error:
                    caught = error
                self.assertIsNotNone(caught)
                self.assertIn("_read_canonical_research_state_snapshot", {
                    frame.name for frame in traceback.extract_tb(caught.__traceback__)
                })
                self.assertEqual((registry.list_records(), ledger.validate(raise_on_error=True)), before)

    def test_real_mechanical_issued_snapshot_is_not_scientific_inventory(self):
        fixture = snapshot_fixtures.SnapshotReferenceReplayTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        before = (fixture.registry.list_records(), fixture.ledger.validate(raise_on_error=True))
        for current in (False, True):
            with self.assertRaisesRegex(ValidationError, "Result/Test closure is empty"):
                boundary.require_scientific_external_validity_boundary(
                    fixture.registry, fixture.ledger, expected_ledger_run_id="run-1",
                    snapshot_artifact_sha256=fixture.snapshot.sha256,
                    claim_graph_artifact_sha256=_digest("not-an-owned-graph"),
                    central_claim_ids=("claim-a",), require_whole_current=current,
                )
            self.assertEqual((fixture.registry.list_records(), fixture.ledger.validate(raise_on_error=True)), before)

    def test_source_replay_order_is_upstream_only_and_nonissuing(self):
        source = inspect.getsource(boundary.require_scientific_external_validity_boundary)
        calls = [node.func.id for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        for name in ("_require_research_state_snapshot_issuance", "_preflight_boundary_selectors",
                     "resolve_research_state_authority", "resolve_bound_research_state_authority",
                     "_require_bound_snapshot_no_post_snapshot_core_drift",
                     "_resolve_claim_graph_authority", "_result_test_members", "_require_member_domain"):
            self.assertIn(name, calls)
        self.assertLess(source.index("    _preflight_boundary_selectors("),
                        source.index("        state = resolve_research_state_authority("))
        module = inspect.getsource(boundary)
        self.assertNotIn("put_json", module)
        self.assertNotIn("_require_semantic", module)
        self.assertNotIn("_require_scientific_audit_cohort", module)
        self.assertNotIn("assess_soundness(", module)

    def test_member_joins_only_reference_actual_source_owner_fields(self):
        # Mechanical API compatibility, not proof of any successful owner.
        types = {"resolution": (ScientificResultPromotionResolutionV3,),
                 "assessment": (CheckedResultAssessment,),
                 "primary": (ScientificResultCanonicalProjectionV3, ScientificResultCanonicalProjectionV4)}
        for node in ast.walk(ast.parse(inspect.getsource(boundary._require_member_domain))):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in types:
                for cls in types[node.value.id]:
                    with self.subTest(cls=cls.__name__, field=node.attr):
                        self.assertTrue(node.attr in cls.__dataclass_fields__ or hasattr(cls, node.attr))

    def test_pure_round_join_never_turns_inventory_or_adverse_audit_into_adequacy(self):
        value, audit = _inert_boundary_round()
        gate.require_scientific_external_validity_audit_join(value, audit)
        self.assertEqual(value.scientific_adequacy, "UNTESTED")
        self.assertNotEqual(value.evidence_hashes, audit.evidence_artifact_hashes)
        for status in (gates.SemanticChallengeAuditStatus.FAIL, gates.SemanticChallengeAuditStatus.UNTESTED):
            with self.subTest(status=status):
                gate.require_scientific_external_validity_audit_join(value, replace(audit, status=status))
                self.assertEqual(value.scientific_adequacy, "UNTESTED")

    def test_pure_round_join_rejects_source_record_cohort_and_chronology_substitution(self):
        value, audit = _inert_boundary_round()
        variants = (
            replace(value, state=replace(value.state, run_id="another-run")),
            replace(value, state=replace(value.state, snapshot_artifact_sha256=_digest("another-S"))),
            replace(value, snapshot_record=replace(value.snapshot_record, origin="substituted", record_hash=None)),
            replace(value, graph_record=replace(value.graph_record, origin="substituted", record_hash=None)),
            replace(value, result_test_bindings=value.result_test_bindings[:-1]),
            replace(value, result_test_bindings=value.result_test_bindings[::-1]),
            replace(value, state=replace(value.state, ledger_event_count=audit.slot_event_index + 1)),
        )
        for index, candidate in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValidationError):
                gate.require_scientific_external_validity_audit_join(candidate, audit)

    def test_new_contract_does_not_reinterpret_the_historical_fourteen(self):
        self.assertEqual(len(gates.CHALLENGER_ATTACK_RESOLVER_CONTRACTS), 14)
        self.assertEqual(len(gates.SCIENTIFIC_EXTERNAL_VALIDITY_RESOLVER_CONTRACTS), 1)
        key, = gates.SCIENTIFIC_EXTERNAL_VALIDITY_RESOLVER_CONTRACTS
        self.assertEqual(key, (gates.ChallengeCategory.EXTERNAL_VALIDITY,
                              gates.ChallengerExecutorKind.DETERMINISTIC,
                              boundary.SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_ID,
                              boundary.SCIENTIFIC_EXTERNAL_VALIDITY_PROCEDURE_VERSION))
        self.assertNotIn(key, gates.CHALLENGER_ATTACK_RESOLVER_CONTRACTS)
        self.assertIn(key, gates._ALL_CHALLENGER_ATTACK_RESOLVER_CONTRACTS)
        self.assertIs(gates._CHALLENGER_ATTACK_RESOLVERS[key],
                      gates._resolve_scientific_external_validity_challenger_attack)

    def test_evaluator_replays_and_joins_before_the_explicit_untested_projection(self):
        source = inspect.getsource(evaluators._derive_complete_challenger_status)
        self.assertLess(source.index("boundary = require_scientific_external_validity_execution_record("),
                        source.index("require_scientific_external_validity_audit_join(boundary, anchor)"))
        self.assertLess(source.index("require_scientific_external_validity_audit_join(boundary, anchor)"),
                        source.index("external_adequacy_untested = True"))
        tree = ast.parse(source)
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "external_adequacy_untested")
        self.assertEqual(ast.unparse(branch.body[0]),
                         "return (AuthorityStatus.UNTESTED, 'EXTERNAL_VALIDITY_SCIENTIFIC_ADEQUACY_UNTESTED', tuple(checks))")

    def test_soundness_only_executed_semantic_reviews_claim_snapshot_coverage(self):
        # Evaluate the actual pure loop-selection expression, not an owner or
        # a successful Soundness call. Missing reviews still reach the existing
        # MORE_EXPERIMENTS_REQUIRED derivation instead of failing this join.
        function = ast.parse(inspect.getsource(gate.require_scientific_external_validity_soundness_join)).body[0]
        loop = next(node for node in function.body if isinstance(node, ast.For))
        branch = loop.body[0]
        self.assertIsInstance(branch, ast.If)
        self.assertIsInstance(branch.body[0], ast.Continue)
        expression = compile(ast.Expression(branch.test), "<inert-external-review-selector>", "eval")
        for category in gates.ChallengeCategory:
            for status in gates.ChallengerExecutionStatus:
                skip = eval(expression, {
                    "__builtins__": {},
                    "_SEMANTIC_CHALLENGER_CATEGORIES": gates._SEMANTIC_CHALLENGER_CATEGORIES,
                    "ChallengerExecutionStatus": gates.ChallengerExecutionStatus,
                }, {"review": SimpleNamespace(category=category, execution_status=status)})
                self.assertIs(skip, category not in gates._SEMANTIC_CHALLENGER_CATEGORIES
                              or status is not gates.ChallengerExecutionStatus.EXECUTED)


if __name__ == "__main__":
    unittest.main()
