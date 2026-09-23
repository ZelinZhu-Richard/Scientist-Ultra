"""Inert coverage arithmetic only; no owner mocks or authority issuance.

All companions are constructed non-evidentiary shapes. These tests neither
authenticate scientific sources nor exercise a positive production bundle.
"""

from dataclasses import replace
from types import SimpleNamespace
import unittest

from scientist_one.evaluators import (
    AuthorityScope, AuthorityStatus, EvaluatorClass, RCheck, RCheckAuthority,
    _RCheckAuthorityReplay,
)
from scientist_one.roles import Role
from scientist_one.scientific_r_checks import (
    _ScientificCohortDesignObligation,
    _cohort_scientific_check_targets,
    _cohort_scientific_leaf_coverage,
)
from tests import test_scientific_cohort_design as design_fixtures
from tests import test_scientific_r_checks as check_fixtures


class CohortLeafCoverageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = design_fixtures.ScientificCohortDesignTests()
        self.fixture.setUp()
        self.cohort = self.fixture.cohort
        self.designs = tuple(_ScientificCohortDesignObligation(
            execution, None, (), "SCIENTIFIC_EXECUTION_AUTHORITY_UNAVAILABLE",
        ) for execution in self.cohort.executions)

    def _matching(self, *, status=AuthorityStatus.FAIL):
        r1, design, member, subject, admissions = self.fixture._matching_result_member()
        question = replace(design.questions[0], question=SimpleNamespace(
            object_id="inert-question", artifact_sha256=design_fixtures._digest("question"),
        ))
        design = replace(design, questions=(question,))
        cohort = replace(
            self.cohort, executions=(member.execution,), results=(member,),
            round_key=replace(self.cohort.round_key, run_id=subject["run_id"]),
        )
        resolution = replace(
            r1, r_check=RCheck.R4, subject_key=tuple(subject.items()),
            source_admissions=admissions[:2],
        )
        authority = RCheckAuthority(
            run_id=subject["run_id"], r_check=RCheck.R4,
            evaluator_class=EvaluatorClass.E0, actor_role=Role.ORCHESTRATOR,
            status=status, scope=AuthorityScope.SYSTEM_FIXTURE,
            source_bindings=(), ledger_prefix_head_hash=design_fixtures._digest("prefix"),
            ledger_prefix_event_count=1, reason_code="INERT_OUTER_VERDICT",
            derivation_checks=(),
        )
        leaf = _RCheckAuthorityReplay(
            authority, check_fixtures._record("inert-leaf", "r_check_authority"),
            (), resolution, cohort.audit_source.entry_snapshot,
        )
        return cohort, (design,), leaf

    def test_empty_leaves_preserve_every_result_and_resultless_execution(self):
        rows = _cohort_scientific_leaf_coverage(self.cohort, self.designs, ())
        # Six executions * (two R1 + two R3) plus five Result/Test pairs
        # * (two R2 + two R4), independent of the submitted empty leaf set.
        self.assertEqual(len(rows), 44)
        self.assertTrue(all(row.status is AuthorityStatus.UNTESTED for row in rows))
        self.assertTrue(all(row.authority_artifact_sha256 is None for row in rows))
        extra = next(item for item in self.cohort.executions
                     if item.run.research_object.object_id == "extra-run-without-result")
        self.assertEqual(sum(extra.run.artifact_sha256 in row.target.subject_artifact_sha256s
                             for row in rows), 4)
        self.assertEqual({row.target.r_check for row in rows},
                         {RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4})

    def test_design_inventory_cannot_omit_duplicate_or_empty_executions(self):
        for designs in (self.designs[:-1], (self.designs[0],) * len(self.designs)):
            with self.subTest(designs=designs), self.assertRaisesRegex(ValueError, "execution"):
                _cohort_scientific_check_targets(self.cohort, designs)
        with self.assertRaisesRegex(ValueError, "complete execution"):
            _cohort_scientific_check_targets(replace(self.cohort, executions=()), ())

    def test_matched_outer_failure_is_retained_despite_missing_other_leaves(self):
        cohort, designs, leaf = self._matching()
        rows = _cohort_scientific_leaf_coverage(cohort, designs, (leaf,))
        self.assertEqual(len(rows), 8)
        matched = tuple(row for row in rows if row.authority_artifact_sha256)
        self.assertEqual(len(matched), 1)
        self.assertIs(matched[0].status, AuthorityStatus.FAIL)
        self.assertIs(leaf.scientific_resolution.status, AuthorityStatus.UNTESTED)
        self.assertEqual(matched[0].authority_artifact_record_hash, leaf.record.record_hash)
        self.assertEqual(sum(row.status is AuthorityStatus.UNTESTED for row in rows), 7)

    def test_inert_fixture_pass_does_not_gain_scientific_scope_from_matching(self):
        cohort, designs, leaf = self._matching(status=AuthorityStatus.PASS)
        rows = _cohort_scientific_leaf_coverage(cohort, designs, (leaf,))
        matched = next(row for row in rows if row.authority_artifact_sha256)
        self.assertIs(matched.status, AuthorityStatus.UNTESTED)
        self.assertIs(matched.scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertEqual(matched.reason_code, "MATCHED_LEAF_NOT_SCIENTIFIC_AUTHORITY")

    def test_competing_same_cell_and_duplicate_input_leaves_are_rejected(self):
        cohort, designs, leaf = self._matching()
        with self.assertRaisesRegex(ValueError, "unique bounded"):
            _cohort_scientific_leaf_coverage(cohort, designs, (leaf, leaf))
        competing = replace(leaf, record=check_fixtures._record("competing", "r_check_authority"))
        with self.assertRaisesRegex(ValueError, "competing evaluator"):
            _cohort_scientific_leaf_coverage(cohort, designs, (leaf, competing))

    def test_wrong_member_and_stale_source_view_are_not_counted(self):
        cohort, designs, leaf = self._matching()
        subject = dict(leaf.scientific_resolution.subject_key)
        subject["canonical_result_artifact_sha256"] = design_fixtures._digest("another-result")
        wrong = replace(leaf, scientific_resolution=replace(
            leaf.scientific_resolution, subject_key=tuple(subject.items()),
        ))
        with self.assertRaisesRegex(ValueError, "authenticated membership"):
            _cohort_scientific_leaf_coverage(cohort, designs, (wrong,))
        with self.assertRaisesRegex(ValueError, "same full source replay view"):
            _cohort_scientific_leaf_coverage(cohort, designs, (
                replace(leaf, entry_snapshot=("stale", None)),
            ))

    def test_target_order_does_not_depend_on_inventory_order(self):
        first = _cohort_scientific_check_targets(self.cohort, self.designs)
        shuffled = replace(self.cohort, executions=tuple(reversed(self.cohort.executions)),
                           results=tuple(reversed(self.cohort.results)))
        second = _cohort_scientific_check_targets(shuffled, tuple(reversed(self.designs)))
        self.assertEqual(first, second)

    def test_one_leaf_can_cover_distinct_fixed_shared_question_memberships(self):
        cohort, (design,), leaf = self._matching(status=AuthorityStatus.UNTESTED)
        first = design.questions[0]
        second = replace(first,
            question=SimpleNamespace(object_id="inert-question-2",
                                     artifact_sha256=design_fixtures._digest("question-2")),
            gate_record=check_fixtures._record("inert-gate-2", "research_question_gate_receipt"),
        )
        design = replace(design, questions=(first, second))
        r1 = self.fixture._matching_result_member()[0]
        leaf = replace(leaf, authority=replace(leaf.authority, r_check=RCheck.R1),
                       scientific_resolution=r1)
        rows = _cohort_scientific_leaf_coverage(cohort, (design,), (leaf,))
        matches = tuple(row for row in rows if row.authority_artifact_sha256)
        self.assertEqual(len(rows), 10)
        self.assertEqual(len(matches), 2)
        self.assertEqual({row.target.subject_artifact_sha256s[1] for row in matches},
                         {first.question.artifact_sha256, second.question.artifact_sha256})
        self.assertTrue(all(row.status is AuthorityStatus.UNTESTED for row in matches))

    def test_shared_question_expansion_is_bounded_without_truncation(self):
        cohort, (design,), _leaf = self._matching()
        questions = tuple(replace(design.questions[0], question=SimpleNamespace(
            artifact_sha256=design_fixtures._digest(f"inert-question-{index}"),
        )) for index in range(2049))
        with self.assertRaisesRegex(ValueError, "bounded capacity"):
            _cohort_scientific_check_targets(cohort, (replace(design, questions=questions),))

    def test_missing_question_reason_does_not_mislabel_other_missing_leaves(self):
        cohort, (design,), leaf = self._matching()
        reason = "SCIENTIFIC_QUESTION_GATE_UNAVAILABLE_BEFORE_DESIGN"
        design = replace(design, questions=(), unmet_reason=reason)
        rows = _cohort_scientific_leaf_coverage(cohort, (design,), (leaf,))
        for row in rows:
            if row.target.r_check is RCheck.R1:
                self.assertEqual(row.reason_code, reason)
            elif row.authority_artifact_sha256:
                self.assertIs(row.status, AuthorityStatus.FAIL)
            else:
                self.assertEqual(row.reason_code, "REQUIRED_COHORT_LEAF_MISSING")


if __name__ == "__main__":
    unittest.main()
