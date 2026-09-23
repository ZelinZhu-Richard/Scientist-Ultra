"""Private projection guards; no successful paper or scientific authority."""

import ast
import inspect
import unittest

from scientist_one import terminal_outcomes as terminal
from scientist_one.errors import ValidationError
from scientist_one.paper_pipeline import HardBlocker, PaperVerification
from scientist_one.roles import Role
from tests import test_vnext_state as fixtures


class PaperTerminalSharedReplayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ResearchStateRepositoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.repository = self.fixture.repository
        self.registry = self.fixture.registry
        self.ledger = self.fixture.ledger
        self.failure = PaperVerification(
            passed=False,
            blockers=(HardBlocker.UNRESOLVED_AUTHORITY,),
            discrepancies=("authority_absent",),
            verified_claim_ids=(),
        )

    def _snapshot(self):
        return self.registry.list_records(), self.ledger.validate(raise_on_error=True)

    def test_public_owner_precedes_private_projection_and_has_no_bypass_argument(self):
        function = terminal.derive_from_registered_paper_verification
        tree = ast.parse(inspect.getsource(function))
        calls = {
            node.func.id: node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertLess(
            calls["require_paper_verification"],
            calls["_derive_from_replayed_paper_verification"],
        )
        self.assertEqual(
            tuple(inspect.signature(function).parameters),
            ("repository", "source_artifact_sha256", "expected_candidate_id"),
        )

    def test_projection_does_not_reenter_paper_or_soundness_owner(self):
        source = inspect.getsource(terminal._derive_from_replayed_paper_verification)
        tree = ast.parse(source)
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("require_paper_verification", calls)
        self.assertNotIn("require_scientific_soundness_assessment", calls)
        self.assertIn("derive_from_paper_verification", calls)
        self.assertIn("TerminalAuthorityScope.NON_EVIDENTIARY_MECHANICAL", source)
        self.assertIn("mapping_id=PAPER_PUBLICATION_TERMINAL_MAPPING_ID", source)

    def test_absent_record_refuses_without_mutation(self):
        before = self._snapshot()
        with self.assertRaisesRegex(ValidationError, "absent or corrupt"):
            terminal._derive_from_replayed_paper_verification(
                self.repository, "a" * 64, self.failure,
                expected_candidate_id="absent-paper",
            )
        self.assertEqual(self._snapshot(), before)

    def test_unrelated_inert_record_cannot_stand_in_for_replayed_paper(self):
        inert = self.registry.put_json(
            {"notice": "inert negative control; not paper authority"},
            logical_type="inert_paper_projection_control",
            origin="negative control only",
            creator_role=Role.EVIDENCE_CURATOR,
            creation_command=("scientist-one", "test-paper-projection-refusal"),
            schema_version="1.0", mime_type="application/json",
            validation_result="PASS", frozen=True,
        )
        before = self._snapshot()
        with self.assertRaisesRegex(ValidationError, "source binding changed"):
            terminal._derive_from_replayed_paper_verification(
                self.repository, inert.sha256, self.failure,
                expected_candidate_id="absent-paper",
            )
        self.assertEqual(self._snapshot(), before)

    def test_untyped_verification_refuses_without_mutation(self):
        before = self._snapshot()
        with self.assertRaisesRegex(ValidationError, "typed sources"):
            terminal._derive_from_replayed_paper_verification(
                self.repository, "a" * 64, {"passed": False},
                expected_candidate_id="absent-paper",
            )
        self.assertEqual(self._snapshot(), before)


if __name__ == "__main__":
    unittest.main()
