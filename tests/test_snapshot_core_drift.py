"""Structural, non-evidentiary snapshot drift controls.

The registry and ledger are real temporary stores, but snapshot DTOs are inert
and unissued.  No scientific source owner is mocked, issued, or granted PASS.
"""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
import tempfile
import unittest

from scientist_one import gates
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import LedgerEvent
from scientist_one.research_state import (
    Critique,
    ResearchQuestion,
    ResearchStateAuthorityBinding,
    ResearchStateAuthoritySnapshot,
    ResearchStateRepository,
    VenueAssessment,
    resolve_bound_research_state_authority,
)
from scientist_one.roles import Role
from tests import test_challenger_audit_authority as audit_fixtures
from tests.test_paper_verification_shared_replay import _portable_ast_dump


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _body_hash(body):
    value = _portable_ast_dump(ast.Module(body=body, type_ignores=[]))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SnapshotCoreDriftTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.fixtures = audit_fixtures.SemanticChallengerAuditAuthorityTests()
        self.registry, self.ledger = self.fixtures._runtime(Path(self.directory.name))
        self.question = ResearchQuestion(
            object_id="structural-question",
            producer=Role.PROBLEM_INVESTIGATOR,
            research_goal="Exercise structural replay without scientific evidence.",
            question="Does the structural fixture preserve the snapshot boundary?",
            falsification_condition="A post-snapshot core addition is accepted.",
            code_version="semantic-audit-test",
        )
        self.question_artifact, self.question_event = (
            self.fixtures._append_canonical_fixture(
                self.registry, self.ledger, self.question,
            )
        )
        self.slot = self.fixtures._slot(scientific_source_qualified=False)
        self.state = ResearchStateAuthoritySnapshot(
            run_id=self.slot.run_id,
            snapshot_artifact_sha256=self.slot.research_state_snapshot_artifact_hash,
            snapshot_artifact_record_hash=(
                self.slot.research_state_snapshot_artifact_record_hash
            ),
            ledger_head_hash=self.question_event.event_hash,
            ledger_event_count=2,
            code_version=self.question.code_version,
            configuration_hash=self.question_event.configuration_hash,
            entries=(ResearchStateAuthorityBinding(
                research_object=self.question,
                artifact_sha256=self.question_artifact.sha256,
                artifact_record_hash=self.question_artifact.record_hash,
                materialization_event_id=self.question_event.event_id,
                materialization_event_hash=self.question_event.event_hash,
                materialization_event_index=1,
                authority_artifact_hashes=(),
                authority_artifact_record_hashes=(),
                authority_logical_types=(),
                authority_creator_roles=(),
                scientific_evidence_eligible=False,
                claim_semantics=None,
            ),),
        )

    def _read(self, *, state=None):
        return gates._require_bound_snapshot_no_post_snapshot_core_drift(
            self.registry, self.ledger, state=self.state if state is None else state,
        )

    def _stored_state(self):
        return (
            self.registry.verify_all(raise_on_error=True),
            self.ledger.validate(raise_on_error=True),
        )

    def test_body_hash_is_runtime_portable_and_semantically_sensitive(self):
        baseline = _body_hash(ast.parse("x = 1").body)
        self.assertEqual(
            baseline,
            "039874806879bbbb3c244ab91822fce8291188c8fd621af86ffdc0a08f0c3bc5",
        )
        for source in ("x = 2", "y = 1", "x += 1", "x = -1", "x = None"):
            with self.subTest(source=source):
                self.assertNotEqual(_body_hash(ast.parse(source).body), baseline)
        self.assertNotEqual(_body_hash([]), baseline)

    def test_extraction_preserves_exact_historical_prefix_and_semantic_tail(self):
        from tests.test_paper_round_replay import _normalize_audit_round_tail

        # Source preimage c11a5356...: the complete original try prefix, and
        # complete original tail with only the requested snapshot field fix.
        structural = _function(gates._require_bound_snapshot_no_post_snapshot_core_drift)
        structural_try = next(item for item in structural.body if isinstance(item, ast.Try))
        self.assertIsInstance(structural_try.body[-1], ast.Return)
        self.assertEqual(
            _body_hash(structural_try.body[:-1]),
            "20bee260ff455ecfb6baa3f972e9e97c8e651070afc8d313655e4a1dbb93482e",
        )
        audit = _function(gates._require_semantic_challenger_audit_no_post_snapshot_core_drift)
        audit_try = next(item for item in audit.body if isinstance(item, ast.Try))
        self.assertEqual(
            # Every D068 context node is matched exactly before removal. The
            # complete original semantic tail keeps its historical golden.
            _body_hash(_normalize_audit_round_tail(audit_try.body[1:])),
            "7e770e1ece5061dd2fcf21ead7ec2539d3d652327861619e6d261171117af903",
        )
        self.assertEqual(
            tuple(ast.dump(item) for item in structural_try.handlers),
            tuple(ast.dump(item) for item in audit_try.handlers),
        )

    def test_shared_helper_is_audit_free_structural_replay_only(self):
        structural = _function(gates._require_bound_snapshot_no_post_snapshot_core_drift)
        calls = tuple(node.func for node in ast.walk(structural) if isinstance(node, ast.Call))
        self.assertEqual(
            {node.id for node in calls if isinstance(node, ast.Name)},
            {"ResearchStateRepository", "ValidationError", "enumerate", "next", "set", "thaw_json", "tuple"},
        )
        self.assertEqual(
            {node.attr for node in calls if isinstance(node, ast.Attribute)},
            {"validate", "get_metadata", "list_records", "startswith", "load_artifact", "get", "add", "append"},
        )
        signature = inspect.signature(gates._require_bound_snapshot_no_post_snapshot_core_drift)
        self.assertEqual(tuple(signature.parameters), ("registry", "ledger", "state"))
        self.assertIs(signature.parameters["state"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(
            gates._SEMANTIC_CHALLENGE_AUDIT_ALLOWED_POST_SNAPSHOT_TYPES,
            frozenset({"Challenge", "Critique", "Decision", "VenueAssessment"}),
        )

    def test_no_core_drift_returns_checked_repository_and_ledger_without_writes(self):
        before = self._stored_state()
        repository, ledger_result, additions = self._read()
        self.assertIs(type(repository), ResearchStateRepository)
        self.assertIs(repository.registry, self.registry)
        self.assertIs(repository.ledger, self.ledger)
        self.assertEqual(repository.run_id, self.state.run_id)
        self.assertEqual(repository.creation_command, self.question_artifact.creation_command)
        self.assertEqual(repository.load_artifact(self.question_artifact.sha256), self.question)
        self.assertEqual(ledger_result, before[1])
        self.assertEqual(additions, ())
        self.assertEqual(self._stored_state(), before)

    def test_real_typed_snapshot_reaches_nonempty_review_tail_without_alias(self):
        review = Critique(
            object_id="unrelated-structural-review",
            producer=Role.ADVERSARIAL_REVIEWER,
            target_ids=("unrelated-claim",),
            findings=(),
            verdict="RETAIN",
            code_version=self.state.code_version,
        )
        artifact, _event = self.fixtures._append_canonical_fixture(
            self.registry, self.ledger, review,
        )
        before = self._stored_state()
        self.assertIs(type(self.state), ResearchStateAuthoritySnapshot)
        self.assertFalse(hasattr(self.state, "snapshot_artifact_hash"))
        _repository, _ledger_result, additions = self._read()
        self.assertIs(type(additions), tuple)
        self.assertEqual(additions, ((2, review, artifact),))
        gates._require_semantic_challenger_audit_no_post_snapshot_core_drift(
            self.registry, self.ledger, state=self.state, audit_slot=self.slot,
        )
        self.assertEqual(self._stored_state(), before)

    def test_structural_review_return_does_not_replace_audit_semantic_rejection(self):
        review = VenueAssessment(
            object_id="related-unowned-venue",
            producer=Role.SCIENTIFIC_REVIEWER,
            venue="Inert structural review fixture",
            profile="ml-ai",
            evidence_ids=(self.slot.central_claim_ids[0],),
            code_version=self.state.code_version,
        )
        artifact, _event = self.fixtures._append_canonical_fixture(
            self.registry, self.ledger, review,
        )
        before = self._stored_state()
        self.assertEqual(self._read()[2], ((2, review, artifact),))
        with self.assertRaisesRegex(ValidationError, "newly related venue"):
            gates._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                self.registry, self.ledger, state=self.state, audit_slot=self.slot,
            )
        self.assertEqual(self._stored_state(), before)

    def test_actual_appended_core_is_rejected_without_mutation(self):
        self.fixtures._append_canonical_fixture(
            self.registry, self.ledger,
            replace(self.question, object_id="later-question", content_hash=None),
        )
        before = self._stored_state()
        with self.assertRaisesRegex(ValidationError, "scientific core changed after its bound snapshot"):
            self._read()
        self.assertEqual(self._stored_state(), before)

    def test_unmatched_post_snapshot_materialization_event_is_rejected(self):
        previous = self.ledger.events()[-1]
        self.ledger.append(LedgerEvent.create(
            run_id=self.state.run_id,
            actor_role=previous.actor_role,
            state_before=previous.state_after,
            requested_state_after=previous.state_after,
            artifact_hashes=(self.question_artifact.sha256,),
            code_version=previous.code_version,
            configuration_hash=previous.configuration_hash,
            reason="Inert unmatched materialization marker; no canonical artifact issued.",
            prior_event_hash=previous.event_hash,
            event_id="unmatched-structural-materialization",
            event_type="CHECKPOINT",
            metadata={"research_state_operation": "MATERIALIZED"},
        ))
        before = self._stored_state()
        with self.assertRaisesRegex(ValidationError, "state event lacks canonical content"):
            self._read()
        self.assertEqual(self._stored_state(), before)

    def test_absent_changed_prefix_and_nonprior_seed_are_rejected(self):
        before = self._stored_state()
        for state in (
            replace(self.state, entries=()),
            replace(self.state, ledger_event_count=3),
            replace(self.state, ledger_head_hash="f" * 64),
            replace(self.state, entries=(replace(
                self.state.entries[0], materialization_event_index=2,
            ),)),
        ):
            with self.subTest(state=state), self.assertRaisesRegex(
                ValidationError, "prefix is absent or changed|lacks a prior materialization",
            ):
                self._read(state=state)
        self.assertEqual(self._stored_state(), before)

    def test_unanchored_canonical_artifact_is_rejected(self):
        record = replace(self.question, object_id="unanchored-question", content_hash=None)
        self.registry.put_bytes(
            record.canonical_bytes(),
            logical_type=record.logical_type,
            origin=f"research-state:{record.object_type}:{record.object_id}:r1",
            creator_role=record.producer,
            creation_command=self.question_artifact.creation_command,
            parent_artifacts=(),
            schema_version=record.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=record.created_at,
        )
        before = self._stored_state()
        with self.assertRaisesRegex(ValidationError, "contains an unanchored artifact"):
            self._read()
        self.assertEqual(self._stored_state(), before)

    def test_structural_success_is_not_whole_bound_snapshot_authority(self):
        before = self._stored_state()
        self.assertEqual(self._read()[2], ())
        # This DTO has no snapshot artifact or issuance. The ordinary full
        # owner must still reject it; no positive owner is replaced or mocked.
        with self.assertRaises(ArtifactError):
            resolve_bound_research_state_authority(
                self.registry, self.ledger,
                run_id=self.state.run_id,
                snapshot_artifact_hash=self.state.snapshot_artifact_sha256,
                state_artifact_hashes=(self.question_artifact.sha256,),
                ledger_head_hash=self.state.ledger_head_hash,
                ledger_event_count=self.state.ledger_event_count,
                expected_code_version=self.state.code_version,
                expected_configuration_hash=self.state.configuration_hash,
            )
        self.assertEqual(self._stored_state(), before)


if __name__ == "__main__":
    unittest.main()
