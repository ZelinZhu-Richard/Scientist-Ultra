"""Non-evidentiary controls for the private semantic-audit source companion.

No source owner is patched, no provider or private issuer is invoked, and no
scientific audit is admitted. DTO/control-flow checks and real owner refusals
do not establish a positive scientific audit or cohort roundtrip.
"""

import ast
from dataclasses import MISSING, FrozenInstanceError, fields, replace
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one import gates
from scientist_one.errors import ValidationError
from scientist_one.security import canonical_json_bytes
from tests import test_challenger_audit_authority as fixtures


def _function_tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function))).body[0]


def _calls(tree, name):
    return tuple(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    )


class SemanticAuditSourceCompanionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SemanticChallengerAuditAuthorityTests()
        self.slot = self.fixture._slot(scientific_source_qualified=False)

    def _scope(self):
        slot = self.slot
        return gates._SemanticChallengerAuditCanonicalScope(
            state=None,  # Inert shape only; not a replayed canonical snapshot.
            central_claim_ids=slot.central_claim_ids,
            evidence_artifact_hashes=slot.evidence_artifact_hashes,
            evidence_artifact_record_hashes=slot.evidence_artifact_record_hashes,
            result_artifact_hashes=slot.result_artifact_hashes,
            result_artifact_record_hashes=slot.result_artifact_record_hashes,
            reproducibility_package_artifact_hash=None,
            scientific_source_qualified=False,
            package_authority=None,
        )

    def _authority(self, slot=None, records=None):
        """A closed UNTESTED codec value, never the output of an audit owner."""
        slot = slot or self.slot
        hashes = tuple(
            records[name].sha256 if records else fixtures._digest(name)
            for name in ("judgment", "execution", "review")
        )
        record_hashes = tuple(
            records[name].record_hash if records else fixtures._digest(f"{name}-record")
            for name in ("judgment", "execution", "review")
        )
        common = {
            field.name: getattr(slot, field.name)
            for field in fields(gates.SemanticChallengeAuditAuthority)
            if hasattr(slot, field.name)
        }
        return gates.SemanticChallengeAuditAuthority(
            **common,
            authority_id="inert-audit-authority",
            slot_subject_sha256=slot.subject_sha256,
            slot_event_id=slot.event_id,
            slot_event_hash=slot.event_hash,
            slot_event_index=slot.event_index,
            semantic_judgment_artifact_hash=hashes[0],
            semantic_judgment_artifact_record_hash=record_hashes[0],
            finding_artifact_hashes=(),
            finding_artifact_record_hashes=(),
            challenger_execution_artifact_hash=hashes[1],
            challenger_execution_artifact_record_hash=record_hashes[1],
            challenger_review_artifact_hash=hashes[2],
            challenger_review_artifact_record_hash=record_hashes[2],
            status=gates.SemanticChallengeAuditStatus.UNTESTED,
            residual_risk_summary="Non-evidentiary codec and owner-refusal fixture.",
            input_artifact_hashes=(*slot.scoped_artifact_hashes, *hashes),
            input_artifact_record_hashes=(*slot.scoped_artifact_record_hashes, *record_hashes),
            verification_event_id="inert-verification",
            verification_event_hash=fixtures._digest("inert-verification"),
            verification_event_index=slot.event_index + 1,
        )

    def _source_options(self, authority, record):
        return dict(
            authority_artifact_hash=record.sha256,
            expected_run_id=authority.run_id,
            expected_assessment_id=authority.assessment_id,
            expected_category=authority.category,
            expected_research_state_snapshot_artifact_hash=(
                authority.research_state_snapshot_artifact_hash
            ),
            expected_claim_graph_artifact_hash=authority.claim_graph_artifact_hash,
            expected_central_claim_ids=authority.central_claim_ids,
            expected_reproducibility_package_artifact_hash=None,
        )

    def _slot_binding_bytes(self, slot):
        subject = gates._semantic_challenger_audit_subject_binding(**{
            name: getattr(slot, name) for name in (
                "run_id", "category", "research_state_snapshot_artifact_hash",
                "research_state_snapshot_artifact_record_hash",
                "claim_graph_artifact_hash", "claim_graph_artifact_record_hash",
                "central_claim_ids", "evidence_artifact_hashes",
                "evidence_artifact_record_hashes", "result_artifact_hashes",
                "result_artifact_record_hashes", "reproducibility_package_artifact_hash",
                "scientific_source_qualified",
            )
        })
        return canonical_json_bytes(gates._semantic_challenger_audit_slot_binding(
            slot_id=slot.slot_id, subject_sha256=slot.subject_sha256,
            assessment_id=slot.assessment_id,
            provider_invocation_id=slot.provider_invocation_id,
            contract=gates._semantic_challenger_audit_contract(slot.category),
            subject_binding=subject,
        ))

    def test_public_signatures_are_exact_private_arguments_without_injection_flags(self):
        for public, private in (
            (gates.require_semantic_challenger_audit_slot,
             gates._require_semantic_challenger_audit_slot_with_scope),
            (gates.require_semantic_challenge_audit_authority,
             gates._require_semantic_challenge_audit_source),
        ):
            with self.subTest(public=public.__name__):
                self.assertEqual(inspect.signature(public).parameters, inspect.signature(private).parameters)
                for function in (public, private):
                    signature = inspect.signature(function)
                    self.assertFalse(any(
                        parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                        for parameter in signature.parameters.values()
                    ))
                    for name in ("canonical_scope", "entry_snapshot", "skip_validation", "replay_peers"):
                        self.assertNotIn(name, signature.parameters)

    def test_public_wrappers_delegate_once_without_reparsing_or_resolving_scope(self):
        for public, private in (
            (gates.require_semantic_challenger_audit_slot,
             gates._require_semantic_challenger_audit_slot_with_scope),
            (gates.require_semantic_challenge_audit_authority,
             gates._require_semantic_challenge_audit_source),
        ):
            with self.subTest(public=public.__name__):
                tree = _function_tree(public)
                calls = tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call))
                delegated = _calls(tree, private.__name__)
                self.assertEqual(len(delegated), 1)
                extra_names = tuple(
                    node.func.id for node in calls if node not in delegated
                    and isinstance(node.func, ast.Name)
                )
                if public is gates.require_semantic_challenger_audit_slot:
                    self.assertEqual(set(extra_names), {"type", "ValidationError"})
                    self.assertIn(
                        "type(slot) is not SemanticChallengerAuditSlot",
                        ast.unparse(tree),
                    )
                else:
                    self.assertEqual(extra_names, ())
                self.assertEqual(
                    {keyword.arg for keyword in delegated[0].keywords},
                    set(inspect.signature(private).parameters) - {"registry", "ledger"},
                )
                self.assertTrue(all(
                    isinstance(keyword.value, ast.Name) and keyword.value.id == keyword.arg
                    for keyword in delegated[0].keywords
                ))

    def test_slot_returns_its_same_scope_only_after_complete_freshness_tail(self):
        tree = _function_tree(gates._require_semantic_challenger_audit_slot_with_scope)
        self.assertEqual(len(_calls(tree, "_resolve_semantic_challenger_audit_canonical_scope")), 1)
        self.assertEqual(len(_calls(tree, "_require_semantic_challenger_audit_slot_static")), 1)
        self.assertEqual(len(_calls(tree, "_require_semantic_audit_snapshot_before_slot")), 1)
        self.assertEqual(len(tuple(node for node in ast.walk(tree) if isinstance(node, ast.Return))), 1)
        self.assertEqual(tree.body[-2].value.func.id, "_require_semantic_challenger_audit_snapshot_unchanged")
        self.assertEqual(ast.unparse(tree.body[-1].value), "(slot, canonical_scope)")

    def test_full_source_returns_validated_publication_not_verification_or_loose_reference(self):
        # Both exact-profile wrappers must enter this same complete owner.
        # The profile selector cannot replace replay with DTO interpretation.
        for wrapper, cohort in (
            (gates._require_semantic_challenge_audit_source, False),
            (gates._require_semantic_reproduction_cohort_audit_source, True),
        ):
            wrapper_tree = _function_tree(wrapper)
            delegates = _calls(wrapper_tree, "_require_semantic_audit_source")
            self.assertEqual(len(delegates), 1)
            arguments = {item.arg: item.value for item in delegates[0].keywords}
            self.assertIsInstance(arguments["cohort"], ast.Constant)
            self.assertIs(arguments["cohort"].value, cohort)
            self.assertFalse(_calls(wrapper_tree, "_SemanticChallengeAuditReplay"))
            self.assertFalse(_calls(wrapper_tree, "_SemanticReproductionCohortAuditReplay"))
        tree = _function_tree(gates._require_semantic_audit_source)
        for name in (
            "_replay_semantic_challenge_audit_sources",
            "_validate_semantic_challenge_audit_authority_event",
            "_require_semantic_audit_unique_projection",
            "_validate_semantic_challenge_audit_publication_event",
            "_require_semantic_challenger_audit_snapshot_unchanged",
        ):
            self.assertEqual(len(_calls(tree, name)), 1, name)
        self.assertEqual(len(tuple(node for node in ast.walk(tree) if isinstance(node, ast.Return))), 1)
        self.assertEqual(tree.body[-3].value.func.id, "_require_semantic_challenger_audit_snapshot_unchanged")
        self.assertEqual(
            ast.unparse(tree.body[-2]),
            "replay_type = _SemanticReproductionCohortAuditReplay if cohort else _SemanticChallengeAuditReplay",
        )
        returned = tree.body[-1].value
        self.assertEqual(returned.func.id, "replay_type")
        self.assertEqual(
            {keyword.arg: ast.unparse(keyword.value) for keyword in returned.keywords},
            {
                "authority": "authority",
                "record": "record",
                "slot": "sources.slot",
                "canonical_scope": "sources.canonical_scope",
                "publication_event_id": "publication_event.event_id",
                "publication_event_hash": "publication_event.event_hash",
                "publication_event_index": "publication_index",
                "entry_snapshot": "(entry_registry, entry_ledger)",
            },
        )

    def test_both_production_source_constructors_carry_the_already_derived_scope(self):
        for function, scope_name in (
            (gates._semantic_challenger_audit_static_sources, "scope"),
            (gates._replay_semantic_challenge_audit_sources, "canonical_scope"),
        ):
            with self.subTest(function=function.__name__):
                tree = _function_tree(function)
                calls = _calls(tree, "_SemanticChallengeAuditSources")
                self.assertEqual(len(calls), 1)
                arguments = {keyword.arg: ast.unparse(keyword.value) for keyword in calls[0].keywords}
                self.assertEqual(arguments["canonical_scope"], scope_name)
        replay = _function_tree(gates._replay_semantic_challenge_audit_sources)
        self.assertEqual(len(_calls(replay, "_require_semantic_challenger_audit_slot_with_scope")), 1)
        self.assertFalse(_calls(replay, "require_semantic_challenger_audit_slot"))
        self.assertFalse(_calls(replay, "_resolve_semantic_challenger_audit_canonical_scope"))

    def test_historical_private_inert_constructor_can_omit_scope_but_companion_cannot(self):
        # No validator consumes this inert placeholder; this tests constructor
        # compatibility only, without substituting any production owner.
        values = {
            field.name: None for field in fields(gates._SemanticChallengeAuditSources)
            if field.default is MISSING and field.default_factory is MISSING
        }
        source = gates._SemanticChallengeAuditSources(**values)
        self.assertIsNone(source.canonical_scope)
        for scope in (None, SimpleNamespace(state=None)):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValidationError, "replayed canonical scope"):
                gates._SemanticChallengeAuditReplay(
                    authority=self._authority(), record=None, slot=self.slot,
                    canonical_scope=scope, publication_event_id="inert-publication",
                    publication_event_hash=fixtures._digest("inert-publication"),
                    publication_event_index=5, entry_snapshot=(None, None),
                )

    def test_inert_companion_is_frozen_and_cannot_change_slot_or_authority_codec(self):
        authority = self._authority()
        slot_bytes = self._slot_binding_bytes(self.slot)
        authority_bytes = canonical_json_bytes(authority.to_dict())
        scope = self._scope()
        companion = gates._SemanticChallengeAuditReplay(
            authority=authority, record=None, slot=self.slot, canonical_scope=scope,
            publication_event_id="inert-publication",
            publication_event_hash=fixtures._digest("inert-publication"),
            publication_event_index=5, entry_snapshot=(None, None),
        )
        self.assertIs(companion.canonical_scope, scope)
        self.assertIs(companion.authority, authority)
        self.assertIs(companion.slot, self.slot)
        self.assertFalse(companion.authority.scientific_source_qualified)
        self.assertIs(companion.authority.status, gates.SemanticChallengeAuditStatus.UNTESTED)
        self.assertEqual(self._slot_binding_bytes(companion.slot), slot_bytes)
        self.assertEqual(canonical_json_bytes(companion.authority.to_dict()), authority_bytes)
        self.assertEqual(gates.SemanticChallengeAuditAuthority.from_dict(authority.to_dict()), authority)
        with self.assertRaises(FrozenInstanceError):
            companion.canonical_scope = None
        for name in ("canonical_scope", "entry_snapshot", "publication_event_index"):
            changed = {**authority.to_dict(), name: None}
            with self.subTest(field=name), self.assertRaises(ValidationError):
                gates.SemanticChallengeAuditAuthority.from_dict(changed)

    def test_real_missing_slot_refusal_is_identical_and_read_only(self):
        with TemporaryDirectory(prefix="inert-audit-companion-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            errors = []
            for owner in (gates.require_semantic_challenger_audit_slot,
                          gates._require_semantic_challenger_audit_slot_with_scope):
                with self.assertRaises(ValidationError) as caught:
                    owner(registry, ledger, slot_id=self.slot.slot_id, expected_run_id=self.slot.run_id)
                errors.append((type(caught.exception), str(caught.exception)))
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)
            self.assertEqual(errors[0], errors[1])

    def test_closed_unqualified_receipt_cannot_replace_missing_full_source_replay(self):
        with TemporaryDirectory(prefix="inert-audit-companion-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            records = {
                name: registry.put_json(
                    {"inert_kind": name, "scientific_evidence": False},
                    logical_type="non_evidentiary_audit_companion_input",
                    creator_role=gates.Role.ORCHESTRATOR,
                    origin="NON_EVIDENTIARY_OWNER_REFUSAL",
                    creation_command=("fixture-only",),
                    validation_result="PASS", frozen=True,
                )
                for name in ("snapshot", "graph", "result", "judgment", "execution", "review")
            }
            slot = replace(
                self.slot,
                research_state_snapshot_artifact_hash=records["snapshot"].sha256,
                research_state_snapshot_artifact_record_hash=records["snapshot"].record_hash,
                claim_graph_artifact_hash=records["graph"].sha256,
                claim_graph_artifact_record_hash=records["graph"].record_hash,
                evidence_artifact_hashes=(records["snapshot"].sha256,),
                evidence_artifact_record_hashes=(records["snapshot"].record_hash,),
                result_artifact_hashes=(records["result"].sha256,),
                result_artifact_record_hashes=(records["result"].record_hash,),
            )
            authority = self._authority(slot, records)
            # Canonical bytes/metadata do not authenticate the absent prospective
            # slot, canonical scope, judgment or execution. Both full owners refuse.
            record = registry.put_json(
                authority.to_dict(),
                logical_type=gates.SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
                schema_version=gates.SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
                creator_role=gates.Role.ADVERSARIAL_REVIEWER,
                origin=gates._SEMANTIC_CHALLENGE_AUDIT_ORIGIN,
                creation_command=gates._SEMANTIC_CHALLENGE_AUDIT_COMMAND,
                parent_artifacts=authority.input_artifact_hashes,
                mime_type="application/json",
                validation_result="PASS", frozen=True,
            )
            before = (registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True))
            errors = []
            for owner in (gates.require_semantic_challenge_audit_authority,
                          gates._require_semantic_challenge_audit_source):
                with self.assertRaisesRegex(ValidationError, "slot") as caught:
                    owner(registry, ledger, **self._source_options(authority, record))
                errors.append((type(caught.exception), str(caught.exception)))
                self.assertEqual((registry.verify_all(raise_on_error=True), ledger.validate(raise_on_error=True)), before)
            self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
