"""D069 source-structure, inert-value, mechanical and real-negative controls.

No successful scientific owner, completed semantic round, review reuse entry,
or Venue publication is fabricated. The metadata preflight tests never write
their unissued Venue DTOs. Isolated predicates and byte-only preflight views
are not source authority or evidence of a positive scientific lifecycle.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime
import hashlib
import inspect
from types import SimpleNamespace
import traceback
import unittest

from scientist_one import gates, paper_pipeline as paper, research_state as rs
from scientist_one.artifacts import ArtifactRecord, RegistryValidationResult
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests import test_snapshot_reference_replay as fixtures
from tests.test_gates_paper import legacy_placeholder_bundle
from tests.test_paper_bundle_source_companion import _inert_candidate
from tests.test_paper_round_replay import (
    _assert_node, _body_hash, _calls, _dump, _expression, _node,
    _paper_record_chronology_guards, _predicate, _refusal_condition,
)


def _function(value):
    source = inspect.getsource(value)
    # Retain literal docstring bytes in class methods when reconstructing the
    # full-module preimage; dedenting the source would alter those strings.
    return ast.parse("if True:\n" + source).body[0].body[0] if source.startswith(" ") else ast.parse(source).body[0]


_CONTEXT = _expression('{"_round_replay": _round_replay} if _round_replay is not None else {}')
_CUTOFF = _expression('''{"_before_event_index": _round_replay.reviews.before_event_index}
                         if _round_replay is not None else {}''')
_FORWARD_CUTOFF = _expression('''{"_before_event_index": _before_event_index}
                                 if _before_event_index is not None else {}''')
_SOURCE_GUARD = _node('''if _round_replay is not None:
    _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
''')
_ASSESS_ROUTE = _node('''if _round_replay is None:
    fresh_verification = verify_paper(candidate, bundle, registry, ledger)
else:
    source = _require_paper_verification_bundle_source(
        registry, ledger, bundle, _round_replay=_round_replay,
    )
    _require_paper_state_binding_join(_round_replay.audited_state, source.state_authority)
    fresh_verification = _verify_paper_from_replayed_bundle(candidate, source, registry, ledger)
''')
_FINAL_PAPER_ROUTE = _node('''if _round_replay is None:
    verification = require_paper_verification(
        registry, ledger, run_id=run_id,
        verification_artifact_hash=paper_verification_artifact_hash,
        expected_candidate_id=candidate.candidate_id,
    )
else:
    verification, _paper_source = _require_paper_verification_with_round_sources(
        registry, ledger, expected_run_id=run_id,
        verification_artifact_hash=paper_verification_artifact_hash,
        expected_candidate_id=candidate.candidate_id,
        audited_state=_round_replay.audited_state, soundness=_round_replay.soundness,
        review_replay=_round_replay.reviews,
    )
''')
_SEMANTIC_CUTOFF = _node('''if _before_event_index is not None:
    transport = _require_audited_live_semantic_transport(
        registry, ledger, run_id=run_id, receipt=selected,
    )
    events = ledger.validate(raise_on_error=True).events
    index = transport.ledger_prefix_event_count
    if (
        type(_before_event_index) is not int
        or not 0 <= index < _before_event_index < len(events)
        or events[index].event_id != transport.ledger_event_id
        or events[index].event_hash != transport.ledger_event_hash
    ):
        raise ValidationError("Venue semantic admission does not precede its canonical projection")
''')


def _normalize_venue_owner(function):
    """Reconstruct the full saved preimage, admitting only exact added nodes."""
    name = function.__name__
    counts = {key: 0 for key in ("route", "kwargs", "manuscript", "guard", "selector", "selected")}
    expected = {
        "_assess_venue": (1, 3, 0, 0, 0, 0),
        "_resolve_final_venue_inputs": (1, 4, 1, 0, 1, 0),
        "_resolve_venue_readiness_manifest": (0, 0, 1, 0, 0, 0),
        "_resolve_venue_requirement_receipt": (0, 1, 0, 0, 0, 0),
        "_resolve_venue_requirements": (0, 1, 0, 0, 0, 0),
        "_resolve_venue_dimension_assessment": (0, 1, 0, 0, 0, 0),
        "_require_live_venue_semantic_judgment": (0, 0, 0, 1, 0, 1),
        "_require_venue_assessment": (0, 1, 0, 2, 0, 0),
    }

    class Normalize(ast.NodeTransformer):
        def visit_If(self, node):
            if _dump(node) in {_dump(_ASSESS_ROUTE), _dump(_FINAL_PAPER_ROUTE)}:
                _assert_node(node, _ASSESS_ROUTE if name == "_assess_venue" else _FINAL_PAPER_ROUTE)
                counts["route"] += 1
                return deepcopy(node.body)
            if _dump(node) in {_dump(_SOURCE_GUARD), _dump(_SEMANTIC_CUTOFF)}:
                _assert_node(node, _SOURCE_GUARD if name == "_require_venue_assessment" else _SEMANTIC_CUTOFF)
                counts["guard"] += 1
                return None
            return self.generic_visit(node)

        def visit_Assign(self, node):
            if _dump(node) == _dump(_node("venue_assessor = assess_venue if _round_replay is None else _assess_venue")):
                assert name == "_resolve_final_venue_inputs"
                counts["selector"] += 1
                return None
            if name == "_require_live_venue_semantic_judgment" and _dump(node.targets[0]) == _dump(ast.Name(id="selected", ctx=ast.Store())):
                assert len(node.targets) == 1 and isinstance(node.value, ast.Call)
                assert node.value.func.id == "require_scientific_semantic_judgment_receipt"
                counts["selected"] += 1
                return ast.Expr(value=node.value)
            return self.generic_visit(node)

        def visit_Call(self, node):
            callee = node.func.id if isinstance(node.func, ast.Name) else None
            if callee == "_require_venue_manuscript_revision":
                assert name in {"_resolve_venue_readiness_manifest", "_resolve_final_venue_inputs"}
                keyword = next(item for item in node.keywords if item.arg == "_round_replay")
                _assert_node(keyword.value, _expression("_round_replay"))
                node.keywords.remove(keyword)
                node.func.id = "require_paper_manuscript_revision"
                counts["manuscript"] += 1
            if callee == "venue_assessor":
                assert name == "_resolve_final_venue_inputs"
                node.func.id = "assess_venue"
            for keyword in tuple(node.keywords):
                if keyword.arg is not None:
                    continue
                allowed = {
                    "_resolve_venue_readiness_manifest": _CONTEXT,
                    "_resolve_final_venue_inputs": _CONTEXT,
                    "venue_assessor": _CONTEXT,
                    "_resolve_venue_requirements": _CUTOFF,
                    "_resolve_venue_dimension_assessment": _CUTOFF,
                    "_resolve_venue_requirement_receipt": _FORWARD_CUTOFF,
                    "_require_live_venue_semantic_judgment": _FORWARD_CUTOFF,
                }
                assert callee in allowed, (name, callee)
                _assert_node(keyword.value, allowed[callee])
                node.keywords.remove(keyword)
                counts["kwargs"] += 1
            return self.generic_visit(node)

    tree = Normalize().visit(_function(function))
    if name == "_require_venue_assessment":
        _assert_node(tree.body[0], _node('"Full shared Venue owner; private context changes no source obligation."'))
        tree.body[0] = _node('"Rehydrate and freshly replay one final venue-assessment artifact."')
    assert tuple(counts.values()) == expected[name], (name, counts)
    return tree.body


def _inert_authority(run_id="inert-venue-run", *, assessed_at="2026-09-06T00:00:09Z"):
    """Unissued negative value; its labels and hashes grant no source ownership."""
    assessment = paper.VenueAssessment(
        profile_id="ml-ai", classification=paper.VenueFit.NOT_READY,
        dimension_scores=tuple((name, 0.0) for name in paper.READINESS_DIMENSIONS),
        hard_blockers=(paper.HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED,),
        rationale="Non-evidentiary unissued metadata fixture only.",
        run_id=run_id, candidate_artifact_hash="a" * 64, bundle_artifact_hash="b" * 64,
        profile_artifact_hash="c" * 64, readiness_manifest_hash="d" * 64,
        requirement_receipt_hashes=("e" * 64,), dimension_assessment_hashes=("f" * 64,),
    )
    return paper.VenueAssessmentAuthority(
        assessment_id=paper._venue_assessment_identity(
            run_id=run_id, candidate_artifact_hash=assessment.candidate_artifact_hash,
            bundle_artifact_hash=assessment.bundle_artifact_hash,
            profile_artifact_hash=assessment.profile_artifact_hash,
            readiness_manifest_hash=assessment.readiness_manifest_hash,
        ),
        run_id=run_id, candidate_id="inert-candidate", venue_family=paper.VenueFamily.ML_AI,
        evidence_ids=("inert-claim",), assessed_at=assessed_at,
        paper_verification_artifact_hash="1" * 64, assessment=assessment,
    )


class VenueRoundStructureTests(unittest.TestCase):
    def test_complete_old_owner_and_classification_bodies_after_exact_normalization(self):
        # These are hashes of complete bodies in the saved D068 preimage,
        # not hashes refreshed from the new candidate.
        for function, digest in (
            (paper._assess_venue, "cc36629850e399ceed41cae621e021f8c0b1d852deb6fc2ae4976ed31f8ee4a7"),
            (paper._require_venue_assessment, "e176316555aaf9be8d48a990ec41aabeb77a4166ecd944f3ca693306349855f5"),
            (paper._resolve_final_venue_inputs, "9c02d1d5f7e8e04d8fac10328713f65417b7e63020d7c0a2640b7db61e40d120"),
            (paper._resolve_venue_readiness_manifest, "e5d4cf775e1725fb6b2f0d46fcd64c3d6f7b2c0c698550b3eb6c3300d295cbf1"),
            (paper._require_live_venue_semantic_judgment, "763996b5094ee8cb288b685a66a534ccfe03421dbd0a3ab752ad6543848901b9"),
            (paper._resolve_venue_requirement_receipt, "041a092d6f9f9f22aa49b8afca4f9cbac9504df21a2a87144f16d84c37301ddc"),
            (paper._resolve_venue_requirements, "76769d1bdda1d9fa6fa280aec3ea65d0160a4675ad0762fd844c1cfd5f09220a"),
            (paper._resolve_venue_dimension_assessment, "988f3da68d4ec48d4a393a277b507954ef7f1178778502473148ef9cd88e4129"),
        ):
            with self.subTest(function=function.__name__):
                self.assertEqual(_body_hash(_normalize_venue_owner(function)), digest)

    def test_public_signatures_and_closed_values_slots_and_codecs_unchanged(self):
        for function, digest in (
            (paper.assess_venue, "f57bea6267375a03e025608be4fc00244603875f78c29fd77a6f062d0d098206"),
            (paper.require_venue_assessment, "8e4e8eb4b9aecdad5f8e21fa38b76f49d59244b671390b13b6c49f6be6081c4a"),
            (paper.register_venue_assessment, "96fad841e25e5e2abcd22e05d4cfd601d12f6bab3499850820febe8d7fee0be4"),
        ):
            self.assertEqual(hashlib.sha256(_dump(_function(function).args).encode()).hexdigest(), digest)
            self.assertNotIn("_round_replay", inspect.signature(function).parameters)
        for value, digest in (
            (paper.VenueAssessment, "4ce11092e645c2c26dc5f3094836c7fe67c5182dbe692e255ecf88b29fcffc1c"),
            (paper.VenueAssessmentAuthority, "1b30775487cf66652dae89b720f7895acc1c99bd47b61524abd6500f4f0d4514"),
            (paper._venue_assessment_from_json, "c71508af62dd4eb463134092a3ad82715c62a943bc5cdfdd6cde0fc48da538a0"),
            (paper._venue_assessment_authority_from_json, "d2f7f9e008c7ab880ebbdf4f0ab5a5ae19676e1ffe99d433a24afccfc3595828"),
            (paper._venue_assessment_identity, "8d0282fccc4d58d4f2a1e8f746499ff9bd68a7f48b92405fe31e618e5b097786"),
            (paper._final_venue_records, "29ddb546f34510e3f69928fdc64d9a5f16f9a252e56864a409e53f3190f43959"),
        ):
            with self.subTest(value=value.__name__):
                self.assertEqual(_body_hash(_function(value).body), digest)
        for public, private in ((paper.assess_venue, "_assess_venue"),
                                (paper.require_venue_assessment, "_require_venue_assessment")):
            calls = _calls(_function(public).body, private)
            self.assertEqual(len(calls), 1)
            self.assertFalse(any(item.arg is None or item.arg == "_round_replay" for item in calls[0].keywords))

    def test_full_native_canonical_conjunction_is_exactly_extracted_not_replaced(self):
        projection = _function(rs.ResearchStateRepository._require_final_venue_projection)
        _assert_node(projection.body[1], _node("from .paper_pipeline import VenueFit as PaperVenueFit"))
        counts = {"import": 0, "projection": 0}

        class Restore(ast.NodeTransformer):
            def visit_ImportFrom(self, node):
                if node.module == "paper_pipeline" and [item.name for item in node.names] == ["require_venue_assessment"]:
                    _assert_node(node, _node("from .paper_pipeline import require_venue_assessment"))
                    node.names.insert(0, ast.alias(name="VenueFit", asname="PaperVenueFit"))
                    counts["import"] += 1
                return node

            def visit_Expr(self, node):
                expected = _node('''self._require_final_venue_projection(
                    record, by_content, assessment_record=assessment_record, authority=authority,
                )''')
                if _dump(node) == _dump(expected):
                    counts["projection"] += 1
                    return deepcopy(projection.body[2:])
                return self.generic_visit(node)

        restored = Restore().visit(_function(rs.ResearchStateRepository._resolve_object_authority))
        self.assertEqual(counts, {"import": 1, "projection": 1})
        self.assertEqual(_body_hash(restored.body), "50e492fdb2b53cfa4122c6bf9c7fe4b84ed43b06123864b8c8cd778d08fe09fa")

    def test_venue_reuse_only_expands_exact_type_set_and_never_eligibility(self):
        tree = _function(rs._SameRoundReviewReplay)
        matches = [node for node in ast.walk(tree) if isinstance(node, ast.Set)
                   and _dump(node) == _dump(_expression("{Challenge, Critique, Decision, VenueAssessment}"))]
        self.assertEqual(len(matches), 1)
        matches[0].elts.pop()
        self.assertEqual(_body_hash(tree.body), "38cc7a56f24006d0e3f97885351c467130a44bc959ae66ab2906551361652ee2")
        self.assertEqual(_body_hash(_function(rs._resolve_object_with_replayed_review).body),
                         "d3673f8081a26913ebf341d4cb2ffc8714082a6007074740b01b9e95bc8e6b73")
        self.assertIs(rs._ResolvedObjectAuthority(()).scientific_evidence_eligible, False)

    def test_strict_venue_source_checks_epoch_before_after_and_keeps_full_owner(self):
        body = _function(paper._require_venue_assessment_with_round_sources).body
        guards = _calls(body, "_require_paper_round_sources")
        full = _calls(body, "_require_venue_assessment")
        self.assertEqual((len(guards), len(full)), (2, 1))
        self.assertLess(guards[0].lineno, full[0].lineno)
        self.assertLess(full[0].lineno, guards[1].lineno)
        self.assertFalse(any(isinstance(node, ast.ExceptHandler) for node in ast.walk(_function(paper._require_venue_assessment_with_round_sources))))
        owner = _function(paper._require_venue_assessment).body
        sources = _calls(owner, "_require_paper_round_sources")
        self.assertEqual(len(sources), 2)
        self.assertLess(sources[0].lineno, _calls(owner, "_read_registry_json")[0].lineno)
        self.assertLess(_calls(owner, "_final_venue_records")[0].lineno, sources[1].lineno)
        self.assertLess(sources[1].lineno, owner[-1].lineno)

    def test_manifest_and_final_readback_both_replay_current_manuscript_then_admission(self):
        body = _function(paper._require_venue_manuscript_revision).body
        default = next(node for node in body if isinstance(node, ast.If))
        _assert_node(default, _node('''if _round_replay is None:
            return require_paper_manuscript_revision(registry, ledger, revision_artifact_hash=revision_artifact_hash)
        '''))
        full = _calls(body, "_require_paper_manuscript_revision")
        cutoff = _calls(body, "_require_venue_prior_event")
        self.assertEqual((len(full), len(cutoff)), (1, 1))
        self.assertLess(full[0].lineno, cutoff[0].lineno)
        _assert_node(cutoff[0], _expression("_require_venue_prior_event(_round_replay, revision.issuance_event)"))
        for function in (paper._resolve_venue_readiness_manifest, paper._resolve_final_venue_inputs):
            self.assertEqual(len(_calls(_function(function).body, "_require_venue_manuscript_revision")), 1)
        body = _function(paper._resolve_final_venue_inputs).body
        order = [
            _calls(body, name)[0].lineno for name in (
                "_require_paper_verification_with_round_sources", "_resolve_venue_readiness_manifest",
                "_require_venue_manuscript_revision", "_resolve_venue_requirements", "_resolve_venue_dimension_assessment",
            )
        ]
        self.assertEqual(order, sorted(order))
        # F and Soundness remain complete shared paper owners, not a new Venue cache.
        alternate = _ASSESS_ROUTE.orelse
        self.assertEqual([_calls(alternate, name)[0].lineno for name in (
            "_require_paper_verification_bundle_source", "_require_paper_state_binding_join", "_verify_paper_from_replayed_bundle",
        )], sorted(_calls(alternate, name)[0].lineno for name in (
            "_require_paper_verification_bundle_source", "_require_paper_state_binding_join", "_verify_paper_from_replayed_bundle",
        )))

    def test_audit_native_projection_has_no_legacy_or_failed_source_fallback(self):
        body = _function(gates._semantic_challenger_audit_exact_venue_projection).body
        names = ("_validate_canonical_ancestry_budget", "_authority_records", "_require_exact_authority_roles",
                 "_require_venue_assessment_with_round_sources", "_require_final_venue_projection")
        order = [_calls(body, name)[0].lineno for name in names]
        self.assertEqual(order, sorted(order))
        self.assertEqual([len(_calls(body, name)) for name in names], [1] * len(names))
        text = inspect.getsource(gates._semantic_challenger_audit_exact_venue_projection)
        self.assertIn('len(records) != 1 or records[0].origin != (', text)
        self.assertIn('fresh deterministic venue assessment over exact paper authority', text)
        self.assertFalse(_calls(body, "_resolve_object_authority"))
        self.assertFalse(_calls(body, "assess_venue"))
        self.assertFalse(_calls(body, "require_venue_assessment"))
        self.assertLess(_calls(body, names[-1])[0].lineno,
                        next(node.lineno for node in ast.walk(_function(gates._semantic_challenger_audit_exact_venue_projection))
                             if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and node.value.value is True))

    def test_gateway_full_owner_return_keeps_entire_old_replay_body(self):
        tree = _function(gates._require_audited_live_semantic_transport)
        _assert_node(tree.body[-1], _node("return authority"))
        self.assertEqual(_body_hash(tree.body[:-1]), "9d6de9b1d4af79ed0042e8a872afba9cb7e21fc7c619382074dece231a053ed8")
        body = _function(paper._require_live_venue_semantic_judgment).body
        self.assertEqual(_dump(body[-1]), _dump(_SEMANTIC_CUTOFF))
        full = _calls(body, "require_scientific_semantic_judgment_receipt")
        transport = _calls(body, "_require_audited_live_semantic_transport")
        self.assertEqual((len(full), len(transport)), (2, 1))
        self.assertTrue(all(item.lineno < transport[0].lineno for item in full))

    def test_publication_preserves_source_prefix_and_orders_full_CAS_and_readback(self):
        body = _function(paper.register_venue_assessment).body
        before = _node("before = _locked_research_state_source_snapshot(registry, ledger, run_id=run_id)")
        _assert_node(body[1], before)
        parent_index = next(index for index, node in enumerate(body) if isinstance(node, ast.Assign)
                            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "parents")
        self.assertEqual(_body_hash([body[0], *body[2:parent_index + 1]]),
                         "87e0655e19077884e818876e2b249ed606b7c9295d100ee04b74e38380e1e5e5")
        names = ("_resolve_final_venue_inputs", "_preflight_venue_publication", "_final_venue_records",
                 "_open_mutation_lock", "_open_lock", "_put_bytes_locked", "require_venue_assessment")
        order = [_calls(body, name)[0].lineno for name in names]
        self.assertEqual(order, sorted(order))
        self.assertEqual([len(_calls(body, name)) for name in names], [1] * len(names))
        write = _calls(body, "_put_bytes_locked")[0]
        cas = _refusal_condition(paper.register_venue_assessment, "Venue sources changed before publication")
        self.assertLess(cas.lineno, write.lineno)
        guard = next(node for node in ast.walk(_function(paper.register_venue_assessment))
                     if isinstance(node, ast.If) and _dump(node.test) == _dump(_expression("record is None")))
        self.assertEqual(len(_calls(guard.body, "_put_bytes_locked")), 1)
        self.assertFalse(_calls(body, "append"))
        self.assertFalse(_calls(body, "_append_locked"))
        self.assertLess(_calls(body, "require_venue_assessment")[0].lineno,
                        _calls(body, "_locked_research_state_source_snapshot")[-1].lineno)
        _assert_node(body[-1], _node("return record"))


class VenueRoundInertAndNegativeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SnapshotReferenceReplayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.ledger, self.state = self.fixture.registry, self.fixture.ledger, self.fixture.state

    def _state(self):
        return self.registry.list_records(), self.ledger.events()

    def test_missing_public_sources_and_invalid_private_round_refuse_without_delta(self):
        before = self._state()
        with self.assertRaises(ArtifactError):
            paper.require_venue_assessment(self.registry, self.ledger, run_id=self.state.run_id,
                                           assessment_artifact_hash="f" * 64)
        with self.assertRaisesRegex(ValidationError, "exact completed sources"):
            paper._require_venue_assessment_with_round_sources(
                self.registry, self.ledger, run_id=self.state.run_id,
                assessment_artifact_hash="f" * 64, audited_state=self.state,
                soundness=None, review_replay=None,
            )
        bundle = replace(
            legacy_placeholder_bundle(), run_id=self.state.run_id,
            research_state_hash=self.state.snapshot_artifact_sha256,
            research_state_artifact_hashes=tuple(item.artifact_sha256 for item in self.state.entries),
            research_state_ledger_head_hash=self.state.ledger_head_hash,
            research_state_ledger_event_count=self.state.ledger_event_count,
            research_state_code_version=self.state.code_version,
            research_state_configuration_hash=self.state.configuration_hash,
        )
        frames = []
        with self.assertRaises((ArtifactError, ValidationError)):
            try:
                paper.register_venue_assessment(
                    self.registry, self.ledger, _inert_candidate(), bundle, paper.default_venue_profiles()[0],
                    run_id=self.state.run_id, candidate_artifact_hash="a" * 64,
                    bundle_artifact_hash="b" * 64, paper_verification_artifact_hash="c" * 64,
                    profile_artifact_hash="d" * 64, readiness_manifest_hash="e" * 64,
                    requirement_receipt_hashes=("1" * 64,), dimension_assessment_hashes=("2" * 64,),
                )
            except (ArtifactError, ValidationError) as exc:
                frames = [item.name for item in traceback.extract_tb(exc.__traceback__)]
                raise
        self.assertIn("_resolve_final_venue_inputs", frames)
        self.assertIn("_resolve_candidate_bundle_artifacts", frames)
        self.assertEqual(self._state(), before)

    def test_default_current_manuscript_route_reaches_real_missing_owner(self):
        before = self._state()
        frames = []
        with self.assertRaises((ArtifactError, ValidationError)):
            try:
                paper._require_venue_manuscript_revision(self.registry, self.ledger,
                                                        revision_artifact_hash="f" * 64)
            except (ArtifactError, ValidationError) as exc:
                frames = [item.name for item in traceback.extract_tb(exc.__traceback__)]
                raise
        self.assertIn("_require_paper_manuscript_revision", frames)
        self.assertEqual(self._state(), before)

    def test_public_unowned_scores_remain_source_free_not_ready_diagnostics(self):
        verification = paper.PaperVerification(False, (), ("inert-not-verified",), ())
        profile = paper.default_venue_profiles()[0]
        for score in (0.0, 1.0):
            scores = {name: score for name in paper.READINESS_DIMENSIONS}
            public = paper.assess_venue(profile, verification, scores,
                                        external_validation_complete=True, rationale="Inert caller summary only.")
            private = paper._assess_venue(profile, verification, scores,
                                          external_validation_complete=True, rationale="Inert caller summary only.")
            self.assertEqual(public, private)
            self.assertIs(public.classification, paper.VenueFit.NOT_READY)
            self.assertIsNone(public.run_id)
            self.assertTrue(all(score == 0 for _, score in public.dimension_scores))
            self.assertIn(paper.HardBlocker.VENUE_REQUIREMENTS_UNRESOLVED, public.hard_blockers)

    def test_actual_event_identity_and_strict_cutoff_not_wall_clock_proxy(self):
        # Actual mechanical events, passed only to the isolated identity helper.
        # The namespace is deliberately not a completed _PaperRoundReplay.
        events = self.ledger.events()
        self.assertGreaterEqual(len(events), 2)
        def replay(items=events, cutoff=1):
            return SimpleNamespace(reviews=SimpleNamespace(
                ledger_snapshot=SimpleNamespace(events=items), before_event_index=cutoff,
            ))
        self.assertIsNone(paper._require_venue_prior_event(replay(), events[0]))
        for context, event in ((replay(), events[1]), (replay(cutoff=len(events)), events[0]),
                               (replay(), replace(events[0], reason="unowned identity substitution", event_hash=None)),
                               (replay(items=(events[0], events[0], events[1]), cutoff=2), events[0])):
            with self.subTest(event=event.event_id), self.assertRaisesRegex(ValidationError, "does not precede"):
                paper._require_venue_prior_event(context, event)

    def test_gateway_cutoff_uses_owned_event_id_hash_and_index(self):
        predicate = _SEMANTIC_CUTOFF.body[-1].test
        event = self.ledger.events()[0]
        def rejected(*, index=0, cutoff=1, identity=None, digest=None):
            return _predicate(predicate, type=type, int=int, _before_event_index=cutoff, index=index,
                              events=(event, event), transport=SimpleNamespace(
                                  ledger_event_id=event.event_id if identity is None else identity,
                                  ledger_event_hash=event.event_hash if digest is None else digest))
        self.assertFalse(rejected())
        for changes in ({"index": -1}, {"index": 1}, {"cutoff": True}, {"cutoff": 0},
                        {"cutoff": 2}, {"identity": "other-admission"}, {"digest": "f" * 64}):
            with self.subTest(changes=changes):
                self.assertTrue(rejected(**changes))

    def test_venue_rollback_only_relaxes_terminal_clock_not_internal_source_order(self):
        guards = _paper_record_chronology_guards()
        def rejected(kind, times):
            records = [SimpleNamespace(created_at=f"2026-09-06T00:00:{value:02d}Z") for value in times]
            return any(_predicate(
                guard, timestamp=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")),
                soundness=SimpleNamespace(record=records[0]),
                stored=SimpleNamespace(bundle_record=records[1], candidate_record=records[2], record=records[3]),
                cutoff=SimpleNamespace(timestamp=records[4].created_at, metadata={"object_type": kind}),
            ) for guard in guards)
        for kind in ("VenueAssessment", "Decision", None, "VenueAssessment-substitute"):
            self.assertFalse(rejected(kind, (1, 2, 3, 4, 5)))
            self.assertEqual(rejected(kind, (1, 2, 3, 4, 0)), kind != "VenueAssessment")
            for times in ((2, 1, 3, 4, 5), (1, 3, 2, 4, 5), (1, 2, 4, 3, 5)):
                self.assertTrue(rejected(kind, times))

    def test_inert_preflight_exact_bytes_metadata_and_no_registry_admission(self):
        before = self._state()
        authority = _inert_authority(self.state.run_id)
        snapshot = self.registry.verify_all(raise_on_error=True)
        parents = (snapshot.records[0].sha256,)
        raw, existing, planned = paper._preflight_venue_publication(self.registry, snapshot, authority, parents)
        self.assertIsNone(existing)
        self.assertIs(type(planned), ArtifactRecord)
        self.assertEqual(raw, canonical_json_bytes(authority.to_dict()) + b"\n")
        self.assertEqual(planned.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(planned.size, len(raw))
        self.assertEqual(planned.parent_artifacts, parents)
        self.assertEqual((planned.logical_type, planned.schema_version, planned.creator_role, planned.created_at),
                         ("venue_readiness_assessment", "1.0", Role.SCIENTIFIC_REVIEWER, authority.assessed_at))
        self.assertEqual((planned.origin, planned.creation_command), (paper._VENUE_ASSESSMENT_ORIGIN, paper._VENUE_ASSESSMENT_COMMAND))
        self.assertEqual(paper._venue_assessment_authority_from_json(authority.to_dict()), authority)
        with self.assertRaises(FrozenInstanceError):
            authority.assessed_at = "substituted"
        with self.assertRaises(ArtifactError):
            paper.require_venue_assessment(self.registry, self.ledger, run_id=self.state.run_id,
                                           assessment_artifact_hash=planned.sha256)
        self.assertEqual(self._state(), before)

    def test_inert_preflight_same_slot_requires_exact_bytes_and_all_metadata(self):
        authority = _inert_authority(self.state.run_id)
        snapshot = self.registry.verify_all(raise_on_error=True)
        parents = (snapshot.records[0].sha256,)
        raw, _, planned = paper._preflight_venue_publication(self.registry, snapshot, authority, parents)

        class BytesOnlyView:
            # Only this pure planning helper receives this local byte view.
            # No registry writer or full source owner is replaced or invoked.
            _object_relative = self.registry._object_relative
            _metadata_relative = self.registry._metadata_relative

            def __init__(self, observed):
                self.observed = observed

            def get_bytes(self, digest):
                assert digest == planned.sha256
                return self.observed

        completed_shape = replace(snapshot, records=(*snapshot.records, planned))
        self.assertEqual(paper._preflight_venue_publication(BytesOnlyView(raw), completed_shape, authority, parents),
                         (raw, planned, planned))
        for field, value in (("origin", "inert substitution"), ("created_at", "2026-09-07T00:00:00Z"),
                             ("schema_version", "2.0"), ("parent_artifacts", ()),
                             ("validation_result", "PENDING"), ("frozen", False)):
            changes = {field: value}
            if field == "validation_result":
                changes["frozen"] = False
            changed = replace(planned, **changes, record_hash=None)
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                paper._preflight_venue_publication(BytesOnlyView(raw), replace(snapshot, records=(*snapshot.records, changed)), authority, parents)
        for observed in (raw[:-1], raw + b"\n", raw.replace(b"NOT_READY", b"UNCERTAIN")):
            with self.subTest(observed=observed[-15:]), self.assertRaisesRegex(ValidationError, "different bytes or metadata"):
                paper._preflight_venue_publication(BytesOnlyView(observed), completed_shape, authority, parents)

    def test_preflight_parent_and_registry_capacity_guards_are_complete_and_inclusive(self):
        predicate = _refusal_condition(paper._preflight_venue_publication, "Venue publication lacks source or registry capacity")
        def rejected(*, n=256, duplicate=False, absent=False, count=9999, existing=None):
            parents = tuple(f"{index:064x}" for index in range(n))
            indexed = dict.fromkeys(parents)
            if duplicate:
                parents = (*parents[:-1], parents[0])
            if absent:
                indexed.pop(parents[0])
            return _predicate(predicate, set=set, int=int, parents=parents, indexed=indexed,
                              snapshot=SimpleNamespace(count=count), existing=existing,
                              MAX_ARTIFACT_PARENTS=paper.MAX_ARTIFACT_PARENTS,
                              MAX_REGISTRY_RECORDS=paper.MAX_REGISTRY_RECORDS)
        self.assertFalse(rejected())
        self.assertFalse(rejected(count=10000, existing=object()))
        for changes in ({"n": 257}, {"duplicate": True}, {"absent": True},
                        {"count": 10000}, {"count": 10001, "existing": object()}):
            with self.subTest(changes=changes):
                self.assertTrue(rejected(**changes))
        snapshot = self.registry.verify_all(raise_on_error=True)
        with self.assertRaisesRegex(ValidationError, "source or registry capacity"):
            paper._preflight_venue_publication(self.registry, snapshot, _inert_authority(), ("f" * 64,))

    def test_publication_delta_is_zero_or_one_exact_record_and_no_ledger_change(self):
        predicate = _refusal_condition(paper.register_venue_assessment, "Venue publication produced an unexpected source delta")
        record = self.registry.list_records()[0]
        planned = replace(record, sha256="f" * 64, record_hash=None)
        def rejected(*, exists=False, observed=None, extra=False, changed_ledger=False, changed_record=False):
            before_records = (record, planned) if exists else (record,)
            expected = {item.sha256: item for item in (*before_records, planned)}
            after_records = tuple(expected.values()) if observed is None else observed
            if extra:
                after_records += (replace(record, sha256="e" * 64, record_hash=None),)
            return _predicate(predicate, int=int, record=record if changed_record else planned,
                              planned=planned, existing_record=planned if exists else None,
                              before=(RegistryValidationResult(True, before_records), "exact-ledger"),
                              after_registry=RegistryValidationResult(True, after_records), expected=expected,
                              after_ledger="changed" if changed_ledger else "exact-ledger")
        self.assertFalse(rejected())
        self.assertFalse(rejected(exists=True))
        for changes in ({"observed": (record,)}, {"extra": True}, {"changed_ledger": True}, {"changed_record": True}):
            with self.subTest(changes=changes):
                self.assertTrue(rejected(**changes))


if __name__ == "__main__":
    unittest.main()
