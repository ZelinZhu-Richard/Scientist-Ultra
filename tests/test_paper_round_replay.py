"""D068 mechanical, pure-identity, and real-negative controls only.

No completed semantic round, scientific source owner, or paper approval is
fabricated or mocked. A real mechanical snapshot exercises the default bound
route; isolated AST predicates exercise chronology without claiming that their
inputs establish a valid round. Historical body goldens normalize only the
explicit, exactly checked private-context plumbing, not arbitrary new code.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime
import hashlib
import inspect
from textwrap import dedent
import traceback
from types import SimpleNamespace
import unittest

from scientist_one import gates, paper_pipeline as paper, research_state as rs
from scientist_one import scientific_cohort_bundle as cohort_bundle, terminal_outcomes as terminal
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.roles import Role
from tests.test_gates_paper import legacy_placeholder_bundle
from tests.test_paper_bundle_source_companion import _inert_candidate
from tests import test_snapshot_reference_replay as snapshot_fixtures
from tests.test_paper_verification_shared_replay import _portable_ast_dump


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _dump(value):
    return _portable_ast_dump(value)


def _body_hash(body):
    return hashlib.sha256(_dump(ast.Module(body=body, type_ignores=[])).encode()).hexdigest()


def _node(text):
    nodes = ast.parse(dedent(text)).body
    assert len(nodes) == 1
    return nodes[0]


def _expression(text):
    return ast.parse("(" + dedent(text).strip() + ")", mode="eval").body


def _calls(body, name):
    tree = ast.Module(body=body, type_ignores=[])
    return tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Name) and node.func.id == name)
                      or (isinstance(node.func, ast.Attribute) and node.func.attr == name)))


def _assert_node(actual, expected):
    assert _dump(actual) == _dump(expected), (_dump(actual), _dump(expected))


_ROUND_BUILD_GUARD = _node('''
    if _round_replay is not None:
        raise ValidationError("same-round paper construction requires fully replayed F")
''')

_LIVE_SOUNDNESS_INITIAL = _node('''use_live_soundness = (
    _round_replay is not None or bool(canonical_confirmatory_claim_authorities)
)''')
_LIVE_SOUNDNESS_SHAPE_ROUTE = _node('''if not use_live_soundness:
    use_live_soundness = _semantic_challenger_audit_parse_soundness(
        registry, registry.get_metadata(soundness_assessment_hash)
    ).run_id is not None
''')


class _NormalizePaperRoundRouting(ast.NodeTransformer):
    """Reconstruct old full-owner calls, permitting only exact D068 plumbing."""

    def __init__(self, function_name):
        self.function_name = function_name

    def visit_If(self, node):
        if _dump(node) in {_dump(_ROUND_BUILD_GUARD), _dump(_LIVE_SOUNDNESS_SHAPE_ROUTE)}:
            assert self.function_name == "_build_authoritative_research_bundle"
            return None
        return self.generic_visit(node)

    def visit_Assign(self, node):
        if _dump(node) == _dump(_LIVE_SOUNDNESS_INITIAL):
            assert self.function_name == "_build_authoritative_research_bundle"
            return None
        return self.generic_visit(node)

    def visit_Call(self, node):
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if self.function_name == "_build_authoritative_research_bundle" and name == "_resolve_soundness":
            for keyword in node.keywords:
                if keyword.arg in {"ledger", "run_id"}:
                    _assert_node(keyword.value, _expression(f"{keyword.arg} if use_live_soundness else None"))
                    keyword.value = _expression(f"{keyword.arg} if canonical_confirmatory_claim_authorities else None")
        if name == "_resolve_paper_bound_state":
            _assert_node(node, _expression(
                "_resolve_paper_bound_state(registry, ledger, bundle, replay=_round_replay)"
            ))
            run = "run_id" if self.function_name == "_build_authoritative_research_bundle" else "bundle.run_id"
            return _expression(f'''resolve_bound_research_state_authority(
                registry, ledger, run_id={run},
                snapshot_artifact_hash=bundle.research_state_hash,
                state_artifact_hashes=bundle.research_state_artifact_hashes,
                ledger_head_hash=bundle.research_state_ledger_head_hash,
                ledger_event_count=bundle.research_state_ledger_event_count,
                expected_code_version=bundle.research_state_code_version,
                expected_configuration_hash=bundle.research_state_configuration_hash,
            )''')
        for keyword in tuple(node.keywords):
            if keyword.arg == "_round_replay":
                assert (self.function_name, name) in {
                    ("_build_authoritative_research_bundle", "_resolve_soundness"),
                    ("_require_paper_verification_bundle_source", "_build_authoritative_research_bundle"),
                    ("_require_paper_verification_bundle_source", "_find_issued_authoritative_bundle"),
                    ("_find_issued_authoritative_bundle", "_require_authoritative_bundle_issuance"),
                }
                _assert_node(keyword.value, _expression("_round_replay"))
                node.keywords.remove(keyword)
        return self.generic_visit(node)


def _normalize_paper_round_body(function):
    tree = _function(function)
    if function.__name__ == "_resolve_soundness":
        branch = tree.body[0]
        assert isinstance(branch, ast.If)
        _assert_node(branch.test, _expression("_round_replay is None"))
        # Its old default owner body remains intact. The alternate exact-source
        # branch has separate type, epoch, identity and call-order controls.
        tree.body[:1] = branch.body
    tree = _NormalizePaperRoundRouting(function.__name__).visit(tree)
    return tree.body


_AUDIT_ROUND_ADDITIONS = tuple(_node(text) for text in (
    "from .research_state import _ReplayedCanonicalReview, _SameRoundReviewReplay",
    '''paper_replay_required = any(
        item.object_type == "Decision"
        and thaw_json(item.metadata).get("terminal_source_kind") == "PAPER_VERIFICATION"
        for _index, item, _artifact in post_snapshot_reviews
    )''',
    "paired_snapshot = None",
    '''if paper_replay_required:
        paired_snapshot = _locked_semantic_challenger_audit_snapshot(
            registry, ledger, run_id=state.run_id,
        )
        if paired_snapshot[1] != ledger_result:
            raise ValidationError("paper round ledger changed before source replay")''',
    "replayed_reviews: list[_ReplayedCanonicalReview] = []",
    '''if paired_snapshot is not None:
        replayed_reviews.append(_ReplayedCanonicalReview(
            research_object=record, artifact=artifact,
            authority_records=repository._authority_records(record),
            materialization_event_index=event_index,
        ))''',
    '''if paired_snapshot is not None:
        _require_semantic_challenger_audit_snapshot_unchanged(
            registry, ledger, run_id=state.run_id,
            expected_registry=paired_snapshot[0], expected_ledger=paired_snapshot[1],
        )''',
))

_AUDIT_CONTEXT = _expression('''
    _SameRoundReviewReplay(
        run_id=state.run_id, code_version=state.code_version,
        configuration_hash=state.configuration_hash,
        before_event_index=event_index,
        registry_snapshot=paired_snapshot[0], ledger_snapshot=paired_snapshot[1],
        reviews=tuple(replayed_reviews),
    ) if paired_snapshot is not None
         and thaw_json(record.metadata).get("terminal_source_kind") == "PAPER_VERIFICATION"
      else None
''')


_VENUE_AUDIT_ROUTE = _node('''paper_replay_required = any(
    item.object_type == "VenueAssessment"
    or (
        item.object_type == "Decision"
        and thaw_json(item.metadata).get("terminal_source_kind") == "PAPER_VERIFICATION"
    )
    for _index, item, _artifact in post_snapshot_reviews
)''')
_VENUE_SOURCE_GUARD = _node('''if record.object_type == "VenueAssessment" and (
    len(record.authority_artifact_hashes) != 1
    or source_types.get(record.authority_artifact_hashes[0])
    != "venue_readiness_assessment"
):
    raise ValidationError("newly related venue lacks its exact source authority")
''')
_OLD_VENUE_REFUSAL = _node('''if record.object_type == "VenueAssessment":
    raise ValidationError(
        "semantic audit scientific core changed: newly related venue "
        "assessment has no complete same-round source replay"
    )
''')
_VENUE_AUDIT_BRANCH = _node('''if record.object_type == "VenueAssessment":
    admitted = _semantic_challenger_audit_exact_venue_projection(
        registry, repository, record, soundness=soundness,
        accepted_objects=accepted_objects, accepted_artifacts=accepted_artifacts,
        audited_state=state,
        review_replay=(
            _SameRoundReviewReplay(
                run_id=state.run_id, code_version=state.code_version,
                configuration_hash=state.configuration_hash,
                before_event_index=event_index,
                registry_snapshot=paired_snapshot[0], ledger_snapshot=paired_snapshot[1],
                reviews=tuple(replayed_reviews),
            ) if paired_snapshot is not None else None
        ),
    )
''')


def _normalize_venue_audit_additions(body):
    """Restore D068 only after matching every complete D069 routing node."""
    counts = {"route": 0, "guard": 0, "branch": 0}

    class Normalize(ast.NodeTransformer):
        def visit_Assign(self, node):
            if _dump(node) == _dump(_VENUE_AUDIT_ROUTE):
                counts["route"] += 1
                return deepcopy(_AUDIT_ROUND_ADDITIONS[1])
            return self.generic_visit(node)

        def visit_If(self, node):
            if _dump(node) == _dump(_VENUE_SOURCE_GUARD):
                counts["guard"] += 1
                # Removing the new branch alone would lose the old refusal.
                return deepcopy(_OLD_VENUE_REFUSAL)
            if _dump(node) == _dump(_VENUE_AUDIT_BRANCH):
                counts["branch"] += 1
                return None
            return self.generic_visit(node)

    tree = Normalize().visit(ast.Module(body=deepcopy(body), type_ignores=[]))
    assert counts == {"route": 1, "guard": 1, "branch": 1}, counts
    return tree.body


def _normalize_audit_round_tail(body):
    """Normalize exact D069, then D068 nodes, retaining the old tail golden."""
    body = _normalize_venue_audit_additions(body)
    expected = {_dump(node) for node in _AUDIT_ROUND_ADDITIONS}
    counts = dict.fromkeys(expected, 0)

    class Normalize(ast.NodeTransformer):
        def visit(self, node):
            identity = _dump(node)
            if identity in expected:
                counts[identity] += 1
                return None
            return super().visit(node)

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "_semantic_challenger_audit_exact_decision_projection":
                removed = set()
                for keyword in tuple(node.keywords):
                    if keyword.arg in {"audited_state", "review_replay"}:
                        expected_value = _expression("state") if keyword.arg == "audited_state" else _AUDIT_CONTEXT
                        _assert_node(keyword.value, expected_value)
                        node.keywords.remove(keyword)
                        removed.add(keyword.arg)
                assert removed == {"audited_state", "review_replay"}
            return self.generic_visit(node)

    tree = Normalize().visit(ast.Module(body=deepcopy(body), type_ignores=[]))
    assert set(counts.values()) == {1}, counts
    return tree.body


def _refusal_condition(function, message):
    """Extract only one existing rejection predicate, never an owner body."""
    candidates = []
    for node in ast.walk(_function(function)):
        if isinstance(node, ast.If) and any(
            isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call)
            and statement.exc.args and isinstance(statement.exc.args[0], ast.Constant)
            and statement.exc.args[0].value == message
            for statement in node.body
        ):
            candidates.append(node.test)
    assert len(candidates) == 1
    return candidates[0]


def _predicate(expression, **inputs):
    # Inert native scalars and namespace leaves only; these never enter a full
    # owner. This tests the actual guard expression, not a duplicate formula.
    namespace = {"__builtins__": {}, "len": len, "any": any, "bool": bool, **inputs}
    code = compile(ast.fix_missing_locations(ast.Expression(deepcopy(expression))), "<inert-guard>", "eval")
    return eval(code, namespace)


def _paper_record_chronology_guards():
    """Exact D069 split: preserve source order and only relax the Venue clock."""
    expected = tuple(_node(text) for text in (
        '''if not (
            timestamp(soundness.record.created_at)
            <= timestamp(stored.bundle_record.created_at)
            <= timestamp(stored.candidate_record.created_at)
            <= timestamp(stored.record.created_at)
        ):
            raise ValidationError("paper source record chronology was substituted")''',
        '''if (
            cutoff.metadata.get("object_type") != "VenueAssessment"
            and timestamp(stored.record.created_at) > timestamp(cutoff.timestamp)
        ):
            raise ValidationError("paper source record chronology was substituted")''',
    ))
    body = _function(paper._require_paper_verification_with_round_sources).body
    for node in (*expected, _node("cutoff = events[review_replay.before_event_index]")):
        assert sum(_dump(item) == _dump(node) for item in body) == 1
    return tuple(node.test for node in expected)


class PaperRoundReplayStructureTests(unittest.TestCase):
    def test_all_old_full_owner_bodies_survive_only_explicit_context_normalization(self):
        # Preimage paper 00cbb821..., before D068 integration; not new goldens.
        for function, expected in (
            (paper._build_authoritative_research_bundle, "db942f09d751bd74d9b72b5508f7b1a57df108268d3c1ecfc1333d62f23ab9ae"),
            (paper._require_paper_verification_bundle_source, "f3805c6af9882f2cec7bd64516333d678e2b365078e640ef240cd99ee372c2ca"),
            (paper._require_authoritative_bundle_issuance, "77e24cb399fee106da0edca0b89e37da5a7b214c2632e19bcdf77845e0f10105"),
            (paper._find_issued_authoritative_bundle, "9571b87cfe67455a782d32fff9f6064da53fec3fecccc33a9f44b8b57fb9d965"),
            (paper._resolve_soundness, "8450a666f5fb666059bfce76887224cf248a2581257866ba42a340527d3dd71c"),
        ):
            with self.subTest(function=function.__name__):
                self.assertEqual(_body_hash(_normalize_paper_round_body(function)), expected)

    def test_public_verify_readback_and_stored_reader_bodies_are_exactly_unchanged(self):
        for function, expected in (
            (paper.verify_paper, "008a2de1648c7234eee9a5d4780c40f15fa3efa48558529d56f0039097dfd7bf"),
            (paper.require_paper_verification, "77fe1a982e54df999d94e4b4d5fb82f7c74dbdebdf5d31b28ff4e4907199b6cb"),
            (paper._read_paper_verification_source, "d956eaff3fdff3deccb18b0fad9d9ab5fb1138b1887a17b4e9d4bd152bdf6521"),
        ):
            with self.subTest(function=function.__name__):
                self.assertEqual(_body_hash(_function(function).body), expected)
        for function in (paper.verify_paper, paper.require_paper_verification,
                         paper.build_authoritative_research_bundle, paper.register_authoritative_research_bundle,
                         paper.register_paper_verification):
            with self.subTest(function=function.__name__):
                self.assertFalse({"_round_replay", "_review_replay", "source", "callback", "skip"}
                                 .intersection(inspect.signature(function).parameters))

    def test_initial_final_and_issuance_share_identical_full_bound_routing(self):
        for function in (paper._require_paper_verification_bundle_source,
                         paper._build_authoritative_research_bundle, paper._require_authoritative_bundle_issuance):
            body = _function(function).body
            calls = _calls(body, "_resolve_paper_bound_state")
            with self.subTest(function=function.__name__):
                self.assertEqual(len(calls), 1)
                _assert_node(calls[0], _expression(
                    "_resolve_paper_bound_state(registry, ledger, bundle, replay=_round_replay)"
                ))
                self.assertFalse(_calls(body, "resolve_bound_research_state_authority"))
        body = _function(paper._resolve_paper_bound_state).body
        selectors = body[1]
        _assert_node(selectors, _node('''selectors = dict(
            run_id=bundle.run_id, snapshot_artifact_hash=bundle.research_state_hash,
            state_artifact_hashes=bundle.research_state_artifact_hashes,
            ledger_head_hash=bundle.research_state_ledger_head_hash,
            ledger_event_count=bundle.research_state_ledger_event_count,
            expected_code_version=bundle.research_state_code_version,
            expected_configuration_hash=bundle.research_state_configuration_hash,
        )'''))
        _assert_node(body[2], _node('''if replay is None:
            return resolve_bound_research_state_authority(registry, ledger, **selectors)'''))
        _assert_node(body[-1].value, _expression('''_resolve_bound_research_state_authority(
            registry, ledger, **selectors, _review_replay=replay.reviews,
        )'''))
        self.assertLess(_calls(body, "_require_paper_round_sources")[0].lineno, body[-1].lineno)

    def test_strict_route_has_no_diagnostic_catch_and_orders_complete_owner_before_verifier(self):
        body = _function(paper._require_paper_verification_with_round_sources).body
        names = ("_require_paper_round_sources", "_read_paper_verification_source",
                 "_require_paper_verification_bundle_source", "_require_paper_state_binding_join",
                 "_verify_paper_from_replayed_bundle")
        calls = {name: _calls(body, name) for name in names}
        self.assertEqual(tuple(len(calls[name]) for name in names), (2, 1, 1, 1, 1))
        ordered = [calls[name][0].lineno for name in names] + [calls[names[0]][1].lineno, body[-1].lineno]
        self.assertEqual(ordered, sorted(ordered))
        self.assertFalse(_calls(body, "verify_paper"))
        self.assertFalse(_calls(body, "PaperVerification"))
        self.assertFalse(_calls(body, "require_paper_verification"))
        handlers = [node for node in ast.walk(ast.Module(body=body, type_ignores=[]))
                    if isinstance(node, ast.ExceptHandler)]
        self.assertEqual(len(handlers), 1)
        self.assertEqual(handlers[0].type.id, "ValueError")
        self.assertEqual(len(handlers[0].body), 1)
        self.assertIsInstance(handlers[0].body[0], ast.Raise)
        self.assertEqual(len([node for node in ast.walk(ast.Module(body=body, type_ignores=[]))
                              if isinstance(node, ast.Return)]), 2)  # Timestamp helper plus final tuple.
        _assert_node(body[-1].value, _expression("(fresh, source)"))
        joined = inspect.getsource(paper._require_paper_verification_with_round_sources)
        for identity in ("source.issued_bundle != stored.bundle_record", "stored.stored_verification != fresh",
                         'stored.payload["verification"] != _plain_json(fresh)',
                         "bundle.soundness_assessment_hash != soundness.record.sha256",
                         "bundle.claim_graph_hash != soundness.assessment.claim_graph_artifact_hash",
                         "bundle.central_claim_ids != soundness.assessment.central_claim_ids",
                         "soundness.assessment.confirmatory_claim_authority_hashes"):
            self.assertIn(identity, joined)

    def test_round_source_guard_retains_exact_types_record_identities_and_paired_epoch(self):
        body = _function(paper._require_paper_round_sources).body
        guard = _refusal_condition(paper._require_paper_round_sources,
                                   "paper round replay does not bind exact completed sources")
        _assert_node(guard, _expression('''
            type(replay) is not _PaperRoundReplay
            or type(replay.audited_state) is not ResearchStateAuthoritySnapshot
            or type(replay.soundness) is not _SemanticChallengerAuditRoundSoundness
            or type(replay.reviews) is not _SameRoundReviewReplay
            or replay.audited_state.run_id != run_id
            or replay.soundness.assessment.run_id != run_id
            or replay.audited_state.code_version != replay.reviews.code_version
            or replay.audited_state.configuration_hash != replay.reviews.configuration_hash
        '''))
        self.assertEqual(len(_calls(body, "_require_same_round_review_snapshot")), 1)
        self.assertEqual(len(_calls(body, "get_metadata")), 2)
        self.assertEqual(len(_calls(body, "_semantic_challenger_audit_parse_soundness")), 1)
        _assert_node(_refusal_condition(paper._require_paper_round_sources,
                                       "paper round source records changed after complete replay"), _expression('''
            registry.get_metadata(replay.audited_state.snapshot_artifact_sha256).record_hash
            != replay.audited_state.snapshot_artifact_record_hash
            or registry.get_metadata(replay.soundness.record.sha256) != replay.soundness.record
            or _semantic_challenger_audit_parse_soundness(registry, replay.soundness.record)
            != replay.soundness.assessment
        '''))

    def test_round_soundness_reuses_only_exact_rechecked_source_and_preserves_all_old_joins(self):
        body = _function(paper._resolve_soundness).body
        branch = body[0]
        self.assertEqual(len(_calls(branch.body, "require_scientific_soundness_assessment")), 1)
        self.assertFalse(_calls(branch.orelse, "require_scientific_soundness_assessment"))
        _assert_node(branch.orelse[0], _node('''if ledger is None or run_id is None:
            raise ValidationError("same-round paper Soundness requires its exact run and ledger")'''))
        _assert_node(branch.orelse[1].value, _expression(
            "_require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)"
        ))
        _assert_node(branch.orelse[2], _node('''if assessment_hash != _round_replay.soundness.record.sha256:
            raise ValidationError("paper Soundness differs from the completed round source")'''))
        _assert_node(branch.orelse[3], _node("assessment = _round_replay.soundness.assessment"))
        self.assertEqual(len(branch.orelse), 4)

    def test_nonconfirmatory_soundness_shape_selects_full_build_run_never_source_run(self):
        body = _function(paper._build_authoritative_research_bundle).body
        tree = ast.Module(body=body, type_ignores=[])
        for expected in (_LIVE_SOUNDNESS_INITIAL, _LIVE_SOUNDNESS_SHAPE_ROUTE):
            self.assertEqual(sum(_dump(node) == _dump(expected) for node in ast.walk(tree)), 1)
        initial = next(node for node in ast.walk(tree) if _dump(node) == _dump(_LIVE_SOUNDNESS_INITIAL))
        route = next(node for node in ast.walk(tree) if _dump(node) == _dump(_LIVE_SOUNDNESS_SHAPE_ROUTE))
        full = _calls(body, "_resolve_soundness")[0]
        self.assertLess(initial.lineno, route.lineno)
        self.assertLess(route.end_lineno, full.lineno)
        self.assertEqual(len(_calls(route.body, "_semantic_challenger_audit_parse_soundness")), 1)
        self.assertFalse(_calls(route.body, "_require_scientific_soundness_assessment"))
        for keyword in full.keywords:
            if keyword.arg in {"ledger", "run_id"}:
                _assert_node(keyword.value, _expression(f"{keyword.arg} if use_live_soundness else None"))

        # Pure expression vectors: the exact parser-call shape is proved above.
        # Only its value is substituted inside this isolated predicate, never
        # in production or in a scientific/source-owner call.
        source_has_run = deepcopy(route.body[0].value)
        source_has_run.left.value = ast.Name(id="inert_parsed_value", ctx=ast.Load())
        inputs = {keyword.arg: keyword.value for keyword in full.keywords if keyword.arg in {"ledger", "run_id"}}
        for round_present in (False, True):
            for confirmations in ((), ("a" * 64,)):
                for source_run in (None, "build-run", "foreign-run"):
                    with self.subTest(round_present=round_present, confirmations=confirmations, source_run=source_run):
                        selected = _predicate(initial.value, _round_replay=object() if round_present else None,
                                              canonical_confirmatory_claim_authorities=confirmations)
                        if not selected:
                            selected = _predicate(source_has_run, inert_parsed_value=SimpleNamespace(run_id=source_run))
                        expected = round_present or bool(confirmations) or source_run is not None
                        self.assertEqual(selected, expected)
                        self.assertEqual(_predicate(inputs["run_id"], use_live_soundness=selected, run_id="build-run"),
                                         "build-run" if expected else None)
                        self.assertEqual(_predicate(inputs["ledger"], use_live_soundness=selected, ledger="build-ledger"),
                                         "build-ledger" if expected else None)

    def test_cohort_does_not_use_empty_confirmations_as_a_runless_authority_proxy(self):
        body = _function(cohort_bundle._require_cohort_paper).body
        soundness = next(node for node in body if isinstance(node, ast.Assign)
                         and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                         and node.value.func.id == "require_scientific_soundness_assessment")
        _assert_node(soundness.value, _expression('''require_scientific_soundness_assessment(
            registry, ledger=ledger, assessment_artifact_hash=bundle.soundness_assessment_hash,
            expected_assessment_id=cohort.round_key.assessment_id, expected_run_id=cohort.round_key.run_id,
        )'''))
        preceding = body[:body.index(soundness)]
        self.assertTrue(_calls(preceding, "_require_paper_verification_bundle_source"))
        self.assertTrue(_calls(preceding, "_require_paper_state_join"))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == "confirmatory_claim_authority_hashes"
                             for node in ast.walk(ast.Module(body=preceding, type_ignores=[]))))

    def test_actual_issuance_and_record_chronology_guard_vectors(self):
        condition = _refusal_condition(paper._require_paper_verification_with_round_sources,
                                       "paper round sources do not precede the canonical terminal")
        def rejected(*, count=2, issuance=(3,), current=5, total=6, peer_indices=(1, 2)):
            return _predicate(condition, issuance=issuance, events=(None,) * total,
                              source=SimpleNamespace(state_authority=SimpleNamespace(ledger_event_count=count)),
                              review_replay=SimpleNamespace(before_event_index=current),
                              soundness=SimpleNamespace(semantic_peers=tuple(
                                  SimpleNamespace(publication_event_index=index) for index in peer_indices)))
        self.assertFalse(rejected())
        for changes in ({"issuance": ()}, {"issuance": (3, 4)}, {"count": 4},
                        {"current": 3}, {"current": 6}, {"peer_indices": (3,)}, {"peer_indices": (4,)}):
            with self.subTest(changes=changes):
                self.assertTrue(rejected(**changes))
        conditions = _paper_record_chronology_guards()
        def bad_order(seconds):
            records = [SimpleNamespace(created_at=f"2026-09-06T00:00:{value:02d}Z") for value in seconds]
            return any(_predicate(
                condition, timestamp=lambda text: datetime.fromisoformat(text.replace("Z", "+00:00")),
                soundness=SimpleNamespace(record=records[0]),
                stored=SimpleNamespace(bundle_record=records[1], candidate_record=records[2], record=records[3]),
                cutoff=SimpleNamespace(timestamp=records[4].created_at, metadata={"object_type": "Decision"}),
            ) for condition in conditions)
        self.assertFalse(bad_order((1, 2, 3, 4, 5)))
        self.assertFalse(bad_order((1, 1, 1, 1, 1)))
        for index in range(4):
            order = [1, 2, 3, 4, 5]
            order[index], order[index + 1] = order[index + 1], order[index]
            with self.subTest(index=index):
                self.assertTrue(bad_order(order))

    def test_review_context_is_created_before_current_and_extended_only_after_related_admission(self):
        body = _function(gates._require_semantic_challenger_audit_no_post_snapshot_core_drift).body
        outer = next(node for node in body if isinstance(node, ast.Try))
        # This also checks every exact added node before removing it.
        self.assertEqual(_body_hash(_normalize_audit_round_tail(outer.body[1:])),
                         "7e770e1ece5061dd2fcf21ead7ec2539d3d652327861619e6d261171117af903")
        loop = next(node for node in outer.body if isinstance(node, ast.For)
                    and isinstance(node.iter, ast.Call) and node.iter.func.id == "sorted")
        related = next(node for node in loop.body if isinstance(node, ast.If)
                       and isinstance(node.test, ast.Name) and node.test.id == "related")
        call = _calls(related.body, "_SameRoundReviewReplay")[0]
        append = _calls(related.body, "append")[0]
        reject = next(node for node in related.body if isinstance(node, ast.If)
                      and _dump(node.test) == _dump(_expression("not admitted")))
        self.assertLess(call.lineno, reject.lineno)
        self.assertLess(reject.lineno, append.lineno)
        self.assertEqual(len(_calls(loop.body, "append")), 1)
        self.assertEqual(len(_calls(related.body, "_ReplayedCanonicalReview")), 1)
        _assert_node(related.body[0], _VENUE_SOURCE_GUARD)
        self.assertEqual(len(_calls(related.body, "_SameRoundReviewReplay")), 2)
        self.assertTrue(all(item.lineno < reject.lineno
                            for item in _calls(related.body, "_SameRoundReviewReplay")))
        self.assertLess(loop.end_lineno, _calls(outer.body, "_require_semantic_challenger_audit_snapshot_unchanged")[0].lineno)

    def test_current_later_and_core_are_excluded_by_actual_context_predicate(self):
        source = inspect.getsource(rs._SameRoundReviewReplay)
        self.assertIn("type(review.research_object) not in {Challenge, Critique, Decision, VenueAssessment}", source)
        self.assertIn("not 0 <= review.materialization_event_index < self.before_event_index", source)
        tree = ast.parse(source)
        # The exact type and immutable-record conditions remain source checked;
        # this finite vector evaluates only the strict chronological comparison.
        expected = _expression("0 <= review.materialization_event_index < self.before_event_index")
        comparisons = [node for node in ast.walk(tree) if _dump(node) == _dump(expected)]
        self.assertEqual(len(comparisons), 1)
        comparison = comparisons[0]
        for index, allowed in ((-1, False), (0, True), (4, True), (5, False), (6, False)):
            self.assertEqual(_predicate(comparison, review=SimpleNamespace(materialization_event_index=index),
                                        self=SimpleNamespace(before_event_index=5)), allowed)

    def test_gate_compares_complete_actual_paper_terminal_not_a_failed_value_or_hash(self):
        body = _function(gates._semantic_challenger_audit_exact_decision_projection).body
        strict = _calls(body, "_require_paper_verification_with_round_sources")
        derived = _calls(body, "_derive_from_replayed_paper_verification")
        normalize = _calls(body, "_normalize_replayed_paper_terminal")
        self.assertEqual((len(strict), len(derived), len(normalize)), (1, 1, 1))
        self.assertLess(strict[0].lineno, derived[0].lineno)
        self.assertLess(derived[0].lineno, normalize[0].lineno)
        self.assertEqual(derived[0].args[2].id, "verification")
        self.assertFalse(_calls(body, "PaperVerification"))
        self.assertIn("resolved.derivation == terminal.derivation",
                      inspect.getsource(gates._semantic_challenger_audit_exact_decision_projection))
        terminal_body = _function(terminal._derive_from_replayed_paper_verification).body
        bindings = _calls(terminal_body, "TerminalSourceBinding")
        self.assertEqual(len(bindings), 1)
        claims = next(keyword.value for keyword in bindings[0].keywords if keyword.arg == "source_claim_ids")
        _assert_node(claims, _expression("verification.verified_claim_ids"))


class PaperRoundReplayMechanicalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = snapshot_fixtures.SnapshotReferenceReplayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.ledger, self.state = self.fixture.registry, self.fixture.ledger, self.fixture.state
        self.bundle = replace(
            legacy_placeholder_bundle(), run_id=self.state.run_id,
            research_state_hash=self.state.snapshot_artifact_sha256,
            research_state_artifact_hashes=tuple(item.artifact_sha256 for item in self.state.entries),
            research_state_ledger_head_hash=self.state.ledger_head_hash,
            research_state_ledger_event_count=self.state.ledger_event_count,
            research_state_code_version=self.state.code_version,
            research_state_configuration_hash=self.state.configuration_hash,
        )

    def _before(self):
        return self.registry.list_records(), self.ledger.events()

    def test_real_default_bound_route_retains_mechanical_scope_and_unrelated_append_compatibility(self):
        for appended in (False, True):
            if appended:
                self.fixture._append()
            before = self._before()
            self.assertEqual(paper._resolve_paper_bound_state(self.registry, self.ledger, self.bundle), self.state)
            self.assertTrue(all(not item.scientific_evidence_eligible for item in self.state.entries))
            self.assertEqual(self._before(), before)

    def test_real_default_bound_route_rejects_missing_identity_and_later_correction(self):
        before = self._before()
        for changes, error in (({"research_state_hash": "f" * 64}, ArtifactError),
                               ({"research_state_ledger_event_count": self.state.ledger_event_count + 1}, ValidationError),
                               ({"research_state_code_version": "substituted-code"}, ValidationError)):
            with self.subTest(changes=changes), self.assertRaises(error):
                paper._resolve_paper_bound_state(self.registry, self.ledger, replace(self.bundle, **changes))
        self.assertEqual(self._before(), before)
        self.ledger.append_correction(
            f"rss-{self.fixture.snapshot.sha256[:48]}", actor_role=Role.ORCHESTRATOR,
            reason="Withdraw the mechanical snapshot only.", corrected_fields={"authority": "WITHDRAWN"},
            event_id="withdraw-paper-fixture-snapshot", timestamp="2026-08-29T12:00:03Z",
        )
        before = self._before()
        with self.assertRaisesRegex(ValidationError, "issuance was later corrected"):
            paper._resolve_paper_bound_state(self.registry, self.ledger, self.bundle)
        self.assertEqual(self._before(), before)

    def test_strict_invalid_round_and_missing_bundle_raise_without_owned_failed_diagnostic(self):
        before = self._before()
        # No _SemanticChallengerAuditRoundSoundness or positive owner stand-in.
        with self.assertRaisesRegex(ValidationError, "exact completed sources"):
            paper._require_paper_verification_with_round_sources(
                self.registry, self.ledger, verification_artifact_hash="e" * 64,
                expected_run_id=self.state.run_id, expected_candidate_id="inert-candidate",
                audited_state=self.state, soundness=None, review_replay=None,
            )
        missing = replace(self.bundle, research_state_hash="f" * 64)
        with self.assertRaises(ArtifactError):
            paper._require_paper_verification_bundle_source(self.registry, self.ledger, missing)
        diagnostic = paper.verify_paper(_inert_candidate(), missing, self.registry, self.ledger)
        self.assertFalse(diagnostic.passed)
        self.assertEqual(diagnostic.discrepancies, ("authoritative_bundle_does_not_resolve",))
        self.assertEqual(self._before(), before)

    def test_run_bound_nonconfirmatory_soundness_still_requires_real_missing_source_owner(self):
        before = self._before()
        # An empty confirmation tuple is permitted as input shape, not proof.
        # The full ordinary owner must actually reject the absent source.
        frames = []
        with self.assertRaises((ArtifactError, ValidationError)):
            try:
                paper._resolve_soundness(
                    self.registry, "e" * 64, claim_graph_hash="a" * 64,
                    central_claim_ids=("inert-claim",), ledger=self.ledger,
                    run_id=self.state.run_id, confirmatory_claim_authority_hashes=(),
                )
            except (ArtifactError, ValidationError) as failure:
                frames = [frame.name for frame in traceback.extract_tb(failure.__traceback__)]
                raise
        self.assertIn("require_scientific_soundness_assessment", frames)
        self.assertEqual(self._before(), before)

    def test_private_context_is_frozen_but_construction_cannot_grant_source_authority(self):
        self.assertEqual(tuple(field.name for field in fields(paper._PaperRoundReplay)),
                         ("audited_state", "soundness", "reviews"))
        invalid = paper._PaperRoundReplay(self.state, None, None)
        with self.assertRaises(FrozenInstanceError):
            invalid.soundness = None
        before = self._before()
        for value in (invalid, SimpleNamespace(), None):
            with self.subTest(value=type(value)), self.assertRaisesRegex(ValidationError, "exact completed sources"):
                paper._require_paper_round_sources(self.registry, self.ledger, value, run_id=self.state.run_id)
        self.assertEqual(self._before(), before)

    def test_pure_F_S_join_accepts_equal_or_earlier_complete_bindings_without_authorizing_them(self):
        for count in (1, self.state.ledger_event_count, self.state.ledger_event_count + 10):
            final = replace(self.state, ledger_event_count=count, snapshot_artifact_sha256="e" * 64)
            self.assertIsNone(paper._require_paper_state_binding_join(self.state, final))
        # An allowed review-type addition is a pure shape compatibility check;
        # these unissued bindings do not establish the necessary review owner.
        records = (
            rs.Challenge(object_id="inert-challenge", producer=Role.ADVERSARIAL_REVIEWER,
                         target_claim_ids=("inert-claim",), finding="Unissued pure shape only."),
            rs.Critique(object_id="inert-critique", producer=Role.ADVERSARIAL_REVIEWER,
                        target_ids=("inert-claim",), verdict="UNTESTED"),
            rs.Decision(object_id="inert-decision", producer=Role.SCIENTIFIC_REVIEWER,
                        decision_type="INERT", outcome="UNTESTED", governing_rule="Pure identity fixture.",
                        reason="No source authority is asserted."),
            rs.VenueAssessment(object_id="inert-venue", producer=Role.SCIENTIFIC_REVIEWER,
                               venue="Inert fixture", profile="ml-ai"),
        )
        for record in records:
            review = replace(self.state.entries[0], research_object=record, artifact_sha256="d" * 64)
            with self.subTest(object_type=record.object_type):
                paper._require_paper_state_binding_join(self.state, replace(self.state, entries=(*self.state.entries, review)))

    def test_pure_F_S_join_rejects_omission_spliced_records_duplicates_and_new_core(self):
        binding = self.state.entries[0]
        with self.assertRaisesRegex(ValidationError, "entries must be unique"):
            replace(self.state, entries=(binding, binding))
        # Invalid, in-memory mutation only: the pure join also refuses duplicate
        # identities rather than trusting construction as scientific authority.
        duplicate = replace(self.state)
        object.__setattr__(duplicate, "entries", (binding, binding))
        alternatives = (
            replace(self.state, entries=()),
            replace(self.state, entries=(replace(binding, artifact_record_hash="a" * 64),)),
            duplicate,
            replace(self.state, entries=(binding, replace(binding, research_object=replace(
                binding.research_object, object_id="another-unaudited-question", content_hash=None,
            ), artifact_sha256="d" * 64))),
            replace(self.state, entries=(replace(binding, scientific_evidence_eligible=True),)),
        )
        for final in alternatives:
            with self.subTest(final=final), self.assertRaisesRegex(ValueError, "competing|omits or changes|unaudited"):
                paper._require_paper_state_binding_join(self.state, final)


if __name__ == "__main__":
    unittest.main()
