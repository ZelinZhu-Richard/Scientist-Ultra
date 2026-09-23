"""D069 manuscript routing controls, not scientific lifecycle evidence.

Whole-source AST normalization permits only the explicit private context
plumbing. Real registry/ledger tests stop at absent, PENDING, or invalid sources;
no completed semantic round or successful scientific owner is fabricated or
mocked. Isolated predicate/signature checks grant no source authority.
"""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import inspect
from tempfile import TemporaryDirectory
from textwrap import dedent
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import EventLedger
from scientist_one import paper_composition as composition
from scientist_one.roles import Role
from tests.test_gates_paper import legacy_placeholder_bundle
from tests.test_paper_bundle_source_companion import _inert_candidate
from tests.test_paper_verification_shared_replay import _portable_ast_dump


def _dump(value):
    return _portable_ast_dump(value)


def _function(value):
    return ast.parse(inspect.getsource(value)).body[0]


def _node(text):
    values = ast.parse(dedent(text)).body
    assert len(values) == 1
    return values[0]


def _expression(text):
    return ast.parse("(" + dedent(text).strip() + ")", mode="eval").body


def _calls(body, name):
    return tuple(node for node in ast.walk(ast.Module(body=body, type_ignores=[]))
                 if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Name) and node.func.id == name)
                      or (isinstance(node.func, ast.Attribute) and node.func.attr == name)))


def _same(actual, expected):
    assert _dump(actual) == _dump(expected), (_dump(actual), _dump(expected))


_CONTEXT_KWARGS = _expression('{"_round_replay": _round_replay} if _round_replay is not None else {}')
_SOURCE_GUARD = _node('''if _round_replay is not None:
    _require_paper_round_sources(registry, ledger, _round_replay, run_id=run_id)
''')
_BEFORE_GUARD = _node('''if _round_replay is not None and (
    before_registry != _round_replay.reviews.registry_snapshot
    or before_ledger != _round_replay.reviews.ledger_snapshot
):
    raise ValidationError("manuscript round sources changed before fresh composition replay")
''')
_AFTER_GUARD = _node('''if _round_replay is not None and (
    after_registry != _round_replay.reviews.registry_snapshot
    or after_ledger != _round_replay.reviews.ledger_snapshot
):
    raise ValidationError("manuscript round sources changed after fresh composition replay")
''')
_PAPER_ROUTE = _node('''if _round_replay is None:
    verification = require_paper_verification(registry, ledger, run_id=run_id, verification_artifact_hash=verification_artifact_hash, expected_candidate_id=candidate.candidate_id)
else:
    verification, _paper_source = _require_paper_verification_with_round_sources(
        registry, ledger,
        verification_artifact_hash=verification_artifact_hash,
        expected_run_id=run_id,
        expected_candidate_id=candidate.candidate_id,
        audited_state=_round_replay.audited_state,
        soundness=_round_replay.soundness,
        review_replay=_round_replay.reviews,
    )
''')
_PUBLIC_WRAPPER = _node('''def require_paper_manuscript_revision(
    registry: ArtifactRegistry, ledger: EventLedger, *, revision_artifact_hash: str,
) -> RegisteredPaperManuscriptRevision:
    """Freshly replay one current revision and only historical predecessors."""
    return _require_paper_manuscript_revision(
        registry, ledger, revision_artifact_hash=revision_artifact_hash,
    )
''')


def _normalized_source():
    """Reconstruct the entire 028375a6 preimage, not a newly blessed body."""
    counts = {"wrapper": 0, "parameters": 0, "imports": 0, "route": 0,
              "source_guard": 0, "before_guard": 0, "after_guard": 0, "kwargs": 0}
    private_functions = {"_derive_composition_input", "_derive_composition_input_stably",
                         "_require_paper_manuscript_revision"}
    context_imports = {"_PaperRoundReplay", "_require_paper_round_sources",
                       "_require_paper_verification_with_round_sources"}

    class Normalize(ast.NodeTransformer):
        owner = None

        def visit_ImportFrom(self, node):
            if node.module == "paper_pipeline":
                for item in tuple(node.names):
                    if item.name in context_imports:
                        assert item.asname is None
                        node.names.remove(item)
                        counts["imports"] += 1
            return node

        def visit_FunctionDef(self, node):
            if node.name == "require_paper_manuscript_revision":
                _same(node, _PUBLIC_WRAPPER)
                counts["wrapper"] += 1
                return None
            previous = self.owner
            self.owner = node.name
            if node.name in private_functions:
                positions = [index for index, item in enumerate(node.args.kwonlyargs) if item.arg == "_round_replay"]
                assert len(positions) == 1
                index = positions[0]
                _same(node.args.kwonlyargs[index].annotation, _expression("_PaperRoundReplay | None"))
                _same(node.args.kw_defaults[index], _expression("None"))
                node.args.kwonlyargs.pop(index)
                node.args.kw_defaults.pop(index)
                counts["parameters"] += 1
            result = self.generic_visit(node)
            if node.name == "_require_paper_manuscript_revision":
                node.name = "require_paper_manuscript_revision"
            self.owner = previous
            return result

        def visit_If(self, node):
            for label, expected in (("source_guard", _SOURCE_GUARD), ("before_guard", _BEFORE_GUARD),
                                    ("after_guard", _AFTER_GUARD)):
                if _dump(node) == _dump(expected):
                    assert self.owner == "_derive_composition_input_stably"
                    counts[label] += 1
                    return None
            if _dump(node) == _dump(_PAPER_ROUTE):
                assert self.owner == "_derive_composition_input"
                counts["route"] += 1
                return node.body
            return self.generic_visit(node)

        def visit_Call(self, node):
            for keyword in tuple(node.keywords):
                if keyword.arg is None and _dump(keyword.value) == _dump(_CONTEXT_KWARGS):
                    assert (self.owner, node.func.id) in {
                        ("_derive_composition_input", "_require_authoritative_bundle_issuance"),
                        ("_derive_composition_input", "_resolve_soundness"),
                        ("_derive_composition_input_stably", "_derive_composition_input"),
                        ("_require_paper_manuscript_revision", "_derive_composition_input_stably"),
                    }
                    node.keywords.remove(keyword)
                    counts["kwargs"] += 1
            return self.generic_visit(node)

    normalized = Normalize().visit(ast.parse(inspect.getsource(composition)))
    assert counts == {"wrapper": 1, "parameters": 3, "imports": 3, "route": 1,
                      "source_guard": 2, "before_guard": 1, "after_guard": 1, "kwargs": 4}, counts
    return normalized


def _predicate(expression, **inputs):
    code = compile(ast.fix_missing_locations(ast.Expression(deepcopy(expression))), "<inert-manuscript-guard>", "eval")
    return eval(code, {"__builtins__": {}, **inputs})


def _arguments():
    return dict(run_id="inert-run", manuscript_id="inert-manuscript", revision=1,
                predecessor_revision_artifact_hash=None, candidate_artifact_hash="a" * 64,
                bundle_artifact_hash="b" * 64, verification_artifact_hash="c" * 64)


class ManuscriptRoundReplayStructureTests(unittest.TestCase):
    def test_entire_preimage_survives_only_exact_private_routing_normalization(self):
        # Complete original source SHA-256:
        # 028375a611e068c00fce6041668d20f4d4fe132eba226e700ae9a5daac54c1e6.
        self.assertEqual(hashlib.sha256(_dump(_normalized_source()).encode()).hexdigest(),
                         "b53a36cdb7d994cc3ac9146cfce585ff83ebd37a68e2c38f0eb285ad27036a9f")

    def test_public_signature_and_wrapper_cannot_supply_private_context(self):
        _same(_function(composition.require_paper_manuscript_revision), _PUBLIC_WRAPPER)
        self.assertEqual(tuple(inspect.signature(composition.require_paper_manuscript_revision).parameters),
                         ("registry", "ledger", "revision_artifact_hash"))
        self.assertNotIn("_round_replay", inspect.signature(composition.register_paper_manuscript_revision).parameters)
        self.assertNotIn("_require_paper_manuscript_revision", composition.__all__)
        private = inspect.signature(composition._require_paper_manuscript_revision).parameters
        self.assertEqual(tuple(private), ("registry", "ledger", "revision_artifact_hash", "_round_replay"))
        self.assertIs(private["_round_replay"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(private["_round_replay"].default)

    def test_none_omits_context_keyword_for_every_existing_callback_signature(self):
        calls = []
        for function in (composition._derive_composition_input, composition._derive_composition_input_stably,
                         composition._require_paper_manuscript_revision):
            calls.extend(node for node in ast.walk(_function(function)) if isinstance(node, ast.Call)
                         and any(keyword.arg is None for keyword in node.keywords))
        self.assertEqual(len(calls), 4)
        marker = object()
        for call in calls:
            with self.subTest(callee=call.func.id):
                (expansion,) = (keyword.value for keyword in call.keywords if keyword.arg is None)
                _same(expansion, _CONTEXT_KWARGS)
                self.assertEqual(_predicate(expansion, _round_replay=None), {})
                self.assertEqual(_predicate(expansion, _round_replay=marker), {"_round_replay": marker})
                signature = inspect.signature(getattr(composition, call.func.id))
                legacy = signature.replace(parameters=[value for name, value in signature.parameters.items()
                                                       if name != "_round_replay"])
                explicit = {keyword.arg: marker for keyword in call.keywords if keyword.arg is not None}
                # Signature binding only: no callback or source owner executes.
                legacy.bind(*([marker] * len(call.args)), **explicit, **_predicate(expansion, _round_replay=None))

    def test_strict_paper_branch_joins_actual_context_and_keeps_full_authorization(self):
        body = _function(composition._derive_composition_input).body
        handler = next(node for node in body if isinstance(node, ast.Try))
        self.assertEqual(len(handler.body), 1)
        _same(handler.body[0], _PAPER_ROUTE)
        self.assertEqual(len(_calls(body, "require_paper_verification")), 1)
        self.assertEqual(len(_calls(body, "_require_paper_verification_with_round_sources")), 1)
        ordered = [handler.end_lineno]
        for name in ("_validate_composition_authority", "_resolve_candidate_bundle_artifacts",
                     "_require_authoritative_bundle_issuance", "_resolve_soundness"):
            calls = _calls(body, name)
            self.assertEqual(len(calls), 1)
            ordered.append(calls[0].lineno)
        self.assertEqual(ordered, sorted(ordered))
        for caught in handler.handlers:
            self.assertTrue(all(isinstance(node, ast.Raise) for node in caught.body))
        self.assertFalse(_calls(body, "PaperVerification"))
        self.assertIn("set(eligible_ids).issubset(verification.verified_claim_ids)",
                      inspect.getsource(composition._derive_composition_input))

    def test_stable_replay_checks_round_before_and_after_and_matches_both_paired_snapshots(self):
        body = _function(composition._derive_composition_input_stably).body
        guards = _calls(body, "_require_paper_round_sources")
        snapshots = _calls(body, "_locked_paper_authority_snapshot")
        derived = _calls(body, "_derive_composition_input")
        self.assertEqual((len(guards), len(snapshots), len(derived)), (2, 2, 1))
        order = [guards[0].lineno, snapshots[0].lineno, derived[0].lineno,
                 guards[1].lineno, snapshots[1].lineno]
        self.assertEqual(order, sorted(order))
        for expected in (_BEFORE_GUARD, _AFTER_GUARD):
            matches = [node for node in body if _dump(node) == _dump(expected)]
            self.assertEqual(len(matches), 1)
        source = inspect.getsource(composition._derive_composition_input_stably)
        self.assertIn("after_registry != before_registry or after_ledger != before_ledger", source)
        self.assertIn("composition.historical_ledger_head_hash != after_ledger.head_hash", source)
        self.assertIn("composition.historical_ledger_event_count != after_ledger.event_count", source)

    def test_context_snapshot_mismatch_predicates_reject_either_changed_component(self):
        registry_marker, ledger_marker = object(), object()
        # Inert scalar relation only, not a _PaperRoundReplay or completed source.
        context = SimpleNamespace(reviews=SimpleNamespace(
            registry_snapshot=registry_marker, ledger_snapshot=ledger_marker,
        ))
        for prefix, guard in (("before", _BEFORE_GUARD), ("after", _AFTER_GUARD)):
            for registry_value, ledger_value, rejected in (
                (registry_marker, ledger_marker, False), (object(), ledger_marker, True),
                (registry_marker, object(), True), (object(), object(), True),
            ):
                with self.subTest(prefix=prefix, rejected=rejected):
                    values = {f"{prefix}_registry": registry_value, f"{prefix}_ledger": ledger_value}
                    self.assertEqual(_predicate(guard.test, _round_replay=context, **values), rejected)
                    self.assertFalse(_predicate(guard.test, _round_replay=None, **values))

    def test_historical_chain_never_receives_current_context_or_scientific_owner(self):
        for function, expected in (
            (composition._replay_immutable_revision, "f362a4b0d625bd5b8b75fc3e6759a6182a6d74a4c9ba40e1f35e1ae4bbea094c"),
            (composition._require_historical_predecessor_lineage, "5fb550075b946c093d8be9371d9036f8f3843ce4981c3c3e0cdd2a97e18a851e"),
            (composition.register_paper_manuscript_revision, "fb8956d59bf139254cf3d4d65eaef2173105d3671a74ed218d81b8c4bac5bedd"),
        ):
            with self.subTest(function=function.__name__):
                body = _function(function).body
                self.assertEqual(hashlib.sha256(_dump(ast.Module(body=body, type_ignores=[])).encode()).hexdigest(), expected)
                self.assertNotIn("_round_replay", inspect.getsource(function))
        body = _function(composition._require_paper_manuscript_revision).body
        fresh = _calls(body, "_derive_composition_input_stably")[0]
        historical = _calls(body, "_require_historical_predecessor_lineage")[0]
        self.assertLess(fresh.lineno, historical.lineno)
        self.assertTrue(all(keyword.arg != "_round_replay" for keyword in historical.keywords))
        final_snapshot = _calls(body, "_locked_paper_authority_snapshot")[0]
        self.assertLess(historical.lineno, final_snapshot.lineno)

    def test_exactly_stored_head_count_normalize_and_final_currentness_check_remains_last(self):
        body = _function(composition._require_paper_manuscript_revision).body
        replacements = [node for node in body if isinstance(node, ast.Assign)
                        and isinstance(node.targets[0], ast.Subscript)
                        and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == "fresh_value"]
        self.assertEqual({node.targets[0].slice.value for node in replacements},
                         {"historical_ledger_head_hash", "historical_ledger_event_count"})
        self.assertEqual(len(replacements), 2)
        for node in replacements:
            _same(node.value, _expression(f'stored_value["{node.targets[0].slice.value}"]'))
        self.assertIn("fresh_value != stored_value", inspect.getsource(composition._require_paper_manuscript_revision))
        _same(body[-2].test, _expression('''final_registry != fresh_replay.registry_snapshot
            or final_ledger != fresh_replay.ledger_snapshot'''))
        self.assertEqual(body[-1].value.func.id, "RegisteredPaperManuscriptRevision")


class ManuscriptRoundReplayNegativeTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.registry, self.ledger = ArtifactRegistry(self.directory.name), EventLedger(self.directory.name)

    def _before(self):
        return self.registry.verify_all(), self.ledger.validate()

    def test_real_absent_revision_has_identical_default_public_private_refusal_and_zero_delta(self):
        before = self._before()
        failures = []
        for owner in (composition.require_paper_manuscript_revision, composition._require_paper_manuscript_revision):
            with self.subTest(owner=owner.__name__), self.assertRaises(ArtifactError) as failure:
                owner(self.registry, self.ledger, revision_artifact_hash="f" * 64)
            failures.append((type(failure.exception), str(failure.exception)))
        self.assertEqual(failures[0], failures[1])
        self.assertEqual(self._before(), before)

    def test_pending_revision_and_wrong_runtime_roots_cannot_grant_manuscript_authority(self):
        record = self.registry.put_json(
            {"scope": "INERT", "notice": "No manuscript issuance or source authority."},
            logical_type="paper_manuscript_revision", origin="negative test only", creator_role=Role.PAPER_WRITER,
            validation_result="PENDING", frozen=False,
        )
        before = self._before()
        for owner in (composition.require_paper_manuscript_revision, composition._require_paper_manuscript_revision):
            with self.subTest(owner=owner.__name__), self.assertRaisesRegex(ValidationError, "frozen PASS"):
                owner(self.registry, self.ledger, revision_artifact_hash=record.sha256)
            with self.assertRaisesRegex(ValidationError, "one concrete registry/ledger root"):
                owner(object(), self.ledger, revision_artifact_hash=record.sha256)
        self.assertEqual(self._before(), before)

    def test_invalid_round_fails_before_fresh_derivation_without_diagnostic_or_mutation(self):
        before = self._before()
        with self.assertRaisesRegex(ValidationError, "exact completed sources"):
            composition._derive_composition_input_stably(
                self.registry, self.ledger, _inert_candidate(), legacy_placeholder_bundle(),
                **_arguments(), _round_replay=object(),
            )
        self.assertEqual(self._before(), before)

    def test_default_fresh_derivation_still_requires_actual_paper_record(self):
        before = self._before()
        for derive in (composition._derive_composition_input, composition._derive_composition_input_stably):
            with self.subTest(derive=derive.__name__), self.assertRaises(ArtifactError):
                derive(self.registry, self.ledger, _inert_candidate(), legacy_placeholder_bundle(), **_arguments())
        self.assertEqual(self._before(), before)


if __name__ == "__main__":
    unittest.main()
