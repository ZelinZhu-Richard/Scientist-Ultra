"""Mechanical extraction, inert downstream failures, and real source refusals.

No scientific owner is mocked, no paper authority is issued, and no positive
scientific lifecycle is claimed. Private transport construction is not source
admission. AST goldens preserve the exact pre-extraction verification logic;
they are structural regression controls, not evidence of scientific adequacy.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import inspect
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from scientist_one.artifacts import ArtifactRecord, ArtifactRegistry
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.gates import SoundnessVerdict
from scientist_one.ledger import EventLedger
from scientist_one import paper_pipeline as paper
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests.test_gates_paper import legacy_placeholder_bundle
from tests.test_paper_bundle_source_companion import _inert_candidate


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _function(function):
    return ast.parse(inspect.getsource(function)).body[0]


_AST_LIST_FIELDS = frozenset({
    "args", "bases", "body", "cases", "comparators", "decorator_list",
    "defaults", "elts", "finalbody", "generators", "handlers", "ifs",
    "items", "keywords", "kw_defaults", "kwonlyargs", "kwd_attrs", "kwd_patterns",
    "keys", "names", "orelse", "ops", "patterns", "posonlyargs",
    "targets", "type_ignores", "type_params", "values",
})


def _portable_ast_dump(value):
    """Match the pre-extraction 3.14 ast.dump shape across supported runtimes."""
    if isinstance(value, ast.AST):
        parts = []
        cls = type(value)
        for name in value._fields:
            try:
                child = getattr(value, name)
            except AttributeError:
                continue
            field_types = getattr(cls, "_field_types", {})
            field_type = field_types.get(name) if isinstance(field_types, dict) else None
            if child == [] and (
                name in _AST_LIST_FIELDS
                or getattr(field_type, "__origin__", None) is list
            ):
                continue
            if child is None and getattr(cls, name, ...) is None:
                continue
            parts.append(f"{name}={_portable_ast_dump(child)}")
        suffix = f"({', '.join(parts)})" if parts else "()"
        return f"{type(value).__name__}{suffix}"
    if isinstance(value, list):
        return "[" + ", ".join(_portable_ast_dump(item) for item in value) + "]"
    return repr(value)


def _body_hash(body):
    value = _portable_ast_dump(ast.Module(body=body, type_ignores=[]))
    return _digest(value)


class _Rename(ast.NodeTransformer):
    def __init__(self, names):
        self.names = names

    def visit_Name(self, node):
        node.id = self.names.get(node.id, node.id)
        return node


def _calls(body, name):
    return tuple(
        node for node in ast.walk(ast.Module(body=body, type_ignores=[]))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == name
    )


def _record(label):
    """An unregistered native PENDING record, never scientific authority."""
    digest = _digest(label)
    return ArtifactRecord(
        sha256=digest, path=f"inert/{label}", relative_path=f"inert/{label}",
        metadata_path=f"inert/{label}.json", logical_type="inert_paper_transport",
        schema_version="1.0", mime_type="application/json", size=1,
        origin="non-evidentiary paper transport fixture", creator_role=Role.ORCHESTRATOR,
        creation_command=("test", "inert-paper-transport"), parent_artifacts=(),
        validation_result="PENDING", frozen=False, created_at="2026-09-06T00:00:00Z",
    )


def _diagnostic(discrepancy):
    return paper.PaperVerification(
        passed=False, blockers=(paper.HardBlocker.UNRESOLVED_AUTHORITY,),
        discrepancies=(discrepancy,), verified_claim_ids=(),
    )


def _ineligible_view():
    """Match one explicitly ineligible legacy claim; no owner is called here."""
    bundle = legacy_placeholder_bundle()
    claim = bundle.claims[0]
    candidate = replace(
        _inert_candidate(),
        claims=(paper.PaperClaim(
            claim_id=claim.claim_id, text=claim.text, strength=claim.expressed_strength,
            evidence_hashes=claim.evidence_hashes, central=True, claim_type=claim.claim_type,
            scope=claim.scope, confidence=claim.confidence,
            verification_method=claim.verification_method, permitted_strength=claim.permitted_strength,
            dependency_claim_ids=claim.dependency_claim_ids,
        ),),
        method_code_bindings=bundle.method_code_bindings,
        limitations=bundle.required_limitations,
        source_bundle_hashes=(
            bundle.research_state_hash, bundle.claim_graph_hash, bundle.soundness_assessment_hash,
        ),
    )
    return candidate, bundle


class PaperVerificationExtractionStructureTests(unittest.TestCase):
    # SHA-256 of the complete original source:
    # 62780c6bf40fbb3ea43a960c385140a98f99cca51e10350136a56c933ba6cb77.
    # Hashes below are ast.dump(..., include_attributes=False) of named bodies.
    def test_portable_ast_dump_is_format_stable_and_semantically_sensitive(self):
        tree = ast.Module(
            body=[ast.Assign(
                targets=[ast.Name(id="answer", ctx=ast.Store())],
                value=ast.Constant(value=None),
            )],
            type_ignores=[],
        )
        dumped = _portable_ast_dump(tree)
        self.assertIn("Constant(value=None)", dumped)
        self.assertNotIn("type_ignores=[]", dumped)
        self.assertIn("value=[]", _portable_ast_dump(ast.Constant(value=[])))
        self.assertIn("value=()", _portable_ast_dump(ast.Constant(value=())))
        self.assertIn("value=False", _portable_ast_dump(ast.Constant(value=False)))
        self.assertIn("value=0", _portable_ast_dump(ast.Constant(value=0)))
        call = ast.Call(func=ast.Name(id="f", ctx=ast.Load()), args=[], keywords=[])
        self.assertNotIn("args=[]", _portable_ast_dump(call))
        self.assertNotIn("keywords=[]", _portable_ast_dump(call))
        self.assertIn(
            "args=[Constant(value=None)]",
            _portable_ast_dump(ast.Call(
                func=ast.Name(id="f", ctx=ast.Load()),
                args=[ast.Constant(value=None)],
                keywords=[],
            )),
        )
        if "show_empty" in inspect.signature(ast.dump).parameters:
            self.assertEqual(
                dumped,
                ast.dump(tree, include_attributes=False, show_empty=False),
            )
        changed = ast.Module(
            body=[ast.Assign(
                targets=[ast.Name(id="different", ctx=ast.Store())],
                value=ast.Constant(value=None),
            )],
            type_ignores=[],
        )
        self.assertNotEqual(dumped, _portable_ast_dump(changed))
        self.assertNotEqual(
            _portable_ast_dump(tree),
            _portable_ast_dump(ast.Module(body=[], type_ignores=[])),
        )

    def test_public_verify_preserves_runtime_and_diagnostic_prefix_exactly(self):
        function = _function(paper.verify_paper)
        prefix = function.body[:-1]
        renamed = _Rename({"_resolved": "resolved", "_issued_bundle": "issued_bundle"})
        prefix = [renamed.visit(node) for node in prefix]
        self.assertEqual(
            _body_hash(prefix),
            "d46a075038ce86bde8929a03ee36f211d9d97b579e2a2fea96939b165e7dd978",
        )
        call = function.body[-1]
        self.assertIsInstance(call, ast.Return)
        self.assertEqual(call.value.func.id, "_verify_paper_from_replayed_bundle")
        self.assertEqual(tuple(arg.id for arg in call.value.args),
                         ("candidate", "source", "registry", "ledger"))
        self.assertEqual(call.value.keywords, [])
        self.assertEqual(len(_calls(prefix, "_require_paper_verification_bundle_source")), 1)
        self.assertEqual(len(_calls(prefix, "_verify_paper_from_replayed_bundle")), 0)

    def test_complete_downstream_claim_reference_metric_asset_policy_body_is_unchanged(self):
        body = _function(paper._verify_paper_from_replayed_bundle).body
        start = next(index for index, node in enumerate(body)
                     if isinstance(node, ast.AnnAssign) and node.target.id == "blockers")
        self.assertEqual(
            _body_hash(body[start:]),
            "bb49b2edab733bbd4194ab98810804530a9885c70748204192cfc980535c15a6",
        )
        for name in ("_candidate_source_bundle_resolves", "_verify_reference_use",
                     "_verify_generated_asset", "_exact_numeric_equal"):
            with self.subTest(name=name):
                self.assertTrue(_calls(body, name))
        self.assertFalse(_calls(body, "_require_paper_verification_bundle_source"))

    def test_stored_reader_preserves_every_original_validation_and_identity_check(self):
        body = _function(paper._read_paper_verification_source).body
        prefix = body[1:-1]  # Only the private docstring and returned transport are new.
        renamed = _Rename({"candidate_record": "_", "bundle_record": "_"})
        prefix = [renamed.visit(node) for node in prefix]
        self.assertEqual(
            _body_hash(prefix),
            "dbcc86b4d788b85ed7ed49bc8f0e2a89ec0da8fddbdd84cc47d0aab3314e4565",
        )
        self.assertEqual(len(_calls(prefix, "_read_registry_json")), 3)
        self.assertEqual(len(_calls(prefix, "_resolve_candidate_bundle_artifacts")), 1)
        self.assertFalse(_calls(body, "verify_paper"))
        self.assertFalse(_calls(body, "_verify_paper_from_replayed_bundle"))
        returned = body[-1].value
        self.assertEqual(returned.func.id, "_PaperVerificationSource")
        self.assertEqual({item.arg: item.value.id for item in returned.keywords}, {
            "candidate": "candidate", "bundle": "bundle", "stored_verification": "stored",
            "record": "record", "payload": "payload", "candidate_record": "candidate_record",
            "candidate_wrapper": "candidate_wrapper", "bundle_record": "bundle_record",
            "bundle_wrapper": "bundle_wrapper",
        })

    def test_public_readback_still_runs_full_verify_and_exact_stored_equality(self):
        body = _function(paper.require_paper_verification).body
        self.assertEqual(
            _body_hash(body[-3:]),
            "5cf635b8e5dd38cb24b4783a1d61306b3a55dc825c34f1d053333a270ed5030a",
        )
        calls = _calls(body, "_read_paper_verification_source")
        self.assertEqual(len(calls), 1)
        self.assertEqual(tuple(arg.id for arg in calls[0].args), ("registry", "ledger"))
        self.assertEqual({item.arg: item.value.id for item in calls[0].keywords}, {
            "run_id": "run_id", "verification_artifact_hash": "verification_artifact_hash",
            "expected_candidate_id": "expected_candidate_id",
        })
        self.assertFalse(_calls(body, "_verify_paper_from_replayed_bundle"))
        self.assertLess(calls[0].lineno, _calls(body, "verify_paper")[0].lineno)

    def test_complete_bundle_owner_and_registration_bodies_are_unchanged(self):
        from tests.test_paper_round_replay import _normalize_paper_round_body

        for function, expected in (
            (paper._require_paper_verification_bundle_source,
             "f3805c6af9882f2cec7bd64516333d678e2b365078e640ef240cd99ee372c2ca"),
            (paper.register_paper_verification,
             "082a5b5decd70e88725194b1da6cc2cc0b4977ab9d221336aed22ff30efef02f"),
        ):
            with self.subTest(function=function.__name__):
                body = (_normalize_paper_round_body(function)
                        if function is paper._require_paper_verification_bundle_source
                        else _function(function).body)
                # Keep the historical whole-body golden. Only exact D068
                # private routing is normalized, not the source obligations.
                self.assertEqual(_body_hash(body), expected)

    def test_signatures_have_no_skip_flags_callbacks_or_public_source_transport(self):
        for function, names in (
            (paper.verify_paper, ("candidate", "bundle", "registry", "ledger")),
            (paper._verify_paper_from_replayed_bundle, ("candidate", "source", "registry", "ledger")),
            (paper.require_paper_verification,
             ("registry", "ledger", "run_id", "verification_artifact_hash", "expected_candidate_id")),
            (paper._read_paper_verification_source,
             ("registry", "ledger", "run_id", "verification_artifact_hash", "expected_candidate_id")),
        ):
            with self.subTest(function=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertEqual(tuple(parameters), names)
                self.assertFalse(any(item.kind in (item.VAR_POSITIONAL, item.VAR_KEYWORD)
                                     for item in parameters.values()))
        self.assertEqual(inspect.signature(paper.require_paper_verification).parameters,
                         inspect.signature(paper._read_paper_verification_source).parameters)

    def test_private_frozen_transport_retains_actual_objects_not_an_eligibility_alias(self):
        candidate, bundle = _ineligible_view()
        stored = _diagnostic("authoritative_bundle_does_not_resolve")
        record, candidate_record, bundle_record = (_record(label) for label in ("verdict", "candidate", "bundle"))
        payload = {"verification": paper._plain_json(stored)}
        candidate_wrapper = {"candidate": paper._plain_json(candidate)}
        bundle_wrapper = {"bundle": paper._plain_json(bundle)}
        values = dict(candidate=candidate, bundle=bundle, stored_verification=stored, record=record,
                      payload=payload, candidate_record=candidate_record, candidate_wrapper=candidate_wrapper,
                      bundle_record=bundle_record, bundle_wrapper=bundle_wrapper)
        source = paper._PaperVerificationSource(**values)
        self.assertEqual(tuple(item.name for item in fields(source)), tuple(values))
        for name, value in values.items():
            with self.subTest(name=name):
                self.assertIs(getattr(source, name), value)
        self.assertEqual(source.record.validation_result, "PENDING")
        self.assertFalse(source.bundle.claims[0].scientific_writer_eligible)
        self.assertFalse(source.stored_verification.passed)
        self.assertFalse(hasattr(source, "scientific_evidence_eligible"))
        with self.assertRaises(FrozenInstanceError):
            source.bundle = bundle


class PaperVerificationSharedReplayBoundaryTests(unittest.TestCase):
    def test_no_registry_diagnostic_bytes_are_unchanged(self):
        result = paper.verify_paper(_inert_candidate(), legacy_placeholder_bundle())
        self.assertEqual(result, _diagnostic("authoritative_registry_required"))
        self.assertEqual(canonical_json_bytes(paper._plain_json(result)),
                         b'{"blockers":["UNRESOLVED_AUTHORITY"],'
                         b'"discrepancies":["authoritative_registry_required"],'
                         b'"passed":false,"verified_claim_ids":[]}')

    def test_invalid_runtime_types_keep_original_validation(self):
        for candidate, bundle in ((object(), legacy_placeholder_bundle()), (_inert_candidate(), object())):
            with self.subTest(candidate=type(candidate), bundle=type(bundle)), self.assertRaisesRegex(
                ValidationError, "paper verification requires typed candidate and bundle"
            ):
                paper.verify_paper(candidate, bundle)
        for function in (paper._read_paper_verification_source, paper.require_paper_verification):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(
                ValidationError, "paper verification readback requires registry and ledger"
            ):
                function(object(), object(), run_id="inert-run", verification_artifact_hash=_digest("absent"))

    def test_real_registry_unavailable_bundle_retains_failure_and_zero_delta(self):
        with TemporaryDirectory() as root:
            registry, ledger = ArtifactRegistry(root), EventLedger(root)
            before = (registry.verify_all(), ledger.validate())
            result = paper.verify_paper(_inert_candidate(), legacy_placeholder_bundle(), registry, ledger)
            self.assertEqual(result, _diagnostic("authoritative_bundle_does_not_resolve"))
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_real_missing_stored_source_private_and_public_refusals_are_identical(self):
        with TemporaryDirectory() as root:
            registry, ledger = ArtifactRegistry(root), EventLedger(root)
            before = (registry.verify_all(), ledger.validate())
            failures = []
            for function in (paper._read_paper_verification_source, paper.require_paper_verification):
                with self.subTest(function=function.__name__), self.assertRaises(ArtifactError) as caught:
                    function(registry, ledger, run_id="inert-run", verification_artifact_hash=_digest("absent"))
                failures.append((type(caught.exception), str(caught.exception)))
            self.assertEqual(failures[0], failures[1])
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_pending_stored_verdict_cannot_be_read_as_authority_and_adds_no_delta(self):
        with TemporaryDirectory() as root:
            registry, ledger = ArtifactRegistry(root), EventLedger(root)
            record = registry.put_json(
                {"scope": "INERT", "verification": paper._plain_json(_diagnostic("unavailable"))},
                logical_type="paper_verification", origin="non-evidentiary refusal fixture",
                creator_role=Role.SCIENTIFIC_REVIEWER, validation_result="PENDING", frozen=False,
            )
            before = (registry.verify_all(), ledger.validate())
            for function in (paper._read_paper_verification_source, paper.require_paper_verification):
                with self.subTest(function=function.__name__), self.assertRaisesRegex(
                    ValidationError, "paper authority requires a frozen PASS artifact"
                ):
                    function(registry, ledger, run_id="inert-run", verification_artifact_hash=record.sha256)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_inert_downstream_view_preserves_ineligible_claim_and_all_policy_failures(self):
        candidate, bundle = _ineligible_view()
        flags = dict(required_baselines_complete=False, leakage_resolved=False,
                     evaluator_exploitation_resolved=False, statistics_valid=False,
                     novelty_supported=False, selection_integrity_valid=False, clean_reproduction_passed=False)
        bundle = replace(bundle, **flags, soundness_verdict=SoundnessVerdict.REJECT_RESEARCH_DIRECTION)
        candidate = replace(candidate, limitations=())
        source = paper._PaperVerificationBundleSource(
            state_authority=SimpleNamespace(scope="SYSTEM_FIXTURE", status="UNTESTED"),
            bundle=bundle, issued_bundle=_record("inert-issued-bundle"),
        )
        with TemporaryDirectory() as root:
            registry, ledger = ArtifactRegistry(root), EventLedger(root)
            before = (registry.verify_all(), ledger.validate())
            result = paper._verify_paper_from_replayed_bundle(candidate, source, registry, ledger)
            expected = {
                paper.HardBlocker.UNSUPPORTED_CENTRAL_CLAIM, paper.HardBlocker.UNRESOLVED_AUTHORITY,
                paper.HardBlocker.OMITTED_REQUIRED_BASELINE, paper.HardBlocker.UNRESOLVED_LEAKAGE,
                paper.HardBlocker.EVALUATOR_EXPLOITATION, paper.HardBlocker.INVALID_STATISTICS,
                paper.HardBlocker.UNSUPPORTED_NOVELTY, paper.HardBlocker.SELECTION_BIAS,
                paper.HardBlocker.FAILED_CLEAN_REPRODUCTION, paper.HardBlocker.UNRESOLVED_BLOCKING_CHALLENGE,
            }
            self.assertEqual(result.blockers, tuple(item for item in paper.HardBlocker if item in expected))
            self.assertFalse(result.passed)
            self.assertEqual(result.verified_claim_ids, ())
            self.assertIn("claim_lacks_scientific_writer_authority:claim-main", result.discrepancies)
            self.assertIn("missing_limitation:Fixture-only external validation remains untested.",
                          result.discrepancies)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)


if __name__ == "__main__":
    unittest.main()
