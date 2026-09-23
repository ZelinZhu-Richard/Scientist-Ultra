"""Inert controls for evaluator R-check source-replay companions.

The companions are ephemeral transport values.  These tests do not issue a
scientific authority, patch a source owner, or synthesize provider/trust
evidence; real owner compatibility remains covered by the existing focused
integration suites.
"""

import ast
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
import inspect
from types import SimpleNamespace
import textwrap
import unittest

from scientist_one.evaluators import (
    AuthorityScope,
    AuthoritySourceBinding,
    AuthorityStatus,
    EvaluatorClass,
    RCheck,
    RCheckAuthority,
    _RCheckAuthorityDerivation,
    _RCheckAuthorityReplay,
    _derive_r_check_authority,
    _derive_r_check_authority_source,
    resolve_r_check_authority,
    _resolve_r_check_authority,
    _resolve_r_check_authority_source,
)
from scientist_one.roles import Role


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _function_tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function))).body[0]


def _calls(tree, name):
    return tuple(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    )


class RCheckSourceCompanionTests(unittest.TestCase):
    """DTO and source-shape checks only; no scientific owner is substituted."""

    def _companion_values(self):
        binding = AuthoritySourceBinding(
            artifact_sha256=_digest("inert-source"),
            artifact_record_hash=_digest("inert-source-record"),
            logical_type="audit_report",
            creator_role=Role.ORCHESTRATOR,
            parent_artifacts=(),
            ledger_event_id="inert-source-event",
            ledger_event_hash=_digest("inert-source-event"),
            ledger_event_index=1,
        )
        authority = RCheckAuthority(
            run_id="inert-companion-run",
            r_check=RCheck.R0,
            evaluator_class=EvaluatorClass.E0,
            actor_role=Role.ORCHESTRATOR,
            status=AuthorityStatus.UNTESTED,
            scope=AuthorityScope.SYSTEM_FIXTURE,
            source_bindings=(binding,),
            ledger_prefix_head_hash=_digest("inert-prefix"),
            ledger_prefix_event_count=2,
            reason_code="INERT_NON_EVIDENTIARY",
            derivation_checks=(("fixture", "UNTESTED"),),
        )
        source_record = SimpleNamespace(
            sha256=_digest("inert-source-record-object"),
            record_hash=_digest("inert-record-hash"),
            logical_type="audit_report",
        )
        target_record = SimpleNamespace(
            sha256=_digest("inert-authority-record"),
            record_hash=_digest("inert-authority-record-hash"),
            logical_type="r_check_authority",
        )
        resolution = SimpleNamespace(
            r_check=RCheck.R0,
            evaluator_class=EvaluatorClass.E0,
            status=AuthorityStatus.UNTESTED,
        )
        snapshot = (
            SimpleNamespace(kind="inert-registry-snapshot"),
            SimpleNamespace(kind="inert-ledger-snapshot"),
        )
        derivation = _RCheckAuthorityDerivation(
            authority=authority,
            source_records=(source_record,),
            scientific_resolution=resolution,
            entry_snapshot=snapshot,
        )
        replay = _RCheckAuthorityReplay(
            authority=authority,
            record=target_record,
            source_records=(source_record,),
            scientific_resolution=resolution,
            entry_snapshot=snapshot,
        )
        return derivation, replay, source_record, target_record, resolution, snapshot

    def test_companion_codecs_are_exact_frozen_ephemeral_transport(self) -> None:
        derivation, replay, source_record, target_record, resolution, snapshot = (
            self._companion_values()
        )
        for cls, names in (
            (
                _RCheckAuthorityDerivation,
                ("authority", "source_records", "scientific_resolution", "entry_snapshot"),
            ),
            (
                _RCheckAuthorityReplay,
                ("authority", "record", "source_records", "scientific_resolution", "entry_snapshot"),
            ),
        ):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(is_dataclass(cls))
                self.assertEqual(tuple(item.name for item in fields(cls)), names)
                self.assertTrue(cls.__dataclass_params__.frozen)
                self.assertEqual(set(cls.__slots__), set(names))
                self.assertFalse(hasattr(cls, "to_dict"))
                self.assertFalse(hasattr(cls, "canonical_bytes"))

        self.assertIs(derivation.authority, replay.authority)
        self.assertIs(derivation.source_records[0], source_record)
        self.assertIs(replay.record, target_record)
        self.assertIs(derivation.scientific_resolution, resolution)
        self.assertIs(replay.scientific_resolution, resolution)
        self.assertIs(derivation.entry_snapshot, snapshot)
        self.assertIs(replay.entry_snapshot, snapshot)
        before = {
            "derivation": tuple(getattr(derivation, item.name) for item in fields(derivation)),
            "replay": tuple(getattr(replay, item.name) for item in fields(replay)),
        }
        with self.assertRaises(FrozenInstanceError):
            derivation.authority = None
        with self.assertRaises(FrozenInstanceError):
            replay.record = None
        with self.assertRaises((AttributeError, TypeError)):
            derivation.extra = None
        self.assertFalse(hasattr(derivation, "extra"))
        self.assertEqual(
            tuple(getattr(derivation, item.name) for item in fields(derivation)),
            before["derivation"],
        )
        for item, prior in zip(fields(derivation), before["derivation"], strict=True):
            self.assertIs(getattr(derivation, item.name), prior)
        self.assertEqual(
            tuple(getattr(replay, item.name) for item in fields(replay)),
            before["replay"],
        )
        for item, prior in zip(fields(replay), before["replay"], strict=True):
            self.assertIs(getattr(replay, item.name), prior)

    def test_legacy_wrappers_keep_exact_signatures_and_tuple_or_authority_returns(self) -> None:
        expected = {
            _derive_r_check_authority: (
                "registry", "ledger", "run_id", "r_check", "evaluator_class",
                "source_artifact_sha256s", "_replayed_semantic_peer",
            ),
            _resolve_r_check_authority: (
                "registry", "ledger", "authority_artifact_sha256", "run_id",
                "_replayed_semantic_peer",
            ),
        }
        for function, names in expected.items():
            with self.subTest(function=function.__name__):
                signature = inspect.signature(function)
                self.assertEqual(tuple(signature.parameters), names)
                parameters = tuple(signature.parameters.values())
                self.assertEqual(
                    tuple(parameter.kind for parameter in parameters[:2]),
                    (inspect.Parameter.POSITIONAL_OR_KEYWORD,) * 2,
                )
                self.assertTrue(all(
                    parameter.kind is inspect.Parameter.KEYWORD_ONLY
                    for parameter in parameters[2:]
                ))

        derive_tree = _function_tree(_derive_r_check_authority)
        derive_calls = _calls(derive_tree, "_derive_r_check_authority_source")
        self.assertEqual(len(derive_calls), 1)
        self.assertEqual(
            {item.arg for item in derive_calls[0].keywords},
            {"run_id", "r_check", "evaluator_class", "source_artifact_sha256s", "_replayed_semantic_peer"},
        )
        self.assertEqual(
            ast.unparse(derive_tree.body[-1].value),
            "(derivation.authority, derivation.source_records)",
        )

        resolve_tree = _function_tree(_resolve_r_check_authority)
        resolve_calls = _calls(resolve_tree, "_resolve_r_check_authority_source")
        self.assertEqual(len(resolve_calls), 1)
        self.assertEqual(
            {item.arg for item in resolve_calls[0].keywords},
            {"authority_artifact_sha256", "run_id", "_replayed_semantic_peer"},
        )
        self.assertEqual(ast.unparse(resolve_tree.body[-1].value), "replay.authority")
        for tree in (derive_tree, resolve_tree):
            self.assertFalse(_calls(tree, "_r_check_read_snapshot"))
            self.assertFalse(_calls(tree, "_validate_runtime"))

    def test_full_private_bodies_return_companions_after_original_freshness_tails(self) -> None:
        derive_tree = _function_tree(_derive_r_check_authority_source)
        self.assertEqual(
            ast.unparse(derive_tree.body[-1].value.func),
            "_RCheckAuthorityDerivation",
        )
        self.assertEqual(len(_calls(derive_tree, "_r_check_read_snapshot")), 2)
        self.assertEqual(len(_calls(derive_tree, "_validate_runtime")), 1)
        derive_text = textwrap.dedent(inspect.getsource(_derive_r_check_authority_source))
        self.assertIn("source_records=tuple(records)", derive_text)
        self.assertIn("scientific_resolution=scientific_resolution", derive_text)
        self.assertIn("entry_snapshot=entry_snapshot", derive_text)

        resolve_tree = _function_tree(_resolve_r_check_authority_source)
        self.assertEqual(
            ast.unparse(resolve_tree.body[-1].value.func),
            "_RCheckAuthorityReplay",
        )
        self.assertEqual(len(_calls(resolve_tree, "_r_check_read_snapshot")), 2)
        self.assertEqual(len(_calls(resolve_tree, "_validate_runtime")), 1)
        self.assertEqual(len(_calls(resolve_tree, "_derive_r_check_authority_source")), 1)
        resolve_text = textwrap.dedent(inspect.getsource(_resolve_r_check_authority_source))
        for expression in (
            "record.parent_artifacts",
            "_ledger_prefix_is_current(",
            "R-check target or sources changed during complete replay",
            "source_records=source_records",
            "scientific_resolution=derivation.scientific_resolution",
            "entry_snapshot=entry_snapshot",
        ):
            self.assertIn(expression, resolve_text)

    def test_replayed_semantic_peer_remains_one_private_r7_seam_without_injection_flags(self) -> None:
        forbidden = {
            "canonical_scope", "entry_snapshot", "source_records", "scientific_resolution",
            "skip_validation", "owner_injection", "replay_peers",
        }
        for function in (
            _derive_r_check_authority,
            _derive_r_check_authority_source,
            _resolve_r_check_authority,
            _resolve_r_check_authority_source,
        ):
            self.assertTrue(forbidden.isdisjoint(inspect.signature(function).parameters))

        derive_text = textwrap.dedent(inspect.getsource(_derive_r_check_authority_source))
        resolve_text = textwrap.dedent(inspect.getsource(_resolve_r_check_authority_source))
        self.assertEqual(derive_text.count("_replayed_semantic_peer"), 5)
        self.assertEqual(resolve_text.count("_replayed_semantic_peer"), 5)
        self.assertIn("r_check is not RCheck.R7", resolve_text)
        self.assertIn("evaluator_class is not EvaluatorClass.E3", resolve_text)
        self.assertIn("values != (_replayed_semantic_peer.record.sha256,)", derive_text)
        self.assertNotIn("_replayed_semantic_peer", inspect.getsource(resolve_r_check_authority))
        self.assertIn("_replayed_semantic_peer", inspect.getsource(_derive_r_check_authority))


if __name__ == "__main__":
    unittest.main()
