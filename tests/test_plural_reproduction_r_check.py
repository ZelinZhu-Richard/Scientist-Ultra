"""Non-evidentiary plural R7 dispatch, finite conjunction, and refusal controls.

No source owner is replaced with a passing substitute and no authority issuer
is called. The exact private peer DTOs remain UNTESTED/unqualified; their use
tests the pre-existing recursion seam, not a scientific publication. Numerical
status vectors are pure truth tables, not evidence of a production lifecycle.
"""

import ast
from dataclasses import replace
import inspect
from itertools import product
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one import evaluators, gates
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.reproduction import ScientificCleanRerunOutcome
from scientist_one.research_state import ReproducibilityPackage
from scientist_one.roles import Role
from tests import test_challenger_audit_authority as legacy_fixtures
from tests import test_semantic_reproduction_cohort_audit as cohort_fixtures
from tests import test_soundness_round_replay as peer_fixtures

_digest = cohort_fixtures._digest


def _record(schema="2.0"):
    return SimpleNamespace(
        sha256=_digest("unissued-plural-r-check"),
        record_hash=_digest("unissued-plural-r-check-record"),
        logical_type="semantic_challenge_audit_authority",
        schema_version=schema,
        creator_role=Role.ADVERSARIAL_REVIEWER,
        parent_artifacts=(),
    )


def _peer(slot, authority, record):
    return gates._SemanticChallengerAuditPublishedPeer(
        authority=authority, record=record, slot=slot, findings=(),
        publication_event_index=5, review=None,
    )


def _tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function)))


def _calls(tree, name):
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == name]


class PluralReproductionRCheckTests(unittest.TestCase):
    def test_exact_incomplete_old_and_plural_peers_do_not_reenter_audit(self):
        old_slot, old_authority = peer_fixtures._incomplete_authority_dto()
        new_slot = cohort_fixtures._slot()
        for slot, authority, record in (
            (old_slot, old_authority, _record("1.0")),
            (new_slot, cohort_fixtures._authority(new_slot), _record()),
        ):
            with self.subTest(schema=record.schema_version):
                # None contexts cannot supply an audit or package source owner.
                actual, packages = evaluators._replay_semantic_audit_source_with_packages(
                    None, None, authority.run_id, record, authority.to_dict(),
                    expected_category=gates.ChallengeCategory.REPRODUCTION,
                    _replayed_peer=_peer(slot, authority, record),
                )
                self.assertEqual(actual, authority)
                self.assertIs(actual.status, gates.SemanticChallengeAuditStatus.UNTESTED)
                self.assertIs(actual.scientific_source_qualified, False)
                self.assertIsNone(packages)
                self.assertEqual(evaluators._replay_semantic_audit_source(
                    None, None, authority.run_id, record, authority.to_dict(),
                    expected_category=gates.ChallengeCategory.REPRODUCTION,
                    _replayed_peer=_peer(slot, authority, record),
                ), authority)

    def test_closed_registry_payload_dispatch_applies_before_peer_reuse(self):
        slot = cohort_fixtures._slot()
        authority = cohort_fixtures._authority(slot)
        record = _record()
        peer = _peer(slot, authority, record)
        variants = (
            ("1.0", authority.to_dict()),
            ("3.0", authority.to_dict()),
            ("2.0", {**authority.to_dict(), "schema_version": "semantic-challenge-audit-authority/v1"}),
            ("2.0", {**authority.to_dict(), "schema_version": "semantic-challenge-audit-authority/v3"}),
            ("2.0", {**authority.to_dict(), "schema_version": None}),
            ("2.0", {**authority.to_dict(), "category": "STATISTICS"}),
            ("2.0", {**authority.to_dict(), "procedure_version": "2.0"}),
            ("2.0", {**authority.to_dict(), "reproducibility_package_artifact_hash": None}),
        )
        for schema, payload in variants:
            with self.subTest(schema=schema, payload=payload), self.assertRaises((ValueError, ValidationError)):
                evaluators._replay_semantic_audit_source(
                    None, None, authority.run_id,
                    SimpleNamespace(**{**vars(record), "schema_version": schema}), payload,
                    expected_category=gates.ChallengeCategory.REPRODUCTION,
                    _replayed_peer=peer,
                )
        old_slot, old = peer_fixtures._incomplete_authority_dto()
        with self.assertRaisesRegex(ValueError, "versions do not match"):
            evaluators._replay_semantic_audit_source(
                None, None, old.run_id, record, old.to_dict(),
                expected_category=gates.ChallengeCategory.REPRODUCTION,
                _replayed_peer=_peer(old_slot, old, record),
            )

    def test_private_peer_has_exact_type_record_authority_run_and_category(self):
        slot = cohort_fixtures._slot()
        authority = cohort_fixtures._authority(slot)
        record = _record()
        peer = _peer(slot, authority, record)

        class PeerSubclass(gates._SemanticChallengerAuditPublishedPeer):
            pass

        for case in ("subclass", "record", "authority", "run", "category", "no-category", "payload", "logical-type"):
            changed_peer = peer
            changed_record = record
            payload = authority.to_dict()
            category = gates.ChallengeCategory.REPRODUCTION
            run_id = authority.run_id
            if case == "subclass":
                changed_peer = PeerSubclass(authority, record, slot, (), 5, None)
            elif case == "record":
                changed_record = SimpleNamespace(**{**vars(record), "record_hash": _digest("changed-record")})
            elif case == "authority":
                changed_peer = replace(peer, authority=SimpleNamespace(**authority.to_dict()))
            elif case == "run":
                run_id = "another-run"
            elif case == "category":
                category = gates.ChallengeCategory.STATISTICS
            elif case == "no-category":
                category = None
            elif case == "payload":
                payload["residual_risk_summary"] = "Substituted inert text."
            else:
                changed_record = SimpleNamespace(**{**vars(record), "logical_type": "diagnostic"})
            with self.subTest(case=case), self.assertRaises(ValueError):
                evaluators._replay_semantic_audit_source(
                    None, None, run_id, changed_record, payload,
                    expected_category=category, _replayed_peer=changed_peer,
                )

    def test_plural_owner_and_shared_r5_r7_routes_refuse_unissued_sources(self):
        with TemporaryDirectory(prefix="inert-plural-r-check-owner-") as directory:
            registry, ledger = legacy_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))
            authority = cohort_fixtures._authority()
            record = registry.put_json(
                authority.to_dict(), **gates._semantic_audit_artifact_metadata(True),
                mime_type="application/json", parent_artifacts=(), validation_result="PASS", frozen=True,
            )
            before = (registry.verify_all(), ledger.validate())
            for category in (None, gates.ChallengeCategory.REPRODUCTION):
                with self.subTest(category=category), self.assertRaises(ValidationError):
                    evaluators._replay_semantic_audit_source(
                        registry, ledger, authority.run_id, record, authority.to_dict(),
                        expected_category=category,
                    )
            for check, expected_reason in (
                (evaluators.RCheck.R5, "CHALLENGER_AUDIT_OWNER_REPLAY_FAILED"),
                (evaluators.RCheck.R7, "R7_CLEAN_PACKAGE_AUDIT_OWNER_REPLAY_FAILED"),
            ):
                status, reason, checks = evaluators._derive_status(
                    registry, ledger, authority.run_id, check, evaluators.EvaluatorClass.E3,
                    (record,), (authority.to_dict(),), evaluators.AuthorityScope.SYSTEM_FIXTURE,
                )
                self.assertIs(status, evaluators.AuthorityStatus.FAIL)
                self.assertEqual(reason, expected_reason)
                self.assertNotIn(("complete_reproduction_audit_owner_replay", "PASS"), checks)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_static_peer_cannot_turn_unmaterialized_package_into_a_full_owner(self):
        with TemporaryDirectory(prefix="inert-plural-r-check-package-") as directory:
            registry, ledger = legacy_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))
            package = ReproducibilityPackage(
                object_id="inert-package", producer=Role.REPRODUCTION_VERIFIER,
                run_ids=("inert-original", "inert-rerun"),
                manifest_artifact_hashes=(_digest("manifest-a"), _digest("manifest-b")),
                environment_artifact_hashes=(_digest("environment-a"), _digest("environment-b")),
                source_revision="inert-source", evaluator_version="inert-evaluator",
            )
            package_record = registry.put_json(
                package.to_dict(), logical_type=package.logical_type, schema_version=package.schema_version,
                mime_type="application/json", origin="inert unmaterialized package",
                creator_role=package.producer, creation_command=("test",),
                parent_artifacts=(), validation_result="PASS", frozen=True,
            )
            slot = cohort_fixtures._slot(count=1)
            row = replace(slot.reproduction_package_bindings[0],
                          reproducibility_package_artifact_sha256=package_record.sha256,
                          reproducibility_package_artifact_record_hash=package_record.record_hash)
            roots = sorted(((slot.research_state_snapshot_artifact_hash, slot.research_state_snapshot_artifact_record_hash),
                            (package_record.sha256, package_record.record_hash)))
            slot = replace(slot, reproduction_package_bindings=(row,),
                           evidence_artifact_hashes=tuple(item[0] for item in roots),
                           evidence_artifact_record_hashes=tuple(item[1] for item in roots))
            authority = cohort_fixtures._authority(slot)
            before = (registry.verify_all(), ledger.validate())
            with self.assertRaisesRegex(ValidationError, "lacks exact canonical parents"):
                evaluators._replay_reproduction_cohort_packages(registry, ledger, authority.run_id, authority)
            status, reason, _checks = evaluators._derive_status(
                registry, ledger, authority.run_id, evaluators.RCheck.R7, evaluators.EvaluatorClass.E3,
                (_record(),), (authority.to_dict(),), evaluators.AuthorityScope.SYSTEM_FIXTURE,
                _replayed_semantic_peer=_peer(slot, authority, _record()),
            )
            self.assertIs(status, evaluators.AuthorityStatus.FAIL)
            self.assertEqual(reason, "R7_CLEAN_PACKAGE_AUDIT_OWNER_REPLAY_FAILED")
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_missing_mapped_package_is_not_dropped_or_replaced_with_first_package(self):
        with TemporaryDirectory(prefix="inert-plural-r-check-missing-") as directory:
            registry, ledger = legacy_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))
            authority = cohort_fixtures._authority()
            before = (registry.verify_all(), ledger.validate())
            with self.assertRaises(ArtifactError):
                evaluators._replay_reproduction_cohort_packages(registry, ledger, authority.run_id, authority)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_all_clean_outcomes_and_audit_outcomes_have_conservative_conjunction(self):
        # Exhaustive finite mapping, with no authority DTOs or source owners.
        for outcomes, audit_status, scope in product(
            product(ScientificCleanRerunOutcome, repeat=3),
            gates.SemanticChallengeAuditStatus,
            evaluators.AuthorityScope,
        ):
            if any(value is not ScientificCleanRerunOutcome.PASS for value in outcomes):
                expected = evaluators.AuthorityStatus.FAIL, "SCIENTIFIC_CLEAN_RERUN_FAILED"
            elif audit_status is gates.SemanticChallengeAuditStatus.FAIL:
                expected = evaluators.AuthorityStatus.FAIL, "REPRODUCTION_AUDIT_FAILED"
            elif (audit_status is not gates.SemanticChallengeAuditStatus.PASS
                  or scope is not evaluators.AuthorityScope.SCIENTIFIC):
                expected = evaluators.AuthorityStatus.UNTESTED, "REPRODUCTION_AUDIT_INCOMPLETE"
            else:
                expected = evaluators.AuthorityStatus.PASS, "SCIENTIFIC_CLEAN_COHORT_AND_AUDIT_REPLAYED"
            with self.subTest(outcomes=outcomes, audit=audit_status, scope=scope):
                self.assertEqual(evaluators._derive_reproduction_cohort_status(outcomes, audit_status, scope), expected)

    def test_outcome_projection_rejects_empty_string_and_bool_shortcuts(self):
        valid = ((ScientificCleanRerunOutcome.PASS,), gates.SemanticChallengeAuditStatus.PASS,
                 evaluators.AuthorityScope.SCIENTIFIC)
        variants = (((), *valid[1:]), ([ScientificCleanRerunOutcome.PASS], *valid[1:]),
                    (("PASS",), *valid[1:]), ((True,), *valid[1:]),
                    (valid[0], "PASS", valid[2]), (valid[0], valid[1], "SCIENTIFIC"))
        for vector in variants:
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                evaluators._derive_reproduction_cohort_status(*vector)

    def test_full_package_output_count_is_mapping_not_result_test_union(self):
        authority = cohort_fixtures._authority()
        self.assertEqual(len(authority.reproduction_package_bindings), 2)
        self.assertEqual(len(authority.result_artifact_hashes), 3)
        for values in ((), (object(),), (object(), object(), object())):
            with self.subTest(count=len(values)), self.assertRaisesRegex(ValueError, "coverage is incomplete"):
                evaluators._reproduction_cohort_clean_outcomes(authority.run_id, authority, values)
        with self.assertRaisesRegex(ValueError, "full package sources disagree"):
            evaluators._reproduction_cohort_clean_outcomes(authority.run_id, authority, (object(), object()))

    def test_actual_v2_publication_metadata_is_selected_not_later_reference(self):
        with TemporaryDirectory(prefix="inert-plural-r-check-publication-") as directory:
            registry, ledger = legacy_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))
            slot = cohort_fixtures._slot()
            authority = cohort_fixtures._authority(slot)
            record = _record()
            previous = ledger.events()[-1]
            metadata = gates._semantic_challenge_audit_publication_metadata(record, authority)
            self.assertEqual(metadata["semantic_challenge_audit_authority_publication"]["schema_version"],
                             "semantic_challenge_audit_authority_event/v2")
            before_use = cohort_fixtures._event(slot, previous, event_id="inert-before-use",
                                               artifact_hashes=(record.sha256,), metadata={})
            publication = cohort_fixtures._event(slot, before_use, event_id="inert-publication",
                                                artifact_hashes=(record.sha256,), metadata=metadata)
            after_use = cohort_fixtures._event(slot, publication, event_id="inert-after-use",
                                              artifact_hashes=(record.sha256,), metadata={})
            events = (previous, before_use, publication, after_use)
            binding = evaluators._event_binding(events, record)
            self.assertEqual((binding.ledger_event_id, binding.ledger_event_hash, binding.ledger_event_index),
                             (publication.event_id, publication.event_hash, 2))
            with self.assertRaisesRegex(ValueError, "one exact ledger admission"):
                evaluators._event_binding((*events, publication), record)
            substituted = cohort_fixtures._event(
                slot, before_use, event_id="inert-substituted-publication", artifact_hashes=(record.sha256,),
                metadata={**metadata, "artifact_record_hashes": [_digest("another-record")]},
            )
            with self.assertRaisesRegex(ValueError, "substituted"):
                evaluators._event_binding((previous, substituted, after_use), record)

    def test_legacy_bundle_profile_guard_keeps_plural_out_of_r5_and_r7_v1(self):
        evaluators._require_legacy_bundle_source_profile((_record("1.0"),))
        for schema in ("2.0", "3.0"):
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "cohort-aware V2"):
                evaluators._require_legacy_bundle_source_profile((_record(schema),))

    def test_source_flow_retains_full_companion_and_all_peer_package_owners(self):
        replay = _tree(evaluators._replay_semantic_audit_source_with_packages)
        self.assertEqual(len(_calls(replay, "require_semantic_challenge_audit_authority")), 1)
        self.assertEqual(len(_calls(replay, "_require_semantic_reproduction_cohort_audit_source")), 1)
        self.assertTrue(any(isinstance(node, ast.Attribute) and node.attr == "package_authorities"
                            for node in ast.walk(replay)))
        wrapper = _tree(evaluators._replay_semantic_audit_source)
        self.assertEqual(len(_calls(wrapper, "_replay_semantic_audit_source_with_packages")), 1)
        packages = _tree(evaluators._replay_reproduction_cohort_packages)
        loops = [node for node in ast.walk(packages) if isinstance(node, ast.For)]
        self.assertEqual(len(loops), 1)
        self.assertEqual(ast.unparse(loops[0].iter), "audit.reproduction_package_bindings")
        self.assertEqual(len(_calls(loops[0], "require_scientific_reproducibility_package")), 1)
        self.assertFalse(any(isinstance(node, (ast.Break, ast.Continue, ast.Return)) for node in ast.walk(loops[0])))
        self.assertFalse(_calls(packages, "_require_semantic_reproduction_cohort_audit_source"))
        status = _tree(evaluators._derive_status)
        for name in ("_replay_semantic_audit_source_with_packages", "_replay_reproduction_cohort_packages",
                     "_reproduction_cohort_clean_outcomes", "_derive_reproduction_cohort_status"):
            self.assertEqual(len(_calls(status, name)), 1)
        for function in (evaluators.register_r_check_authority, evaluators.resolve_r_check_authority):
            self.assertFalse(any("peer" in name for name in inspect.signature(function).parameters))


if __name__ == "__main__":
    unittest.main()
