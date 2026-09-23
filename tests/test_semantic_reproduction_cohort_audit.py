"""Non-evidentiary plural audit codec, finite capacity, and owner-refusal controls.

No scientific source owner is mocked, no semantic/private issuer is called,
and no live provider or scientific audit is admitted. Inert DTOs, diagnostic
registry content, and mechanical ledger events test shape/custody only.
"""

import ast
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import inspect
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one import gates
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.ledger import LedgerEvent
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests import test_challenger_audit_authority as fixtures

_digest = fixtures._digest


def _slot(count=2):
    legacy = fixtures.SemanticChallengerAuditAuthorityTests()._slot(
        category=gates.ChallengeCategory.REPRODUCTION,
        scientific_source_qualified=False,
    )
    rows = tuple(sorted((
        gates.ReproductionResultPackageBinding(
            _digest(f"result-{index}"), _digest(f"result-record-{index}"),
            _digest(f"package-{index}"), _digest(f"package-record-{index}"),
        ) for index in range(count)
    ), key=lambda item: item.result_artifact_sha256))
    results = sorted((
        *((row.result_artifact_sha256, row.result_artifact_record_hash) for row in rows),
        (_digest("statistical-test"), _digest("statistical-test-record")),
    ))
    evidence = sorted((
        (legacy.research_state_snapshot_artifact_hash, legacy.research_state_snapshot_artifact_record_hash),
        *((row.reproducibility_package_artifact_sha256, row.reproducibility_package_artifact_record_hash)
          for row in rows),
    ))
    contract = gates._semantic_challenger_audit_contract(
        gates.ChallengeCategory.REPRODUCTION, procedure_version="3.0",
    )
    common = {
        field.name: getattr(legacy, field.name)
        for field in fields(gates.SemanticReproductionCohortAuditSlot)
        if hasattr(legacy, field.name)
    }
    common.update(
        evidence_artifact_hashes=tuple(item[0] for item in evidence),
        evidence_artifact_record_hashes=tuple(item[1] for item in evidence),
        result_artifact_hashes=tuple(item[0] for item in results),
        result_artifact_record_hashes=tuple(item[1] for item in results),
        procedure_version=contract.procedure_version,
        prompt_template_hash=contract.prompt_template_hash,
    )
    return gates.SemanticReproductionCohortAuditSlot(**common, reproduction_package_bindings=rows)


def _authority(slot=None, finding_count=0):
    """Closed UNTESTED codec, never a production owner result."""
    slot = slot or _slot()
    common = {
        field.name: getattr(slot, field.name)
        for field in fields(gates.SemanticReproductionCohortAuditAuthority)
        if hasattr(slot, field.name)
    }
    findings = tuple(_digest(f"finding-{index}") for index in range(finding_count))
    finding_records = tuple(_digest(f"finding-record-{index}") for index in range(finding_count))
    return gates.SemanticReproductionCohortAuditAuthority(
        **common, authority_id="inert-cohort-authority",
        slot_subject_sha256=slot.subject_sha256,
        slot_event_id=slot.event_id, slot_event_hash=slot.event_hash,
        slot_event_index=slot.event_index,
        semantic_judgment_artifact_hash=_digest("judgment"),
        semantic_judgment_artifact_record_hash=_digest("judgment-record"),
        finding_artifact_hashes=findings, finding_artifact_record_hashes=finding_records,
        challenger_execution_artifact_hash=_digest("execution"),
        challenger_execution_artifact_record_hash=_digest("execution-record"),
        challenger_review_artifact_hash=_digest("review"),
        challenger_review_artifact_record_hash=_digest("review-record"),
        status=gates.SemanticChallengeAuditStatus.UNTESTED,
        residual_risk_summary="Inert codec; no positive scientific audit.",
        input_artifact_hashes=(*slot.scoped_artifact_hashes, _digest("judgment"), *findings,
                               _digest("execution"), _digest("review")),
        input_artifact_record_hashes=(*slot.scoped_artifact_record_hashes, _digest("judgment-record"),
                                      *finding_records, _digest("execution-record"), _digest("review-record")),
        verification_event_id="inert-verification", verification_event_hash=_digest("verification"),
        verification_event_index=slot.event_index + 1,
    )


def _event(slot, previous, **overrides):
    subject = gates._semantic_audit_subject_binding(
        scope=slot, run_id=slot.run_id, category=slot.category,
        research_state_snapshot_artifact_hash=slot.research_state_snapshot_artifact_hash,
        claim_graph_artifact_hash=slot.claim_graph_artifact_hash,
        claim_graph_artifact_record_hash=slot.claim_graph_artifact_record_hash,
    )
    binding = gates._semantic_challenger_audit_slot_binding(
        slot_id=slot.slot_id, subject_sha256=slot.subject_sha256,
        assessment_id=slot.assessment_id, provider_invocation_id=slot.provider_invocation_id,
        contract=gates._semantic_audit_contract_for(slot), subject_binding=subject,
    )
    options = dict(
        run_id=slot.run_id, actor_role=Role.ADVERSARIAL_REVIEWER,
        state_before=previous.state_after, requested_state_after=previous.state_after,
        artifact_hashes=slot.scoped_artifact_hashes, code_version=previous.code_version,
        configuration_hash=previous.configuration_hash,
        dataset_identifiers=previous.dataset_identifiers, random_seeds=previous.random_seeds,
        evaluator_outputs=(), reason="reserved one prospective semantic Challenger audit",
        prior_event_hash=previous.event_hash, event_id=slot.event_id, event_type="CHECKPOINT",
        metadata={"semantic_challenger_audit_slot": binding},
    )
    options.update(overrides)
    return LedgerEvent.create(**options)


def _scope(slot):
    """Inert projection inputs; never substituted for a canonical/source owner."""
    packages = []
    for index, row in enumerate(slot.reproduction_package_bindings):
        def leaf(sha, record):
            return SimpleNamespace(
                artifact_sha256=sha, artifact_record_hash=record,
                materialization_event_id=f"inert-source-{index}",
                materialization_event_hash=_digest(f"source-event-{index}"),
                materialization_event_index=0,
            )
        packages.append(SimpleNamespace(
            package_binding=leaf(row.reproducibility_package_artifact_sha256,
                                 row.reproducibility_package_artifact_record_hash),
            original_result_binding=leaf(row.result_artifact_sha256, row.result_artifact_record_hash),
            clean_rerun_authority=SimpleNamespace(verification_event_index=0),
            clean_rerun_authority_artifact_sha256=_digest(f"clean-{index}"),
            clean_rerun_authority_record_hash=_digest(f"clean-record-{index}"),
            run_bindings=(leaf(_digest(f"original-run-{index}"), _digest(f"original-run-record-{index}")),
                          leaf(_digest(f"clean-run-{index}"), _digest(f"clean-run-record-{index}"))),
        ))
    return gates._SemanticReproductionCohortAuditCanonicalScope(
        state=SimpleNamespace(entries=(), snapshot_artifact_record_hash=slot.research_state_snapshot_artifact_record_hash,
                              ledger_head_hash=_digest("inert-head"), ledger_event_count=1),
        central_claim_ids=slot.central_claim_ids,
        evidence_artifact_hashes=slot.evidence_artifact_hashes,
        evidence_artifact_record_hashes=slot.evidence_artifact_record_hashes,
        result_artifact_hashes=slot.result_artifact_hashes,
        result_artifact_record_hashes=slot.result_artifact_record_hashes,
        reproduction_package_bindings=slot.reproduction_package_bindings,
        scientific_source_qualified=False, package_authorities=tuple(packages),
        clean_publications=tuple(gates._SemanticReproductionCohortCleanPublication(
            package.clean_rerun_authority_artifact_sha256, package.clean_rerun_authority_record_hash,
            f"inert-clean-publication-{index}", _digest(f"inert-clean-publication-{index}"), 1,
        ) for index, package in enumerate(packages)),
    )


class SemanticReproductionCohortAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SemanticChallengerAuditAuthorityTests()

    def test_explicit_contract_family_preserves_legacy_map_and_instructions(self):
        self.assertEqual(len(gates.SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS), 12)
        self.assertEqual(len(gates.SEMANTIC_REPRODUCTION_COHORT_AUDIT_RESOLVER_CONTRACTS), 1)
        old = gates._semantic_challenger_audit_contract(gates.ChallengeCategory.REPRODUCTION)
        new = gates._semantic_audit_contract_for(_slot())
        self.assertEqual(old.procedure_version, "2.0")
        self.assertEqual(new.procedure_version, "3.0")
        self.assertNotEqual(old.prompt_template_hash, new.prompt_template_hash)
        self.assertEqual(new.prompt_template_hash, hashlib.sha256(
            gates.semantic_reproduction_cohort_audit_instructions().encode()).hexdigest())
        self.assertIn(new.key, gates._CHALLENGER_ATTACK_RESOLVERS)
        for category in gates.ChallengeCategory:
            if category is not gates.ChallengeCategory.REPRODUCTION:
                with self.subTest(category=category), self.assertRaises(ValidationError):
                    gates._semantic_challenger_audit_contract(category, procedure_version="3.0")

    def test_closed_plural_codec_is_frozen_and_has_no_singular_alias(self):
        authority = _authority()
        payload = authority.to_dict()
        self.assertEqual(payload["schema_version"], "semantic-challenge-audit-authority/v2")
        self.assertEqual(gates.SemanticReproductionCohortAuditAuthority.from_dict(payload), authority)
        for value in (_slot(), authority, _scope(_slot())):
            self.assertFalse(hasattr(value, "reproducibility_package_artifact_hash"))
        self.assertNotIn("reproducibility_package_artifact_hash", payload)
        with self.assertRaises(FrozenInstanceError):
            authority.reproduction_package_bindings = ()
        for name, value in (("reproducibility_package_artifact_hash", None), ("skip_validation", True)):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                gates.SemanticReproductionCohortAuditAuthority.from_dict({**payload, name: value})
        with self.assertRaises(ValidationError):
            gates.SemanticChallengeAuditAuthority.from_dict(payload)

    def test_mixed_versions_and_procedures_are_not_relabels(self):
        authority = _authority()
        for field, value in (("schema_version", "semantic-challenge-audit-authority/v1"),
                             ("procedure_version", "2.0"), ("category", "STATISTICS")):
            payload = {**authority.to_dict(), field: value}
            with self.subTest(field=field), self.assertRaises(ValidationError):
                gates.SemanticReproductionCohortAuditAuthority.from_dict(payload)
        with self.assertRaises(ValidationError):
            replace(_slot(), procedure_version="2.0")

    def test_new_scalar_and_collection_leaves_are_closed_without_changing_old_dto(self):
        class Integer(int):
            pass
        class Text(str):
            pass
        for value in (_slot(), _authority()):
            field = "event_index" if type(value) is gates.SemanticReproductionCohortAuditSlot else "verification_event_index"
            for changes in ({field: Integer(getattr(value, field))},
                            {"run_id": Text(value.run_id)},
                            {"result_artifact_hashes": list(value.result_artifact_hashes)},
                            {"scientific_source_qualified": 0}):
                with self.subTest(changes=changes), self.assertRaises(ValidationError):
                    replace(value, **changes)
        with self.assertRaises(ValidationError):
            _authority(finding_count=33)

    def test_mapping_has_exact_native_hashes_and_no_repeated_or_spliced_rows(self):
        slot = _slot()
        first, second = slot.reproduction_package_bindings
        class Text(str):
            pass
        for field in fields(first):
            with self.subTest(field=field.name), self.assertRaises(ValidationError):
                replace(first, **{field.name: Text(getattr(first, field.name))})
        alternatives = (
            (), list(slot.reproduction_package_bindings), (second, first), (first, first),
            (replace(first, result_artifact_record_hash=_digest("splice")), second),
            (first, replace(second, reproducibility_package_artifact_sha256=first.reproducibility_package_artifact_sha256)),
            (SimpleNamespace(**first.to_dict()), second),
        )
        for rows in alternatives:
            with self.subTest(rows=rows), self.assertRaises(ValidationError):
                replace(slot, reproduction_package_bindings=rows)
        for rows in (None, (), [{}], [{**first.to_dict(), "result_outcome": "PASS"}]):
            payload = {**_authority(slot).to_dict(), "reproduction_package_bindings": rows}
            with self.subTest(rows=rows), self.assertRaises(ValidationError):
                gates.SemanticReproductionCohortAuditAuthority.from_dict(payload)

    def test_coverage_targets_actual_results_not_the_test_union(self):
        slot = _slot()
        rows = slot.reproduction_package_bindings
        results = tuple((row.result_artifact_sha256, row.result_artifact_record_hash) for row in rows)
        packages = tuple((row.reproducibility_package_artifact_sha256, row.reproducibility_package_artifact_record_hash) for row in rows)
        gates._require_reproduction_cohort_coverage(rows, result_artifact_records=results, package_artifact_records=packages)
        cases = (
            (rows[:-1], results, packages),
            (rows, results[:-1], packages),
            (rows, results, packages[:-1]),
            (rows, tuple(zip(slot.result_artifact_hashes, slot.result_artifact_record_hashes)), packages),
            (rows, (*results, (_digest("extra-result"), _digest("extra-record"))), packages),
            (rows, results, (*packages, (_digest("extra-package"), _digest("extra-package-record")))),
        )
        for mapping, result_pairs, package_pairs in cases:
            with self.subTest(mapping=mapping), self.assertRaises(ValidationError):
                gates._require_reproduction_cohort_coverage(mapping, result_artifact_records=result_pairs, package_artifact_records=package_pairs)

    def test_every_package_chronology_includes_both_runs(self):
        slot = _slot()
        scope = _scope(slot)
        self.assertEqual(gates._semantic_reproduction_cohort_chronology(scope, slot), 1)
        for index, package in enumerate(scope.package_authorities):
            for leaf, field in ((package.package_binding, "materialization_event_index"),
                                (package.original_result_binding, "materialization_event_index"),
                                (package.clean_rerun_authority, "verification_event_index"),
                                *((run, "materialization_event_index") for run in package.run_bindings)):
                setattr(leaf, field, slot.event_index)
                with self.subTest(package=index, field=field), self.assertRaises(ValidationError):
                    gates._semantic_reproduction_cohort_chronology(scope, slot)
                setattr(leaf, field, 0)
        with self.assertRaises(ValidationError):
            gates._semantic_reproduction_cohort_chronology(replace(scope, package_authorities=scope.package_authorities[:1]), slot)

    def test_clean_publication_must_precede_slot_without_new_package_order_semantics(self):
        slot = _slot()
        scope = _scope(slot)
        # This inert package materialization is index 0 and publication index 1.
        # The new guard intentionally requires publication-before-slot only.
        self.assertEqual(gates._semantic_reproduction_cohort_chronology(scope, slot), 1)
        original = scope.clean_publications[0]
        for changed in (
            replace(original, event_index=slot.event_index),
            replace(original, event_index=slot.event_index + 1),
            replace(original, event_index=0),
            replace(original, artifact_sha256=_digest("wrong-clean")),
            replace(original, artifact_record_hash=_digest("wrong-clean-record")),
        ):
            tampered = replace(scope, clean_publications=(changed, *scope.clean_publications[1:]))
            with self.subTest(changed=changed), self.assertRaises(ValidationError):
                gates._semantic_reproduction_cohort_chronology(tampered, slot)
        with self.assertRaises(ValidationError):
            gates._semantic_reproduction_cohort_chronology(replace(scope, clean_publications=()), slot)

    def test_clean_publication_selector_matches_full_owner_predicate_not_raw_references(self):
        with TemporaryDirectory(prefix="inert-clean-publication-") as directory:
            _registry, ledger = self.fixture._runtime(Path(directory))
            slot = _slot()
            clean_hash, plan_hash = _digest("clean-authority"), _digest("clean-plan")
            ordinary = ledger.append(_event(slot, ledger.events()[-1], event_id="ordinary-clean-reference",
                artifact_hashes=(clean_hash,), metadata={"inert": "untagged reference"}))
            unrelated = ledger.append(_event(slot, ordinary, event_id="unrelated-clean-publication",
                artifact_hashes=(_digest("other-clean"),), metadata={
                    "scientific_clean_rerun_authority_publication": {"plan_artifact_sha256": _digest("other-plan")}}))
            selected = ledger.append(_event(slot, unrelated, event_id="inert-selected-clean-publication",
                artifact_hashes=(clean_hash,), metadata={
                    "scientific_clean_rerun_authority_publication": {"plan_artifact_sha256": plan_hash}}))
            before = ledger.validate(raise_on_error=True)
            self.assertEqual(gates._semantic_reproduction_cohort_clean_publication_candidates(
                before.events, artifact_sha256=clean_hash, plan_artifact_sha256=plan_hash), ((3, selected),))
            alias = ledger.append(_event(slot, selected, event_id="inert-plan-alias",
                artifact_hashes=(_digest("unrelated-artifact"),), metadata={
                    "scientific_clean_rerun_authority_publication": {"plan_artifact_sha256": plan_hash}}))
            self.assertEqual(gates._semantic_reproduction_cohort_clean_publication_candidates(
                ledger.validate(raise_on_error=True).events, artifact_sha256=clean_hash,
                plan_artifact_sha256=plan_hash), ((3, selected), (4, alias)))

    def test_slot_event_exact_version_roundtrip_and_context_replay(self):
        with TemporaryDirectory(prefix="inert-cohort-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            before = (registry.verify_all(), ledger.validate())
            slot = _slot()
            previous = before[1].events[-1]
            event = _event(slot, previous)
            decoded = gates._semantic_challenger_audit_slot_from_event(event, 1, ledger_path=slot.ledger_path)
            self.assertIs(type(decoded), gates.SemanticReproductionCohortAuditSlot)
            self.assertEqual(decoded.reproduction_package_bindings, slot.reproduction_package_bindings)
            gates._validate_semantic_challenger_audit_slot_event(event, 1, (previous, event), slot=decoded)
            for field, value in (("schema_version", gates.SEMANTIC_CHALLENGER_AUDIT_SLOT_EVENT_SCHEMA),
                                 ("procedure_version", "2.0")):
                binding = dict(event.to_dict()["metadata"]["semantic_challenger_audit_slot"])
                binding[field] = value
                malformed = _event(slot, previous, metadata={"semantic_challenger_audit_slot": binding})
                with self.subTest(field=field), self.assertRaises(ValidationError):
                    gates._semantic_challenger_audit_slot_from_event(malformed, 1, ledger_path=slot.ledger_path)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_actual_valid_ledger_rejects_cross_version_one_use_slot_and_invocation(self):
        for category in (gates.ChallengeCategory.REPRODUCTION, gates.ChallengeCategory.STATISTICS):
            with self.subTest(category=category), TemporaryDirectory(prefix="inert-cohort-collision-") as directory:
                registry, ledger = self.fixture._runtime(Path(directory))
                old = self.fixture._slot(category=category, scientific_source_qualified=False)
                first = ledger.append(_event(old, ledger.events()[-1]))
                slot = _slot()
                ledger.append(_event(slot, first, event_id="inert-second-reservation"))
                validated = ledger.validate(raise_on_error=True)
                self.assertTrue(validated.valid)
                before = (registry.verify_all(), validated)
                with self.assertRaisesRegex(ValidationError, "one exact prospective slot|duplicated or rerolled"):
                    gates._require_semantic_challenger_audit_slot_static(
                        registry, validated, ledger_path=slot.ledger_path,
                        slot_id=slot.slot_id, expected_run_id=slot.run_id,
                    )
                self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_common_round_key_does_not_create_a_version_reroll_namespace(self):
        slot = _slot()
        authority = _authority(slot)
        self.assertEqual(gates._semantic_challenger_audit_round_key(slot),
                         gates._semantic_challenger_audit_authority_round_key(authority))
        old = self.fixture._slot(category=gates.ChallengeCategory.REPRODUCTION, scientific_source_qualified=False)
        self.assertEqual(slot.slot_id, old.slot_id)
        self.assertEqual(slot.subject_sha256, old.subject_sha256)
        self.assertNotEqual(slot.procedure_version, old.procedure_version)

    def test_parent_capacity_reserves_all_32_findings_and_three_source_roots(self):
        maximum = gates.MAX_ARTIFACT_PARENTS - 32 - 3
        gates._require_reproduction_cohort_parent_capacity(maximum)
        for value in (maximum + 1, gates.MAX_ARTIFACT_PARENTS, True, 0, -1, float(maximum)):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                gates._require_reproduction_cohort_parent_capacity(value)

    def test_worst_case_wire_arithmetic_bounds_complete_authority_and_events(self):
        with TemporaryDirectory(prefix="inert-cohort-size-") as directory:
            _registry, ledger = self.fixture._runtime(Path(directory))
            for count in (1, 2, 30, 70):
                slot = _slot(count)
                event = _event(slot, ledger.events()[-1])
                authority_bound, verification_bound, publication_bound = gates._semantic_reproduction_cohort_wire_capacity(slot, event)
                authority = replace(_authority(slot, 32), residual_risk_summary="\u0001" * gates.MAX_TEXT)
                self.assertGreaterEqual(authority_bound, len(canonical_json_bytes(authority.to_dict())) + 1)
                self.assertGreater(verification_bound, publication_bound)
                self.assertLess(authority_bound, gates.MAX_GATE_RECEIPT_BYTES)
                if count == 30:
                    self.assertLess(verification_bound, gates._MAX_SEMANTIC_CHALLENGE_AUDIT_EVENT_BYTES)
                elif count == 70:
                    self.assertGreater(verification_bound, gates._MAX_SEMANTIC_CHALLENGE_AUDIT_EVENT_BYTES)

    def test_complete_inert_input_retains_plural_joins_and_adverse_content(self):
        with TemporaryDirectory(prefix="inert-cohort-input-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            def diagnostic(name, content, parents=()):
                return registry.put_json({"inert": name, **content}, logical_type="inert_projection_content",
                    schema_version="1.0", mime_type="application/json", origin="non-evidentiary input projection",
                    creator_role=Role.ORCHESTRATOR, creation_command=("test",),
                    parent_artifacts=parents, validation_result="PASS", frozen=True)
            snapshot = diagnostic("snapshot", {})
            graph = diagnostic("graph", {})
            test = diagnostic("test", {})
            rows = []
            result_records = []
            package_records = []
            for index, (outcome, reproduction) in enumerate((("NEGATIVE", "FAIL"), ("NULL", "OUTSIDE_TOLERANCE"))):
                result = diagnostic(f"result-{index}", {"outcome": outcome})
                package = diagnostic(f"package-{index}", {"outcome": reproduction, "original": result.sha256}, (result.sha256,))
                result_records.append(result)
                package_records.append(package)
                rows.append(gates.ReproductionResultPackageBinding(result.sha256, result.record_hash, package.sha256, package.record_hash))
            evidence = sorted((snapshot, *package_records), key=lambda record: record.sha256)
            results = sorted((*result_records, test), key=lambda record: record.sha256)
            slot = replace(_slot(),
                research_state_snapshot_artifact_hash=snapshot.sha256,
                research_state_snapshot_artifact_record_hash=snapshot.record_hash,
                claim_graph_artifact_hash=graph.sha256, claim_graph_artifact_record_hash=graph.record_hash,
                evidence_artifact_hashes=tuple(item.sha256 for item in evidence),
                evidence_artifact_record_hashes=tuple(item.record_hash for item in evidence),
                result_artifact_hashes=tuple(item.sha256 for item in results),
                result_artifact_record_hashes=tuple(item.record_hash for item in results),
                reproduction_package_bindings=tuple(sorted(rows, key=lambda row: row.result_artifact_sha256)))
            scope = _scope(slot)
            before = (registry.verify_all(), ledger.validate())
            text = gates._semantic_challenger_audit_input_from_scope(registry, slot=slot, canonical_scope=scope)
            payload = json.loads(text)
            self.assertEqual(payload["schema_version"], "semantic-challenger-audit-input/v3")
            self.assertEqual(len(payload["reproduction_package_joins"]), 2)
            self.assertEqual([item["clean_rerun_publication_event_hash"] for item in payload["reproduction_package_joins"]],
                             [item.event_hash for item in scope.clean_publications])
            self.assertEqual(payload["reproduction_package_bindings"], [row.to_dict() for row in slot.reproduction_package_bindings])
            self.assertNotIn("reproduction_package_join", payload)
            self.assertNotIn("reproducibility_package_artifact_hash", payload)
            for outcome in ("NEGATIVE", "NULL", "FAIL", "OUTSIDE_TOLERANCE"):
                self.assertIn(outcome, text)
            gates._preflight_semantic_reproduction_cohort_reservation(
                registry, slot=slot, canonical_scope=scope,
                slot_event=_event(slot, ledger.events()[-1]),
            )
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_shared_event_slot_matchers_keep_id_aliases_but_not_ordinary_references(self):
        with TemporaryDirectory(prefix="inert-cohort-event-slots-") as directory:
            _registry, ledger = self.fixture._runtime(Path(directory))
            slot = _slot()
            authority = _authority(slot)
            verification_id = f"semantic-audit-verification-{authority.authority_id[-24:]}"
            publication_id = f"semantic-audit-publication-{authority.authority_id[-24:]}"
            previous = ledger.events()[-1]
            for metadata in ({}, {"renamed": True}, {"semantic_challenge_audit_authority": "malformed"}):
                event = _event(slot, previous, event_id=verification_id, metadata=metadata)
                self.assertTrue(gates._semantic_audit_verification_candidate(event,
                    slot_id=slot.slot_id, judgment_hash=authority.semantic_judgment_artifact_hash,
                    authority_id=authority.authority_id))
            for metadata in ({}, {"semantic_challenge_audit_authority_publication": "malformed"}):
                event = _event(slot, previous, event_id=publication_id, metadata=metadata)
                self.assertTrue(gates._semantic_audit_publication_candidate(event,
                    slot_id=slot.slot_id, authority_id=authority.authority_id, authority_hash=_digest("published")))
            ordinary = _event(slot, previous, event_id="ordinary-reference", metadata={}, artifact_hashes=(_digest("published"),))
            self.assertFalse(gates._semantic_audit_publication_candidate(ordinary,
                slot_id=slot.slot_id, authority_id=authority.authority_id, authority_hash=_digest("published")))

    def test_structural_authority_inventory_matches_old_new_identity_and_parent_aliases(self):
        slot = _slot()
        authority = _authority(slot)
        cases = (
            {"slot_id": slot.slot_id}, {"authority_id": authority.authority_id},
            {"provider_invocation_id": slot.provider_invocation_id},
            {"run_id": slot.run_id, "category": "REPRODUCTION"},
        )
        for schema in ("1.0", "2.0"):
            for payload in cases:
                with self.subTest(schema=schema, payload=payload), TemporaryDirectory(prefix="inert-cohort-inventory-") as directory:
                    registry, ledger = self.fixture._runtime(Path(directory))
                    record = registry.put_json({"inert": True, **payload},
                        logical_type=gates.SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
                        schema_version=schema, mime_type="application/json", origin="inert structural collision",
                        creator_role=Role.ORCHESTRATOR, creation_command=("test",),
                        parent_artifacts=(), validation_result="PASS", frozen=True)
                    before = (registry.verify_all(), ledger.validate())
                    self.assertEqual(gates._semantic_reproduction_cohort_authority_candidates(
                        registry, before[0].records, slot=slot,
                        judgment_hash=authority.semantic_judgment_artifact_hash,
                        authority_id=authority.authority_id, input_hashes=authority.input_artifact_hashes), (record,))
                    self.assertEqual((registry.verify_all(), ledger.validate()), before)
        with TemporaryDirectory(prefix="inert-cohort-renamed-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            parent = registry.list_records()[0]
            alias = registry.put_bytes(b"\x00\xff", logical_type="renamed_diagnostic", schema_version="1.0",
                mime_type="application/octet-stream", origin="inert alias", creator_role=Role.ORCHESTRATOR,
                creation_command=("test",), parent_artifacts=(parent.sha256,), validation_result="PASS", frozen=True)
            self.assertEqual(gates._semantic_reproduction_cohort_authority_candidates(
                registry, tuple(registry.list_records()), slot=slot,
                judgment_hash=authority.semantic_judgment_artifact_hash, authority_id=authority.authority_id,
                input_hashes=(parent.sha256,)), (alias,))

    def test_full_content_preflight_does_not_truncate_large_or_binary_diagnostics(self):
        with TemporaryDirectory(prefix="inert-cohort-content-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            def diagnostic(content):
                return registry.put_bytes(content, logical_type="inert_content",
                    schema_version="1.0", mime_type="application/octet-stream", origin="non-evidentiary",
                    creator_role=Role.ORCHESTRATOR, creation_command=("test",), parent_artifacts=(), validation_result="PASS", frozen=True)
            binary = diagnostic(bytes(range(256)))
            projected = gates._semantic_challenger_audit_content_projection(registry, (binary.sha256,))
            self.assertEqual(projected[0]["content_encoding"], "BASE64")
            large = diagnostic(b"x" * (gates._MAX_SEMANTIC_CHALLENGE_AUDIT_INPUT_BYTES // 6 + 1))
            before = (registry.verify_all(), ledger.validate())
            with self.assertRaisesRegex(ValidationError, "preflight bound"):
                gates._semantic_challenger_audit_content_projection(registry, (large.sha256,))
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_actual_owners_refuse_inert_or_missing_sources_without_writes(self):
        with TemporaryDirectory(prefix="inert-cohort-refusal-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            slot = _slot()
            before = (registry.verify_all(), ledger.validate())
            calls = (
                lambda: gates.reserve_semantic_reproduction_cohort_audit_slot(registry, ledger,
                    assessment_id=slot.assessment_id, run_id=slot.run_id,
                    research_state_snapshot_artifact_hash=slot.research_state_snapshot_artifact_hash,
                    claim_graph_artifact_hash=slot.claim_graph_artifact_hash,
                    provider_invocation_id=slot.provider_invocation_id),
                lambda: gates.require_semantic_reproduction_cohort_audit_slot(registry, ledger,
                    slot_id=slot.slot_id, expected_run_id=slot.run_id),
                lambda: gates.semantic_reproduction_cohort_audit_input(registry, ledger, slot=slot),
                lambda: gates.register_semantic_reproduction_cohort_audit_authority(registry, ledger,
                    slot_id=slot.slot_id, expected_run_id=slot.run_id,
                    semantic_judgment_artifact_hash=_digest("judgment"), finding_artifact_hashes=(),
                    challenger_execution_artifact_hash=_digest("execution"), challenger_review_artifact_hash=_digest("review")),
            )
            for operation in calls:
                with self.assertRaises((ValidationError, ArtifactError)):
                    operation()
                self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_inert_unissued_plural_authority_cannot_enter_full_owner(self):
        with TemporaryDirectory(prefix="inert-cohort-authority-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            authority = _authority()
            # Ordinary JSON registry mechanics only; no authority issuer.
            record = registry.put_json(authority.to_dict(), **gates._semantic_audit_artifact_metadata(True),
                mime_type="application/json", parent_artifacts=(), validation_result="PASS", frozen=True)
            before = (registry.verify_all(), ledger.validate())
            common = dict(authority_artifact_hash=record.sha256, expected_run_id=authority.run_id,
                expected_assessment_id=authority.assessment_id,
                expected_research_state_snapshot_artifact_hash=authority.research_state_snapshot_artifact_hash,
                expected_claim_graph_artifact_hash=authority.claim_graph_artifact_hash,
                expected_central_claim_ids=authority.central_claim_ids)
            for owner in (gates.require_semantic_reproduction_cohort_audit_authority,
                          gates._require_semantic_reproduction_cohort_audit_source):
                with self.assertRaises(ValidationError):
                    owner(registry, ledger, **common)
            with self.assertRaises(ValidationError):
                gates.require_semantic_challenge_audit_authority(registry, ledger,
                    **common, expected_category=gates.ChallengeCategory.REPRODUCTION)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_inert_crash_prefixes_preserve_only_ordered_verification_artifact_publication(self):
        with TemporaryDirectory(prefix="inert-cohort-prefix-") as directory:
            registry, ledger = self.fixture._runtime(Path(directory))
            before = (registry.verify_all(), ledger.validate())
            prior = ledger.events()[-1]
            slot = replace(_slot(), event_index=0)
            authority = _authority(slot)
            verification = _event(slot, prior, event_id="inert-verification", metadata={"inert": "verification-shape"})
            authority = replace(authority, verification_event_hash=verification.event_hash)
            wire = canonical_json_bytes(authority.to_dict()) + b"\n"
            # In-memory descriptor only. It is not put into the registry and
            # is not returned by a source or private authority issuer.
            record = replace(registry.list_records()[0], sha256=hashlib.sha256(wire).hexdigest(),
                size=len(wire), parent_artifacts=authority.input_artifact_hashes, record_hash=None,
                created_at=verification.timestamp,
                **gates._semantic_audit_artifact_metadata(True))
            publication = _event(slot, verification,
                event_id=f"semantic-audit-publication-{authority.authority_id[-24:]}",
                artifact_hashes=(record.sha256,),
                reason="admitted source-owned semantic Challenger audit authority",
                metadata=gates._semantic_challenge_audit_publication_metadata(record, authority))
            events = (prior, verification, publication)
            options = dict(authority=authority, events=events)
            valid = (((), (), ()), ((), ((1, verification),), ()),
                     ((record,), ((1, verification),), ()),
                     ((record,), ((1, verification),), ((2, publication),)))
            for records, verified, published in valid:
                gates._require_semantic_reproduction_cohort_publication_prefix(**options,
                    authority_records=records, verification_matches=verified, publication_matches=published)
            invalid = (((record,), (), ()), ((), (), ((2, publication),)),
                       ((), ((1, verification),), ((2, publication),)),
                       ((record, record), ((1, verification),), ()),
                       ((record,), ((1, verification), (1, verification)), ()),
                       ((record,), ((1, verification),), ((2, publication), (2, publication))),
                       ((record,), ((0, verification),), ()),
                       ((replace(record, sha256=_digest("substituted"), record_hash=None),), ((1, verification),), ()))
            for records, verified, published in invalid:
                with self.subTest(records=len(records), verified=len(verified), published=len(published)), self.assertRaises(ValidationError):
                    gates._require_semantic_reproduction_cohort_publication_prefix(**options,
                        authority_records=records, verification_matches=verified, publication_matches=published)
            malformed = _event(slot, verification,
                event_id=publication.event_id, artifact_hashes=(record.sha256,), metadata={"renamed": True})
            with self.assertRaises(ValidationError):
                gates._require_semantic_reproduction_cohort_publication_prefix(authority=authority,
                    events=(prior, verification, malformed), authority_records=(record,),
                    verification_matches=((1, verification),), publication_matches=((2, malformed),))
            future_record = replace(record, created_at="2099-01-01T00:00:00.000000Z", record_hash=None)
            future_publication = _event(slot, verification,
                event_id=publication.event_id, artifact_hashes=(future_record.sha256,),
                reason="admitted source-owned semantic Challenger audit authority",
                metadata=gates._semantic_challenge_audit_publication_metadata(future_record, authority))
            for published in ((), ((2, future_publication),)):
                with self.subTest(future_record=True, published=bool(published)), self.assertRaisesRegex(ValidationError, "chronology"):
                    gates._require_semantic_reproduction_cohort_publication_prefix(authority=authority,
                        events=(prior, verification, future_publication), authority_records=(future_record,),
                        verification_matches=((1, verification),), publication_matches=published)
            with self.assertRaisesRegex(ValidationError, "chronology"):
                gates._validate_semantic_challenge_audit_publication_event(
                    future_publication, 2, (prior, verification, future_publication),
                    record=future_record, authority=authority, verification_event=verification)
            self.assertEqual((registry.verify_all(), ledger.validate()), before)

    def test_publication_chronology_is_preflighted_at_exact_utc_boundaries(self):
        for values in (
            ("2026-01-01T00:00:00Z",) * 3,
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000001Z", "2026-01-01T00:00:00.000002Z"),
        ):
            gates._require_semantic_reproduction_cohort_publication_chronology(
                verification_timestamp=values[0], authority_created_at=values[1], publication_timestamp=values[2])
        for values in (
            ("2026-01-01T00:00:00.000002Z", "2026-01-01T00:00:00.000001Z", "2026-01-01T00:00:00.000003Z"),
            ("2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "bad", "2026-01-01T00:00:00Z"),
            ("2026-01-01Z", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ):
            with self.subTest(values=values), self.assertRaises(ValidationError):
                gates._require_semantic_reproduction_cohort_publication_chronology(
                    verification_timestamp=values[0], authority_created_at=values[1], publication_timestamp=values[2])

    def test_production_control_flow_retains_full_owners_and_prewrite_content_capacity(self):
        source = inspect.getsource(gates._derive_semantic_challenger_audit_canonical_scope)
        self.assertIn("require_scientific_reproducibility_package(", source)
        self.assertIn("isinstance(item.research_object, StateResult)", source)
        # No package outcome or original-result outcome can filter coverage.
        plural = source.split("if procedure_version == SEMANTIC_REPRODUCTION_COHORT_PROCEDURE_VERSION:")[1].split("package_authority: Any | None")[0]
        self.assertNotIn("reproduction_passed", plural)
        self.assertNotIn(".outcome", plural)
        self.assertLess(plural.index("require_scientific_reproducibility_package("),
                        plural.index("_retain_semantic_reproduction_cohort_clean_publication("))
        tree = ast.parse(textwrap.dedent(inspect.getsource(gates._reserve_semantic_audit_slot)))
        builder = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "build_slot")
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        preflights = [node for node in calls if node.func.id == "_preflight_semantic_reproduction_cohort_reservation"]
        self.assertEqual(len(preflights), 1)
        lock = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "_open_mutation_lock")
        self.assertLess(preflights[0].lineno, lock.lineno)
        self.assertIn("return prospective_event", ast.unparse(builder))
        self.assertIsInstance(builder.body[-1], ast.Return)
        preflight = inspect.getsource(gates._preflight_semantic_reproduction_cohort_reservation)
        self.assertIn("_semantic_challenger_audit_input_from_scope(", preflight)
        self.assertIn("_semantic_reproduction_cohort_wire_capacity(", preflight)
        publication = ast.parse(textwrap.dedent(inspect.getsource(gates._register_semantic_audit_authority)))
        prefix_check = next(node for node in ast.walk(publication) if isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name)
                            and node.func.id == "_require_semantic_reproduction_cohort_publication_prefix")
        first_write = min(node.lineno for node in ast.walk(publication) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Attribute) and node.func.attr in ("_append_locked", "_put_bytes_locked"))
        self.assertLess(prefix_check.lineno, first_write)
        publication_source = inspect.getsource(gates._register_semantic_audit_authority)
        self.assertIn("created_at=authority_created_at if cohort else None", publication_source)
        self.assertIn("timestamp=publication_timestamp if cohort else None", publication_source)
        chronology = next(node for node in ast.walk(publication) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Name)
                          and node.func.id == "_require_semantic_reproduction_cohort_publication_chronology")
        self.assertLess(chronology.lineno, first_write)
        for function in (gates._semantic_challenger_audit_static_sources,
                         gates._semantic_challenger_audit_published_peers):
            self.assertNotIn("require_semantic_reproduction_cohort_audit_authority(", inspect.getsource(function))

    def test_standalone_plural_slot_replay_checks_chronology_before_freshness_tail(self):
        # Structural routing plus inert rejection, not a positive source-owner
        # replacement. The public reader must receive the guarded shared replay.
        tree = ast.parse(textwrap.dedent(inspect.getsource(
            gates._require_semantic_challenger_audit_slot_with_scope))).body[0]
        guards = [node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "_is_reproduction_cohort(slot)"]
        self.assertEqual(len(guards), 1)
        self.assertEqual(ast.unparse(guards[0].body[0]),
                         "_semantic_reproduction_cohort_chronology(canonical_scope, slot)")
        freshness = tree.body[-2]
        self.assertEqual(freshness.value.func.id, "_require_semantic_challenger_audit_snapshot_unchanged")
        self.assertLess(guards[0].lineno, freshness.lineno)
        self.assertEqual(ast.unparse(tree.body[-1]), "return (slot, canonical_scope)")
        public = ast.parse(textwrap.dedent(inspect.getsource(
            gates.require_semantic_reproduction_cohort_audit_slot)))
        delegates = [node for node in ast.walk(public) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name)
                     and node.func.id == "_require_semantic_challenger_audit_slot_with_scope"]
        self.assertEqual(len(delegates), 1)
        slot = _slot()
        scope = _scope(slot)
        late = replace(scope.clean_publications[0], event_index=slot.event_index)
        with self.assertRaisesRegex(ValidationError, "precede the slot"):
            gates._semantic_reproduction_cohort_chronology(
                replace(scope, clean_publications=(late, *scope.clean_publications[1:])), slot)


if __name__ == "__main__":
    unittest.main()
