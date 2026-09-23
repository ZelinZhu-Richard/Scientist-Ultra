"""Non-evidentiary V2 codec, finite coverage, preflight, and refusal controls.

No complete scientific owner is patched to pass, no private authority issuer
is called, and no valid scientific bundle is registered. Pure DTOs and actual
diagnostic registry/ledger fixtures do not prove a positive cohort lifecycle.
"""

import ast
from dataclasses import FrozenInstanceError, replace
import hashlib
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap
from types import SimpleNamespace
import unittest

from scientist_one import gates, scientific_cohort_bundle as cohort_bundle
from scientist_one.errors import ArtifactError, ValidationError
from scientist_one.evaluators import AuthorityScope, AuthorityStatus, CategoryScoreStatus, EvaluatorClass, RCheck, REQUIRED_R_AUTHORITIES
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes
from tests import test_challenger_audit_authority as audit_fixtures
from tests import test_semantic_reproduction_cohort_audit as plural_fixtures
from tests import test_scientific_cohort_leaf_coverage as coverage_fixtures
from tests import test_soundness_gates as soundness_fixtures


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _obligations():
    return tuple(cohort_bundle.CohortCheckOutcome(
        check, evaluator, (_digest(f"inert-{check.value}-{evaluator.value}"),), None, None,
        AuthorityStatus.UNTESTED, AuthorityScope.SYSTEM_FIXTURE, "INERT_MISSING_OBLIGATION",
    ) for check in RCheck for evaluator in sorted(REQUIRED_R_AUTHORITIES[check], key=lambda value: value.value))


def _bundle():
    return cohort_bundle.RCheckAuthorityBundleV2(
        run_id="audit-run", scope=AuthorityScope.SYSTEM_FIXTURE,
        reproduction_audit_artifact_sha256=_digest("anchor"), reproduction_audit_artifact_record_hash=_digest("anchor-record"),
        assessment_id="inert-assessment", research_state_snapshot_artifact_sha256=_digest("snapshot"),
        research_state_snapshot_artifact_record_hash=_digest("snapshot-record"),
        claim_graph_artifact_sha256=_digest("graph"), claim_graph_artifact_record_hash=_digest("graph-record"),
        central_claim_ids=("inert-claim",), authority_artifact_sha256s=(), obligations=_obligations(),
        semantic_audit_bindings=(cohort_bundle.CohortSemanticAuditBinding("REPRODUCTION", _digest("anchor"), _digest("anchor-record")),),
        rubric_artifact_sha256=_digest("rubric"), rubric_record_hash=_digest("rubric-record"),
        rubric_ledger_event_id="inert-rubric", rubric_ledger_event_hash=_digest("rubric-event"), rubric_ledger_event_index=0,
        category_statuses=(("inert-category", CategoryScoreStatus.UNTESTED),), category_scope=AuthorityScope.SYSTEM_FIXTURE,
        category_score_authority_artifact_sha256s=(), paper_verification_artifact_sha256=None,
        paper_verification_artifact_record_hash=None, candidate_artifact_sha256=None,
        ledger_prefix_head_hash=_digest("prefix"), ledger_prefix_event_count=1,
    )


def _tree(function):
    return ast.parse(textwrap.dedent(inspect.getsource(function)))


def _calls(tree, name):
    return tuple(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == name)


class ScientificCohortBundleTests(unittest.TestCase):
    def _runtime(self, directory):
        return audit_fixtures.SemanticChallengerAuditAuthorityTests()._runtime(Path(directory))

    def _diagnostic(self, registry, label):
        return registry.put_json({"inert": label}, logical_type="cohort_diagnostic", schema_version="1.0",
                                 mime_type="application/json", origin="non-evidentiary cohort preflight",
                                 creator_role=Role.ORCHESTRATOR, creation_command=("test",),
                                 parent_artifacts=(), validation_result="PASS", frozen=True)

    def _preflight_inputs(self, registry, ledger):
        # These records have deliberately non-authoritative logical types.
        # Only the finite metadata preflight consumes them; public owners refuse.
        anchor = self._diagnostic(registry, "anchor")
        rubric = self._diagnostic(registry, "rubric")
        event = ledger.events()[-1]
        value = replace(_bundle(), reproduction_audit_artifact_sha256=anchor.sha256,
                        reproduction_audit_artifact_record_hash=anchor.record_hash,
                        semantic_audit_bindings=(cohort_bundle.CohortSemanticAuditBinding("REPRODUCTION", anchor.sha256, anchor.record_hash),),
                        rubric_artifact_sha256=rubric.sha256, rubric_record_hash=rubric.record_hash,
                        rubric_ledger_event_id=event.event_id, rubric_ledger_event_hash=event.event_hash,
                        ledger_prefix_head_hash=event.event_hash)
        return value, (anchor, rubric), cohort_bundle._r_check_read_snapshot(registry, ledger)

    def test_distinct_closed_codec_preserves_omissions_without_empty_pass(self):
        value = _bundle()
        raw = cohort_bundle._bundle_bytes(value)
        self.assertEqual(cohort_bundle.RCheckAuthorityBundleV2.from_dict(value.to_dict()), value)
        self.assertEqual(raw, canonical_json_bytes(value.to_dict()) + b"\n")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "af05ad4c84720a5d6ef97d24a2cef5a12715a1d7f80a06d9c7286ec7e8b9c380")
        self.assertEqual(value.to_dict()["schema_version"], "r-check-authority-bundle/v2")
        self.assertFalse(value.mandatory_pass)
        self.assertFalse(value.scientific_mandatory_pass)
        self.assertIs(value.readiness_scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertEqual(set(value.status_by_r_check), {item.value for item in RCheck})
        self.assertEqual(set(value.status_by_r_check.values()), {"UNTESTED"})
        with self.assertRaises(FrozenInstanceError):
            value.scope = AuthorityScope.SCIENTIFIC
        for changes in ({"obligations": ()}, {"obligations": value.obligations[:-1]},
                        {"obligations": (*value.obligations, value.obligations[-1])},
                        {"scope": AuthorityScope.SCIENTIFIC}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(value, **changes)

    def test_codec_rejects_unknown_mixed_and_non_native_fields(self):
        value = _bundle()
        for changes in ({"schema_version": "r-check-authority-bundle/v1"}, {"scope": "UNKNOWN"},
                        {"e4_synthesized": True}, {"human_independence_claimed": 0}, {"skip_replay": True},
                        {"ledger_prefix_event_count": True}, {"obligations": tuple(value.to_dict()["obligations"])},
                        {"statuses": {check.value: "PASS" for check in RCheck}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                cohort_bundle.RCheckAuthorityBundleV2.from_dict({**value.to_dict(), **changes})
        class Text(str):
            pass
        class Integer(int):
            pass
        for changes in ({"run_id": Text(value.run_id)}, {"ledger_prefix_event_count": Integer(1)},
                        {"central_claim_ids": ["inert-claim"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(value, **changes)
        tampered = _bundle()
        object.__setattr__(tampered, "run_id", Text(tampered.run_id))
        with self.assertRaises(ValueError):
            cohort_bundle._bundle_bytes(tampered)

    def test_owned_adverse_row_dominates_omissions_without_issuing_a_leaf(self):
        value = _bundle()
        rows = tuple(replace(row, status=AuthorityStatus.FAIL, reason_code="INERT_OWNED_ANCHOR_ADVERSE")
                     if row.r_check is RCheck.R7 else row for row in value.obligations)
        adverse = replace(value, obligations=rows)
        self.assertEqual(adverse.status_by_r_check["R7"], "FAIL")
        self.assertEqual(adverse.status_by_r_check["R5"], "UNTESTED")
        self.assertEqual(adverse.authority_artifact_sha256s, ())
        with self.assertRaisesRegex(ValueError, "omitted cohort leaf"):
            replace(rows[-1], status=AuthorityStatus.PASS, scope=AuthorityScope.SCIENTIFIC)

    def test_variable_cardinality_uses_existing_complete_coverage_rows(self):
        fixture = coverage_fixtures.CohortLeafCoverageTests()
        fixture.setUp()
        coverage = coverage_fixtures._cohort_scientific_leaf_coverage(fixture.cohort, fixture.designs, ())
        scientific_rows = tuple(cohort_bundle.CohortCheckOutcome(
            item.target.r_check, item.target.evaluator_class, item.target.subject_artifact_sha256s,
            item.authority_artifact_sha256, item.authority_artifact_record_hash,
            item.status, item.scope, item.reason_code,
        ) for item in coverage)
        globals_ = tuple(row for row in _bundle().obligations if row.r_check in {RCheck.R0, RCheck.R5, RCheck.R6, RCheck.R7})
        bundle = replace(_bundle(), obligations=tuple(sorted((*scientific_rows, *globals_), key=lambda row: row.identity)))
        self.assertEqual(len(bundle.obligations), 50)
        self.assertEqual(bundle.authority_artifact_sha256s, ())
        self.assertEqual(set(bundle.status_by_r_check.values()), {"UNTESTED"})
        self.assertEqual(cohort_bundle.RCheckAuthorityBundleV2.from_dict(bundle.to_dict()), bundle)

    def test_native_row_checks_keep_exact_record_and_scientific_scope(self):
        row = _bundle().obligations[0]
        for changes in ({"authority_artifact_sha256": _digest("leaf")},
                        {"authority_artifact_record_hash": _digest("leaf-record")},
                        {"status": "FAIL"}, {"scope": "SCIENTIFIC"},
                        {"subject_artifact_sha256s": []}, {"evaluator_class": EvaluatorClass.E4}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(row, **changes)
        selected = replace(row, authority_artifact_sha256=_digest("leaf"), authority_artifact_record_hash=_digest("leaf-record"))
        with self.assertRaisesRegex(ValueError, "non-scientific"):
            replace(selected, status=AuthorityStatus.PASS)
        with self.assertRaisesRegex(ValueError, "exactly the authorities"):
            replace(_bundle(), obligations=(selected, *_bundle().obligations[1:]))

    def test_parent_budget_is_joint_and_iterators_are_bounded_without_truncation(self):
        consumed = []
        def unbounded():
            for index in range(1000):
                consumed.append(index)
                yield _digest(f"source-{index}")
        with self.assertRaisesRegex(ValueError, "bounded exact tuple"):
            cohort_bundle._selected_hashes(unbounded(), "inert selection", 254)
        self.assertEqual(len(consumed), 255)
        with TemporaryDirectory(prefix="inert-cohort-input-cap-") as directory:
            registry, ledger = self._runtime(directory)
            before = cohort_bundle._r_check_read_snapshot(registry, ledger)
            # 254 leaves + one score + anchor + rubric exceeds 256 parents.
            with self.assertRaisesRegex(ValueError, "direct parents"):
                cohort_bundle.register_r_check_authority_bundle_v2(
                    registry, ledger, run_id="audit-run", reproduction_audit_artifact_sha256=_digest("anchor"),
                    authority_artifact_sha256s=tuple(_digest(f"leaf-{index}") for index in range(254)),
                    rubric_artifact_sha256=_digest("rubric"), category_score_authority_artifact_sha256s=(_digest("score"),),
                )
            self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), before)

    def test_complete_byte_budget_rejects_oversize_below_the_row_count_cap(self):
        value = _bundle()
        extras = tuple(replace(value.obligations[1],
                               subject_artifact_sha256s=(_digest(f"run-{index}"), _digest(f"question-{index}"), _digest(f"freeze-{index}")),
                               reason_code="INERT_CAPACITY_VECTOR_" + "x" * 90)
                       for index in range(3000))
        rows = tuple(sorted((*value.obligations, *extras), key=lambda row: row.identity))
        self.assertLess(len(rows), cohort_bundle.MAX_COHORT_BUNDLE_OBLIGATIONS)
        enlarged = replace(value, obligations=rows)
        with self.assertRaisesRegex(ValueError, "one-MiB"):
            cohort_bundle._bundle_bytes(enlarged)
        payload = value.to_dict()
        payload["obligations"] *= 300
        with self.assertRaisesRegex(ValueError, "bounded JSON array"):
            cohort_bundle.RCheckAuthorityBundleV2.from_dict(payload)

    def test_category_score_omission_and_paper_identity_are_explicit(self):
        value = _bundle()
        paper = replace(value, paper_verification_artifact_sha256=_digest("paper"),
                        paper_verification_artifact_record_hash=_digest("paper-record"), candidate_artifact_sha256=_digest("candidate"))
        self.assertEqual(paper.category_score_authority_artifact_sha256s, ())
        self.assertIs(paper.category_scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertEqual(cohort_bundle.RCheckAuthorityBundleV2.from_dict(paper.to_dict()), paper)
        for changes in ({"candidate_artifact_sha256": _digest("candidate")},
                        {"category_statuses": (("inert-category", CategoryScoreStatus.SCORED),)},
                        {"category_score_authority_artifact_sha256s": (_digest("score"),)},
                        {"category_statuses": (("same", CategoryScoreStatus.UNTESTED), ("same", CategoryScoreStatus.UNTESTED))}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(value, **changes)

    def test_semantic_category_bindings_are_distinct_not_singular_aliases(self):
        value = _bundle()
        statistics = cohort_bundle.CohortSemanticAuditBinding("STATISTICS", _digest("statistics"), _digest("statistics-record"))
        expanded = replace(value, semantic_audit_bindings=tuple(sorted((*value.semantic_audit_bindings, statistics), key=lambda row: row.category)))
        self.assertEqual(len(expanded.semantic_audit_bindings), 2)
        for bindings in ((statistics,), (*value.semantic_audit_bindings, value.semantic_audit_bindings[0]),
                         (replace(value.semantic_audit_bindings[0], authority_artifact_record_hash=_digest("wrong")),)):
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                replace(value, semantic_audit_bindings=bindings)

    def test_bound_final_state_retains_exact_audited_core_but_can_add_owned_reviews(self):
        binding = SimpleNamespace(research_object=SimpleNamespace(object_type="Claim", object_id="inert-claim"),
                                  artifact_sha256=_digest("claim"), artifact_record_hash=_digest("claim-record"))
        initial = SimpleNamespace(entries=(binding,), ledger_event_count=3)
        cohort = SimpleNamespace(audit_source=SimpleNamespace(canonical_scope=SimpleNamespace(state=initial)),
                                 round_key=SimpleNamespace(run_id="audit-run", claim_graph_artifact_hash=_digest("graph"), central_claim_ids=("inert-claim",)))
        review = SimpleNamespace(research_object=SimpleNamespace(object_type="Critique", object_id="inert-review"))
        final = SimpleNamespace(entries=(binding, review), run_id="audit-run", snapshot_artifact_sha256=_digest("later-F"), ledger_event_count=8)
        bundle = SimpleNamespace(run_id="audit-run", claim_graph_hash=_digest("graph"), central_claim_ids=("inert-claim",), research_state_hash=_digest("later-F"))
        source = SimpleNamespace(state_authority=final, bundle=bundle)
        # Pure topology only. No canonical/source owner is substituted.
        cohort_bundle._require_paper_state_join(cohort, source)
        earlier = replace_namespace(final, entries=(binding,), ledger_event_count=2)
        cohort_bundle._require_paper_state_join(
            cohort, SimpleNamespace(state_authority=earlier, bundle=bundle),
        )
        for entries in ((review,), (replace_namespace(binding, artifact_record_hash=_digest("changed")), review),
                        (binding, SimpleNamespace(research_object=SimpleNamespace(object_type="Result", object_id="extra-result"))),
                        (binding, binding)):
            changed = SimpleNamespace(state_authority=replace_namespace(final, entries=entries), bundle=bundle)
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                cohort_bundle._require_paper_state_join(cohort, changed)

    def test_deterministic_source_bindings_are_closed_and_do_not_confer_authority(self):
        binding = cohort_bundle._CohortDeterministicReviewBinding(
            "EXTERNAL_VALIDITY", _digest("review"), _digest("review-record"),
        )
        for changes in ({"category": "STATISTICS"}, {"review_artifact_record_hash": None},
                        {"alternative_authority_artifact_sha256": _digest("alternative")},
                        {"alternative_authority_artifact_sha256": _digest("alternative"),
                         "alternative_authority_artifact_record_hash": _digest("alternative-record")}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(binding, **changes)
        replay = cohort_bundle._CohortChallengerLeafReplay(AuthorityStatus.UNTESTED, "INERT_FULL_SOURCE_SHAPE", (binding,))
        with self.assertRaises(FrozenInstanceError):
            replay.status = AuthorityStatus.PASS
        for changes in ({"status": "FAIL"}, {"deterministic_reviews": [binding]},
                        {"deterministic_reviews": (binding, binding)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(replay, **changes)
        with self.assertRaisesRegex(ValueError, "closed bindings"):
            cohort_bundle._require_deterministic_review_identity_join(SimpleNamespace(**vars_for_slots(binding)), binding)

    def test_selected_deterministic_reviews_and_aggregates_require_exact_paper_identities(self):
        alternative = cohort_bundle._CohortDeterministicReviewBinding(
            "ALTERNATIVE_EXPLANATION", _digest("alternative-review"), _digest("alternative-review-record"),
            _digest("alternative-authority"), _digest("alternative-authority-record"),
        )
        external = cohort_bundle._CohortDeterministicReviewBinding(
            "EXTERNAL_VALIDITY", _digest("external-review"), _digest("external-review-record"),
        )
        # Distinct categories retain distinct sources; no global review alias.
        for binding in (alternative, external):
            cohort_bundle._require_deterministic_review_identity_join(binding, binding)
        for status in (AuthorityStatus.FAIL, AuthorityStatus.UNTESTED):
            replay = cohort_bundle._CohortChallengerLeafReplay(status, "INERT_ADVERSE_SOURCE", (alternative, external))
            for changes in ({"review_artifact_sha256": _digest("different-review")},
                            {"review_artifact_record_hash": _digest("different-review-record")},
                            {"alternative_authority_artifact_sha256": _digest("another-plan-authority")},
                            {"alternative_authority_artifact_record_hash": _digest("another-authority-record")},
                            {"alternative_authority_artifact_sha256": None, "alternative_authority_artifact_record_hash": None}):
                with self.subTest(status=status, changes=changes), self.assertRaises(ValueError):
                    cohort_bundle._require_deterministic_review_identity_join(replay.deterministic_reviews[0], replace(alternative, **changes))
        raw_alternative = replace(alternative, alternative_authority_artifact_sha256=None,
                                  alternative_authority_artifact_record_hash=None)
        cohort_bundle._require_deterministic_review_identity_join(raw_alternative, alternative)
        partial = cohort_bundle._CohortChallengerLeafReplay(AuthorityStatus.UNTESTED, "INERT_PARTIAL_SELECTION", (external,))
        with self.assertRaisesRegex(ValueError, "same-category deterministic"):
            cohort_bundle._require_deterministic_review_identity_join(
                partial.deterministic_reviews[0], replace(external, review_artifact_sha256=_digest("paper-adverse-review")),
            )
        self.assertEqual(partial.deterministic_reviews, (external,))

    def test_real_negative_external_reviews_can_coexist_but_cannot_be_cross_composed(self):
        fixture = soundness_fixtures.SoundnessGateAuthorityTests()
        fixture.setUp()
        try:
            receipt, major_record = fixture._external_execution("review-cohort-major")
            major = gates._load_challenge_finding(fixture.registry, major_record.sha256)
            blocking_record = gates.register_challenge_finding(fixture.registry, replace(
                major, challenge_id="finding-cohort-blocking", severity=gates.ChallengeSeverity.BLOCKING,
            ))
            bindings = []
            subjects = []
            records = []
            for label, finding_record in (("major", major_record), ("blocking", blocking_record)):
                execution = replace(receipt, receipt_id="execution-cohort-" + label,
                                    review_id="review-cohort-" + label, finding_artifact_hashes=(finding_record.sha256,))
                execution_record = gates.register_challenger_attack_execution_receipt(fixture.registry, execution)
                review = gates.ChallengerCategoryReview(
                    review_id=execution.review_id, category=execution.category,
                    execution_status=gates.ChallengerExecutionStatus.EXECUTED,
                    target_claim_ids=execution.target_claim_ids, claim_graph_artifact_hash=execution.claim_graph_artifact_hash,
                    evidence_hashes=execution.evidence_hashes, finding_artifact_hashes=execution.finding_artifact_hashes,
                    execution_receipt_hash=execution_record.sha256,
                    attack="Replay the real negative external-validity fixture boundary.",
                    conclusion="No scientific external-validity authority is established.", deterministic=True,
                )
                record = gates.register_challenger_category_review(fixture.registry, review)
                fresh = gates._load_challenger_category_review(fixture.registry, record.sha256)
                self.assertEqual(fresh, review)
                finding = gates._load_challenge_finding(fixture.registry, fresh.finding_artifact_hashes[0])
                self.assertIs(finding.severity, gates.ChallengeSeverity.MAJOR if label == "major" else gates.ChallengeSeverity.BLOCKING)
                subjects.append((execution.run_id, fresh.category, fresh.claim_graph_artifact_hash, fresh.target_claim_ids, fresh.evidence_hashes))
                bindings.append(cohort_bundle._CohortDeterministicReviewBinding(fresh.category.value, record.sha256, record.record_hash))
                records.append(record)
            self.assertEqual(subjects[0], subjects[1])
            self.assertNotEqual(bindings[0].review_artifact_sha256, bindings[1].review_artifact_sha256)
            before = fixture.registry.verify_all(raise_on_error=True), fixture.ledger.validate(raise_on_error=True)
            cohort_bundle._require_deterministic_review_identity_join(bindings[0], bindings[0])
            with self.assertRaisesRegex(ValueError, "same-category deterministic"):
                cohort_bundle._require_deterministic_review_identity_join(bindings[0], bindings[1])
            # The real negative review alone is not a complete R5 source. The
            # ordinary full replay's diagnostic return cannot mint a companion.
            leaf = SimpleNamespace(source_records=(records[0],),
                                   authority=SimpleNamespace(r_check=RCheck.R5, scope=AuthorityScope.SYSTEM_FIXTURE))
            cohort = SimpleNamespace(round_key=SimpleNamespace(run_id=receipt.run_id))
            with self.assertRaisesRegex(ValueError, "lacks complete source-owner replay"):
                cohort_bundle._require_complete_challenger_leaf(fixture.registry, fixture.ledger, cohort, leaf)
            self.assertEqual((fixture.registry.verify_all(raise_on_error=True), fixture.ledger.validate(raise_on_error=True)), before)
        finally:
            fixture.tearDown()

    def test_publication_preflight_is_read_only_and_rejects_capacity_and_metadata_collision(self):
        with TemporaryDirectory(prefix="inert-cohort-preflight-") as directory:
            registry, ledger = self._runtime(directory)
            value, parents, snapshot = self._preflight_inputs(registry, ledger)
            raw, candidate, needed = cohort_bundle._preflight_bundle_publication(registry, value, parents, snapshot)
            self.assertTrue(needed)
            self.assertEqual(candidate.schema_version, "2.0")
            self.assertEqual(candidate.sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), snapshot)
            # Finite preflight counter only, never passed to a source owner.
            full = SimpleNamespace(count=cohort_bundle.MAX_REGISTRY_RECORDS,
                                   records=snapshot[0].records)
            with self.assertRaisesRegex(ValueError, "registry capacity"):
                cohort_bundle._preflight_bundle_publication(registry, value, parents, (full, snapshot[1]))
            registry.put_bytes(raw, logical_type="cohort_diagnostic", schema_version="1.0", mime_type="application/json",
                               origin="non-evidentiary immutable collision", creator_role=Role.ORCHESTRATOR,
                               creation_command=("test",), parent_artifacts=(), validation_result="PASS", frozen=True)
            collided = cohort_bundle._r_check_read_snapshot(registry, ledger)
            with self.assertRaisesRegex(ValueError, "different immutable registry identity"):
                cohort_bundle._preflight_bundle_publication(registry, value, parents, collided)
            self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), collided)

    def test_owned_checkpoint_identity_and_corrections_are_not_late_reference_aliases(self):
        with TemporaryDirectory(prefix="inert-cohort-checkpoint-") as directory:
            _registry, ledger = self._runtime(directory)
            event = ledger.events()[0]
            self.assertEqual(cohort_bundle._require_owned_event((event,), event.event_id, event.event_hash, 0), 0)
            for event_id, digest, index in (("different", event.event_hash, 0), (event.event_id, _digest("different"), 0),
                                           (event.event_id, event.event_hash, 1), (event.event_id, event.event_hash, True)):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    cohort_bundle._require_owned_event((event,), event_id, digest, index)
            correction = SimpleNamespace(event_type="CORRECTION", supersedes_event_id=event.event_id)
            with self.assertRaisesRegex(ValueError, "corrected"):
                cohort_bundle._require_owned_event((event, correction), event.event_id, event.event_hash, 0)

    def test_actual_owners_refuse_missing_and_unissued_plural_anchor_without_writes(self):
        with TemporaryDirectory(prefix="inert-cohort-owner-refusal-") as directory:
            registry, ledger = self._runtime(directory)
            authority = plural_fixtures._authority()
            record = registry.put_json(authority.to_dict(), **gates._semantic_audit_artifact_metadata(True),
                                       mime_type="application/json", parent_artifacts=(), validation_result="PASS", frozen=True)
            before = cohort_bundle._r_check_read_snapshot(registry, ledger)
            for digest in (_digest("absent-anchor"), record.sha256):
                with self.subTest(digest=digest), self.assertRaises((ArtifactError, ValidationError, ValueError)):
                    cohort_bundle.register_r_check_authority_bundle_v2(
                        registry, ledger, run_id="audit-run", reproduction_audit_artifact_sha256=digest,
                        authority_artifact_sha256s=(), rubric_artifact_sha256=_digest("rubric"),
                    )
                self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), before)
            with self.assertRaises((ArtifactError, ValidationError, ValueError)):
                cohort_bundle.resolve_r_check_authority_bundle_v2(registry, ledger, bundle_artifact_sha256=record.sha256, run_id="audit-run")
            self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), before)

    def test_stored_inert_v2_codec_cannot_replace_full_bundle_recomputation(self):
        with TemporaryDirectory(prefix="inert-cohort-readback-refusal-") as directory:
            registry, ledger = self._runtime(directory)
            value = _bundle()
            record = registry.put_json(value.to_dict(), logical_type="r_check_authority_bundle", schema_version="2.0",
                                       mime_type="application/json", origin="inert unissued bundle", creator_role=Role.ORCHESTRATOR,
                                       creation_command=("test",), parent_artifacts=(), validation_result="PASS", frozen=True)
            before = cohort_bundle._r_check_read_snapshot(registry, ledger)
            with self.assertRaises((ArtifactError, ValidationError, ValueError)):
                cohort_bundle.resolve_r_check_authority_bundle_v2(registry, ledger, bundle_artifact_sha256=record.sha256, run_id="audit-run")
            self.assertEqual(cohort_bundle._r_check_read_snapshot(registry, ledger), before)

    def test_source_order_and_publication_structure_keep_full_owners_and_no_peer_injection(self):
        derive = _tree(cohort_bundle._derive_r_check_authority_bundle_v2)
        names = ("_require_scientific_audit_cohort", "_require_scientific_cohort_designs", "_cohort_scientific_check_targets",
                 "_resolve_r_check_authority_source", "_cohort_scientific_leaf_coverage")
        positions = [min(node.lineno for node in _calls(derive, name)) for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(_calls(derive, "_cohort_scientific_leaf_coverage")), 1)
        paper = _tree(cohort_bundle._require_cohort_paper)
        for name in ("require_paper_verification", "_require_paper_verification_bundle_source", "require_scientific_soundness_assessment"):
            self.assertEqual(len(_calls(paper, name)), 1)
        deterministic_join = _calls(paper, "_require_paper_deterministic_review_joins")
        self.assertEqual(len(deterministic_join), 1)
        self.assertLess(_calls(paper, "require_scientific_soundness_assessment")[0].lineno, deterministic_join[0].lineno)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name) and node.value.func.id == "_require_paper_deterministic_review_joins"
                            for node in paper.body[0].body))
        companion = _tree(cohort_bundle._require_complete_challenger_leaf)
        marker_guard = next(node for node in ast.walk(companion) if isinstance(node, ast.If)
                            and "complete_challenger_audit_owner_replay" in ast.unparse(node.test))
        for name in ("_load_challenger_category_review", "require_alternative_explanations_authority", "_CohortChallengerLeafReplay"):
            self.assertLess(marker_guard.lineno, _calls(companion, name)[0].lineno)
        paper_join = _tree(cohort_bundle._require_paper_deterministic_review_joins)
        self.assertEqual(len(_calls(paper_join, "_load_soundness_dimension_receipt")), 1)
        self.assertLess(_calls(paper_join, "_load_soundness_dimension_receipt")[0].lineno,
                        _calls(paper_join, "_require_deterministic_review_identity_join")[0].lineno)
        publication = _tree(cohort_bundle.register_r_check_authority_bundle_v2)
        preflight_line = _calls(publication, "_preflight_bundle_publication")[0].lineno
        mutations = [node for node in ast.walk(publication) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "_put_bytes_locked"]
        self.assertEqual(len(mutations), 1)
        self.assertLess(preflight_line, mutations[0].lineno)
        locks = [node for node in ast.walk(publication) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr in {"_open_mutation_lock", "_open_lock"}]
        self.assertLess(next(node.lineno for node in locks if node.func.attr == "_open_mutation_lock"),
                        next(node.lineno for node in locks if node.func.attr == "_open_lock"))
        self.assertEqual(len(_calls(publication, "resolve_r_check_authority_bundle_v2")), 1)
        self.assertNotIn("_replayed_semantic_peer", inspect.getsource(cohort_bundle))
        for function in (cohort_bundle.register_r_check_authority_bundle_v2, cohort_bundle.resolve_r_check_authority_bundle_v2):
            self.assertFalse(any("skip" in name or "cache" in name or "peer" in name for name in inspect.signature(function).parameters))


def replace_namespace(value, **changes):
    return SimpleNamespace(**{**vars(value), **changes})


def vars_for_slots(value):
    return {name: getattr(value, name) for name in value.__slots__}


if __name__ == "__main__":
    unittest.main()
