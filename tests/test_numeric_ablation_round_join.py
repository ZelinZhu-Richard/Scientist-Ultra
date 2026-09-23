"""Pure inert composition/outcome controls and real negative source replay.

No audit, independent judgment, numeric owner or scientific publication is
mocked successful or issued. Exact DTO joins below are not lifecycle evidence.
"""

import ast
from dataclasses import replace
import inspect
from tempfile import TemporaryDirectory
import traceback
from types import SimpleNamespace
import unittest

from scientist_one import evaluators as ev, gates
from scientist_one import scientific_numeric_ablation_soundness as soundness
from scientist_one.scientific_design import _locked_checked_result_authority_snapshot
from scientist_one.scientific_numeric_ablation import ScientificNumericAblationError
from scientist_one.scientific_numeric_ablation_cohort import (
    NATIVE_ABLATION_COVERAGE_RATIONALE, NATIVE_ABLATION_COVERAGE_RULE,
    ScientificNumericAblationCohort,
)
from scientist_one.reproduction import ScientificCleanRerunOutcome
from scientist_one.security import canonical_json_bytes
from scientist_one.experiments import SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY
from scientist_one.scientific_numeric_ablation import SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY
from tests.test_semantic_reproduction_cohort_audit import _slot, _authority
from tests.test_scientific_numeric_ablation_cohort import _observation_case, _state, _record, _digest
from tests.test_scientific_audit_cohort import _member
from tests.test_scientific_method_alignment import _prepared_canonical_timeline
from tests import test_snapshot_reference_replay as snapshot_fixtures


def _descriptor(record, **changes):
    return replace(record, **changes, record_hash=None)


class _InertSpecReads:
    """Byte/descriptor inputs for the applicability selector, not an owner."""
    def __init__(self, spec, record):
        self.spec, self.record = spec, record

    def get_metadata(self, sha):
        if sha != self.record.sha256:
            raise ValueError("inert source absent")
        return self.record

    def get_bytes(self, sha):
        self.get_metadata(sha)
        return canonical_json_bytes(self.spec.to_dict()) + b"\n"


def _applicability_case(spec, label="a"):
    entries = _member(label, "NEGATIVE", 4)
    run = next(item for item in entries if item.research_object.object_type == "Run")
    result = next(item for item in entries if item.research_object.object_type == "Result")
    spec = replace(spec, run_id=run.research_object.object_id,
                   experiment_id=run.research_object.experiment_id)
    record = _descriptor(_record(80 + ord(label), "frozen_run_spec"), validation_result="PASS", frozen=True)
    run = replace(run, authority_artifact_hashes=(record.sha256,),
                  authority_artifact_record_hashes=(record.record_hash,),
                  authority_logical_types=(record.logical_type,), authority_creator_roles=(record.creator_role,))
    return _InertSpecReads(spec, record), _state((result, run))


def _case():
    """Unregistered PENDING descriptors and inert typed source outputs only."""
    member, _, observation = _observation_case()
    slot = _slot(1)
    snapshot = _descriptor(_record(40, "canonical_research_state_snapshot"),
                       sha256=slot.research_state_snapshot_artifact_hash)
    pairs = tuple(sorted((item.artifact_sha256, item.artifact_record_hash)
                         for item in (member.result, member.statistical_test)))
    row = replace(slot.reproduction_package_bindings[0],
                  result_artifact_sha256=member.result.artifact_sha256,
                  result_artifact_record_hash=member.result.artifact_record_hash)
    evidence = tuple(sorted((
        (snapshot.sha256, snapshot.record_hash),
        (row.reproducibility_package_artifact_sha256, row.reproducibility_package_artifact_record_hash),
    )))
    slot = replace(slot, research_state_snapshot_artifact_record_hash=snapshot.record_hash,
                   reproduction_package_bindings=(row,),
                   result_artifact_hashes=tuple(sha for sha, _ in pairs),
                   result_artifact_record_hashes=tuple(record for _, record in pairs),
                   evidence_artifact_hashes=tuple(sha for sha, _ in evidence),
                   evidence_artifact_record_hashes=tuple(record for _, record in evidence))
    state = replace(_state((member.result, member.statistical_test, *member.ablations)),
                    run_id=slot.run_id, snapshot_artifact_sha256=snapshot.sha256,
                    snapshot_artifact_record_hash=snapshot.record_hash,
                    ledger_event_count=slot.event_index)
    native_evidence = tuple(sorted((item.artifact_sha256, item.artifact_record_hash)
                                   for item in state.entries))
    cohort = ScientificNumericAblationCohort(
        state, snapshot, (member,), (observation,),
        tuple(sha for sha, _ in native_evidence), tuple(record for _, record in native_evidence), None,
    )
    audit = _authority(slot)
    graph = _descriptor(_record(41, "claim_evidence_graph"), sha256=audit.claim_graph_artifact_hash)
    review_record = _descriptor(_record(42, "challenger_category_review"),
                            sha256=audit.challenger_review_artifact_hash)
    execution = _descriptor(_record(43, "challenger_attack_execution_receipt"),
                        sha256=audit.challenger_execution_artifact_hash)
    audit = replace(audit, claim_graph_artifact_record_hash=graph.record_hash,
                    challenger_review_artifact_record_hash=review_record.record_hash,
                    challenger_execution_artifact_record_hash=execution.record_hash)
    receipt = gates.SoundnessDimensionEvidenceReceipt(
        receipt_id="inert-native-dimension", dimension=gates.SoundnessDimension.ABLATIONS,
        status=gates.DimensionStatus.UNTESTED, authority_kind=gates.SoundnessAuthorityKind.DETERMINISTIC,
        authority_artifact_hash=snapshot.sha256, evidence_hashes=cohort.evidence_hashes,
        governing_rule=NATIVE_ABLATION_COVERAGE_RULE, rationale=NATIVE_ABLATION_COVERAGE_RATIONALE,
        reviewer_id="inert-reviewer",
    )
    review = gates.ChallengerCategoryReview(
        review_id="inert-review", category=gates.ChallengeCategory.REPRODUCTION,
        execution_status=gates.ChallengerExecutionStatus.EXECUTED,
        target_claim_ids=audit.central_claim_ids, claim_graph_artifact_hash=graph.sha256,
        evidence_hashes=audit.evidence_artifact_hashes, finding_artifact_hashes=audit.finding_artifact_hashes,
        execution_receipt_hash=execution.sha256,
        attack="Inert shape only, no attack executed.", conclusion="No scientific authority.",
    )
    return cohort, audit, dict(
        ablation_receipt=receipt, assessment_id=audit.assessment_id, claim_graph_record=graph,
        central_claim_ids=audit.central_claim_ids, review_record=review_record,
        review=review, execution_record=execution,
    )


class NumericAblationRoundJoinTests(unittest.TestCase):
    def test_exact_pure_cohort_and_round_joins_do_not_equalize_different_evidence_sets(self):
        cohort, audit, args = _case()
        soundness._require_numeric_ablation_audit_cohort_join(cohort, audit, run_id=audit.run_id)
        soundness._require_native_numeric_ablation_round_join(cohort, audit, **args)
        self.assertNotEqual(audit.evidence_artifact_hashes, cohort.evidence_hashes)
        self.assertEqual(set(audit.result_artifact_hashes),
                         {cohort.members[0].result.artifact_sha256,
                          cohort.members[0].statistical_test.artifact_sha256})
        self.assertIs(args["ablation_receipt"].status, gates.DimensionStatus.UNTESTED)

    def test_cohort_rejects_altered_snapshot_record_run_results_tests_and_slot_order(self):
        cohort, audit, _ = _case()
        member = cohort.members[0]
        variants = (
            replace(cohort, snapshot_record=_descriptor(cohort.snapshot_record, origin="other descriptor")),
            replace(cohort, state=replace(cohort.state, run_id="another-run")),
            replace(cohort, state=replace(cohort.state, snapshot_artifact_sha256=_digest("other-s"))),
            replace(cohort, state=replace(cohort.state, snapshot_artifact_record_hash=_digest("other-record"))),
            replace(cohort, state=replace(cohort.state, ledger_event_count=audit.slot_event_index + 1)),
            replace(cohort, members=()),
            replace(cohort, members=(member, member)),
            *(replace(cohort, members=(replace(member, **{field: replace(getattr(member, field),
                artifact_record_hash=_digest("substituted-record"))}),))
              for field in ("result", "statistical_test")),
        )
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ScientificNumericAblationError):
                soundness._require_numeric_ablation_audit_cohort_join(variant, audit, run_id=audit.run_id)
        with self.assertRaises(ScientificNumericAblationError):
            soundness._require_numeric_ablation_audit_cohort_join(cohort, audit, run_id="other")

    def test_round_rejects_every_independent_identity_join(self):
        cohort, audit, args = _case()
        variants = [
            {"assessment_id": "other-assessment"}, {"central_claim_ids": ("other-claim",)},
            {"ablation_receipt": replace(args["ablation_receipt"], authority_artifact_hash=_digest("other-s"))},
            {"ablation_receipt": replace(args["ablation_receipt"], evidence_hashes=(_digest("other-evidence"),))},
            {"review": replace(args["review"], category=gates.ChallengeCategory.STATISTICS)},
            {"review": replace(args["review"], claim_graph_artifact_hash=_digest("other-graph"))},
            {"review": replace(args["review"], target_claim_ids=("other-claim",))},
            {"review": replace(args["review"], execution_receipt_hash=_digest("other-execution"))},
            {"review": replace(args["review"], evidence_hashes=(_digest("other-evidence"),))},
            {"review": replace(args["review"], finding_artifact_hashes=(_digest("other-finding"),))},
        ]
        for key in ("claim_graph_record", "review_record", "execution_record"):
            variants.extend(({key: _descriptor(args[key], sha256=_digest("other-artifact"))},
                             {key: _descriptor(args[key], origin="other metadata identity")}))
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ScientificNumericAblationError):
                soundness._require_native_numeric_ablation_round_join(cohort, audit, **{**args, **variant})

    def test_adequacy_preserves_all_clean_and_audit_adverse_outcomes(self):
        for clean in ScientificCleanRerunOutcome:
            for audit_status in gates.SemanticChallengeAuditStatus:
                for scope in ev.AuthorityScope:
                    with self.subTest(clean=clean, audit=audit_status, scope=scope):
                        expected, reason = ev._derive_reproduction_cohort_status((clean,), audit_status, scope)
                        actual, actual_reason = ev._derive_native_numeric_ablation_adequacy((clean,), audit_status, scope)
                        self.assertIs(actual, ev.AuthorityStatus.UNTESTED if expected is ev.AuthorityStatus.PASS else expected)
                        self.assertEqual(actual_reason, "NATIVE_ABLATION_SCIENTIFIC_ADEQUACY_UNTESTED"
                                         if expected is ev.AuthorityStatus.PASS else reason)
                        self.assertIsNot(actual, ev.AuthorityStatus.PASS)
        with self.assertRaises(ValueError):
            ev._derive_native_numeric_ablation_adequacy((), gates.SemanticChallengeAuditStatus.PASS,
                                                       ev.AuthorityScope.SCIENTIFIC)

    def test_real_absent_audit_owner_refuses_all_labels_without_source_deltas(self):
        with TemporaryDirectory() as directory:
            values = _prepared_canonical_timeline(directory)
            registry, ledger = values["registry"], values["ledger"]
            before = _locked_checked_result_authority_snapshot(registry, ledger)
            # Unregistered descriptor selects an absent source; no source is issued.
            record = _descriptor(_record(60, "semantic_challenge_audit_authority"), schema_version="2.0")
            audit = replace(_authority(), run_id="timeline", ledger_path="runs/timeline/events.jsonl")
            for label in ("UNTESTED", "FAIL", "PASS"):
                payload = {**audit.to_dict(), "status": label}
                status, reason, checks = ev._derive_status(
                    registry, ledger, "timeline", ev.RCheck.R5, ev.EvaluatorClass.E2,
                    (record,), (payload,), ev.AuthorityScope.SCIENTIFIC,
                )
                self.assertIs(status, ev.AuthorityStatus.FAIL)
                self.assertEqual(reason, "NATIVE_ABLATION_COHORT_OWNER_REPLAY_FAILED")
                self.assertNotIn(("source_failure", "TRUE"), checks)
                self.assertEqual(_locked_checked_result_authority_snapshot(registry, ledger), before)

    def test_mixed_and_duplicate_sources_retain_legacy_non_authoritative_behavior(self):
        record = _descriptor(_record(60, "semantic_challenge_audit_authority"), schema_version="2.0")
        for records in ((record, record), (record, _record(61, "ablation_validation"))):
            for label in ("UNTESTED", "PASS", "FAIL"):
                payload = {"schema_version": "semantic-challenge-audit-authority/v2", "status": label}
                status, reason, _ = ev._derive_status(
                    None, None, "absent", ev.RCheck.R5, ev.EvaluatorClass.E2,
                    records, (payload, payload), ev.AuthorityScope.SCIENTIFIC,
                )
                self.assertIs(status, ev.AuthorityStatus.FAIL if label == "FAIL" else ev.AuthorityStatus.UNTESTED)
                self.assertEqual(reason, "SOURCE_AUTHORITY_FAILED" if label == "FAIL"
                                 else "REQUIRED_SEMANTIC_AUTHORITY_UNAVAILABLE")

    def test_applicability_uses_prospective_key_presence_not_v4_or_surviving_observations(self):
        with TemporaryDirectory() as directory:
            spec = _prepared_canonical_timeline(directory)["spec"]
            sources, state = _applicability_case(spec)
            self.assertFalse(soundness._native_numeric_ablation_declared_in_owned_state(sources, state))
            self.assertFalse(any(item.research_object.object_type == "Ablation" for item in state.entries))
            cases = (
                ({SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY: None}, ()),
                ({SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY: {}}, ()),
                ({SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY: False}, spec.required_ablations),
                ({SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY: {}}, spec.required_ablations),
            )
            for metadata, required in cases:
                with self.subTest(metadata=metadata, required=required):
                    sources.spec = replace(sources.spec, metadata=metadata, required_ablations=required)
                    self.assertTrue(soundness._native_numeric_ablation_declared_in_owned_state(sources, state))
            sources.spec = replace(sources.spec, metadata={SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY: {}},
                                   required_ablations=())
            self.assertFalse(soundness._native_numeric_ablation_declared_in_owned_state(sources, state))

    def test_applicability_missing_run_spec_identity_or_changed_descriptor_is_not_absence(self):
        with TemporaryDirectory() as directory:
            sources, state = _applicability_case(_prepared_canonical_timeline(directory)["spec"])
            result, run = state.entries
            variants = (
                replace(state, entries=(result,)),
                replace(state, entries=(result, replace(run, authority_logical_types=("another-kind",)))),
                replace(state, entries=(result, replace(run, authority_artifact_record_hashes=(_digest("other"),)))),
                replace(state, entries=(result, replace(run, authority_artifact_hashes=(),
                    authority_artifact_record_hashes=(), authority_logical_types=(), authority_creator_roles=()))),
            )
            for variant in variants:
                with self.subTest(variant=variant), self.assertRaises(ScientificNumericAblationError):
                    soundness._native_numeric_ablation_declared_in_owned_state(sources, variant)
            for field in ("run_id", "experiment_id"):
                changed = _InertSpecReads(replace(sources.spec, **{field: "other"}), sources.record)
                with self.subTest(field=field), self.assertRaises(ScientificNumericAblationError):
                    soundness._native_numeric_ablation_declared_in_owned_state(changed, state)

    def test_native_canonical_marker_is_supplementary_and_never_required_for_selection(self):
        cohort, _, _ = _case()
        # A marker selects strict replay even if no spec can be read; it does
        # not itself authorize coverage or permit the R5 legacy fallback.
        self.assertTrue(soundness._native_numeric_ablation_declared_in_owned_state(None, cohort.state))

    def test_applicability_checks_every_result_bound_spec_without_selecting_a_subset(self):
        with TemporaryDirectory() as directory:
            spec = _prepared_canonical_timeline(directory)["spec"]
            first, first_state = _applicability_case(spec, "a")
            second, second_state = _applicability_case(spec, "b")
            inputs = {item.record.sha256: item for item in (first, second)}

            class InertManySpecs:
                def get_metadata(self, sha):
                    return inputs[sha].get_metadata(sha)

                def get_bytes(self, sha):
                    return inputs[sha].get_bytes(sha)

            state = replace(first_state, entries=(*first_state.entries, *second_state.entries))
            sources = InertManySpecs()
            self.assertFalse(soundness._native_numeric_ablation_declared_in_owned_state(sources, state))
            second.spec = replace(second.spec, metadata={SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY: None})
            self.assertTrue(soundness._native_numeric_ablation_declared_in_owned_state(sources, state))
            with self.assertRaises(ScientificNumericAblationError):
                soundness._native_numeric_ablation_declared_in_owned_state(sources,
                    replace(state, entries=(*first_state.entries, second_state.entries[0])))

    def test_applicability_preserves_owned_legacy_reproduced_by_run_relation(self):
        with TemporaryDirectory() as directory:
            sources, state = _applicability_case(_prepared_canonical_timeline(directory)["spec"])
            result, run = state.entries
            parent = next(item for item in result.research_object.parents if item.object_type == "Run")
            for relation in ("aggregates", "reproduced_by"):
                changed = replace(result.research_object, content_hash=None,
                    parents=tuple(replace(item, relation=relation) if item is parent else item
                                  for item in result.research_object.parents))
                view = replace(state, entries=(replace(result, research_object=changed), run))
                self.assertFalse(soundness._native_numeric_ablation_declared_in_owned_state(sources, view))
            for changes in ({"content_hash": _digest("other")}, {"evaluated": False}):
                changed = replace(result.research_object, content_hash=None,
                    parents=tuple(replace(item, **changes) if item is parent else item
                                  for item in result.research_object.parents))
                with self.assertRaises(ScientificNumericAblationError):
                    soundness._native_numeric_ablation_declared_in_owned_state(sources,
                        replace(state, entries=(replace(result, research_object=changed), run)))
            multiple_relations = replace(result.research_object, content_hash=None,
                parents=(*result.research_object.parents, replace(parent, relation="reproduced_by")))
            self.assertFalse(soundness._native_numeric_ablation_declared_in_owned_state(sources,
                replace(state, entries=(replace(result, research_object=multiple_relations), run))))

    def test_snapshot_selector_unions_review_and_r7_sources_without_using_ablation_receipt(self):
        cohort, audit, _ = _case()
        source = _descriptor(_record(95, "semantic_challenge_audit_authority"),
                             schema_version="2.0", validation_result="PASS", frozen=True)
        other = _record(96, "inert_old_review_evidence")
        records = {item.sha256: item for item in (source, cohort.snapshot_record, other)}

        class InertSelectors:
            def get_metadata(self, sha):
                return records[sha]

            def get_bytes(self, sha):
                if sha != source.sha256:
                    raise ValueError("inert source absent")
                return canonical_json_bytes(audit.to_dict()) + b"\n"

        inputs = InertSelectors()
        for review_evidence, r7_evidence in (
            ((cohort.snapshot_record.sha256,), (other.sha256,)),
            ((other.sha256,), (source.sha256,)),  # Old no-S review cannot hide R7's S.
            ((cohort.snapshot_record.sha256,), (source.sha256,)),
        ):
            selected = soundness._soundness_ablation_snapshot_selectors(
                inputs, SimpleNamespace(evidence_hashes=review_evidence),
                SimpleNamespace(evidence_hashes=r7_evidence), run_id=audit.run_id,
            )
            self.assertEqual(selected, (cohort.snapshot_record,))
        self.assertEqual(soundness._soundness_ablation_snapshot_selectors(
            inputs, SimpleNamespace(evidence_hashes=(other.sha256,)),
            SimpleNamespace(evidence_hashes=(other.sha256,)), run_id=audit.run_id), ())
        extra = _record(97, "canonical_research_state_snapshot")
        records[extra.sha256] = extra
        self.assertEqual(len(soundness._soundness_ablation_snapshot_selectors(
            inputs, SimpleNamespace(evidence_hashes=(extra.sha256,)),
            SimpleNamespace(evidence_hashes=(source.sha256,)), run_id=audit.run_id)), 2)
        records[cohort.snapshot_record.sha256] = _descriptor(cohort.snapshot_record, origin="changed")
        with self.assertRaises(ScientificNumericAblationError):
            soundness._soundness_ablation_snapshot_selectors(
                inputs, SimpleNamespace(evidence_hashes=(other.sha256,)),
                SimpleNamespace(evidence_hashes=(source.sha256,)), run_id=audit.run_id)

    def test_real_mechanical_snapshot_applicability_replays_without_audit_authority(self):
        fixture = snapshot_fixtures.SnapshotReferenceReplayTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        before = _locked_checked_result_authority_snapshot(fixture.registry, fixture.ledger)
        self.assertEqual(soundness._require_soundness_ablation_applicability_state(
            fixture.registry, fixture.ledger, fixture.snapshot, run_id="run-1"), fixture.state)
        fixture._append()  # Ordinary later reference remains compatible.
        after_reference = _locked_checked_result_authority_snapshot(fixture.registry, fixture.ledger)
        self.assertEqual(soundness._require_soundness_ablation_applicability_state(
            fixture.registry, fixture.ledger, fixture.snapshot, run_id="run-1"), fixture.state)
        self.assertEqual(_locked_checked_result_authority_snapshot(fixture.registry, fixture.ledger), after_reference)
        self.assertEqual(before[0], after_reference[0])
        self.assertTrue(all(not item.scientific_evidence_eligible for item in fixture.state.entries))

    def test_old_ablation_choice_does_not_skip_real_review_snapshot_applicability(self):
        fixture = snapshot_fixtures.SnapshotReferenceReplayTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        # Inert legacy-shaped receipt, never issued or passed through an owner.
        # The actual owned S contains only a mechanical Question, no Results.
        ablation = gates.SoundnessDimensionEvidenceReceipt(
            receipt_id="inert-older-a", dimension=gates.SoundnessDimension.ABLATIONS,
            status=gates.DimensionStatus.PASS, authority_kind=gates.SoundnessAuthorityKind.DETERMINISTIC,
            authority_artifact_hash=fixture.materialized.artifact.sha256,
            evidence_hashes=(fixture.snapshot.sha256,), governing_rule="Inert legacy shape",
            rationale="No scientific execution or authority.", reviewer_id="inert-reviewer",
        )
        before = _locked_checked_result_authority_snapshot(fixture.registry, fixture.ledger)
        try:
            soundness.require_native_numeric_ablation_soundness_join(
                fixture.registry, fixture.ledger, run_id="run-1", assessment_id="inert-round",
                claim_graph_artifact_hash=_digest("unissued-graph"), central_claim_ids=("inert-claim",),
                ablation_receipt=ablation,
                reproduction_receipt=SimpleNamespace(evidence_hashes=(fixture.materialized.artifact.sha256,)),
                reproduction_review_hash=_digest("unissued-review"),
                reproduction_review=SimpleNamespace(evidence_hashes=(fixture.snapshot.sha256,)),
                replay_peers=None,
            )
        except ScientificNumericAblationError as exc:
            self.assertIn("empty Result cohort", str(exc))
            self.assertIn("_native_numeric_ablation_declared_in_owned_state",
                          {frame.name for frame in traceback.extract_tb(exc.__traceback__)})
        else:
            self.fail("old A selection skipped actual reviewed snapshot applicability")
        self.assertEqual(_locked_checked_result_authority_snapshot(fixture.registry, fixture.ledger), before)

    def test_source_dispatch_is_full_and_acyclic_and_private_r7_guards_stay_closed(self):
        source = inspect.getsource(ev._derive_status)
        self.assertLess(source.index("_derive_native_numeric_ablation_status("), source.index("_explicit_failure("))
        native = inspect.getsource(ev._derive_native_numeric_ablation_status)
        for name in ("_require_semantic_reproduction_cohort_audit_source", "require_scientific_numeric_ablation_cohort",
                     "_require_numeric_ablation_audit_cohort_join", "_reproduction_cohort_clean_outcomes"):
            self.assertIn(name + "(", native)
        self.assertLess(native.index("_require_semantic_reproduction_cohort_audit_source("),
                        native.index("_native_numeric_ablation_declared_in_owned_state("))
        self.assertLess(native.index("_native_numeric_ablation_declared_in_owned_state("),
                        native.index("require_scientific_numeric_ablation_cohort("))
        self.assertIn("replay.canonical_scope.state", native)
        self.assertNotIn("_replayed_peer=", native)
        join = inspect.getsource(soundness.require_native_numeric_ablation_soundness_join)
        self.assertIn("_replayed_peer=peer", join)
        self.assertNotIn("_resolve_r_check_authority(", join)
        calls = {node.func.id for node in ast.walk(ast.parse(join))
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertIn("require_scientific_numeric_ablation_cohort", calls)
        self.assertIn("_require_native_numeric_ablation_round_join", calls)
        self.assertIn("require_native_numeric_ablation_soundness_join(", inspect.getsource(gates._derive_soundness_assessment))
        assembly = ast.parse(inspect.getsource(gates._derive_soundness_assessment)).body[0]
        direct_calls = [node for node in assembly.body if isinstance(node, ast.Expr)
                        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                        and node.value.func.id == "require_native_numeric_ablation_soundness_join"]
        self.assertEqual(len(direct_calls), 1)  # Not conditional on caller's A profile.
        self.assertLess(join.index("_require_soundness_ablation_applicability_state("),
                        join.index("require_native_numeric_ablation_dimension_shape("))
        applicability = inspect.getsource(soundness._require_soundness_ablation_applicability_state)
        for name in ("_require_research_state_snapshot_issuance", "resolve_bound_research_state_authority",
                     "_require_bound_snapshot_no_post_snapshot_core_drift"):
            self.assertIn(name + "(", applicability)
        self.assertNotIn("_semantic_challenger_audit_round_soundness", applicability)
        for function in (ev._derive_r_check_authority_source, ev._resolve_r_check_authority_source):
            self.assertNotIn("RCheck.R5", inspect.getsource(function))
        self.assertIn("receipt.r_check is not RCheck.R7", inspect.getsource(gates._resolve_reproduction_authority))


if __name__ == "__main__":
    unittest.main()
