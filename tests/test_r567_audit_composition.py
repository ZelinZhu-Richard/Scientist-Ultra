"""Pure evaluator composition contracts; substituted replay is not evidence.

No test here issues a scientific audit, signature, or production authority.
Owner substitutes exercise Boolean joins only; the registry test uses the real
owner and verifies that an ordinary PASS-labeled source is rejected.
"""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    AuditSummary,
    EvaluatorClass,
    RCheck,
    _alternative_source_binding,
    _derive_r_check_authority,
    _derive_status,
    _derive_r_check_authority_bundle,
    _event_binding,
    _fixture_scope,
    _payload_is_non_evidentiary_fixture,
    register_r_check_authority,
    register_r_check_authority_bundle,
    register_readiness_category_score_authority,
    require_gate,
    resolve_r_check_authority,
    resolve_r_check_authority_bundle,
    resolve_readiness_category_score_authority,
)
from scientist_one.gates import (
    AlternativeExplanationsStatus,
    ChallengeCategory,
    ChallengerExecutionStatus,
    ChallengerExecutorKind,
    SemanticChallengeAuditStatus,
)
from scientist_one.research_state import ReproducibilityPackage
from scientist_one.readiness import evaluate_readiness
from scientist_one.roles import Role
from tests import test_evaluator_authority as fixtures


def _audit(category, *, status=SemanticChallengeAuditStatus.PASS):
    return SimpleNamespace(
        assessment_id="assessment-one",
        run_id="run-authority",
        category=category,
        research_state_snapshot_artifact_hash="a" * 64,
        research_state_snapshot_artifact_record_hash="b" * 64,
        claim_graph_artifact_hash="c" * 64,
        claim_graph_artifact_record_hash="d" * 64,
        central_claim_ids=("claim-one",),
        result_artifact_hashes=("2" * 64, "e" * 64),
        result_artifact_record_hashes=("3" * 64, "f" * 64),
        reproducibility_package_artifact_hash=(
            "1" * 64 if category is ChallengeCategory.REPRODUCTION else None
        ),
        status=status,
    )


def _record(index=1, *, logical_type="semantic_challenge_audit_authority"):
    return SimpleNamespace(
        sha256=f"{index:064x}",
        record_hash="9" * 64,
        logical_type=logical_type,
        schema_version="1.0",
        creator_role=Role.ADVERSARIAL_REVIEWER,
        parent_artifacts=(),
    )


class AuditCompositionTests(unittest.TestCase):
    def test_bundle_rejects_drift_after_a_component_was_freshly_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            authorities = harness.authorities()
            changed = False

            def append_after_owner(*args, **kwargs):
                nonlocal changed
                result = resolve_r_check_authority(*args, **kwargs)
                if not changed:
                    changed = True
                    harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 3})
                return result

            with (
                patch("scientist_one.evaluators.resolve_r_check_authority", side_effect=append_after_owner),
                self.assertRaisesRegex(ValueError, "bundle sources changed"),
            ):
                _derive_r_check_authority_bundle(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    authority_artifact_sha256s=tuple(record.sha256 for record in authorities),
                    rubric_artifact_sha256=harness.rubric.sha256,
                )
            self.assertTrue(changed)

    def test_bundle_target_read_is_inside_the_outer_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            _audit_value, _authorities, bundle = harness.audit()
            original = harness.registry.get_bytes
            changed = False

            def append_after_target(digest):
                nonlocal changed
                content = original(digest)
                if digest == bundle.sha256 and not changed:
                    changed = True
                    harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 4})
                return content

            with (
                patch.object(harness.registry, "get_bytes", side_effect=append_after_target),
                self.assertRaisesRegex(ValueError, "bundle target or sources changed"),
            ):
                resolve_r_check_authority_bundle(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    bundle_artifact_sha256=bundle.sha256,
                )
            self.assertTrue(changed)

    def test_readiness_rejects_drift_after_bundle_and_component_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            audit, authorities, _bundle = harness.audit()
            changed = False

            def append_after_last_owner(*args, **kwargs):
                nonlocal changed
                result = resolve_r_check_authority(*args, **kwargs)
                if kwargs["authority_artifact_sha256"] == authorities[-1].sha256:
                    changed = True
                    harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 5})
                return result

            with (
                patch("scientist_one.readiness.resolve_r_check_authority", side_effect=append_after_last_owner),
                self.assertRaisesRegex(ValueError, "readiness authorities changed"),
            ):
                evaluate_readiness(audit, registry=harness.registry, ledger=harness.ledger, run_id=harness.run_id)
            self.assertTrue(changed)

    def test_fixture_integrity_gate_rejects_drift_after_outer_owner_reads(self):
        # The one passing check is system integrity, not scientific evidence.
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            source = harness.source("audit_report", Role.ORCHESTRATOR, {"fixture_notice": "non-evidentiary registry integrity"})
            authorities = tuple(
                register_r_check_authority(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    r_check=check, evaluator_class=evaluator_class,
                    source_artifact_sha256s=(source.sha256,) if check is RCheck.R0 else (),
                )
                for check, evaluator_class in fixtures._identities()
            )
            bundle = register_r_check_authority_bundle(
                harness.registry, harness.ledger, run_id=harness.run_id,
                authority_artifact_sha256s=tuple(record.sha256 for record in authorities),
                rubric_artifact_sha256=harness.rubric.sha256,
            )
            audit = AuditSummary([], bundle.sha256)
            options = dict(
                r_checks=(RCheck.R0,), registry=harness.registry, ledger=harness.ledger,
                run_id=harness.run_id, required_scope=AuthorityScope.SYSTEM_FIXTURE,
            )
            require_gate(audit, (EvaluatorClass.E0,), **options)
            calls = 0

            def append_after_outer_last(*args, **kwargs):
                nonlocal calls
                result = resolve_r_check_authority(*args, **kwargs)
                calls += 1
                if calls == 2 * len(authorities):
                    harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 6})
                return result

            with (
                patch("scientist_one.evaluators.resolve_r_check_authority", side_effect=append_after_outer_last),
                self.assertRaisesRegex(ValueError, "gate authorities changed"),
            ):
                require_gate(audit, (EvaluatorClass.E0,), **options)
            self.assertEqual(calls, 2 * len(authorities))

    def test_category_score_target_is_inside_the_outer_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            candidate = harness.source("paper_candidate", Role.PAPER_WRITER, {"fixture_notice": "synthetic candidate"})
            evidence = harness.source("readiness_evidence", Role.SCIENTIFIC_REVIEWER, {"scientific_evidence": False})
            category = json.loads(fixtures.RUBRIC_BYTES)["categories"][0]["id"]
            judgment = harness.fixture_score_judgment(
                category_id=category, score_fraction=1.0,
                candidate_sha256=candidate.sha256, evidence_sha256s=(evidence.sha256,),
            )
            score = register_readiness_category_score_authority(
                harness.registry, harness.ledger, run_id=harness.run_id,
                category_id=category, asserted_score_fraction=1.0,
                rubric_artifact_sha256=harness.rubric.sha256,
                candidate_artifact_sha256=candidate.sha256,
                evidence_artifact_sha256s=(evidence.sha256,),
                semantic_judgment_artifact_sha256=judgment.sha256,
            )
            original = harness.registry.get_bytes
            changed = False

            def append_after_target(digest):
                nonlocal changed
                content = original(digest)
                if digest == score.sha256 and not changed:
                    changed = True
                    harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 7})
                return content

            with (
                patch.object(harness.registry, "get_bytes", side_effect=append_after_target),
                self.assertRaisesRegex(ValueError, "category score target or sources changed"),
            ):
                resolve_readiness_category_score_authority(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    authority_artifact_sha256=score.sha256,
                )
            self.assertTrue(changed)

    def test_unqualified_audit_is_non_evidentiary_in_both_scope_consumers(self):
        record = _record()
        for flag in (False, None, 0, 1, "true", "false"):
            for payload in (
                {"scientific_source_qualified": flag},
                {"sources": [{"scientific_source_qualified": flag}]},
            ):
                with self.subTest(flag=flag, payload=payload):
                    self.assertIs(_fixture_scope((record,), (payload,)), AuthorityScope.SYSTEM_FIXTURE)
                    self.assertTrue(_payload_is_non_evidentiary_fixture(payload))
        qualified = {"scientific_source_qualified": True}
        self.assertIs(_fixture_scope((record,), (qualified,)), AuthorityScope.SCIENTIFIC)
        self.assertFalse(_payload_is_non_evidentiary_fixture(qualified))
        # Known domain evidence classification must also remain non-evidentiary
        # in readiness scoring; it is not free-form scientific claim text.
        for scope in ("SYSTEM_FIXTURE", "NON_EVIDENTIARY_FIXTURE", "NON_EVIDENTIARY"):
            self.assertTrue(_payload_is_non_evidentiary_fixture({"evidence_scope": scope}))

    def test_complete_owner_read_rejects_mid_read_source_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            original = _derive_status

            def change_after_derivation(*args, **kwargs):
                result = original(*args, **kwargs)
                harness.source("ordinary_observation", Role.ORCHESTRATOR, {"value": 1})
                return result

            with (
                patch(
                    "scientist_one.evaluators._derive_status",
                    side_effect=change_after_derivation,
                ),
                self.assertRaisesRegex(ValueError, "sources changed during complete"),
            ):
                register_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    r_check=RCheck.R0,
                    evaluator_class=EvaluatorClass.E0,
                )
            self.assertFalse(
                any(
                    record.logical_type == "r_check_authority"
                    for record in harness.registry.list_records()
                )
            )

    def test_authority_target_read_is_inside_the_snapshot_bracket(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            authority = register_r_check_authority(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                r_check=RCheck.R0,
                evaluator_class=EvaluatorClass.E0,
            )
            original = harness.registry.get_bytes
            changed = False

            def change_after_target_read(digest):
                nonlocal changed
                content = original(digest)
                if digest == authority.sha256 and not changed:
                    changed = True
                    harness.source(
                        "ordinary_observation", Role.ORCHESTRATOR, {"value": 2}
                    )
                return content

            with (
                patch.object(
                    harness.registry,
                    "get_bytes",
                    side_effect=change_after_target_read,
                ),
                self.assertRaisesRegex(ValueError, "target or sources changed"),
            ):
                resolve_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    authority_artifact_sha256=authority.sha256,
                )
            self.assertTrue(changed)

    def test_owner_publication_is_distinct_from_input_and_later_use(self):
        record = _record()

        def event(identifier, metadata):
            return SimpleNamespace(
                event_id=identifier,
                event_hash="2" * 64,
                artifact_hashes=(record.sha256,),
                metadata=metadata,
            )

        publication = event(
            "publication",
            {
                "semantic_challenge_audit_authority_publication": {},
                "artifact_types": [record.logical_type],
                "artifact_record_hashes": [record.record_hash],
            },
        )
        events = (event("input-use", {}), publication, event("later-use", {}))
        binding = _event_binding(events, record)
        self.assertEqual(binding.ledger_event_id, "publication")
        self.assertEqual(binding.ledger_event_index, 1)
        with self.assertRaisesRegex(ValueError, "one exact ledger admission"):
            _event_binding((*events, publication), record)
        publication.metadata["artifact_record_hashes"] = ["3" * 64]
        with self.assertRaisesRegex(ValueError, "substituted"):
            _event_binding(events, record)

    def test_pass_labeled_audit_source_is_rejected_by_real_owner_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            source = harness.source(
                "semantic_challenge_audit_authority",
                Role.ADVERSARIAL_REVIEWER,
                {
                    "schema_version": "semantic-challenge-audit-authority/v1",
                    "status": "PASS",
                },
            )
            registry_before = harness.registry.verify_all(raise_on_error=True)
            ledger_before = harness.ledger.validate(raise_on_error=True)
            for check in (RCheck.R5, RCheck.R6, RCheck.R7):
                with self.subTest(check=check):
                    authority, _ = _derive_r_check_authority(
                        harness.registry,
                        harness.ledger,
                        run_id=harness.run_id,
                        r_check=check,
                        evaluator_class=EvaluatorClass.E3,
                        source_artifact_sha256s=(source.sha256,),
                    )
                    self.assertIs(authority.status, AuthorityStatus.FAIL)
            self.assertEqual(
                harness.registry.verify_all(raise_on_error=True), registry_before
            )
            self.assertEqual(
                harness.ledger.validate(raise_on_error=True), ledger_before
            )

    def test_r6_requires_complete_scientific_overclaiming_audit(self):
        record = _record()
        registry, ledger = object(), object()
        for status, scope, expected in (
            (
                SemanticChallengeAuditStatus.PASS,
                AuthorityScope.SCIENTIFIC,
                AuthorityStatus.PASS,
            ),
            (
                SemanticChallengeAuditStatus.FAIL,
                AuthorityScope.SCIENTIFIC,
                AuthorityStatus.FAIL,
            ),
            (
                SemanticChallengeAuditStatus.UNTESTED,
                AuthorityScope.SCIENTIFIC,
                AuthorityStatus.UNTESTED,
            ),
            (
                SemanticChallengeAuditStatus.PASS,
                AuthorityScope.SYSTEM_FIXTURE,
                AuthorityStatus.UNTESTED,
            ),
        ):
            with (
                self.subTest(status=status, scope=scope),
                patch(
                    "scientist_one.evaluators._replay_semantic_audit_source",
                    return_value=_audit(ChallengeCategory.OVERCLAIMING, status=status),
                ) as replay,
            ):
                result, _, _ = _derive_status(
                    registry,
                    ledger,
                    "run-authority",
                    RCheck.R6,
                    EvaluatorClass.E3,
                    (record,),
                    ({},),
                    scope,
                )
                self.assertIs(result, expected)
                replay.assert_called_once_with(
                    registry,
                    ledger,
                    "run-authority",
                    record,
                    {},
                    expected_category=ChallengeCategory.OVERCLAIMING,
                )

    def test_labeled_alternative_source_is_rejected_without_any_owner_substitute(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = fixtures.AuthorityHarness(Path(directory))
            source = harness.source(
                "alternative_explanations_scientific_authority",
                Role.SCIENTIFIC_REVIEWER,
                {"status": "EXHAUSTIVELY_FALSIFIED"},
            )
            registry_before = harness.registry.verify_all(raise_on_error=True)
            ledger_before = harness.ledger.validate(raise_on_error=True)
            with self.assertRaises(ValueError):
                _derive_r_check_authority(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    r_check=RCheck.R5, evaluator_class=EvaluatorClass.E3,
                    source_artifact_sha256s=(source.sha256,),
                )
            self.assertEqual(harness.registry.verify_all(raise_on_error=True), registry_before)
            self.assertEqual(harness.ledger.validate(raise_on_error=True), ledger_before)

    def test_r5_requires_all_categories_and_one_exact_scientific_subject(self):
        deterministic = {
            ChallengeCategory.ALTERNATIVE_EXPLANATION,
            ChallengeCategory.EXTERNAL_VALIDITY,
        }
        audits = [
            _audit(category)
            for category in ChallengeCategory
            if category not in deterministic
        ]
        audit_records = tuple(_record(index + 10) for index in range(len(audits)))
        review_records = tuple(
            _record(index + 50, logical_type="challenger_category_review")
            for index in range(2)
        )
        reviews = [
            SimpleNamespace(
                category=category,
                execution_status=ChallengerExecutionStatus.EXECUTED,
                deterministic=True,
                claim_graph_artifact_hash="c" * 64,
                target_claim_ids=("claim-one",),
                execution_receipt_hash=f"{index + 70:064x}",
                finding_artifact_hashes=(),
            )
            for index, category in enumerate(
                sorted(deterministic, key=lambda value: value.value)
            )
        ]
        executions = [
            SimpleNamespace(
                category=review.category,
                executor_kind=ChallengerExecutorKind.DETERMINISTIC,
                procedure_id=(
                    "external-validity-boundary-audit"
                    if review.category is ChallengeCategory.EXTERNAL_VALIDITY
                    else "alternative-explanations-falsification"
                ),
                procedure_version="1.0",
                run_id="run-authority",
                claim_graph_artifact_hash="c" * 64,
                target_claim_ids=("claim-one",),
            )
            for review in reviews
        ]
        for case in (
            "complete",
            "missing",
            "different_result",
            "different_snapshot",
            "different_snapshot_record",
            "duplicate_category",
        ):
            selected = list(audits)
            records = audit_records
            if case == "missing":
                selected, records = selected[:-1], records[:-1]
            elif case == "different_result":
                selected[0] = _audit(selected[0].category)
                selected[0].result_artifact_hashes = ("4" * 64,)
            elif case == "different_snapshot":
                selected[0] = _audit(selected[0].category)
                selected[0].research_state_snapshot_artifact_hash = "4" * 64
            elif case == "different_snapshot_record":
                selected[0] = _audit(selected[0].category)
                selected[0].research_state_snapshot_artifact_record_hash = "4" * 64
            elif case == "duplicate_category":
                selected[0] = _audit(selected[1].category)
            all_records = (*records, *review_records)
            with (
                self.subTest(case=case),
                patch(
                    "scientist_one.evaluators._replay_semantic_audit_source",
                    side_effect=selected,
                ),
                patch(
                    "scientist_one.gates._load_challenger_category_review",
                    side_effect=reviews,
                ),
                patch(
                    "scientist_one.gates._load_challenger_attack_execution_receipt",
                    side_effect=executions,
                ),
            ):
                status, reason, _ = _derive_status(
                    object(),
                    object(),
                    "run-authority",
                    RCheck.R5,
                    EvaluatorClass.E3,
                    all_records,
                    tuple({} for _ in all_records),
                    AuthorityScope.SCIENTIFIC,
                )
            self.assertIs(
                status,
                (
                    AuthorityStatus.UNTESTED
                    if case in {"complete", "missing"}
                    else AuthorityStatus.FAIL
                ),
            )
            if case == "complete":
                self.assertEqual(reason, "ALTERNATIVE_COMPLETENESS_AUTHORITY_UNAVAILABLE")

    def test_r5_requires_aggregate_alternatives_bound_to_audited_results(self):
        """Pure joins; the remaining external fixture never produces R5 PASS."""
        deterministic = {
            ChallengeCategory.ALTERNATIVE_EXPLANATION,
            ChallengeCategory.EXTERNAL_VALIDITY,
        }
        audits = tuple(
            _audit(category) for category in ChallengeCategory
            if category not in deterministic
        )
        records = (
            *(_record(index + 10) for index in range(len(audits))),
            _record(50, logical_type="challenger_category_review"),
            _record(60, logical_type="alternative_explanations_scientific_authority"),
        )
        review = SimpleNamespace(
            category=ChallengeCategory.EXTERNAL_VALIDITY,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            deterministic=True,
            claim_graph_artifact_hash="c" * 64,
            target_claim_ids=("claim-one",),
            execution_receipt_hash="4" * 64,
            finding_artifact_hashes=(),
        )
        execution = SimpleNamespace(
            category=review.category,
            executor_kind=ChallengerExecutorKind.DETERMINISTIC,
            procedure_id="external-validity-boundary-audit",
            procedure_version="1.0",
            run_id="run-authority",
            claim_graph_artifact_hash="c" * 64,
            target_claim_ids=("claim-one",),
        )
        for case in (
            "complete", "unresolved", "surviving", "different_assessment",
            "different_run", "different_graph", "different_claims",
            "different_result", "different_test", "different_result_record",
            "different_test_record", "different_plan", "different_projection_record",
            "owner_refused",
        ):
            alternative = SimpleNamespace(
                assessment_id="assessment-one",
                run_id="run-authority",
                claim_graph_artifact_hash="c" * 64,
                central_claims=(SimpleNamespace(claim_id="claim-one"),),
                plan_artifact_hash="5" * 64,
                plan_artifact_record_hash="6" * 64,
                projection_artifact_hash="7" * 64,
                projection_artifact_record_hash="8" * 64,
                status=AlternativeExplanationsStatus.EXHAUSTIVELY_FALSIFIED,
            )
            attempt = SimpleNamespace(
                result_artifact_hash="e" * 64,
                result_artifact_record_hash="f" * 64,
                statistical_test_artifact_hash="2" * 64,
                statistical_test_artifact_record_hash="3" * 64,
            )
            projection = SimpleNamespace(
                plan_artifact_hash="5" * 64,
                plan_artifact_record_hash="6" * 64,
                attempt_results=(attempt,),
            )
            if case == "unresolved":
                alternative.status = AlternativeExplanationsStatus.UNRESOLVED
            elif case == "surviving":
                alternative.status = AlternativeExplanationsStatus.SURVIVING_EXPLANATION
            elif case == "different_assessment":
                alternative.assessment_id = "another-assessment"
            elif case == "different_run":
                alternative.run_id = "another-run"
            elif case == "different_graph":
                alternative.claim_graph_artifact_hash = "0" * 64
            elif case == "different_claims":
                alternative.central_claims = (SimpleNamespace(claim_id="another-claim"),)
            elif case == "different_result":
                attempt.result_artifact_hash = "0" * 64
            elif case == "different_test":
                attempt.statistical_test_artifact_hash = "0" * 64
            elif case == "different_result_record":
                attempt.result_artifact_record_hash = "0" * 64
            elif case == "different_test_record":
                attempt.statistical_test_artifact_record_hash = "0" * 64
            elif case == "different_plan":
                projection.plan_artifact_hash = "0" * 64
            elif case == "different_projection_record":
                alternative.projection_artifact_record_hash = "0" * 64
            registry = SimpleNamespace(
                get_metadata=lambda digest: SimpleNamespace(record_hash="8" * 64)
            )
            ledger = object()
            with (
                self.subTest(case=case),
                patch("scientist_one.evaluators._replay_semantic_audit_source", side_effect=audits),
                patch("scientist_one.gates._load_challenger_category_review", return_value=review),
                patch("scientist_one.gates._load_challenger_attack_execution_receipt", return_value=execution),
                patch(
                    "scientist_one.gates.require_alternative_explanations_authority",
                    return_value=alternative,
                    side_effect=ValueError("owner refused") if case == "owner_refused" else None,
                ) as replay,
                patch("scientist_one.gates.require_alternative_falsification_projection", return_value=projection),
            ):
                status, reason, _ = _derive_status(
                    registry, ledger, "run-authority", RCheck.R5, EvaluatorClass.E3,
                    records, tuple({} for _ in records), AuthorityScope.SCIENTIFIC,
                )
            replay.assert_called_once_with(
                registry, ledger, authority_artifact_hash=records[-1].sha256,
                expected_assessment_id="assessment-one", expected_run_id="run-authority",
                expected_claim_graph_artifact_hash="c" * 64,
                expected_central_claim_ids=("claim-one",),
            )
            self.assertIs(
                status,
                AuthorityStatus.UNTESTED if case in {"complete", "unresolved"}
                else AuthorityStatus.FAIL,
            )
            if case == "complete":
                self.assertEqual(reason, "EXTERNAL_VALIDITY_SCIENTIFIC_CLOSURE_UNAVAILABLE")

    def test_alternative_checkpoint_binding_requires_fresh_source_owner(self):
        """A parsed selector and event reference alone are not authority."""
        record = _record(60, logical_type="alternative_explanations_scientific_authority")
        stated = SimpleNamespace(
            assessment_id="assessment-one", run_id="run-authority",
            claim_graph_artifact_hash="c" * 64,
            central_claims=(SimpleNamespace(claim_id="claim-one"),),
            verification_event_index=0, verification_event_id="source-checkpoint",
            verification_event_hash="d" * 64, input_artifact_hashes=(),
        )
        event = SimpleNamespace(event_id="source-checkpoint", event_hash="d" * 64)
        registry, ledger = object(), object()
        for case in ("exact", "wrong_event", "wrong_index", "owner_refused"):
            event.event_hash = "0" * 64 if case == "wrong_event" else "d" * 64
            stated.verification_event_index = 1 if case == "wrong_index" else 0
            with (
                self.subTest(case=case),
                patch("scientist_one.gates.AlternativeExplanationsAuthority.from_dict", return_value=stated),
                patch(
                    "scientist_one.gates.require_alternative_explanations_authority",
                    return_value=stated,
                    side_effect=ValueError("owner refused") if case == "owner_refused" else None,
                ) as replay,
            ):
                if case == "exact":
                    binding = _alternative_source_binding(registry, ledger, (event,), "run-authority", record, {})
                    self.assertEqual(binding.ledger_event_id, "source-checkpoint")
                    self.assertEqual(binding.artifact_record_hash, record.record_hash)
                else:
                    with self.assertRaises(ValueError):
                        _alternative_source_binding(registry, ledger, (event,), "run-authority", record, {})
                replay.assert_called_once()

    def test_r7_replays_package_and_requires_exact_result_and_clean_pass(self):
        canonical = ReproducibilityPackage(
            object_id="package-one",
            producer=Role.REPRODUCTION_VERIFIER,
            run_ids=("original-run", "rerun-run"),
            manifest_artifact_hashes=("4" * 64, "5" * 64),
            environment_artifact_hashes=("6" * 64, "7" * 64),
            source_revision="source-one",
            evaluator_version="evaluator-one",
        )
        package_record = SimpleNamespace(record_hash="8" * 64)
        registry = SimpleNamespace(get_metadata=lambda digest: package_record)
        ledger = object()
        for case, use_round_cache in (
            (case, use_round_cache)
            for case in (
                "complete", "clean_failed", "audit_incomplete", "wrong_result",
                "wrong_result_record", "package_replay_failed",
            )
            for use_round_cache in (False, True)
        ):
            # Pure Boolean composition stand-in; not a published peer and not
            # positive production issuance. Exact cache admission is separately
            # tested in test_soundness_round_replay.
            replayed_peer = object() if use_round_cache else None
            audit = _audit(ChallengeCategory.REPRODUCTION)
            if case == "audit_incomplete":
                audit.status = SemanticChallengeAuditStatus.UNTESTED
            package = SimpleNamespace(
                ledger_run_id="run-authority",
                package_binding=SimpleNamespace(
                    artifact_sha256="1" * 64, artifact_record_hash="8" * 64
                ),
                original_result_binding=SimpleNamespace(
                    artifact_sha256="0" * 64 if case == "wrong_result" else "e" * 64,
                    artifact_record_hash="0" * 64
                    if case == "wrong_result_record"
                    else "f" * 64,
                ),
                clean_rerun_authority=SimpleNamespace(
                    reproduction_passed=case != "clean_failed"
                ),
            )
            with (
                self.subTest(case=case, use_round_cache=use_round_cache),
                patch(
                    "scientist_one.evaluators._replay_semantic_audit_source",
                    return_value=audit,
                ) as semantic_replay,
                patch(
                    "scientist_one.evaluators._canonical_json_artifact",
                    return_value=canonical.to_dict(),
                ),
                patch(
                    "scientist_one.research_state.require_scientific_reproducibility_package",
                    return_value=package,
                    side_effect=ValueError("owner refused")
                    if case == "package_replay_failed"
                    else None,
                ) as replay,
            ):
                status, _, _ = _derive_status(
                    registry,
                    ledger,
                    "run-authority",
                    RCheck.R7,
                    EvaluatorClass.E3,
                    (_record(),),
                    ({},),
                    AuthorityScope.SCIENTIFIC,
                    _replayed_semantic_peer=replayed_peer,
                )
                self.assertIs(semantic_replay.call_args.kwargs["_replayed_peer"], replayed_peer)
                replay.assert_called_once_with(
                    registry,
                    ledger,
                    package_state_artifact_sha256="1" * 64,
                    expected_ledger_run_id="run-authority",
                    expected_package_id="package-one",
                )
            self.assertIs(
                status,
                (
                    AuthorityStatus.PASS
                    if case == "complete"
                    else AuthorityStatus.UNTESTED
                    if case == "audit_incomplete"
                    else AuthorityStatus.FAIL
                ),
            )
