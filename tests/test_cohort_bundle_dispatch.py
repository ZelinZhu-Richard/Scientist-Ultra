"""Bounded controls for the exact cohort-bundle profile boundary.

The bundle and obligation values in this module are inert DTOs.  They are
never issued, backed by a trust root, or presented as scientific authority.
Registry coverage is limited to malformed metadata rejection and uses the
existing real registry/ledger harness without source-owner substitution.
"""

from __future__ import annotations

import ast
from dataclasses import fields, replace
import hashlib
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import traceback
import unittest

from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    AuditSummary,
    CategoryScoreStatus,
    EvaluatorClass,
    RCheck,
    RCheckAuthorityBundle,
    R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
    REQUIRED_R_AUTHORITIES,
    resolve_r_check_authority_bundle,
)
from scientist_one.errors import ArtifactError
from scientist_one.readiness import _readiness_objection_sources, evaluate_readiness
from scientist_one.roles import Role
from scientist_one.scientific_cohort_bundle import (
    CohortCheckOutcome,
    CohortSemanticAuditBinding,
    RCheckAuthorityBundleV2,
    _bundle_bytes,
)
from tests import test_evaluator_authority as evaluator_fixtures


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _missing_obligations(*, diagnostic_r7: bool = False) -> tuple[CohortCheckOutcome, ...]:
    rows = []
    for check in RCheck:
        evaluators = sorted(
            REQUIRED_R_AUTHORITIES[check], key=lambda evaluator: evaluator.value
        )
        for evaluator in evaluators:
            diagnostic = (
                check is RCheck.R7
                and evaluator is EvaluatorClass.E3
                and diagnostic_r7
            )
            rows.append(
                CohortCheckOutcome(
                    r_check=check,
                    evaluator_class=evaluator,
                    subject_artifact_sha256s=(
                        _digest(f"inert-subject-{check.value}-{evaluator.value}"),
                    ),
                    authority_artifact_sha256=None,
                    authority_artifact_record_hash=None,
                    status=(
                        AuthorityStatus.FAIL
                        if diagnostic
                        else AuthorityStatus.UNTESTED
                    ),
                    scope=AuthorityScope.SYSTEM_FIXTURE,
                    reason_code=(
                        "OWNED_ANCHOR_DIAGNOSTIC_FAIL"
                        if diagnostic
                        else "MISSING_INERT_OBLIGATION"
                    ),
                )
            )
    return tuple(sorted(rows, key=lambda row: row.identity))


def _inert_v2_bundle(*, diagnostic_r7: bool = False) -> RCheckAuthorityBundleV2:
    reproduction_hash = _digest("inert-reproduction-audit")
    reproduction_record_hash = _digest("inert-reproduction-audit-record")
    category_statuses = (("question_and_importance", CategoryScoreStatus.UNTESTED),)
    return RCheckAuthorityBundleV2(
        run_id="inert-cohort-run",
        scope=AuthorityScope.SYSTEM_FIXTURE,
        reproduction_audit_artifact_sha256=reproduction_hash,
        reproduction_audit_artifact_record_hash=reproduction_record_hash,
        assessment_id="inert-cohort-assessment",
        research_state_snapshot_artifact_sha256=_digest("inert-state-snapshot"),
        research_state_snapshot_artifact_record_hash=_digest(
            "inert-state-snapshot-record"
        ),
        claim_graph_artifact_sha256=_digest("inert-claim-graph"),
        claim_graph_artifact_record_hash=_digest("inert-claim-graph-record"),
        central_claim_ids=("inert-claim",),
        authority_artifact_sha256s=(),
        obligations=_missing_obligations(diagnostic_r7=diagnostic_r7),
        semantic_audit_bindings=(
            CohortSemanticAuditBinding(
                "REPRODUCTION",
                reproduction_hash,
                reproduction_record_hash,
            ),
        ),
        rubric_artifact_sha256=_digest("inert-rubric"),
        rubric_record_hash=_digest("inert-rubric-record"),
        rubric_ledger_event_id="inert-rubric-event",
        rubric_ledger_event_hash=_digest("inert-rubric-event-hash"),
        rubric_ledger_event_index=0,
        category_statuses=category_statuses,
        category_scope=AuthorityScope.SYSTEM_FIXTURE,
        category_score_authority_artifact_sha256s=(),
        paper_verification_artifact_sha256=None,
        paper_verification_artifact_record_hash=None,
        candidate_artifact_sha256=None,
        ledger_prefix_head_hash=_digest("inert-ledger-head"),
        ledger_prefix_event_count=1,
    )


def _inert_v1_bundle() -> RCheckAuthorityBundle:
    required = tuple(
        _digest(f"inert-v1-authority-{index}")
        for index, _identity in enumerate(
            (
                (check, evaluator)
                for check in RCheck
                for evaluator in sorted(
                    REQUIRED_R_AUTHORITIES[check],
                    key=lambda value: value.value,
                )
            )
        )
    )
    return RCheckAuthorityBundle(
        run_id="inert-v1-run",
        scope=AuthorityScope.SYSTEM_FIXTURE,
        authority_artifact_sha256s=required,
        rubric_artifact_sha256=_digest("inert-v1-rubric"),
        rubric_record_hash=_digest("inert-v1-rubric-record"),
        rubric_ledger_event_id="inert-v1-rubric-event",
        rubric_ledger_event_hash=_digest("inert-v1-rubric-event-hash"),
        rubric_ledger_event_index=0,
        statuses=tuple((check, AuthorityStatus.UNTESTED) for check in RCheck),
        category_statuses=(
            ("question_and_importance", CategoryScoreStatus.UNTESTED),
        ),
        category_scope=AuthorityScope.SYSTEM_FIXTURE,
        category_score_authority_artifact_sha256s=(),
        candidate_artifact_sha256=None,
        ledger_prefix_head_hash=_digest("inert-v1-ledger-head"),
        ledger_prefix_event_count=1,
    )


def _admission_snapshot(harness: evaluator_fixtures.AuthorityHarness) -> tuple[object, ...]:
    harness.registry.verify_all(raise_on_error=True)
    result = harness.ledger.validate(raise_on_error=True)
    return (
        tuple(
            (record.sha256, str(record.record_hash), record.logical_type)
            for record in harness.registry.list_records()
        ),
        tuple(
            (event.event_id, event.event_hash, event.artifact_hashes)
            for event in result.events
        ),
    )


class CohortBundleDtoTests(unittest.TestCase):
    def test_complete_missing_obligation_rows_cover_every_required_identity(self) -> None:
        bundle = _inert_v2_bundle()
        expected = {
            (check, evaluator)
            for check in RCheck
            for evaluator in REQUIRED_R_AUTHORITIES[check]
        }
        actual = {
            (row.r_check, row.evaluator_class) for row in bundle.obligations
        }
        self.assertEqual(actual, expected)
        self.assertEqual(bundle.authority_artifact_sha256s, ())
        self.assertTrue(
            all(
                row.status is AuthorityStatus.UNTESTED
                for row in bundle.obligations
            )
        )
        self.assertIs(bundle.scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertFalse(bundle.mandatory_pass)

    def test_closed_codec_round_trip_and_exact_obligation_projection(self) -> None:
        bundle = _inert_v2_bundle()
        encoded = bundle.to_dict()
        decoded = RCheckAuthorityBundleV2.from_dict(encoded)
        self.assertEqual(decoded, bundle)
        self.assertEqual(_bundle_bytes(decoded), _bundle_bytes(bundle))
        self.assertEqual(
            tuple(item.name for item in fields(CohortCheckOutcome)),
            (
                "r_check",
                "evaluator_class",
                "subject_artifact_sha256s",
                "authority_artifact_sha256",
                "authority_artifact_record_hash",
                "status",
                "scope",
                "reason_code",
            ),
        )
        encoded["unknown_alias"] = "must-reject"
        with self.assertRaises(ValueError):
            RCheckAuthorityBundleV2.from_dict(encoded)

    def test_diagnostic_omitted_r7_leaf_is_visible_to_critical_e3_projection(self) -> None:
        bundle = _inert_v2_bundle(diagnostic_r7=True)
        selected_leaf_authorities: tuple[object, ...] = ()
        projected = _readiness_objection_sources(bundle, selected_leaf_authorities)
        self.assertIs(projected, bundle.obligations)
        self.assertEqual(
            tuple(
                row.authority_artifact_sha256
                for row in projected
                if row.authority_artifact_sha256 is not None
            ),
            (),
        )
        r7 = next(
            row
            for row in projected
            if row.r_check is RCheck.R7
            and row.evaluator_class is EvaluatorClass.E3
        )
        self.assertIs(r7.status, AuthorityStatus.FAIL)
        self.assertEqual(r7.reason_code, "OWNED_ANCHOR_DIAGNOSTIC_FAIL")
        self.assertIs(r7.scope, AuthorityScope.SYSTEM_FIXTURE)
        self.assertTrue(
            all(
                row.status is AuthorityStatus.UNTESTED
                for row in projected
                if row is not r7
            )
        )
        critical = tuple(
            row
            for row in projected
            if row.evaluator_class in {EvaluatorClass.E2, EvaluatorClass.E3}
            and row.status is AuthorityStatus.FAIL
        )
        self.assertEqual(critical, (r7,))

    def test_v1_readiness_projection_returns_original_authority_tuple(self) -> None:
        bundle = _inert_v1_bundle()
        authorities = (SimpleNamespace(kind="original-v1-authority"),)
        self.assertIs(_readiness_objection_sources(bundle, authorities), authorities)

    def test_unsupported_duck_bundle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no supported full authority profile"):
            _readiness_objection_sources(SimpleNamespace(), ())


class CohortBundleDispatchBoundaryTests(unittest.TestCase):
    def test_registered_native_dto_cannot_replace_missing_full_anchor(self) -> None:
        with TemporaryDirectory(prefix="cohort-bundle-absent-anchor-") as directory:
            harness = evaluator_fixtures.AuthorityHarness(Path(directory))
            stated = replace(_inert_v2_bundle(), run_id=harness.run_id)
            record = harness.registry.put_json(
                stated.to_dict(),
                logical_type=R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
                origin=f"complete source-owned R0-R7 cohort bundle for {harness.run_id}",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "bundle-cohort-r-check-authorities"),
                schema_version="2.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before = _admission_snapshot(harness)
            with self.assertRaisesRegex(ValueError, "cohort bundle authority cannot be freshly resolved") as caught:
                resolve_r_check_authority_bundle(
                    harness.registry, harness.ledger,
                    bundle_artifact_sha256=record.sha256, run_id=harness.run_id,
                )
            causes = []
            cause = caught.exception.__cause__
            while cause is not None:
                causes.append(cause)
                cause = cause.__cause__
            self.assertTrue(any(isinstance(cause, ArtifactError) for cause in causes))
            frames = [frame.name for cause in causes
                      for frame in traceback.extract_tb(cause.__traceback__)]
            self.assertIn("_require_scientific_audit_cohort", frames)
            self.assertIn("_source_records", frames)
            self.assertFalse(
                AuditSummary(authority_bundle_artifact_sha256=record.sha256).mandatory_pass(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                )
            )
            self.assertEqual(_admission_snapshot(harness), before)

    def test_public_dispatcher_has_closed_registry2_dispatch_branch(self) -> None:
        tree = ast.parse(inspect.getsource(resolve_r_check_authority_bundle))
        expected = ast.parse(
            "record.logical_type == R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE "
            "and record.schema_version == '2.0'", mode="eval"
        ).body
        branches = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.dump(node.test) == ast.dump(expected)
        ]
        self.assertEqual(len(branches), 1)
        calls = [
            node for node in ast.walk(branches[0])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        dispatch = [node for node in calls if node.func.id == "resolve_r_check_authority_bundle_v2"]
        self.assertEqual(len(dispatch), 1)
        self.assertEqual([ast.unparse(arg) for arg in dispatch[0].args], ["registry", "ledger"])
        self.assertEqual(
            {kw.arg: ast.unparse(kw.value) for kw in dispatch[0].keywords},
            {"bundle_artifact_sha256": "bundle_artifact_sha256", "run_id": "run_id"},
        )
        self.assertNotIn("_derive_r_check_authority_bundle", [node.func.id for node in calls])
        self.assertIn("_r_check_read_snapshot", [node.func.id for node in calls])
        self.assertEqual(ast.unparse(branches[0].body[-1]), "return resolved")

    def test_readiness_critical_objection_uses_the_complete_projection(self) -> None:
        tree = ast.parse(inspect.getsource(evaluate_readiness))
        assignments = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "objection_sources"
                    for target in node.targets)
        ]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(
            ast.unparse(assignments[0].value),
            "_readiness_objection_sources(bundle, authorities)",
        )
        facts = next(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "facts"
                    for target in node.targets)
        )
        critical = next(value for key, value in zip(facts.keys, facts.values, strict=True)
                        if isinstance(key, ast.Constant) and key.value == "critical_e2_or_e3_objection")
        generators = [node for node in ast.walk(critical) if isinstance(node, ast.comprehension)]
        self.assertEqual(len(generators), 1)
        self.assertEqual(ast.unparse(generators[0].iter), "objection_sources")

    def test_unsupported_native_bundle_metadata_fails_without_registry_delta(self) -> None:
        with TemporaryDirectory(prefix="cohort-bundle-dispatch-") as directory:
            harness = evaluator_fixtures.AuthorityHarness(Path(directory))
            record = harness.registry.put_json(
                {
                    "schema_version": "r-check-authority-bundle/v2",
                    "kind": "R_CHECK_AUTHORITY_BUNDLE",
                    "fixture_notice": "malformed native metadata control",
                },
                logical_type=R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
                origin="inert malformed cohort bundle",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-malformed-cohort-bundle"),
                schema_version="2.1",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            harness._admit(
                harness.ledger,
                record,
                event_id="malformed-cohort-bundle",
                timestamp="2026-09-06T00:00:00Z",
                reason="admit inert malformed cohort bundle metadata",
            )
            before = _admission_snapshot(harness)
            with self.assertRaises(ValueError):
                resolve_r_check_authority_bundle(
                    harness.registry,
                    harness.ledger,
                    bundle_artifact_sha256=record.sha256,
                    run_id=harness.run_id,
                )
            self.assertEqual(_admission_snapshot(harness), before)


if __name__ == "__main__":
    unittest.main()
