"""Registry-and-ledger authority regressions for R0-R7 readiness gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    AuditSummary,
    CategoryScoreStatus,
    Decision,
    Evaluation,
    EvaluatorClass,
    R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
    R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION,
    R_CHECK_AUTHORITY_LOGICAL_TYPE,
    R_CHECK_AUTHORITY_SCHEMA_VERSION,
    READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE,
    READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION,
    READINESS_CATEGORY_SCORE_INSTRUCTIONS,
    REQUIRED_R_AUTHORITIES,
    RCheck,
    _derive_r_check_authority,
    _derive_r_check_authority_bundle,
    _derive_status,
    _fixture_scope,
    _payload_is_non_evidentiary_fixture,
    _readiness_category_score_input,
    _readiness_category_score_schema,
    register_r_check_authority,
    register_r_check_authority_bundle,
    register_readiness_category_score_authority,
    require_gate,
    resolve_r_check_authority,
    resolve_r_check_authority_bundle,
    resolve_readiness_category_score_authority,
)
from scientist_one.external import (
    EgressGateway,
    FixtureTransport,
    TransportResponse,
)
from scientist_one.gates import (
    JudgmentSubjectKind,
    SemanticJudgmentReceipt,
    register_semantic_judgment_receipt,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.paper_pipeline import _venue_score_outcome
from scientist_one.providers import (
    ModelCapability,
    ModelInvocation,
    ModelRunStatus,
    OpenAIResponsesProvider,
    openai_responses_policy,
)
from scientist_one.readiness import (
    evaluate_readiness,
    register_frozen_readiness_rubric,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[1]
RUBRIC_BYTES = (ROOT / "configs/paper_readiness_rubric.json").read_bytes()
CONFIGURATION_HASH = "a" * 64


def _identities() -> tuple[tuple[RCheck, EvaluatorClass], ...]:
    return tuple(
        (check, evaluator_class)
        for check in RCheck
        for evaluator_class in sorted(
            REQUIRED_R_AUTHORITIES[check], key=lambda value: value.value
        )
    )


def _descriptive_passes() -> list[Evaluation]:
    result: list[Evaluation] = []
    for check, evaluator_class in _identities():
        actor = {
            EvaluatorClass.E0: Role.ORCHESTRATOR,
            EvaluatorClass.E2: Role.SCIENTIFIC_REVIEWER,
            EvaluatorClass.E3: (
                Role.REPRODUCTION_VERIFIER
                if check is RCheck.R7
                else Role.ADVERSARIAL_REVIEWER
            ),
        }[evaluator_class]
        result.append(
            Evaluation(
                evaluator_class,
                actor,
                Decision.PASS,
                (),
                "descriptive PASS label with no source custody",
                (check,),
                producer_role=(
                    None
                    if evaluator_class is EvaluatorClass.E0
                    else Role.ORCHESTRATOR
                ),
            )
        )
    return result


class AuthorityHarness:
    def __init__(self, root: Path, *, ledger_name: str = "events.jsonl") -> None:
        self.root = root
        self.run_id = "run-authority"
        self.registry = ArtifactRegistry(root, "registry")
        self.ledger = EventLedger(root, f"runs/{self.run_id}/{ledger_name}")
        self._source_counter = 0
        self.rubric = register_frozen_readiness_rubric(
            self.registry,
            RUBRIC_BYTES,
        )
        self._admit(
            self.ledger,
            self.rubric,
            event_id="rubric-frozen",
            timestamp="2026-08-29T12:00:00Z",
            reason="freeze exact readiness rubric before evidence evaluation",
        )

    def _admit(
        self,
        ledger: EventLedger,
        record: object,
        *,
        event_id: str,
        timestamp: str,
        reason: str,
    ) -> None:
        ledger.record(
            run_id=self.run_id,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=MacroState.AUDIT,
            requested_state_after=MacroState.AUDIT,
            artifact_hashes=(record.sha256,),
            code_version="test-code-version",
            configuration_hash=CONFIGURATION_HASH,
            reason=reason,
            event_id=event_id,
            timestamp=timestamp,
            event_type="CHECKPOINT",
            metadata={
                "artifact_types": [record.logical_type],
                "artifact_record_hashes": [str(record.record_hash)],
            },
        )

    def authorities(self) -> tuple[object, ...]:
        return tuple(
            register_r_check_authority(
                self.registry,
                self.ledger,
                run_id=self.run_id,
                r_check=check,
                evaluator_class=evaluator_class,
            )
            for check, evaluator_class in _identities()
        )

    def source(
        self,
        logical_type: str,
        creator_role: Role,
        payload: object,
        *,
        parents: tuple[str, ...] = (),
        validation_result: str = "PASS",
        frozen: bool = True,
    ) -> object:
        self._source_counter += 1
        record = self.registry.put_json(
            payload,
            logical_type=logical_type,
            origin=f"test source {logical_type}",
            creator_role=creator_role,
            creation_command=("scientist-one", "test-authority-source"),
            parent_artifacts=parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result=validation_result,
            frozen=frozen,
        )
        self._admit(
            self.ledger,
            record,
            event_id=f"source-{self._source_counter}",
            timestamp=f"2026-08-29T12:00:{self._source_counter:02d}Z",
            reason=f"admit exact {logical_type} test source",
        )
        return record

    def fixture_score_judgment(
        self,
        *,
        category_id: str,
        score_fraction: float,
        candidate_sha256: str,
        evidence_sha256s: tuple[str, ...],
        exact_input: bool = True,
        label_suffix: str = "",
        self_report_live: bool = False,
    ) -> object:
        label = f"{category_id.replace('_', '-')}{label_suffix}"
        subject_kind = JudgmentSubjectKind.VENUE_DIMENSION
        context_hashes = (candidate_sha256, self.rubric.sha256)
        exact_inputs = (*evidence_sha256s, *context_hashes)
        outcome = _venue_score_outcome(score_fraction)
        rationale = f"Fixture-only score for {category_id}; not scientific authority."
        instructions = READINESS_CATEGORY_SCORE_INSTRUCTIONS
        rubric_payload = json.loads(self.registry.get_bytes(self.rubric.sha256))
        category = next(
            value for value in rubric_payload["categories"]
            if value["id"] == category_id
        )
        candidate_record = self.registry.get_metadata(candidate_sha256)
        candidate_payload = json.loads(
            self.registry.get_bytes(candidate_sha256)
        )
        evidence = tuple(
            (
                self.registry.get_metadata(digest),
                json.loads(self.registry.get_bytes(digest)),
            )
            for digest in evidence_sha256s
        )
        judged_input = canonical_json_bytes(
            _readiness_category_score_input(
                run_id=self.run_id,
                category=category,
                rubric_record=self.rubric,
                rubric=rubric_payload,
                candidate_record=candidate_record,
                candidate_payload=candidate_payload,
                evidence=evidence,
            )
        ).decode("utf-8")
        if not exact_input:
            judged_input = (
                f"subject_kind={subject_kind.value}\n"
                f"subject_id={category_id}\n"
                + "\n".join(exact_inputs)
            )
        schema = _readiness_category_score_schema()
        invocation_id = f"readiness-score-{label}"
        structured = {
            "subject_kind": subject_kind.value,
            "subject_id": category_id,
            "outcome": outcome,
            "rationale": rationale,
        }
        model = "gpt-5"
        envelope = {
            "id": f"response-readiness-{label}",
            "status": "completed",
            "model": model,
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json_bytes(structured).decode(
                                "utf-8"
                            ),
                        }
                    ],
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 10,
                "total_tokens": 20,
            },
        }
        class SelfReportingFixtureTransport(FixtureTransport):
            network_used = True
            external_validation = (
                "LIVE_RESPONSE_CAPTURED_NOT_SCIENTIFICALLY_VALIDATED"
            )

        transport_type = (
            SelfReportingFixtureTransport
            if self_report_live
            else FixtureTransport
        )
        gateway = EgressGateway(
            openai_responses_policy(maximum_attempts=1, maximum_requests=2),
            transport_type(
                (
                    TransportResponse(
                        status_code=200,
                        headers=(("Content-Type", "application/json"),),
                        body=canonical_json_bytes(envelope),
                        effective_url=(
                            "https://api.openai.com/v1/responses"
                        ),
                    ),
                )
            ),
            registry=self.registry,
            secret_resolver=lambda _name: "focused-fixture-credential",
            sleeper=lambda _delay: None,
            timestamp=lambda: "2026-08-29T12:00:00.000000Z",
        )
        prompt_hash = hashlib.sha256(instructions.encode("utf-8")).hexdigest()
        result = OpenAIResponsesProvider(gateway).invoke(
            ModelInvocation(
                invocation_id=invocation_id,
                capability=ModelCapability.RESEARCH_SYNTHESIS,
                model=model,
                prompt_template_id="readiness-category-score",
                prompt_template_version="1.0",
                prompt_template_hash=prompt_hash,
                instructions=instructions,
                input_text=judged_input,
                output_schema=schema,
                input_artifact_hashes=exact_inputs,
                max_output_tokens=512,
            )
        )
        expected_status = (
            ModelRunStatus.BLOCKED_EXTERNAL
            if self_report_live
            else ModelRunStatus.COMPLETED
        )
        if result.status is not expected_status:
            raise AssertionError("fixture semantic provider did not complete")
        if result.status is not ModelRunStatus.COMPLETED:
            return result
        records = {record.logical_type: record for record in result.artifacts}
        receipt = SemanticJudgmentReceipt(
            judgment_id=f"judgment-readiness-{label}",
            subject_kind=subject_kind,
            subject_id=category_id,
            outcome=outcome,
            evidence_hashes=evidence_sha256s,
            context_hashes=context_hashes,
            instructions_artifact_hash=records[
                "model_judged_instructions"
            ].sha256,
            input_artifact_hash=records["model_judged_input"].sha256,
            output_schema_artifact_hash=records["model_output_schema"].sha256,
            invocation_artifact_hash=records["model_invocation"].sha256,
            request_intent_artifact_hash=records[
                "model_provider_request_intent"
            ].sha256,
            provider_response_artifact_hash=records[
                "model_provider_response"
            ].sha256,
            model_output_artifact_hash=records["model_output"].sha256,
            invocation_id=invocation_id,
            provider_id="openai",
            provider_version="openai-responses-v1",
            model=model,
            model_version=model,
            prompt_template_id="readiness-category-score",
            prompt_template_version="1.0",
            prompt_template_hash=prompt_hash,
            structured_output_sha256=hashlib.sha256(
                canonical_json_bytes(structured)
            ).hexdigest(),
            reviewer_id="scientific-reviewer",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule=(
                "Fixture provider custody can exercise binding but cannot score."
            ),
            rationale=rationale,
        )
        persisted = register_semantic_judgment_receipt(
            self.registry,
            receipt,
        )
        self._source_counter += 1
        self._admit(
            self.ledger,
            persisted,
            event_id=f"semantic-score-{label}",
            timestamp=f"2026-08-29T12:01:{self._source_counter:02d}Z",
            reason=f"admit exact fixture semantic score for {category_id}",
        )
        return persisted

    def audit(self) -> tuple[AuditSummary, tuple[object, ...], object]:
        authorities = self.authorities()
        bundle = register_r_check_authority_bundle(
            self.registry,
            self.ledger,
            run_id=self.run_id,
            authority_artifact_sha256s=(
                record.sha256 for record in authorities
            ),
            rubric_artifact_sha256=self.rubric.sha256,
        )
        return (
            AuditSummary(_descriptive_passes(), bundle.sha256),
            authorities,
            bundle,
        )


class EvaluatorAuthorityTests(unittest.TestCase):
    def test_source_scope_is_closed_and_positive_labels_are_not_authority(self) -> None:
        for logical_type in (
            "unknown_scientific_source", "domain_validity.unknown",
            "reproduction_report", "confirmatory_timeline_receipt",
            "autonomous_implementation.semantic_validation",
        ):
            with self.subTest(logical_type=logical_type):
                self.assertIs(
                    _fixture_scope(
                        (SimpleNamespace(logical_type=logical_type),),
                        ({"scope": "SCIENTIFIC", "scientific_evidence": True},),
                    ),
                    AuthorityScope.SYSTEM_FIXTURE,
                )
        self.assertIs(_fixture_scope((), ()), AuthorityScope.SYSTEM_FIXTURE)
        with self.assertRaisesRegex(ValueError, "paired"):
            _fixture_scope((SimpleNamespace(logical_type="paper_verification"),), ())

    def test_unknown_or_malformed_evidence_scope_is_non_scientific(self) -> None:
        record = SimpleNamespace(logical_type="aggregate_experiment_result")
        payloads = (
            {"scope": "UNKNOWN"}, {"scope": {}}, {"scope": []},
            {"evidence_scope": "OPERATIONAL_BLOCKER"},
            {"evidence_use": ["SCIENTIFIC"]},
            {"scientific_evidence": "true"},
            {"scientific_evidence_eligible": 1},
            {"nested": {"scope": {"value": "SCIENTIFIC"}}},
            {"nested": {"scientific_evidence": False}},
            {"nested": {"evidence_use": "UNKNOWN"}},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertIs(
                    _fixture_scope((record,), (payload,)),
                    AuthorityScope.SYSTEM_FIXTURE,
                )
        # Claim scope is descriptive prose, not an evidence-scope grant.
        self.assertIs(
            _fixture_scope(
                (record,),
                ({"claim": {"scope": "restricted to the preregistered population"}},),
            ),
            AuthorityScope.SCIENTIFIC,
        )

    def test_unknown_domain_source_is_rejected_before_owner_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            source = harness.source(
                "domain_validity.unknown", Role.SCIENTIFIC_REVIEWER,
                {"scope": "SCIENTIFIC_EVIDENCE", "status": "PASS"},
            )
            with self.assertRaisesRegex(ValueError, "wrong logical type"):
                register_r_check_authority(
                    harness.registry, harness.ledger, run_id=harness.run_id,
                    r_check=RCheck.R3, evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=(source.sha256,),
                )

    def test_completed_legacy_replay_adapter_cannot_pass_scientific_r7(self) -> None:
        # Unit-level adapter contract only: real frozen packet replay is covered
        # by the CLI reproduction integration test.  No external run is implied.
        from scientist_one.reproduction import ARCHITECTURE_CONTROL_REPLAY_STATUS

        cases = (
            ("PASS", "verify_frozen_reproduction", "LEGACY_SYNTHETIC"),
            (
                ARCHITECTURE_CONTROL_REPLAY_STATUS,
                "verify_frozen_architecture_control_reproduction",
                "ARCHITECTURE_CONTROL",
            ),
        )
        for status, verifier_name, reason_prefix in cases:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                harness = AuthorityHarness(Path(directory))
                payload = {"status": status, "scientific_evidence": True}
                source = harness.source(
                    "reproduction_report", Role.REPRODUCTION_VERIFIER, payload,
                )
                with patch(
                    f"scientist_one.reproduction.{verifier_name}",
                    return_value=SimpleNamespace(status=status),
                ) as verifier:
                    authority, _ = _derive_r_check_authority(
                        harness.registry, harness.ledger, run_id=harness.run_id,
                        r_check=RCheck.R7, evaluator_class=EvaluatorClass.E3,
                        source_artifact_sha256s=(source.sha256,),
                    )
                verifier.assert_called_once_with(
                    harness.registry.policy.root, harness.run_id, payload,
                )
                self.assertIs(authority.status, AuthorityStatus.UNTESTED)
                self.assertIs(authority.scope, AuthorityScope.SYSTEM_FIXTURE)
                self.assertEqual(
                    authority.reason_code,
                    f"{reason_prefix}_REPRODUCTION_NON_EVIDENTIARY",
                )
                self.assertIs(authority.actor_role, Role.REPRODUCTION_VERIFIER)

    def test_legacy_reproduction_label_without_frozen_packet_fails_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            source = harness.source(
                "reproduction_report", Role.REPRODUCTION_VERIFIER,
                {"run_id": harness.run_id, "status": "PASS"},
            )
            authority, _ = _derive_r_check_authority(
                harness.registry, harness.ledger, run_id=harness.run_id,
                r_check=RCheck.R7, evaluator_class=EvaluatorClass.E3,
                source_artifact_sha256s=(source.sha256,),
            )
            self.assertIs(authority.status, AuthorityStatus.FAIL)
            self.assertIs(authority.scope, AuthorityScope.SYSTEM_FIXTURE)
            self.assertEqual(authority.reason_code, "FROZEN_REPRODUCTION_REPLAY_FAILED")

    def test_scientific_clean_rerun_dto_cannot_authorize_r7_without_owner_replay(self) -> None:
        from tests import test_scientific_clean_rerun as clean_fixtures

        # Construct a typed diagnostic value, never a scientific execution or
        # a registered clean-rerun authority. The real source owner must refuse
        # its ordinary test-origin registry/ledger admission.
        stated = clean_fixtures.ScientificCleanRerunTests("runTest")._authority()
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            source = harness.source(
                "scientific_clean_rerun_authority",
                Role.REPRODUCTION_VERIFIER,
                stated.to_dict(),
            )
            authority, _ = _derive_r_check_authority(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                r_check=RCheck.R7,
                evaluator_class=EvaluatorClass.E3,
                source_artifact_sha256s=(source.sha256,),
            )
            self.assertIs(authority.status, AuthorityStatus.FAIL)
            self.assertEqual(
                authority.reason_code,
                "SCIENTIFIC_CLEAN_RERUN_AUTHORITY_REPLAY_FAILED",
            )
            self.assertNotIn(
                ("scientific_clean_rerun_owner_replay", "PASS"),
                authority.derivation_checks,
            )

    def test_readiness_fixture_traversal_accepts_structured_prose_without_crash(self) -> None:
        self.assertFalse(_payload_is_non_evidentiary_fixture({"scope": {"text": "claim"}}))
        self.assertTrue(_payload_is_non_evidentiary_fixture({"scientific_evidence": "true"}))
        self.assertTrue(
            _payload_is_non_evidentiary_fixture(
                {"scope": [], "nested": {"evidence_use": "NON_EVIDENTIARY"}}
            )
        )

    def test_empty_pass_labels_cannot_authorize_a_gate(self) -> None:
        audit = AuditSummary(_descriptive_passes())
        self.assertEqual(
            set(audit.descriptive_status_by_r_check().values()),
            {"DESCRIPTIVE_ONLY"},
        )
        self.assertEqual(
            set(audit.status_by_r_check().values()),
            {"MISSING_AUTHORITY"},
        )
        self.assertFalse(audit.mandatory_pass())
        with self.assertRaisesRegex(ValueError, "no R-check authority bundle"):
            require_gate(
                audit,
                (EvaluatorClass.E0,),
                r_checks=(RCheck.R0,),
                registry=object(),
                ledger=object(),
                run_id="run-authority",
            )

    def test_exact_bundle_is_freshly_resolved_and_remains_untested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            audit, authorities, bundle_record = harness.audit()
            bundle = audit.resolve_bundle(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
            )

            self.assertEqual(len(authorities), 14)
            self.assertEqual(audit.hashes()[-1], bundle_record.sha256)
            self.assertEqual(bundle.scope, AuthorityScope.SYSTEM_FIXTURE)
            self.assertEqual(
                set(bundle.status_by_r_check.values()),
                {AuthorityStatus.UNTESTED.value},
            )
            self.assertFalse(
                audit.mandatory_pass(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    required_scope=AuthorityScope.SYSTEM_FIXTURE,
                )
            )
            with self.assertRaises(ValueError):
                audit.resolve_bundle(
                    harness.registry,
                    harness.ledger,
                    run_id="run-substituted",
                )
            with self.assertRaisesRegex(ValueError, "missing passing R0/E0"):
                require_gate(
                    audit,
                    (EvaluatorClass.E0,),
                    r_checks=(RCheck.R0,),
                    registry=harness.registry,
                    ledger=harness.ledger,
                    run_id=harness.run_id,
                    required_scope=AuthorityScope.SYSTEM_FIXTURE,
                )

            metadata = harness.registry.get_metadata(bundle_record.sha256)
            payload = json.loads(harness.registry.get_bytes(bundle_record.sha256))
            self.assertEqual(metadata.creator_role, Role.ORCHESTRATOR)
            self.assertEqual(metadata.logical_type, R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE)
            self.assertEqual(metadata.schema_version, R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION)
            self.assertEqual(
                metadata.parent_artifacts,
                (harness.rubric.sha256, *bundle.authority_artifact_sha256s),
            )
            self.assertFalse(payload["human_independence_claimed"])
            self.assertFalse(payload["e4_synthesized"])

            for (check, evaluator_class), record in zip(
                _identities(), authorities, strict=True
            ):
                resolved = resolve_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    authority_artifact_sha256=record.sha256,
                    run_id=harness.run_id,
                )
                expected_actor = (
                    Role.REPRODUCTION_VERIFIER
                    if check is RCheck.R7
                    else {
                        EvaluatorClass.E0: Role.ORCHESTRATOR,
                        EvaluatorClass.E2: Role.SCIENTIFIC_REVIEWER,
                        EvaluatorClass.E3: Role.ADVERSARIAL_REVIEWER,
                    }[evaluator_class]
                )
                self.assertEqual(resolved.r_check, check)
                self.assertEqual(resolved.evaluator_class, evaluator_class)
                self.assertEqual(resolved.actor_role, expected_actor)
                self.assertEqual(resolved.status, AuthorityStatus.UNTESTED)
                self.assertEqual(resolved.scope, AuthorityScope.SYSTEM_FIXTURE)
                authority_metadata = harness.registry.get_metadata(record.sha256)
                self.assertEqual(authority_metadata.creator_role, expected_actor)
                self.assertEqual(authority_metadata.logical_type, R_CHECK_AUTHORITY_LOGICAL_TYPE)
                self.assertEqual(authority_metadata.schema_version, R_CHECK_AUTHORITY_SCHEMA_VERSION)

    def test_high_scores_and_literal_pass_labels_do_not_launder_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            audit, _authorities, _bundle = harness.audit()
            rubric = json.loads(RUBRIC_BYTES)
            scores = {category["id"]: 1.0 for category in rubric["categories"]}

            with self.assertRaises(TypeError):
                evaluate_readiness(
                    scores,
                    audit,
                    registry=harness.registry,
                    ledger=harness.ledger,
                    run_id=harness.run_id,
                )

            substituted_scores = {**scores, "question": 0.0}
            with self.assertRaises(TypeError):
                evaluate_readiness(
                    substituted_scores,
                    audit,
                    registry=harness.registry,
                    ledger=harness.ledger,
                    run_id=harness.run_id,
                )

            result = evaluate_readiness(
                audit,
                registry=harness.registry,
                ledger=harness.ledger,
                run_id=harness.run_id,
            )

            self.assertIsNone(result.score)
            self.assertEqual(
                set(result.category_scores.values()),
                {None},
            )
            self.assertEqual(
                set(result.category_statuses.values()),
                {AuthorityStatus.UNTESTED.value},
            )
            self.assertFalse(result.passed)
            self.assertEqual(result.maximum_label, "INCONCLUSIVE")
            self.assertEqual(result.authority_scope, AuthorityScope.SYSTEM_FIXTURE)
            self.assertIn("mandatory_r_check_failure", result.blockers)
            self.assertIn("SYSTEM_FIXTURE_NOT_SCIENTIFIC_AUTHORITY", result.blockers)
            self.assertIn("NOVELTY_UNVERIFIED", result.blockers)

    def test_fixture_category_scores_bind_full_custody_but_cannot_promote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            candidate = harness.source(
                "paper_candidate",
                Role.PAPER_WRITER,
                {
                    "fixture_notice": "synthetic candidate is non-evidentiary",
                    "candidate": {"id": "fixture-candidate"},
                },
            )
            evidence = harness.source(
                "readiness_evidence",
                Role.SCIENTIFIC_REVIEWER,
                {
                    "fixture_notice": "deterministic readiness fixture",
                    "scientific_evidence": False,
                },
            )
            category_ids = tuple(
                category["id"] for category in json.loads(RUBRIC_BYTES)["categories"]
            )
            score_records = []
            for category_id in category_ids:
                judgment = harness.fixture_score_judgment(
                    category_id=category_id,
                    score_fraction=1.0,
                    candidate_sha256=candidate.sha256,
                    evidence_sha256s=(evidence.sha256,),
                )
                record = register_readiness_category_score_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    category_id=category_id,
                    asserted_score_fraction=1.0,
                    rubric_artifact_sha256=harness.rubric.sha256,
                    candidate_artifact_sha256=candidate.sha256,
                    evidence_artifact_sha256s=(evidence.sha256,),
                    semantic_judgment_artifact_sha256=judgment.sha256,
                )
                resolved = resolve_readiness_category_score_authority(
                    harness.registry,
                    harness.ledger,
                    authority_artifact_sha256=record.sha256,
                    run_id=harness.run_id,
                )
                self.assertEqual(resolved.status, CategoryScoreStatus.UNTESTED)
                self.assertEqual(resolved.scope, AuthorityScope.SYSTEM_FIXTURE)
                self.assertIsNone(resolved.authoritative_score_fraction)
                metadata = harness.registry.get_metadata(record.sha256)
                self.assertEqual(
                    metadata.logical_type,
                    READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE,
                )
                self.assertEqual(
                    metadata.schema_version,
                    READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION,
                )
                score_records.append(record)

            authorities = harness.authorities()
            with self.assertRaisesRegex(ValueError, "empty or complete"):
                register_r_check_authority_bundle(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    authority_artifact_sha256s=(
                        record.sha256 for record in authorities
                    ),
                    rubric_artifact_sha256=harness.rubric.sha256,
                    category_score_authority_artifact_sha256s=(
                        score_records[0].sha256,
                    ),
                )

            bundle_record = register_r_check_authority_bundle(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                authority_artifact_sha256s=(
                    record.sha256 for record in authorities
                ),
                rubric_artifact_sha256=harness.rubric.sha256,
                category_score_authority_artifact_sha256s=(
                    record.sha256 for record in score_records
                ),
            )
            audit = AuditSummary(_descriptive_passes(), bundle_record.sha256)
            bundle = audit.resolve_bundle(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
            )
            self.assertEqual(
                bundle.category_score_authority_artifact_sha256s,
                tuple(record.sha256 for record in score_records),
            )
            self.assertEqual(
                set(bundle.category_status_by_id.values()),
                {CategoryScoreStatus.UNTESTED.value},
            )
            self.assertEqual(bundle.scope, AuthorityScope.SYSTEM_FIXTURE)
            result = evaluate_readiness(
                audit,
                registry=harness.registry,
                ledger=harness.ledger,
                run_id=harness.run_id,
            )
            self.assertIsNone(result.score)
            self.assertEqual(set(result.category_scores.values()), {None})
            self.assertFalse(result.passed)
            self.assertEqual(result.maximum_label, "INCONCLUSIVE")

            self_reporting_result = harness.fixture_score_judgment(
                category_id=category_ids[0],
                score_fraction=1.0,
                candidate_sha256=candidate.sha256,
                evidence_sha256s=(evidence.sha256,),
                label_suffix="-self-report-live",
                self_report_live=True,
            )
            self.assertIs(
                self_reporting_result.status,
                ModelRunStatus.BLOCKED_EXTERNAL,
            )
            self.assertEqual(
                self_reporting_result.external_validation,
                "BLOCKED_EXTERNAL",
            )
            self.assertFalse(self_reporting_result.network_used)
            self.assertEqual(
                self_reporting_result.error_code,
                "PROVIDER_UNAVAILABLE",
            )
            self.assertIsNotNone(self_reporting_result.terminal_receipt)
            blocked_logical_types = {
                record.logical_type
                for record in self_reporting_result.artifacts
            }
            self.assertFalse(
                blocked_logical_types
                & {
                    "external_request",
                    "external_response_receipt",
                    "raw_external_response",
                    "audited_transport_execution_authority",
                    "model_provider_request_intent",
                    "model_provider_response",
                    "model_output",
                    "semantic_judgment_receipt",
                }
            )

            weak_judgment = harness.fixture_score_judgment(
                category_id=category_ids[0],
                score_fraction=1.0,
                candidate_sha256=candidate.sha256,
                evidence_sha256s=(evidence.sha256,),
                exact_input=False,
                label_suffix="-weak-input",
            )
            with self.assertRaisesRegex(ValueError, "exact rubric inputs"):
                register_readiness_category_score_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    category_id=category_ids[0],
                    asserted_score_fraction=1.0,
                    rubric_artifact_sha256=harness.rubric.sha256,
                    candidate_artifact_sha256=candidate.sha256,
                    evidence_artifact_sha256s=(evidence.sha256,),
                    semantic_judgment_artifact_sha256=weak_judgment.sha256,
                )

            first = score_records[0]
            first_metadata = harness.registry.get_metadata(first.sha256)
            first_payload = json.loads(harness.registry.get_bytes(first.sha256))
            with self.assertRaises(ValueError):
                resolve_readiness_category_score_authority(
                    harness.registry,
                    harness.ledger,
                    authority_artifact_sha256=first.sha256,
                    run_id="run-spliced",
                )
            for variant in (
                "rubric",
                "category",
                "evidence",
                "score",
                "fixture_promotion",
            ):
                with self.subTest(variant=variant):
                    payload = json.loads(
                        canonical_json_bytes(first_payload)
                    )
                    if variant == "rubric":
                        payload["rubric_binding"]["artifact_sha256"] = "f" * 64
                    elif variant == "category":
                        payload["category_id"] = category_ids[1]
                    elif variant == "evidence":
                        payload["evidence_bindings"][0][
                            "artifact_sha256"
                        ] = candidate.sha256
                    elif variant == "score":
                        payload["asserted_score_fraction"] = 0.5
                    else:
                        payload["status"] = CategoryScoreStatus.SCORED.value
                        payload["scope"] = AuthorityScope.SCIENTIFIC.value
                    forged = harness.registry.put_json(
                        payload,
                        logical_type=(
                            READINESS_CATEGORY_SCORE_AUTHORITY_LOGICAL_TYPE
                        ),
                        origin=(
                            "registry-and-ledger resolved readiness category "
                            "score authority"
                        ),
                        creator_role=Role.SCIENTIFIC_REVIEWER,
                        creation_command=(
                            "scientist-one",
                            "resolve-readiness-category-score",
                        ),
                        parent_artifacts=first_metadata.parent_artifacts,
                        schema_version=(
                            READINESS_CATEGORY_SCORE_AUTHORITY_SCHEMA_VERSION
                        ),
                        mime_type="application/json",
                        validation_result="PASS",
                        frozen=True,
                    )
                    with self.assertRaises(ValueError):
                        resolve_readiness_category_score_authority(
                            harness.registry,
                            harness.ledger,
                            authority_artifact_sha256=forged.sha256,
                            run_id=harness.run_id,
                        )

    def test_rubric_preserves_exact_noncanonical_frozen_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory), "registry")
            record = register_frozen_readiness_rubric(registry, RUBRIC_BYTES)
            self.assertEqual(registry.get_bytes(record.sha256), RUBRIC_BYTES)
            self.assertEqual(record.sha256, __import__("hashlib").sha256(RUBRIC_BYTES).hexdigest())

            duplicate_key = RUBRIC_BYTES.replace(
                b'{\n  "schema_version": "1.0",',
                b'{\n  "schema_version": "1.0",\n  "schema_version": "1.0",',
                1,
            )
            with self.assertRaisesRegex(ValueError, "not safe JSON"):
                register_frozen_readiness_rubric(registry, duplicate_key)

    def test_bundle_rejects_rubric_frozen_after_evaluated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = ArtifactRegistry(root, "registry")
            ledger = EventLedger(root, "runs/run-authority/events.jsonl")
            source = registry.put_json(
                {"fixture_notice": "pre-rubric system audit"},
                logical_type="audit_report",
                origin="pre-rubric source",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-pre-rubric-source"),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            ledger.record(
                run_id="run-authority",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.AUDIT,
                requested_state_after=MacroState.AUDIT,
                artifact_hashes=(source.sha256,),
                code_version="test-code-version",
                configuration_hash=CONFIGURATION_HASH,
                reason="admit evidence before rubric",
                event_id="pre-rubric-source",
                timestamp="2026-08-29T12:00:00Z",
                event_type="CHECKPOINT",
                metadata={
                    "artifact_types": [source.logical_type],
                    "artifact_record_hashes": [str(source.record_hash)],
                },
            )
            rubric = register_frozen_readiness_rubric(registry, RUBRIC_BYTES)
            ledger.record(
                run_id="run-authority",
                actor_role=Role.PROTOCOL_DESIGNER,
                state_before=MacroState.AUDIT,
                requested_state_after=MacroState.AUDIT,
                artifact_hashes=(rubric.sha256,),
                code_version="test-code-version",
                configuration_hash=CONFIGURATION_HASH,
                reason="rubric frozen too late",
                event_id="late-rubric",
                timestamp="2026-08-29T12:00:01Z",
                event_type="CHECKPOINT",
                metadata={
                    "artifact_types": [rubric.logical_type],
                    "artifact_record_hashes": [str(rubric.record_hash)],
                },
            )
            authorities = []
            for check, evaluator_class in _identities():
                authorities.append(
                    register_r_check_authority(
                        registry,
                        ledger,
                        run_id="run-authority",
                        r_check=check,
                        evaluator_class=evaluator_class,
                        source_artifact_sha256s=(
                            (source.sha256,)
                            if (check, evaluator_class)
                            == (RCheck.R0, EvaluatorClass.E0)
                            else ()
                        ),
                    )
                )
            with self.assertRaisesRegex(ValueError, "not frozen before"):
                register_r_check_authority_bundle(
                    registry,
                    ledger,
                    run_id="run-authority",
                    authority_artifact_sha256s=(
                        record.sha256 for record in authorities
                    ),
                    rubric_artifact_sha256=rubric.sha256,
                )

    def test_literal_source_labels_are_not_semantic_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            contract = harness.source(
                "evaluation_contract",
                Role.PROTOCOL_DESIGNER,
                {
                    "evaluation_contract": {},
                    "fixture_notice": "fabricated structural fixture label",
                },
            )
            aggregate = harness.source(
                "aggregate_experiment_result",
                Role.STATISTICIAN,
                {
                    "baseline_accuracy": 0.0,
                    "candidate_accuracy": 1.0,
                    "effect": 1.0,
                    "fixture_notice": "fabricated aggregate label",
                    "scientific_evidence_eligible": False,
                },
                parents=(contract.sha256,),
            )
            semantic = harness.source(
                "autonomous_implementation.semantic_validation",
                Role.SCIENTIFIC_REVIEWER,
                {
                    "fixture_notice": "fabricated semantic label",
                    "schema_version": (
                        "AUTONOMOUS_IMPLEMENTATION_SEMANTIC_VALIDATION_V1"
                    ),
                    "scientific_evidence": False,
                    "status": "PASS",
                },
                parents=(contract.sha256, aggregate.sha256),
            )
            statistics = harness.source(
                "statistical_analysis",
                Role.STATISTICIAN,
                {
                    "effect": 1.0,
                    "fixture_notice": "fabricated statistical label",
                },
                parents=(aggregate.sha256,),
            )
            custody = harness.source(
                "custody_record",
                Role.HOLDOUT_CUSTODIAN,
                {"fixture_notice": "fabricated custody label", "status": "PASS"},
            )
            machine = harness.source(
                "machine_results",
                Role.EXPERIMENT_RUNNER,
                {"fixture_notice": "fabricated result label", "status": "PASS"},
                parents=(custody.sha256,),
            )
            ablation = harness.source(
                "ablation_validation",
                Role.SCIENTIFIC_REVIEWER,
                {
                    "fixture_notice": "fabricated ablation label",
                    "result": {},
                    "validation": "PASS",
                },
                parents=(aggregate.sha256,),
            )
            scenarios = (
                (
                    RCheck.R2,
                    EvaluatorClass.E0,
                    (contract.sha256, aggregate.sha256),
                ),
                (
                    RCheck.R2,
                    EvaluatorClass.E2,
                    (contract.sha256, aggregate.sha256, semantic.sha256),
                ),
                (
                    RCheck.R3,
                    EvaluatorClass.E0,
                    (custody.sha256, machine.sha256),
                ),
                (
                    RCheck.R4,
                    EvaluatorClass.E2,
                    (aggregate.sha256, statistics.sha256),
                ),
                (RCheck.R5, EvaluatorClass.E2, (ablation.sha256,)),
            )
            for check, evaluator_class, sources in scenarios:
                with self.subTest(check=check, evaluator_class=evaluator_class):
                    record = register_r_check_authority(
                        harness.registry,
                        harness.ledger,
                        run_id=harness.run_id,
                        r_check=check,
                        evaluator_class=evaluator_class,
                        source_artifact_sha256s=sources,
                    )
                    resolved = resolve_r_check_authority(
                        harness.registry,
                        harness.ledger,
                        authority_artifact_sha256=record.sha256,
                        run_id=harness.run_id,
                    )
                    self.assertEqual(resolved.status, AuthorityStatus.UNTESTED)

    def test_paper_and_challenger_authority_reject_spliced_source_identity(self) -> None:
        snapshot = SimpleNamespace(
            logical_type="canonical_research_state_final_snapshot",
            sha256="1" * 64,
        )
        graph = SimpleNamespace(
            logical_type="claim_evidence_graph",
            sha256="2" * 64,
        )
        paper = SimpleNamespace(
            logical_type="paper_verification",
            sha256="3" * 64,
        )
        passed_verification = SimpleNamespace(passed=True)

        with (
            patch(
                "scientist_one.research_state.resolve_research_state_authority"
            ),
            patch(
                "scientist_one.paper_pipeline.require_paper_verification",
                return_value=passed_verification,
            ),
            patch(
                "scientist_one.evaluators._paper_authority_bundle",
                return_value=SimpleNamespace(
                    run_id="run-authority",
                    research_state_hash="4" * 64,
                    claim_graph_hash="5" * 64,
                ),
            ),
        ):
            r0_status, r0_reason, _r0_checks = _derive_status(
                object(),
                object(),
                "run-authority",
                RCheck.R0,
                EvaluatorClass.E0,
                (snapshot, paper),
                ({}, {}),
                AuthorityScope.SCIENTIFIC,
            )
            self.assertEqual(r0_status, AuthorityStatus.FAIL)
            self.assertEqual(r0_reason, "PAPER_AUTHORITY_FAILED")

            with patch("scientist_one.gates._resolve_claim_graph_authority"):
                r6_status, r6_reason, _r6_checks = _derive_status(
                    object(),
                    object(),
                    "run-authority",
                    RCheck.R6,
                    EvaluatorClass.E2,
                    (graph, paper),
                    ({}, {}),
                    AuthorityScope.SCIENTIFIC,
                )
            self.assertEqual(r6_status, AuthorityStatus.FAIL)
            self.assertEqual(r6_reason, "PAPER_AUTHORITY_FAILED")

        from scientist_one.gates import (
            ChallengeCategory,
            ChallengerExecutionStatus,
        )

        review_record = SimpleNamespace(
            logical_type="challenger_category_review",
            sha256="6" * 64,
        )
        review = SimpleNamespace(
            category=ChallengeCategory.OVERCLAIMING,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            execution_receipt_hash="7" * 64,
            finding_artifact_hashes=(),
        )
        registry_context = object()
        ledger_context = object()
        with (
            patch(
                "scientist_one.gates._load_challenger_category_review",
                return_value=review,
            ) as review_loader,
            patch(
                "scientist_one.gates._load_challenger_attack_execution_receipt",
                return_value=SimpleNamespace(run_id="run-spliced"),
            ) as execution_loader,
        ):
            status, reason, _checks = _derive_status(
                registry_context,
                ledger_context,
                "run-authority",
                RCheck.R6,
                EvaluatorClass.E3,
                (review_record,),
                ({},),
                AuthorityScope.SCIENTIFIC,
            )
        self.assertEqual(status, AuthorityStatus.FAIL)
        self.assertEqual(reason, "CHALLENGER_RUN_MISMATCH")
        review_loader.assert_called_once_with(
            registry_context, review_record.sha256, ledger=ledger_context
        )
        execution_loader.assert_called_once_with(
            registry_context, review.execution_receipt_hash, ledger=ledger_context
        )

    def test_challenger_failed_finding_replay_retains_exact_ledger_context(self) -> None:
        """Wiring-only regression; substitutes cannot create registry authority."""
        from scientist_one.gates import ChallengeCategory, ChallengerExecutionStatus

        registry_context = object()
        ledger_context = object()
        record = SimpleNamespace(
            logical_type="challenger_category_review", sha256="6" * 64
        )
        review = SimpleNamespace(
            category=ChallengeCategory.OVERCLAIMING,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            execution_receipt_hash="7" * 64,
            finding_artifact_hashes=("8" * 64,),
        )
        with (
            patch(
                "scientist_one.gates._load_challenger_category_review",
                return_value=review,
            ),
            patch(
                "scientist_one.gates._load_challenger_attack_execution_receipt",
                return_value=SimpleNamespace(run_id="run-authority"),
            ),
            patch(
                "scientist_one.gates._load_challenge_finding",
                side_effect=ValueError("source-owner replay declined"),
            ) as finding_loader,
        ):
            status, reason, _checks = _derive_status(
                registry_context,
                ledger_context,
                "run-authority",
                RCheck.R6,
                EvaluatorClass.E3,
                (record,),
                ({},),
                AuthorityScope.SCIENTIFIC,
            )
        self.assertEqual(status, AuthorityStatus.FAIL)
        self.assertEqual(reason, "CHALLENGER_REPLAY_FAILED")
        finding_loader.assert_called_once_with(
            registry_context, "8" * 64, ledger=ledger_context
        )

    def test_completed_semantic_challenger_is_not_a_complete_finding_audit(self) -> None:
        """A wiring-only completion result cannot become a gate PASS."""
        from scientist_one.gates import (
            ChallengeCategory,
            ChallengerExecutorKind,
            ChallengerExecutionStatus,
        )

        record = SimpleNamespace(
            logical_type="challenger_category_review", sha256="6" * 64
        )
        review = SimpleNamespace(
            category=ChallengeCategory.OVERCLAIMING,
            execution_status=ChallengerExecutionStatus.EXECUTED,
            execution_receipt_hash="7" * 64,
            finding_artifact_hashes=(),
        )
        with (
            patch(
                "scientist_one.gates._load_challenger_category_review",
                return_value=review,
            ),
            patch(
                "scientist_one.gates._load_challenger_attack_execution_receipt",
                return_value=SimpleNamespace(
                    run_id="run-authority",
                    executor_kind=ChallengerExecutorKind.SEMANTIC,
                ),
            ),
        ):
            status, reason, checks = _derive_status(
                object(),
                object(),
                "run-authority",
                RCheck.R6,
                EvaluatorClass.E3,
                (record,),
                ({},),
                AuthorityScope.SCIENTIFIC,
            )
        self.assertEqual(status, AuthorityStatus.UNTESTED)
        self.assertEqual(
            reason, "CHALLENGER_FINDING_CLOSURE_AUTHORITY_UNAVAILABLE"
        )
        self.assertIn(("challenger_execution_replay", "PASS"), checks)

    def test_source_type_role_status_descriptor_and_duplicates_fail_closed(self) -> None:
        cases = ("type", "role", "status", "descriptor")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                harness = AuthorityHarness(Path(directory))
                logical_type = "audit_report"
                creator_role = Role.ORCHESTRATOR
                validation_result = "PASS"
                frozen = True
                if case == "type":
                    logical_type = "unrelated_source"
                elif case == "role":
                    creator_role = Role.PROTOCOL_DESIGNER
                elif case == "status":
                    validation_result = "PENDING"
                    frozen = False
                record = harness.registry.put_json(
                    {"fixture_notice": "untrusted source label", "status": "PASS"},
                    logical_type=logical_type,
                    origin="untrusted source",
                    creator_role=creator_role,
                    creation_command=("scientist-one", "untrusted-source"),
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result=validation_result,
                    frozen=frozen,
                )
                if case == "descriptor":
                    harness.ledger.record(
                        run_id=harness.run_id,
                        actor_role=Role.ORCHESTRATOR,
                        state_before=MacroState.AUDIT,
                        requested_state_after=MacroState.AUDIT,
                        artifact_hashes=(record.sha256,),
                        code_version="test-code-version",
                        configuration_hash=CONFIGURATION_HASH,
                        reason="admit source with substituted descriptor",
                        event_id="bad-descriptor",
                        timestamp="2026-08-29T12:00:01Z",
                        event_type="CHECKPOINT",
                        metadata={
                            "artifact_types": [record.logical_type],
                            "artifact_record_hashes": ["b" * 64],
                        },
                    )
                else:
                    harness._admit(
                        harness.ledger,
                        record,
                        event_id="untrusted-source",
                        timestamp="2026-08-29T12:00:01Z",
                        reason="admit untrusted source",
                    )
                with self.assertRaises(ValueError):
                    register_r_check_authority(
                        harness.registry,
                        harness.ledger,
                        run_id=harness.run_id,
                        r_check=RCheck.R0,
                        evaluator_class=EvaluatorClass.E0,
                        source_artifact_sha256s=(record.sha256,),
                    )

        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            first = harness.source(
                "audit_report",
                Role.ORCHESTRATOR,
                {"fixture_notice": "first audit source"},
            )
            second = harness.source(
                "audit_report",
                Role.ORCHESTRATOR,
                {"fixture_notice": "second audit source"},
            )
            record = register_r_check_authority(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                r_check=RCheck.R0,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(first.sha256, second.sha256),
            )
            resolved = resolve_r_check_authority(
                harness.registry,
                harness.ledger,
                authority_artifact_sha256=record.sha256,
                run_id=harness.run_id,
            )
            self.assertEqual(resolved.status, AuthorityStatus.FAIL)
            self.assertEqual(resolved.reason_code, "SOURCE_AUTHORITY_AMBIGUOUS")

    def test_authority_wrong_type_role_run_parent_and_status_fail_closed(self) -> None:
        variants = (
            "logical_type",
            "creator_role",
            "run_id",
            "parent_artifacts",
            "authority_status",
            "record_status",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                harness = AuthorityHarness(Path(directory))
                authority, _source_records = _derive_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    r_check=RCheck.R0,
                    evaluator_class=EvaluatorClass.E0,
                    source_artifact_sha256s=(),
                )
                payload = authority.to_dict()
                logical_type = R_CHECK_AUTHORITY_LOGICAL_TYPE
                creator_role = Role.ORCHESTRATOR
                parent_artifacts: tuple[str, ...] = ()
                validation_result = "PASS"
                frozen = True
                if variant == "logical_type":
                    logical_type = "r_check_authority_wrong"
                elif variant == "creator_role":
                    creator_role = Role.PROTOCOL_DESIGNER
                elif variant == "run_id":
                    payload["run_id"] = "run-spliced"
                elif variant == "parent_artifacts":
                    parent_artifacts = (harness.rubric.sha256,)
                elif variant == "authority_status":
                    payload["status"] = AuthorityStatus.PASS.value
                elif variant == "record_status":
                    validation_result = "PENDING"
                    frozen = False
                record = harness.registry.put_json(
                    payload,
                    logical_type=logical_type,
                    origin=(
                        "fresh registry-and-ledger R-check authority for "
                        "run-authority:R0:E0"
                    ),
                    creator_role=creator_role,
                    creation_command=(
                        "scientist-one",
                        "resolve-r-check-authority",
                    ),
                    parent_artifacts=parent_artifacts,
                    schema_version=R_CHECK_AUTHORITY_SCHEMA_VERSION,
                    mime_type="application/json",
                    validation_result=validation_result,
                    frozen=frozen,
                )
                with self.assertRaises(ValueError):
                    resolve_r_check_authority(
                        harness.registry,
                        harness.ledger,
                        authority_artifact_sha256=record.sha256,
                        run_id=harness.run_id,
                    )

    def test_bundle_wrong_role_and_parent_fail_closed(self) -> None:
        for variant in (
            "creator_role",
            "parent_artifacts",
            "category_status",
        ):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                harness = AuthorityHarness(Path(directory))
                authorities = harness.authorities()
                bundle, authority_records = _derive_r_check_authority_bundle(
                    harness.registry,
                    harness.ledger,
                    run_id=harness.run_id,
                    authority_artifact_sha256s=(
                        record.sha256 for record in authorities
                    ),
                    rubric_artifact_sha256=harness.rubric.sha256,
                )
                creator_role = Role.ORCHESTRATOR
                parents = (
                    harness.rubric.sha256,
                    *(record.sha256 for record in authority_records),
                )
                if variant == "creator_role":
                    creator_role = Role.SCIENTIFIC_REVIEWER
                elif variant == "parent_artifacts":
                    parents = tuple(reversed(parents))
                payload = bundle.to_dict()
                if variant == "category_status":
                    first_category = next(
                        iter(payload["category_scoring"]["statuses"])
                    )
                    payload["category_scoring"]["statuses"][first_category] = "PASS"
                record = harness.registry.put_json(
                    payload,
                    logical_type=R_CHECK_AUTHORITY_BUNDLE_LOGICAL_TYPE,
                    origin=f"exact R0-R7 authority bundle for {harness.run_id}",
                    creator_role=creator_role,
                    creation_command=(
                        "scientist-one",
                        "bundle-r-check-authorities",
                    ),
                    parent_artifacts=parents,
                    schema_version=R_CHECK_AUTHORITY_BUNDLE_SCHEMA_VERSION,
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                )
                with self.assertRaises(ValueError):
                    resolve_r_check_authority_bundle(
                        harness.registry,
                        harness.ledger,
                        bundle_artifact_sha256=record.sha256,
                        run_id=harness.run_id,
                    )

    def test_authority_rejects_stale_and_spliced_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            authority = register_r_check_authority(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                r_check=RCheck.R0,
                evaluator_class=EvaluatorClass.E0,
            )
            harness.ledger.record(
                run_id=harness.run_id,
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.AUDIT,
                requested_state_after=MacroState.AUDIT,
                artifact_hashes=(),
                code_version="test-code-version",
                configuration_hash=CONFIGURATION_HASH,
                reason="ordinary append preserves source-free authority prefix",
                event_id="later-checkpoint",
                timestamp="2026-08-29T12:00:01Z",
                event_type="CHECKPOINT",
                metadata={
                    "artifact_types": [],
                    "artifact_record_hashes": [],
                },
            )
            resolved = resolve_r_check_authority(
                harness.registry,
                harness.ledger,
                authority_artifact_sha256=authority.sha256,
                run_id=harness.run_id,
            )
            self.assertEqual(resolved.status, AuthorityStatus.UNTESTED)

            harness.ledger.append_correction(
                "rubric-frozen",
                actor_role=Role.ORCHESTRATOR,
                reason="supersede an event inside the bound ledger prefix",
                corrected_fields={"reason": "corrected rubric admission"},
                event_id="correct-rubric-admission",
                timestamp="2026-08-29T12:00:02Z",
            )
            with self.assertRaisesRegex(ValueError, "ledger prefix is stale"):
                resolve_r_check_authority(
                    harness.registry,
                    harness.ledger,
                    authority_artifact_sha256=authority.sha256,
                    run_id=harness.run_id,
                )

        with tempfile.TemporaryDirectory() as directory:
            harness = AuthorityHarness(Path(directory))
            authority = register_r_check_authority(
                harness.registry,
                harness.ledger,
                run_id=harness.run_id,
                r_check=RCheck.R0,
                evaluator_class=EvaluatorClass.E0,
            )
            spliced = EventLedger(
                harness.root,
                f"runs/{harness.run_id}/spliced.jsonl",
            )
            harness._admit(
                spliced,
                harness.rubric,
                event_id="rubric-spliced",
                timestamp="2026-08-29T12:00:00Z",
                reason="same artifact on a different ledger history",
            )
            with self.assertRaises(ValueError):
                resolve_r_check_authority(
                    harness.registry,
                    spliced,
                    authority_artifact_sha256=authority.sha256,
                    run_id=harness.run_id,
                )


if __name__ == "__main__":
    unittest.main()
