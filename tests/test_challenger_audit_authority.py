from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import scientist_one.gates as gates_module
from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import ValidationError
from scientist_one.gates import (
    CHALLENGER_ATTACK_RESOLVER_CONTRACTS,
    SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
    SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
    SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS,
    ChallengeCategory,
    ChallengeSeverity,
    ChallengeStatus,
    ChallengerExecutionStatus,
    JudgmentSubjectKind,
    SemanticChallengeAuditAuthority,
    SemanticChallengeAuditCompletion,
    SemanticChallengeAuditDecision,
    SemanticChallengeAuditStatus,
    SemanticChallengeFindingProjection,
    SemanticChallengerAuditSlot,
    SemanticJudgmentReceipt,
    challenger_semantic_procedure_instructions,
    parse_semantic_challenge_audit_decision,
    register_semantic_challenge_audit_authority,
    require_semantic_challenge_audit_authority,
    reserve_semantic_challenger_audit_slot,
    semantic_challenge_findings_for_audit,
    semantic_challenger_audit_instructions,
    semantic_challenger_audit_output_schema,
)
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
from scientist_one.providers import validate_structured_output_schema
from scientist_one.research_state import (
    Challenge,
    ChallengeResolution as StateChallengeResolution,
    ChallengeSeverity as StateChallengeSeverity,
    Claim,
    ClaimReview,
    Critique,
    ObjectLink,
    ObjectReference,
    RecordStatus,
    ResearchStateRepository,
    Result,
    VerificationStatus,
    VenueAssessment,
)
from scientist_one.roles import Role
from scientist_one.security import canonical_json_bytes


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _claim_projection_fixture() -> Claim:
    """In-memory shape only: neither a published Claim nor scientific authority."""

    return Claim(
        object_id="claim-a",
        producer=Role.SCIENTIFIC_REVIEWER,
        status=RecordStatus.VERIFIED,
        claim_text="Non-evidentiary projection boundary fixture.",
        scope="In-memory DTO checks only.",
        verification_method="Non-evidentiary fixture.",
        verification_status=VerificationStatus.VERIFIED,
        source_artifact_ids=(_digest("graph"),),
        review_history=(ClaimReview(
            reviewer=Role.CLAIM_VERIFIER,
            timestamp="2026-09-05T00:00:00Z",
            verification_status=VerificationStatus.VERIFIED,
            reason="In-memory fixture; no production owner invoked.",
        ),),
        code_version="semantic-audit-test",
    )


class SemanticChallengerAuditAuthorityTests(unittest.TestCase):
    def test_snapshot_admission_precedes_slot_with_exact_count_index_semantics(self) -> None:
        for count, index in ((1, 1), (3, 3), (3, 4)):
            gates_module._require_semantic_audit_snapshot_before_slot(count, index)
        for count, index in ((3, 2), (1, 0), (0, 0), (True, 1), (1, True)):
            with self.subTest(count=count, index=index), self.assertRaises(ValidationError):
                gates_module._require_semantic_audit_snapshot_before_slot(count, index)

    def test_slot_replay_requires_source_owned_event_id_and_prior_context(self) -> None:
        slot = self._slot(scientific_source_qualified=False)
        subject = gates_module._semantic_challenger_audit_subject_binding(**{
            name: getattr(slot, name) for name in (
                "run_id", "category", "research_state_snapshot_artifact_hash",
                "research_state_snapshot_artifact_record_hash",
                "claim_graph_artifact_hash", "claim_graph_artifact_record_hash",
                "central_claim_ids", "evidence_artifact_hashes",
                "evidence_artifact_record_hashes", "result_artifact_hashes",
                "result_artifact_record_hashes", "reproducibility_package_artifact_hash",
                "scientific_source_qualified",
            )
        })
        binding = gates_module._semantic_challenger_audit_slot_binding(
            slot_id=slot.slot_id, subject_sha256=slot.subject_sha256,
            assessment_id=slot.assessment_id, provider_invocation_id=slot.provider_invocation_id,
            contract=gates_module._semantic_challenger_audit_contract(slot.category),
            subject_binding=subject,
        )
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            before_registry = registry.verify_all(raise_on_error=True)
            before_ledger = ledger.validate(raise_on_error=True)
            previous = before_ledger.events[-1]
            base = dict(
                run_id=slot.run_id, actor_role=Role.ADVERSARIAL_REVIEWER,
                state_before=previous.state_after, requested_state_after=previous.state_after,
                artifact_hashes=slot.scoped_artifact_hashes,
                code_version=previous.code_version, configuration_hash=previous.configuration_hash,
                dataset_identifiers=previous.dataset_identifiers, random_seeds=previous.random_seeds,
                evaluator_outputs=(), reason="reserved one prospective semantic Challenger audit",
                prior_event_hash=previous.event_hash, event_id=slot.event_id,
                event_type="CHECKPOINT", metadata={"semantic_challenger_audit_slot": binding},
            )
            for field, replacement in (
                (None, None), ("event_id", "another-slot-event"),
                ("code_version", "another-code"), ("configuration_hash", _digest("other-config")),
                ("dataset_identifiers", ("another-dataset",)), ("random_seeds", (99,)),
            ):
                options = dict(base)
                if field is not None:
                    options[field] = replacement
                event = LedgerEvent.create(**options)
                selected = replace(slot, event_id=event.event_id, event_hash=event.event_hash, event_index=1)
                with self.subTest(field=field):
                    if field is None:
                        gates_module._validate_semantic_challenger_audit_slot_event(
                            event, 1, (previous, event), slot=selected,
                        )
                    else:
                        with self.assertRaises(ValidationError):
                            gates_module._validate_semantic_challenger_audit_slot_event(
                                event, 1, (previous, event), slot=selected,
                            )
            self.assertEqual(registry.verify_all(raise_on_error=True), before_registry)
            self.assertEqual(ledger.validate(raise_on_error=True), before_ledger)

    def test_publication_preflight_rejects_every_immutable_metadata_collision(self) -> None:
        # These are ordinary diagnostic JSON records, never signed audits or
        # valid authority payloads. Exercise exact metadata admission only.
        changes = (
            ("logical_type", "ordinary_diagnostic"), ("schema_version", "other/v1"),
            ("mime_type", "text/plain"), ("origin", "another origin"),
            ("creator_role", Role.ORCHESTRATOR),
            ("creation_command", ("scientist-one", "another-command")),
            ("parent_artifacts", ()), ("validation_result", "FAIL"), ("frozen", False),
        )
        for field, replacement in changes:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                registry, ledger = self._runtime(Path(directory))
                parent = registry.list_records()[0]
                expected = dict(
                    logical_type=SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
                    schema_version=SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
                    mime_type="application/json", origin=gates_module._SEMANTIC_CHALLENGE_AUDIT_ORIGIN,
                    creator_role=Role.ADVERSARIAL_REVIEWER,
                    creation_command=gates_module._SEMANTIC_CHALLENGE_AUDIT_COMMAND,
                    parent_artifacts=(parent.sha256,), validation_result="PASS", frozen=True,
                )
                options = dict(expected)
                options[field] = replacement
                if field == "validation_result":
                    options["frozen"] = False
                record = registry.put_json({"diagnostic_only": True}, **options)
                before_registry = registry.verify_all(raise_on_error=True)
                before_ledger = ledger.validate(raise_on_error=True)
                with self.assertRaisesRegex(ValidationError, "conflicting immutable metadata"):
                    gates_module._preflight_semantic_challenge_audit_artifact(
                        registry, before_registry.records, expected_sha256=record.sha256,
                        parents=(parent.sha256,),
                    )
                self.assertEqual(registry.verify_all(raise_on_error=True), before_registry)
                self.assertEqual(ledger.validate(raise_on_error=True), before_ledger)

    def _slot(
        self,
        *,
        category: ChallengeCategory = ChallengeCategory.STATISTICS,
        scientific_source_qualified: bool = True,
    ) -> SemanticChallengerAuditSlot:
        contract = next(
            value
            for value in SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS.values()
            if value.category is category
        )
        snapshot_hash = _digest("snapshot")
        package_hash = (
            _digest("package")
            if category is ChallengeCategory.REPRODUCTION
            else None
        )
        evidence_hashes = tuple(
            sorted(
                (
                    snapshot_hash,
                    *((package_hash,) if package_hash is not None else ()),
                )
            )
        )
        evidence_records = tuple(
            _digest(f"record-{digest}") for digest in evidence_hashes
        )
        identity = gates_module._semantic_challenger_audit_slot_identity_binding(
            run_id="audit-run",
            category=category,
        )
        subject_sha256 = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        return SemanticChallengerAuditSlot(
            slot_id=f"semantic-audit-{subject_sha256[:24]}",
            subject_sha256=subject_sha256,
            assessment_id="assessment-1",
            run_id="audit-run",
            category=category,
            research_state_snapshot_artifact_hash=snapshot_hash,
            research_state_snapshot_artifact_record_hash=_digest(
                "snapshot-record"
            ),
            claim_graph_artifact_hash=_digest("graph"),
            claim_graph_artifact_record_hash=_digest("graph-record"),
            central_claim_ids=("claim-a", "claim-b"),
            evidence_artifact_hashes=evidence_hashes,
            evidence_artifact_record_hashes=evidence_records,
            result_artifact_hashes=(_digest("result"),),
            result_artifact_record_hashes=(_digest("result-record"),),
            reproducibility_package_artifact_hash=package_hash,
            scientific_source_qualified=scientific_source_qualified,
            provider_invocation_id="invocation-1",
            procedure_id=contract.procedure_id,
            procedure_version=contract.procedure_version,
            prompt_template_hash=str(contract.prompt_template_hash),
            ledger_path="runs/audit-run/events.jsonl",
            event_id=f"semantic-audit-slot-{subject_sha256[:24]}",
            event_hash=_digest("slot-event"),
            event_index=3,
        )

    def _receipt(
        self,
        slot: SemanticChallengerAuditSlot,
        decision: SemanticChallengeAuditDecision,
        *,
        rationale: str | None = None,
    ) -> SemanticJudgmentReceipt:
        custody = tuple(_digest(f"custody-{index}") for index in range(7))
        return SemanticJudgmentReceipt(
            judgment_id="judgment-1",
            subject_kind=JudgmentSubjectKind.CHALLENGER_CATEGORY,
            subject_id=slot.slot_id,
            outcome=ChallengerExecutionStatus.EXECUTED.value,
            evidence_hashes=slot.evidence_artifact_hashes,
            context_hashes=(
                slot.claim_graph_artifact_hash,
                *slot.result_artifact_hashes,
            ),
            instructions_artifact_hash=custody[0],
            input_artifact_hash=custody[1],
            output_schema_artifact_hash=custody[2],
            invocation_artifact_hash=custody[3],
            request_intent_artifact_hash=custody[4],
            provider_response_artifact_hash=custody[5],
            model_output_artifact_hash=custody[6],
            invocation_id=slot.provider_invocation_id,
            provider_id="provider-1",
            provider_version="1.0",
            model="model-1",
            model_version="1.0",
            prompt_template_id=slot.procedure_id,
            prompt_template_version=slot.procedure_version,
            prompt_template_hash=slot.prompt_template_hash,
            structured_output_sha256=_digest("structured-output"),
            reviewer_id="reviewer-1",
            reviewer_role=Role.SCIENTIFIC_REVIEWER,
            governing_rule="Retain the complete prospective finding audit.",
            rationale=rationale or decision.canonical_rationale,
        )

    def _runtime(self, root: Path) -> tuple[ArtifactRegistry, EventLedger]:
        registry = ArtifactRegistry(root, "runs/audit-run/registry")
        ledger = EventLedger(root, "runs/audit-run/events.jsonl")
        seed = registry.put_json(
            {"fixture": "seed"},
            logical_type="semantic_audit_test_fixture",
            origin="non-evidentiary semantic audit unit fixture",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "test-semantic-audit"),
            parent_artifacts=(),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        ledger.append(
            LedgerEvent.create(
                run_id="audit-run",
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.PREFLIGHT,
                requested_state_after=MacroState.PREFLIGHT,
                artifact_hashes=(seed.sha256,),
                code_version="semantic-audit-test",
                configuration_hash=_digest("configuration"),
                evaluator_outputs=(),
                reason="initialize non-evidentiary semantic audit fixture",
                prior_event_hash=None,
                event_type="CHECKPOINT",
            )
        )
        return registry, ledger

    def _append_canonical_fixture(
        self,
        registry: ArtifactRegistry,
        ledger: EventLedger,
        record: Challenge | Claim | Critique | Result | VenueAssessment,
        *,
        registry_parent_artifacts: tuple[str, ...] = (),
    ):
        artifact = registry.put_bytes(
            record.canonical_bytes(),
            logical_type=record.logical_type,
            origin=(
                f"research-state:{record.object_type}:"
                f"{record.object_id}:r{record.revision}"
            ),
            creator_role=record.producer,
            creation_command=("scientist-one", "test-semantic-audit"),
            parent_artifacts=registry_parent_artifacts,
            schema_version=record.schema_version,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=record.created_at,
        )
        previous = ledger.events()[-1]
        supersedes_event_id = None
        if record.revision > 1:
            supersedes = tuple(
                event
                for event in ledger.events()
                if event.metadata.get("object_type") == record.object_type
                and event.metadata.get("object_id") == record.object_id
                and event.metadata.get("content_hash")
                == record.supersedes_content_hash
            )
            if len(supersedes) != 1:
                raise AssertionError("revision fixture lacks its prior canonical event")
            supersedes_event_id = supersedes[0].event_id
        event = ledger.append(
            LedgerEvent.create(
                run_id="audit-run",
                actor_role=record.producer,
                state_before=previous.state_after,
                requested_state_after=previous.state_after,
                artifact_hashes=(artifact.sha256,),
                code_version="semantic-audit-test",
                configuration_hash=_digest("configuration"),
                dataset_identifiers=previous.dataset_identifiers,
                random_seeds=previous.random_seeds,
                evaluator_outputs=(),
                reason="materialize non-evidentiary canonical boundary fixture",
                prior_event_hash=previous.event_hash,
                event_id=f"rs-{artifact.sha256[:48]}",
                timestamp=record.created_at,
                event_type=(
                    "CHECKPOINT" if record.revision == 1 else "CORRECTION"
                ),
                supersedes_event_id=supersedes_event_id,
                metadata={
                    "research_state_operation": (
                        "MATERIALIZED"
                        if record.revision == 1
                        else "SUPERSEDED"
                    ),
                    "object_type": record.object_type,
                    "object_id": record.object_id,
                    "revision": record.revision,
                    "content_hash": record.content_hash,
                    "artifact_hash": artifact.sha256,
                    "schema_version": record.schema_version,
                    "supersedes_content_hash": record.supersedes_content_hash,
                },
            )
        )
        return artifact, event

    def _bound_state_fixture(
        self,
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        ledger_event_count: int,
        projection_objects: tuple[Claim | VenueAssessment, ...] = (),
    ) -> SimpleNamespace:
        events = ledger.events()
        seed = next(
            record
            for record in registry.list_records()
            if record.logical_type == "semantic_audit_test_fixture"
        )
        slot = self._slot()
        return SimpleNamespace(
            run_id="audit-run",
            snapshot_artifact_sha256=slot.research_state_snapshot_artifact_hash,
            snapshot_artifact_record_hash=(
                slot.research_state_snapshot_artifact_record_hash
            ),
            ledger_head_hash=events[ledger_event_count - 1].event_hash,
            ledger_event_count=ledger_event_count,
            code_version="semantic-audit-test",
            configuration_hash=_digest("configuration"),
            entries=(
                SimpleNamespace(
                    artifact_sha256=seed.sha256,
                    materialization_event_index=0,
                    research_object=SimpleNamespace(
                        object_type="Question",
                        object_id="fixture-question",
                    ),
                ),
                *(SimpleNamespace(
                    research_object=item,
                    artifact_sha256=hashlib.sha256(item.canonical_bytes()).hexdigest(),
                    materialization_event_index=next(
                        index for index, event in enumerate(events)
                        if event.metadata.get("content_hash") == item.content_hash
                    ),
                ) for item in projection_objects),
            ),
        )

    def test_v1_contract_bytes_remain_separate_from_v2_finding_audits(self) -> None:
        self.assertEqual(len(CHALLENGER_ATTACK_RESOLVER_CONTRACTS), 14)
        self.assertEqual(len(SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS), 12)
        self.assertTrue(
            set(CHALLENGER_ATTACK_RESOLVER_CONTRACTS).isdisjoint(
                SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS
            )
        )
        self.assertEqual(
            hashlib.sha256(
                challenger_semantic_procedure_instructions(
                    ChallengeCategory.STATISTICS
                ).encode("utf-8")
            ).hexdigest(),
            "220b70dba15d7ff127fa14b746c404e8f314e5668e4f2bd676fe1eb6b6c897af",
        )
        v2 = next(
            value
            for value in SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS.values()
            if value.category is ChallengeCategory.STATISTICS
        )
        self.assertEqual(v2.procedure_version, "2.0")
        self.assertEqual(
            v2.prompt_template_hash,
            hashlib.sha256(
                semantic_challenger_audit_instructions(
                    ChallengeCategory.STATISTICS
                ).encode("utf-8")
            ).hexdigest(),
        )
        with self.assertRaises(TypeError):
            SEMANTIC_CHALLENGE_AUDIT_RESOLVER_CONTRACTS[v2.key] = v2  # type: ignore[index]

    def test_common_round_key_excludes_category_specific_package_scope(self) -> None:
        ordinary = self._slot(category=ChallengeCategory.STATISTICS)
        reproduction = self._slot(
            category=ChallengeCategory.REPRODUCTION,
            scientific_source_qualified=False,
        )
        self.assertNotEqual(
            ordinary.evidence_artifact_hashes,
            reproduction.evidence_artifact_hashes,
        )
        self.assertNotEqual(
            ordinary.reproducibility_package_artifact_hash,
            reproduction.reproducibility_package_artifact_hash,
        )
        self.assertNotEqual(
            ordinary.scientific_source_qualified,
            reproduction.scientific_source_qualified,
        )
        self.assertEqual(
            gates_module._semantic_challenger_audit_round_key(ordinary),
            gates_module._semantic_challenger_audit_round_key(reproduction),
        )

    def test_status_is_derived_from_completion_and_every_adverse_finding(self) -> None:
        slot = self._slot()
        minor = SemanticChallengeFindingProjection(
            challenge_id="finding-minor",
            severity=ChallengeSeverity.MINOR,
            target_claim_ids=("claim-a",),
            evidence_hashes=(slot.result_artifact_hashes[0],),
            attack="A bounded residual limitation remains.",
        )
        major = SemanticChallengeFindingProjection(
            challenge_id="finding-major",
            severity=ChallengeSeverity.MAJOR,
            target_claim_ids=("claim-b",),
            evidence_hashes=(slot.evidence_artifact_hashes[0],),
            attack="A material validity failure remains.",
        )
        complete = SemanticChallengeAuditDecision(
            slot_id=slot.slot_id,
            category=slot.category,
            completion=SemanticChallengeAuditCompletion.COMPLETE,
            findings=(minor,),
            residual_risk_summary="Minor residual risk is retained.",
        )
        self.assertEqual(
            complete.status,
            SemanticChallengeAuditStatus.PASS,
        )
        self.assertEqual(
            SemanticChallengeAuditDecision(
                slot_id=slot.slot_id,
                category=slot.category,
                completion=SemanticChallengeAuditCompletion.COMPLETE,
                findings=(major,),
                residual_risk_summary="Material risk is retained.",
            ).status,
            SemanticChallengeAuditStatus.FAIL,
        )
        self.assertEqual(
            SemanticChallengeAuditDecision(
                slot_id=slot.slot_id,
                category=slot.category,
                completion=SemanticChallengeAuditCompletion.INDETERMINATE,
                findings=(minor,),
                residual_risk_summary="The audit could not establish completeness.",
            ).status,
            SemanticChallengeAuditStatus.UNTESTED,
        )
        self.assertEqual(
            gates_module._semantic_challenge_audit_status(
                SimpleNamespace(
                    decision=complete,
                    slot=self._slot(scientific_source_qualified=False),
                )
            ),
            SemanticChallengeAuditStatus.UNTESTED,
        )

    def test_canonical_rationale_projects_all_findings_one_to_one(self) -> None:
        slot = self._slot()
        projection = SemanticChallengeFindingProjection(
            challenge_id="finding-1",
            severity=ChallengeSeverity.BLOCKING,
            target_claim_ids=("claim-a", "claim-b"),
            evidence_hashes=(slot.result_artifact_hashes[0],),
            attack="The retained result cannot support the target claims.",
        )
        decision = SemanticChallengeAuditDecision(
            slot_id=slot.slot_id,
            category=slot.category,
            completion=SemanticChallengeAuditCompletion.COMPLETE,
            findings=(projection,),
            residual_risk_summary="The blocking risk remains unresolved.",
        )
        parsed = parse_semantic_challenge_audit_decision(
            self._receipt(slot, decision),
            slot=slot,
        )
        self.assertEqual(parsed, decision)
        findings = semantic_challenge_findings_for_audit(slot, parsed)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].challenge_id, projection.challenge_id)
        self.assertEqual(findings[0].severity, ChallengeSeverity.BLOCKING)
        self.assertEqual(findings[0].status, ChallengeStatus.UNRESOLVED)
        self.assertFalse(findings[0].deterministic)

    def test_noncanonical_or_out_of_scope_rationale_is_rejected(self) -> None:
        slot = self._slot()
        decision = SemanticChallengeAuditDecision(
            slot_id=slot.slot_id,
            category=slot.category,
            completion=SemanticChallengeAuditCompletion.COMPLETE,
            findings=(),
            residual_risk_summary="No material finding was identified.",
        )
        with self.assertRaisesRegex(ValidationError, "not canonical JSON"):
            parse_semantic_challenge_audit_decision(
                self._receipt(
                    slot,
                    decision,
                    rationale=f" {decision.canonical_rationale}",
                ),
                slot=slot,
            )
        out_of_scope = SemanticChallengeAuditDecision(
            slot_id=slot.slot_id,
            category=slot.category,
            completion=SemanticChallengeAuditCompletion.COMPLETE,
            findings=(
                SemanticChallengeFindingProjection(
                    challenge_id="finding-foreign",
                    severity=ChallengeSeverity.MAJOR,
                    target_claim_ids=("claim-foreign",),
                    evidence_hashes=(slot.result_artifact_hashes[0],),
                    attack="This finding targets an unrelated claim.",
                ),
            ),
            residual_risk_summary="An out-of-scope finding is invalid.",
        )
        with self.assertRaisesRegex(ValidationError, "frozen slot scope"):
            parse_semantic_challenge_audit_decision(
                self._receipt(slot, out_of_scope),
                slot=slot,
            )

    def test_provider_schema_is_closed_and_executes_without_claiming_pass(self) -> None:
        schema = semantic_challenger_audit_output_schema()
        validate_structured_output_schema(schema)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["outcome"]["enum"],
            [ChallengerExecutionStatus.EXECUTED.value],
        )
        self.assertNotIn("status", schema["properties"])

    def test_authority_round_trip_retains_exact_source_and_event_bindings(self) -> None:
        slot = self._slot()
        judgment_hash = _digest("authority-judgment")
        execution_hash = _digest("authority-execution")
        review_hash = _digest("authority-review")
        input_hashes = (
            *slot.scoped_artifact_hashes,
            judgment_hash,
            execution_hash,
            review_hash,
        )
        input_records = (
            *slot.scoped_artifact_record_hashes,
            _digest("authority-judgment-record"),
            _digest("authority-execution-record"),
            _digest("authority-review-record"),
        )
        authority = SemanticChallengeAuditAuthority(
            authority_id="semantic-audit-authority-1",
            assessment_id=slot.assessment_id,
            run_id=slot.run_id,
            category=slot.category,
            research_state_snapshot_artifact_hash=(
                slot.research_state_snapshot_artifact_hash
            ),
            research_state_snapshot_artifact_record_hash=(
                slot.research_state_snapshot_artifact_record_hash
            ),
            claim_graph_artifact_hash=slot.claim_graph_artifact_hash,
            claim_graph_artifact_record_hash=(
                slot.claim_graph_artifact_record_hash
            ),
            central_claim_ids=slot.central_claim_ids,
            evidence_artifact_hashes=slot.evidence_artifact_hashes,
            evidence_artifact_record_hashes=(
                slot.evidence_artifact_record_hashes
            ),
            result_artifact_hashes=slot.result_artifact_hashes,
            result_artifact_record_hashes=slot.result_artifact_record_hashes,
            reproducibility_package_artifact_hash=None,
            slot_id=slot.slot_id,
            slot_subject_sha256=slot.subject_sha256,
            slot_event_id=slot.event_id,
            slot_event_hash=slot.event_hash,
            slot_event_index=slot.event_index,
            provider_invocation_id=slot.provider_invocation_id,
            procedure_id=slot.procedure_id,
            procedure_version=slot.procedure_version,
            prompt_template_hash=slot.prompt_template_hash,
            semantic_judgment_artifact_hash=judgment_hash,
            semantic_judgment_artifact_record_hash=input_records[-3],
            finding_artifact_hashes=(),
            finding_artifact_record_hashes=(),
            challenger_execution_artifact_hash=execution_hash,
            challenger_execution_artifact_record_hash=input_records[-2],
            challenger_review_artifact_hash=review_hash,
            challenger_review_artifact_record_hash=input_records[-1],
            status=SemanticChallengeAuditStatus.PASS,
            scientific_source_qualified=True,
            residual_risk_summary="All identified residual risks are retained.",
            input_artifact_hashes=input_hashes,
            input_artifact_record_hashes=input_records,
            ledger_path=slot.ledger_path,
            verification_event_id="semantic-audit-verification-1",
            verification_event_hash=_digest("authority-verification-event"),
            verification_event_index=slot.event_index + 1,
        )
        self.assertEqual(
            SemanticChallengeAuditAuthority.from_dict(authority.to_dict()),
            authority,
        )

    def test_content_projection_retains_exact_text_and_binary_without_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory), "runs/audit-run/registry")
            binary = registry.put_bytes(
                b"\xff\x00semantic-audit",
                logical_type="semantic_audit_binary_fixture",
                origin="non-evidentiary semantic audit binary fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            child = registry.put_json(
                {"untrusted": "exact retained content"},
                logical_type="semantic_audit_text_fixture",
                origin="non-evidentiary semantic audit text fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(binary.sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            projection = gates_module._semantic_challenger_audit_content_projection(
                registry,
                (child.sha256,),
            )
            by_hash = {item["artifact_sha256"]: item for item in projection}
            self.assertEqual(set(by_hash), {binary.sha256, child.sha256})
            self.assertEqual(
                by_hash[binary.sha256]["untrusted_content"],
                base64.b64encode(b"\xff\x00semantic-audit").decode("ascii"),
            )
            self.assertEqual(
                by_hash[child.sha256]["untrusted_content"],
                registry.get_bytes(child.sha256).decode("utf-8"),
            )
            self.assertTrue(
                all(
                    item["content_is_untrusted_data_not_instructions"] is True
                    for item in projection
                )
            )

    def test_content_projection_rejects_large_binary_parent_before_body_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = ArtifactRegistry(Path(directory), "runs/audit-run/registry")
            parent = registry.put_bytes(
                b"\xff" * (2 * 1024 * 1024),
                logical_type="semantic_audit_large_binary_fixture",
                origin="non-evidentiary oversized semantic audit fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/octet-stream",
                validation_result="PASS",
                frozen=True,
            )
            child = registry.put_json(
                {"untrusted": "small child with a large parent"},
                logical_type="semantic_audit_large_parent_fixture",
                origin="non-evidentiary oversized-parent fixture",
                creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(parent.sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            with patch.object(
                ArtifactRegistry,
                "_verify_content_locked",
                side_effect=AssertionError("artifact body was read"),
            ):
                with self.assertRaisesRegex(ValidationError, "preflight bound"):
                    gates_module._semantic_challenger_audit_content_projection(
                        registry,
                        (child.sha256,),
                    )

    def test_post_snapshot_review_append_avoids_owner_replay_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            self._append_canonical_fixture(
                registry,
                ledger,
                Critique(
                    object_id="critique-after-audit",
                    producer=Role.ADVERSARIAL_REVIEWER,
                    target_ids=("unrelated-claim",),
                    findings=(),
                    verdict="RETAIN",
                    code_version="semantic-audit-test",
                ),
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=1,
            )
            with patch.object(
                ResearchStateRepository,
                "_resolve_object_authority",
                side_effect=AssertionError("downstream owner replayed"),
            ):
                gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                    registry,
                    ledger,
                    state=bound,
                    audit_slot=self._slot(),
                )

    def test_peer_index_does_not_parse_unpublished_or_unrelated_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            malformed = registry.put_bytes(
                b"not a semantic audit payload",
                logical_type=SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
                origin="non-evidentiary unrelated malformed-source test",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(), schema_version="1.0",
                mime_type="application/json", validation_result="PASS", frozen=True,
            )
            # A different round's event is not authority for this one. This test
            # asserts selection only; it never creates a valid audit publication.
            previous = ledger.events()[-1]
            ledger.append(LedgerEvent.create(
                run_id="audit-run", actor_role=Role.ORCHESTRATOR,
                state_before=previous.state_after,
                requested_state_after=previous.state_after,
                artifact_hashes=(malformed.sha256,),
                code_version=previous.code_version,
                configuration_hash=previous.configuration_hash,
                evaluator_outputs=(), reason="unrelated event selection fixture",
                prior_event_hash=previous.event_hash, event_type="CHECKPOINT",
                metadata={"semantic_challenge_audit_authority_publication": {
                    "assessment_id": "another-assessment", "run_id": "audit-run",
                }},
            ))
            with patch.object(
                gates_module, "_load_gate_artifact",
                side_effect=AssertionError("unrelated artifact body was parsed"),
            ):
                self.assertEqual(gates_module._semantic_challenger_audit_published_peers(
                    registry, ledger, ledger.validate(raise_on_error=True),
                    state=self._bound_state_fixture(registry, ledger, ledger_event_count=1),
                    audit_slot=self._slot(),
                ), ())

    def test_related_venue_append_has_no_same_round_exemption(self) -> None:
        # Canonical/event shape only. No venue or scientific owner is issued.
        for fixture_shaped in (False, True):
            with self.subTest(fixture_shaped=fixture_shaped), tempfile.TemporaryDirectory() as directory:
                registry, ledger = self._runtime(Path(directory))
                venue = VenueAssessment(
                    object_id="venue-assessment-ml-ai" if fixture_shaped else "later-final-venue",
                    producer=Role.SCIENTIFIC_REVIEWER, code_version="semantic-audit-test",
                    venue="No submission target: synthetic integration fixture" if fixture_shaped else "Candidate venue",
                    profile="ml-ai", evidence_ids=("claim-a",),
                )
                self._append_canonical_fixture(registry, ledger, venue)
                state = self._bound_state_fixture(registry, ledger, ledger_event_count=1)
                with patch.object(
                    gates_module, "_semantic_challenger_audit_published_peers",
                    side_effect=AssertionError("unsupported venue must not start recursive replay"),
                ), self.assertRaisesRegex(ValidationError, "newly related venue"):
                    gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                        registry, ledger, state=state, audit_slot=self._slot(),
                    )

    def test_disjoint_later_venue_remains_drift_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            venue = VenueAssessment(
                object_id="disjoint-venue", producer=Role.SCIENTIFIC_REVIEWER,
                code_version="semantic-audit-test", venue="Unrelated target",
                profile="unrelated-profile", evidence_ids=("unrelated-claim",),
            )
            self._append_canonical_fixture(registry, ledger, venue)
            gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                registry, ledger,
                state=self._bound_state_fixture(registry, ledger, ledger_event_count=1),
                audit_slot=self._slot(),
            )

    def test_prebound_related_venue_is_not_reclassified_as_a_new_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            venue = VenueAssessment(
                object_id="already-bound-venue", producer=Role.SCIENTIFIC_REVIEWER,
                code_version="semantic-audit-test", venue="Bound fixture target",
                profile="ml-ai", evidence_ids=("claim-a",),
            )
            self._append_canonical_fixture(registry, ledger, venue)
            gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                registry, ledger,
                state=self._bound_state_fixture(
                    registry, ledger, ledger_event_count=2, projection_objects=(venue,),
                ),
                audit_slot=self._slot(),
            )

    def test_review_source_ancestry_survives_substituted_display_targets(self) -> None:
        graph = _digest("graph")
        finding = _digest("ancestry-finding")
        terminal = _digest("ancestry-terminal")
        unrelated = _digest("unrelated-source")
        records = {
            finding: SimpleNamespace(parent_artifacts=(graph,)),
            terminal: SimpleNamespace(parent_artifacts=(finding,)),
            unrelated: SimpleNamespace(parent_artifacts=(_digest("other-graph"),)),
        }
        review = SimpleNamespace(
            target_ids=("caller-relabeled-target",),
            authority_artifact_hashes=(terminal,),
        )
        closure = gates_module._semantic_challenger_audit_review_ancestry(review, records)
        self.assertEqual(closure, frozenset((terminal, finding, graph)))
        self.assertNotIn(unrelated, closure)

    def test_new_related_blocking_challenge_without_round_publication_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            finding_hash = _digest("unpublished-related-finding")
            self._append_canonical_fixture(
                registry,
                ledger,
                Challenge(
                    object_id="unpublished-related-finding",
                    producer=Role.ADVERSARIAL_REVIEWER,
                    target_claim_ids=("claim-a",),
                    severity=StateChallengeSeverity.BLOCKING,
                    finding="A new blocking observation was not in the audit round.",
                    resolution_status=StateChallengeResolution.UNRESOLVED,
                    evidence_ids=(_digest("result"),),
                    parents=(
                        ObjectReference(
                            object_type="Claim",
                            object_id="claim-a",
                            content_hash=_digest("claim-a-content"),
                            relation="challenges",
                            evaluated=True,
                        ),
                    ),
                    authority_artifact_hashes=(finding_hash,),
                    code_version="semantic-audit-test",
                ),
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=1,
            )
            with self.assertRaisesRegex(ValidationError, "scientific core changed"):
                gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                    registry,
                    ledger,
                    state=bound,
                    audit_slot=self._slot(),
                )

    def test_same_round_sibling_category_finding_projection_is_allowed(self) -> None:
        self._exercise_sibling_projection_registry_parents("exact")

    def test_sibling_projection_rejects_inexact_canonical_registry_dependencies(self) -> None:
        for mode in ("missing", "extra", "substituted", "reordered"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValidationError, "registry parents"):
                self._exercise_sibling_projection_registry_parents(mode)

    def _exercise_sibling_projection_registry_parents(self, mode: str) -> None:
        # Real registry descriptors and event chronology, but the verified
        # Claim/peer remain explicit mechanical stand-ins, not scientific grants.
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            graph = registry.put_json(
                {"non_evidentiary_graph_standin": True}, logical_type="semantic_audit_test_graph",
                origin="mechanical canonical-parent probe", creator_role=Role.EVIDENCE_CURATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                schema_version="1.0", mime_type="application/json", validation_result="PASS", frozen=True,
            )
            claim = replace(_claim_projection_fixture(), content_hash=None, source_artifact_ids=(graph.sha256,))
            claim_artifact, _ = self._append_canonical_fixture(
                registry, ledger, claim, registry_parent_artifacts=(graph.sha256,),
            )
            finding = gates_module.ChallengeFinding(
                challenge_id="same-round-sibling-finding",
                category=ChallengeCategory.SEED_DEPENDENCE,
                severity=ChallengeSeverity.BLOCKING,
                status=ChallengeStatus.UNRESOLVED,
                target_claim_ids=("claim-a",),
                claim_graph_artifact_hash=graph.sha256,
                evidence_hashes=(next(
                    record.sha256 for record in registry.list_records()
                    if record.logical_type == "semantic_audit_test_fixture"
                ),),
                attack="A retained sibling-category blocking finding.",
                deterministic=False,
            )
            finding_artifact = registry.put_json(
                finding.to_dict(), logical_type=gates_module.CHALLENGE_FINDING_LOGICAL_TYPE,
                origin="non-evidentiary finding descriptor probe", creator_role=Role.ADVERSARIAL_REVIEWER,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(graph.sha256, *finding.evidence_hashes),
                schema_version="1.0", mime_type="application/json", validation_result="PASS", frozen=True,
            )
            finding_hash = finding_artifact.sha256
            parents = tuple(sorted((claim_artifact.sha256, finding_hash)))
            if mode == "missing":
                parents = ()
            elif mode == "extra":
                parents = tuple(sorted((*parents, graph.sha256)))
            elif mode == "substituted":
                parents = tuple(sorted((finding_hash, graph.sha256)))
            elif mode == "reordered":
                parents = tuple(reversed(parents))
            self._append_canonical_fixture(
                registry,
                ledger,
                gates_module._semantic_challenger_audit_challenge_projection(
                    finding,
                    finding_artifact_hash=finding_hash,
                    accepted_objects={("Claim", claim.object_id): claim},
                    created_at="2026-09-05T00:00:00Z",
                    code_version="semantic-audit-test",
                ),
                registry_parent_artifacts=parents,
            )
            peer = SimpleNamespace(
                record=SimpleNamespace(sha256=_digest("sibling-audit-authority")),
                authority=SimpleNamespace(
                    category=ChallengeCategory.SEED_DEPENDENCE,
                    finding_artifact_hashes=(finding_hash,),
                ),
                findings=(finding,),
                publication_event_index=0,
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=2,
                projection_objects=(claim,),
            )
            with (
                patch.object(
                    gates_module,
                    "_semantic_challenger_audit_published_peers",
                    return_value=(peer,),
                ),
                patch.object(
                    gates_module,
                    "_semantic_challenger_audit_round_soundness",
                    return_value=None,
                ),
                patch.object(
                    ResearchStateRepository,
                    "_resolve_object_authority",
                    side_effect=AssertionError("downstream owner replayed"),
                ),
            ):
                gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                    registry,
                    ledger,
                    state=bound,
                    audit_slot=replace(
                        self._slot(), claim_graph_artifact_hash=graph.sha256,
                        claim_graph_artifact_record_hash=graph.record_hash,
                    ),
                )

    def test_round_finding_publication_must_precede_canonical_challenge(self) -> None:
        finding = gates_module.ChallengeFinding(
            challenge_id="chronology-finding",
            category=ChallengeCategory.SEED_DEPENDENCE,
            severity=ChallengeSeverity.MAJOR,
            status=ChallengeStatus.UNRESOLVED,
            target_claim_ids=("claim-a",),
            claim_graph_artifact_hash=_digest("graph"),
            evidence_hashes=(_digest("result"),),
            attack="Chronology must be prospective.",
            deterministic=False,
        )
        record = Challenge(
            object_id=finding.challenge_id,
            producer=Role.ADVERSARIAL_REVIEWER,
            target_claim_ids=finding.target_claim_ids,
            severity=StateChallengeSeverity.MAJOR,
            finding=finding.attack,
            resolution_status=StateChallengeResolution.UNRESOLVED,
            evidence_ids=finding.evidence_hashes,
            parents=(
                ObjectReference(
                    object_type="Claim",
                    object_id="claim-a",
                    content_hash=_digest("claim-a-content"),
                    relation="challenges",
                    evaluated=True,
                ),
            ),
            authority_artifact_hashes=(_digest("chronology-finding"),),
        )
        peer = SimpleNamespace(
            authority=SimpleNamespace(
                finding_artifact_hashes=(_digest("chronology-finding"),),
            ),
            findings=(finding,),
            publication_event_index=7,
        )
        self.assertFalse(
            gates_module._semantic_challenger_audit_exact_challenge_projection(
                record,
                event_index=7,
                peers=(peer,),
                soundness=None,
                accepted_objects={},
                code_version="semantic-audit-test",
            )
        )

    def test_same_round_challenge_projection_rejects_all_unretained_fields(self) -> None:
        # Pure composition test, not a positive semantic-audit issuance test.
        claim = _claim_projection_fixture()
        accepted = {("Claim", claim.object_id): claim}
        finding = gates_module.ChallengeFinding(
            challenge_id="exact-projection-finding",
            category=ChallengeCategory.SEED_DEPENDENCE,
            severity=ChallengeSeverity.BLOCKING,
            status=ChallengeStatus.UNRESOLVED,
            target_claim_ids=(claim.object_id,),
            claim_graph_artifact_hash=_digest("graph"),
            evidence_hashes=(_digest("result"),),
            attack="Retain this exact adverse observation.",
            deterministic=False,
        )
        digest = _digest("exact-projection-finding")
        record = gates_module._semantic_challenger_audit_challenge_projection(
            finding,
            finding_artifact_hash=digest,
            accepted_objects=accepted,
            created_at="2026-09-05T00:00:00Z",
            code_version="semantic-audit-test",
        )
        peer = SimpleNamespace(
            authority=SimpleNamespace(finding_artifact_hashes=(digest,)),
            findings=(finding,),
            publication_event_index=1,
        )

        def admits(candidate, objects=accepted, peers=(peer,), soundness=None):
            return gates_module._semantic_challenger_audit_exact_challenge_projection(
                candidate, event_index=2, peers=peers, soundness=soundness,
                accepted_objects=objects, code_version="semantic-audit-test",
            )

        self.assertTrue(admits(record))
        ref = record.parents[0]
        changes = (
            {"evidence_ids": (_digest("substituted-evidence"),)},
            {"producer": Role.ORCHESTRATOR},
            {"status": RecordStatus.DRAFT},
            {"code_version": "other-code"},
            {"metadata": {"caller_extra": "unreviewed"}},
            {"parents": (replace(ref, content_hash=_digest("substituted-content")),)},
            {"parents": (replace(ref, relation="unreviewed"),)},
            {"parents": (replace(ref, evaluated=False),)},
            {"parents": ()},
            {"parents": (*record.parents, replace(ref, relation="extra"))},
            {"relationships": (ObjectLink(
                object_type="Claim", object_id=claim.object_id,
                relation="unreviewed",
            ),)},
            {"object_id": "alias-finding"},
            {"revision": 2, "supersedes_content_hash": record.content_hash},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(admits(replace(record, content_hash=None, **change)))
        self.assertFalse(admits(record, objects={}))
        self.assertFalse(admits(record, objects={
            ("Claim", claim.object_id): replace(
                claim, content_hash=None, source_artifact_ids=(_digest("other-graph"),),
            ),
        }))
        # Inclusion only in aggregate bytes must not invent sibling publication.
        aggregate = SimpleNamespace(assessment=SimpleNamespace(
            finding_artifact_hashes=(digest,), findings=(finding,),
        ), semantic_peers=(peer,))
        self.assertFalse(admits(record, peers=(), soundness=aggregate))

    def test_critique_and_decision_require_closed_projection_of_same_source(self) -> None:
        # This tests view equality only. The aggregate is not production authority.
        claim = _claim_projection_fixture()
        accepted = {("Claim", claim.object_id): claim}
        finding = gates_module.ChallengeFinding(
            challenge_id="projection-finding", category=ChallengeCategory.STATISTICS,
            severity=ChallengeSeverity.MAJOR, status=ChallengeStatus.UNRESOLVED,
            attack="Non-evidentiary retained finding for canonical projection checks.",
            target_claim_ids=(claim.object_id,), claim_graph_artifact_hash=_digest("graph"),
            evidence_hashes=(_digest("projection-finding-evidence"),),
        )
        finding_hash = _digest("projection-finding")
        challenge = gates_module._semantic_challenger_audit_challenge_projection(
            finding, finding_artifact_hash=finding_hash, accepted_objects=accepted,
            created_at="2026-09-05T00:00:00Z", code_version="semantic-audit-test",
        )
        accepted[("Challenge", challenge.object_id)] = challenge
        soundness = SimpleNamespace(
            record=SimpleNamespace(sha256=_digest("projection-soundness")),
            semantic_peers=(SimpleNamespace(publication_event_index=1),),
            assessment=SimpleNamespace(
                central_claim_ids=(claim.object_id,),
                claim_graph_artifact_hash=_digest("graph"),
                finding_artifact_hashes=(finding_hash,), findings=(finding,),
                verdict=gates_module.SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED,
                reason="Non-evidentiary view test with incomplete research.",
            ),
        )
        for kind, builder, checker in (
            ("Critique", gates_module._semantic_challenger_audit_critique_projection,
             gates_module._semantic_challenger_audit_exact_critique_projection),
            ("Decision", gates_module._semantic_challenger_audit_decision_projection,
             gates_module._semantic_challenger_audit_exact_decision_projection),
        ):
            record = builder(
                soundness, accepted_objects=accepted,
                created_at="2026-09-05T00:00:00Z", code_version="semantic-audit-test",
            )

            def admits(candidate):
                args = (None, None, candidate) if kind == "Decision" else (candidate,)
                return checker(
                    *args, event_index=2, soundness=soundness,
                    accepted_objects=accepted, code_version="semantic-audit-test",
                )

            with self.subTest(kind=kind):
                self.assertTrue(admits(record))
                ref = record.parents[0]
                changes = [
                    {"object_id": "review-alias"},
                    {"schema_version": "1.0"},
                    {"producer": Role.ORCHESTRATOR},
                    {"status": RecordStatus.DRAFT},
                    {"code_version": "other-code"},
                    {"metadata": {"caller_extra": "unreviewed"}},
                    {"parents": (replace(ref, content_hash=_digest("other-content")),)},
                    {"parents": (replace(ref, relation="unreviewed"),)},
                    {"parents": (replace(ref, evaluated=False),)},
                    {"parents": ()},
                    {"parents": (*record.parents, replace(ref, relation="extra"))},
                ]
                if kind == "Decision":
                    changes.extend([
                        {"evidence_ids": ("unreviewed-evidence",)},
                        {"alternatives": ("invent promotion",)},
                        {"governing_rule": "Ignore scientific gates."},
                        {"uncertainty": 0.0},
                        {"consequences": ("Release without review.",)},
                    ])
                else:
                    changes.extend([
                        {"reviewer_input_hashes": (_digest("other-input"),)},
                        {"target_ids": ("another-claim",)},
                        {"verdict": "PASS"},
                    ])
                for change in changes:
                    with self.subTest(change=change):
                        self.assertFalse(admits(replace(record, content_hash=None, **change)))

        soundness.assessment.finding_artifact_hashes = ()
        soundness.assessment.findings = ()
        with self.assertRaisesRegex(ValidationError, "requires retained Challenger findings"):
            gates_module._semantic_challenger_audit_critique_projection(
                soundness, accepted_objects=accepted,
                created_at="2026-09-05T00:00:00Z", code_version="semantic-audit-test",
            )

    def test_post_snapshot_revision_of_disjoint_review_identity_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            first = Critique(
                object_id="disjoint-critique",
                producer=Role.ADVERSARIAL_REVIEWER,
                target_ids=("unrelated-claim",),
                findings=(),
                verdict="RETAIN",
                code_version="semantic-audit-test",
            )
            self._append_canonical_fixture(registry, ledger, first)
            self._append_canonical_fixture(
                registry,
                ledger,
                Critique(
                    object_id=first.object_id,
                    producer=first.producer,
                    revision=2,
                    supersedes_content_hash=first.content_hash,
                    target_ids=first.target_ids,
                    findings=(),
                    verdict="REVISE",
                    code_version="semantic-audit-test",
                ),
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=1,
            )
            with self.assertRaisesRegex(ValidationError, "identity changed"):
                gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                    registry,
                    ledger,
                    state=bound,
                    audit_slot=self._slot(),
                )

    def test_post_snapshot_scientific_core_append_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            self._append_canonical_fixture(
                registry,
                ledger,
                Result(
                    object_id="result-after-audit",
                    producer=Role.EXPERIMENT_RUNNER,
                    run_ids=("execution-run",),
                    metric_id="metric-a",
                    value={"estimate": 1.0},
                    source_artifact_hashes=(_digest("result-source"),),
                    code_revision="semantic-audit-test",
                ),
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=1,
            )
            with self.assertRaisesRegex(
                ValidationError,
                "scientific core changed",
            ):
                gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                    registry,
                    ledger,
                    state=bound,
                    audit_slot=self._slot(),
                )

    def test_historical_core_before_bound_prefix_is_not_false_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            self._append_canonical_fixture(
                registry,
                ledger,
                Result(
                    object_id="historical-result",
                    producer=Role.EXPERIMENT_RUNNER,
                    run_ids=("execution-run",),
                    metric_id="metric-a",
                    value={"estimate": 1.0},
                    source_artifact_hashes=(_digest("result-source"),),
                    code_revision="semantic-audit-test",
                ),
            )
            bound = self._bound_state_fixture(
                registry,
                ledger,
                ledger_event_count=2,
            )
            gates_module._require_semantic_challenger_audit_no_post_snapshot_core_drift(
                registry,
                ledger,
                state=bound,
                audit_slot=self._slot(),
            )

    def test_post_reservation_state_replay_uses_bound_snapshot_owner(self) -> None:
        sentinel = SimpleNamespace(entries=(SimpleNamespace(),))
        snapshot_record = SimpleNamespace(sha256=_digest("snapshot"))
        snapshot_value = {
            "repository_code_version": "code-v1",
            "repository_configuration_hash": _digest("configuration"),
        }
        issuance = SimpleNamespace(event_hash=_digest("snapshot-event"))
        slot = self._slot()
        registry = SimpleNamespace()
        ledger = SimpleNamespace(validate=lambda **_kwargs: SimpleNamespace())
        with (
            patch(
                "scientist_one.research_state.resolve_research_state_authority",
                side_effect=AssertionError("whole-current replay recursed"),
            ),
            patch(
                "scientist_one.research_state._read_canonical_research_state_snapshot",
                return_value=(snapshot_record, (_digest("state"),), (), snapshot_value),
            ),
            patch(
                "scientist_one.research_state._require_research_state_snapshot_issuance",
                return_value=(4, issuance),
            ),
            patch(
                "scientist_one.research_state.resolve_bound_research_state_authority",
                return_value=sentinel,
            ) as bound_owner,
            patch.object(
                gates_module,
                "_require_semantic_challenger_audit_no_post_snapshot_core_drift",
            ) as drift_check,
        ):
            resolved = gates_module._resolve_semantic_challenger_audit_state(
                registry,
                ledger,
                run_id="audit-run",
                snapshot_artifact_hash=_digest("snapshot"),
                require_whole_current=False,
                _replay_slot=slot,
            )
        self.assertIs(resolved, sentinel)
        bound_owner.assert_called_once()
        drift_check.assert_called_once_with(
            registry,
            ledger,
            state=sentinel,
            audit_slot=slot,
        )

    def test_reservation_state_replay_requires_whole_current_owner(self) -> None:
        sentinel = SimpleNamespace(entries=(SimpleNamespace(),))
        registry = SimpleNamespace()
        ledger = SimpleNamespace()
        with (
            patch(
                "scientist_one.research_state.resolve_research_state_authority",
                return_value=sentinel,
            ) as whole_owner,
            patch(
                "scientist_one.research_state.resolve_bound_research_state_authority",
                side_effect=AssertionError("reservation used a historical prefix"),
            ),
            patch(
                "scientist_one.research_state._read_canonical_research_state_snapshot",
                side_effect=AssertionError("reservation bypassed whole-current proof"),
            ),
        ):
            resolved = gates_module._resolve_semantic_challenger_audit_state(
                registry,
                ledger,
                run_id="audit-run",
                snapshot_artifact_hash=_digest("snapshot"),
                require_whole_current=True,
            )
        self.assertIs(resolved, sentinel)
        whole_owner.assert_called_once_with(
            registry,
            ledger,
            run_id="audit-run",
            snapshot_artifact_hash=_digest("snapshot"),
        )

    def test_arbitrary_noncanonical_scope_fails_before_slot_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            fake_snapshot = registry.put_json(
                {"run_id": "audit-run", "caller_selected": True},
                logical_type="caller_selected_fake_snapshot",
                origin="non-evidentiary negative fixture",
                creator_role=Role.ORCHESTRATOR,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            fake_graph = registry.put_json(
                {
                    "run_id": "audit-run",
                    "caller_selected": True,
                    "kind": "graph",
                },
                logical_type="caller_selected_fake_graph",
                origin="non-evidentiary negative fixture",
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=("scientist-one", "test-semantic-audit"),
                parent_artifacts=(),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            before_registry = registry.verify_all(raise_on_error=True)
            before_ledger = ledger.validate(raise_on_error=True)
            with self.assertRaises(ValidationError):
                reserve_semantic_challenger_audit_slot(
                    registry,
                    ledger,
                    assessment_id="assessment-1",
                    run_id="audit-run",
                    category=ChallengeCategory.STATISTICS,
                    research_state_snapshot_artifact_hash=fake_snapshot.sha256,
                    claim_graph_artifact_hash=fake_graph.sha256,
                    provider_invocation_id="invocation-1",
                )
            self.assertEqual(
                registry.verify_all(raise_on_error=True),
                before_registry,
            )
            self.assertEqual(ledger.validate(raise_on_error=True), before_ledger)

    def test_fake_or_missing_live_closure_cannot_publish_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry, ledger = self._runtime(Path(directory))
            before_registry = registry.verify_all(raise_on_error=True)
            before_ledger = ledger.validate(raise_on_error=True)
            with self.assertRaises(ValidationError):
                register_semantic_challenge_audit_authority(
                    registry,
                    ledger,
                    slot_id="semantic-audit-missing",
                    expected_run_id="audit-run",
                    semantic_judgment_artifact_hash=_digest("judgment"),
                    finding_artifact_hashes=(),
                    challenger_execution_artifact_hash=_digest("execution"),
                    challenger_review_artifact_hash=_digest("review"),
                )
            self.assertEqual(
                registry.verify_all(raise_on_error=True),
                before_registry,
            )
            self.assertEqual(ledger.validate(raise_on_error=True), before_ledger)

            malformed = registry.put_json(
                {"schema_version": "semantic-challenge-audit-authority/v1"},
                logical_type=SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_LOGICAL_TYPE,
                origin=gates_module._SEMANTIC_CHALLENGE_AUDIT_ORIGIN,
                creator_role=Role.ADVERSARIAL_REVIEWER,
                creation_command=gates_module._SEMANTIC_CHALLENGE_AUDIT_COMMAND,
                parent_artifacts=(),
                schema_version=SEMANTIC_CHALLENGE_AUDIT_AUTHORITY_SCHEMA_VERSION,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            after_fixture_registry = registry.verify_all(raise_on_error=True)
            after_fixture_ledger = ledger.validate(raise_on_error=True)
            with self.assertRaises(ValidationError):
                require_semantic_challenge_audit_authority(
                    registry,
                    ledger,
                    authority_artifact_hash=malformed.sha256,
                    expected_run_id="audit-run",
                    expected_assessment_id="assessment-1",
                    expected_category=ChallengeCategory.STATISTICS,
                    expected_research_state_snapshot_artifact_hash=_digest(
                        "snapshot"
                    ),
                    expected_claim_graph_artifact_hash=_digest("graph"),
                    expected_central_claim_ids=("claim-a",),
                )
            self.assertEqual(
                registry.verify_all(raise_on_error=True),
                after_fixture_registry,
            )
            self.assertEqual(
                ledger.validate(raise_on_error=True),
                after_fixture_ledger,
            )


if __name__ == "__main__":
    unittest.main()
