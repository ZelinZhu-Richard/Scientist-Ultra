"""Real-owner evaluator joins using ordinary, non-evidentiary fixtures.

These tests issue no scientific execution, signature, independent approval,
or positive scientific R-check. The original source owners remain unmodified.
"""

from dataclasses import replace
import tempfile
import unittest

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.evaluators import (
    AuthorityScope,
    AuthorityStatus,
    EvaluatorClass,
    RCheck,
    _derive_r_check_authority,
    _event_binding,
    register_r_check_authority,
    resolve_r_check_authority,
)
from scientist_one.ledger import EventLedger
from scientist_one.models import MacroState
from scientist_one.research_os import _build_design, _run_literature
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    register_evaluation_contract_freeze_gate_receipt,
    register_research_question_gate_assessment,
    record_scientific_design_freeze,
    require_evaluation_contract_freeze_gate_receipt,
    require_research_question_gate_assessment,
)
from tests import test_research_os_literature_integration as literature_fixtures
from tests.test_scientific_design import _prepared_timeline


def _reference_event(ledger, records, *, run_id, publication=False):
    events = ledger.assert_valid().events
    state = events[-1].requested_state_after if events else MacroState.CALIBRATE
    metadata = {
        "artifact_types": [record.logical_type for record in records],
        "artifact_record_hashes": [record.record_hash for record in records],
        "fixture_notice": "Ordinary evaluator boundary fixture only.",
    }
    if publication:
        metadata["scientific_domain_validity"] = {"fixture_only": True}
    return ledger.record(
        run_id=run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=state,
        requested_state_after=state,
        artifact_hashes=tuple(record.sha256 for record in records),
        code_version=f"sha256:{'a' * 64}",
        configuration_hash="b" * 64,
        reason="non-evidentiary source reference for evaluator integration",
        event_type="CHECKPOINT",
        metadata=metadata,
    )


class ScientificRCheckIntegrationTests(unittest.TestCase):
    def test_mechanical_question_assessment_uses_owner_checkpoint_and_scope(self):
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/r1-integration/events.jsonl")
            literature = _run_literature(
                registry, timestamp="2026-08-29T12:00:00Z"
            )
            design = _build_design(
                literature, registry, timestamp="2026-08-29T12:00:00Z"
            )
            design = replace(
                design,
                brief=replace(
                    design.brief,
                    assessment=replace(design.brief.assessment, importance=False),
                ),
            )
            brief, _ = (
                literature_fixtures.ResearchOSLiteratureIntegrationTests._register_durable_gate_roots(
                    registry, literature, design
                )
            )
            source = register_research_question_gate_assessment(
                registry,
                ledger,
                assessment_id="r1-integration-assessment",
                run_id="r1-integration",
                goal_artifact_sha256=literature.goal_artifact.sha256,
                investigation_state_artifact_sha256=(
                    literature.investigation_state_artifact.sha256
                ),
                research_brief_artifact_sha256=brief.sha256,
            )
            assessment = require_research_question_gate_assessment(
                registry,
                ledger,
                assessment_artifact_sha256=source.sha256,
                expected_run_id="r1-integration",
                expected_object_id=design.brief.brief_id,
            )
            self.assertFalse(assessment.scientific_evidence_eligible)
            checkpoint = ledger.assert_valid().events[assessment.gate_event_index]
            self.assertNotIn(source.sha256, checkpoint.artifact_hashes)
            authorities = []
            for evaluator in (EvaluatorClass.E0, EvaluatorClass.E2):
                record = register_r_check_authority(
                    registry,
                    ledger,
                    run_id="r1-integration",
                    r_check=RCheck.R1,
                    evaluator_class=evaluator,
                    source_artifact_sha256s=(source.sha256,),
                )
                authority = resolve_r_check_authority(
                    registry,
                    ledger,
                    authority_artifact_sha256=record.sha256,
                    run_id="r1-integration",
                )
                self.assertIs(authority.status, AuthorityStatus.UNTESTED)
                self.assertIs(authority.scope, AuthorityScope.SYSTEM_FIXTURE)
                self.assertEqual(authority.reason_code, "NON_EVIDENTIARY_MECHANICAL")
                self.assertEqual(
                    authority.source_bindings[0].ledger_event_hash,
                    checkpoint.event_hash,
                )
                authorities.append((record, authority))

            # The receipt's first later use is not its admission. The owner
            # checkpoint remains authoritative after a further ordinary use.
            _reference_event(ledger, (source,), run_id="r1-integration")
            for record, authority in authorities:
                self.assertEqual(
                    resolve_r_check_authority(
                        registry,
                        ledger,
                        authority_artifact_sha256=record.sha256,
                        run_id="r1-integration",
                    ),
                    authority,
                )

    def test_freeze_only_cannot_close_r1_and_binds_actual_design_event(self):
        with tempfile.TemporaryDirectory() as root:
            values = _prepared_timeline(root)
            registry, ledger = values["registry"], values["ledger"]
            selectors = {
                "run_id": "timeline-run",
                "contract": values["contract"],
                "contract_artifact_sha256": values["contract_record"].sha256,
                "experiment_plan_artifact_sha256s": tuple(
                    record.sha256 for record in values["plan_records"]
                ),
                "frozen_run_spec_artifact_sha256": values["spec_record"].sha256,
            }
            record_scientific_design_freeze(registry, ledger, **selectors)
            source = register_evaluation_contract_freeze_gate_receipt(
                registry, ledger, receipt_id="r1-integration-freeze", **selectors
            )
            freeze = require_evaluation_contract_freeze_gate_receipt(
                registry,
                ledger,
                receipt_artifact_sha256=source.sha256,
                expected_run_id="timeline-run",
                expected_contract_id=values["contract"].contract_id,
            )
            checkpoint = ledger.assert_valid().events[freeze.design_freeze_event_index]
            self.assertNotIn(source.sha256, checkpoint.artifact_hashes)
            authority, _ = _derive_r_check_authority(
                registry,
                ledger,
                run_id="timeline-run",
                r_check=RCheck.R1,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(source.sha256,),
            )
            self.assertIs(authority.status, AuthorityStatus.UNTESTED)
            self.assertEqual(
                authority.source_bindings[0].ledger_event_hash,
                checkpoint.event_hash,
            )

    def test_malformed_v3_domain_routes_to_failed_owner_not_pass_labels(self):
        with tempfile.TemporaryDirectory() as root:
            registry = ArtifactRegistry(root)
            ledger = EventLedger(root, "runs/domain-integration/events.jsonl")
            source = registry.put_json(
                {
                    "schema_version": "domain-validity-receipt/v3",
                    "domain": "GENERIC_ML",
                    "object_id": "domain-object",
                    "task_id": "domain-task",
                    "scope": "SCIENTIFIC_EVIDENCE",
                    "status": "PASS",
                },
                logical_type="domain_validity.generic_ml",
                origin="ordinary malformed fixture, not a domain authority",
                creator_role=Role.SCIENTIFIC_REVIEWER,
                creation_command=("scientist-one", "test-domain-integration"),
                parent_artifacts=(),
                schema_version="domain-validity-receipt/v3",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            checkpoint = _reference_event(
                ledger, (source,), run_id="domain-integration", publication=True
            )
            _reference_event(ledger, (source,), run_id="domain-integration")
            binding = _event_binding(ledger.assert_valid().events, source)
            self.assertEqual(binding.ledger_event_hash, checkpoint.event_hash)
            authority, _ = _derive_r_check_authority(
                registry,
                ledger,
                run_id="domain-integration",
                r_check=RCheck.R3,
                evaluator_class=EvaluatorClass.E0,
                source_artifact_sha256s=(source.sha256,),
            )
            self.assertIs(authority.status, AuthorityStatus.FAIL)
            self.assertIs(authority.scope, AuthorityScope.SYSTEM_FIXTURE)
            self.assertEqual(
                authority.reason_code,
                "PROJECTION_BACKED_DOMAIN_OWNER_REPLAY_FAILED",
            )


if __name__ == "__main__":
    unittest.main()
