"""Real operational publication controls; no CUDA execution or scientific PASS.

All prospective sources are registered through their public owners. The
source fixture is design input, not evidence of novelty or empirical merit.
The only successful publication here is a scoped operational blocker.
"""

from __future__ import annotations

from unittest.mock import patch
import unittest

from scientist_one import compute_terminal as compute
from scientist_one.errors import ArtifactError
from scientist_one.research_state import ResearchStateRepository
from scientist_one.roles import Role
from scientist_one.terminal_outcomes import (
    ResearchTerminalOutcome,
    ResearchTerminalRecord,
    TerminalAuthorityScope,
    TerminalPhase,
    derive_from_registered_compute_terminal_assessment,
    load_terminal_outcome,
    materialize_terminal_outcome,
)
from tests import test_gpu_validation_requirement as prospective


class GpuComputeTerminalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = prospective.GpuValidationRequirementTests(
            "test_genuine_prospective_owners_establish_only_the_operational_requirement"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.ledger = self.fixture.registry, self.fixture.ledger

    def arguments(self, inputs):
        return dict(
            assessment_id="unperformed-cuda-obligation",
            expected_ledger_run_id=self.fixture.ledger_run_id,
            expected_execution_run_id=inputs["local"].run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
            compute_escalation_plan_authority_artifact_sha256=inputs["escalation_record"].sha256,
        )

    def register(self, inputs, **changes):
        arguments = self.arguments(inputs)
        arguments.update(changes)
        return compute.register_gpu_requirement_compute_terminal_assessment(
            self.registry, self.ledger, **arguments,
        )

    def require(self, source, inputs):
        return compute.require_compute_terminal_assessment(
            self.registry, self.ledger, assessment_artifact_sha256=source.sha256,
            expected_ledger_run_id=self.fixture.ledger_run_id,
            expected_execution_run_id=inputs["local"].run_id,
        )

    def snapshots(self):
        return self.registry.verify_all(), self.ledger.assert_valid()

    def test_real_source_publication_idempotence_and_canonical_operational_terminal(self):
        inputs = self.fixture.prepare()
        before = self.snapshots()
        source = self.register(inputs)
        after = self.snapshots()
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1].event_count, before[1].event_count + 1)
        assessment = self.require(source, inputs)
        self.assertIs(type(assessment), compute.GpuRequirementComputeTerminalAssessment)
        self.assertFalse(assessment.scientific_evidence)
        self.assertFalse(assessment.spending_authorized)
        self.assertEqual(assessment.external_validation_status, "UNTESTED")
        self.assertEqual(source.schema_version, "2.0")
        self.assertEqual(source.created_at, after[1].events[-1].timestamp)
        self.assertEqual(self.register(inputs), source)
        self.assertEqual(self.snapshots(), after)

        head = self.ledger.events()[-1]
        repository = ResearchStateRepository(
            self.registry, self.ledger, run_id=self.fixture.ledger_run_id,
            code_version=head.code_version, configuration_hash=head.configuration_hash,
            state=head.state_after, creation_command=("scientist-one", "test-gpu-operational-terminal"),
        )
        derivation = derive_from_registered_compute_terminal_assessment(
            repository, source.sha256, expected_assessment_id=assessment.assessment_id,
        )
        self.assertIs(derivation.outcome, ResearchTerminalOutcome.FULL_VALIDATION_REQUIRES_GPU_CLOUD)
        self.assertIs(derivation.authority_scope, TerminalAuthorityScope.OPERATIONAL_BLOCKER)
        self.assertEqual(derivation.source_binding.source_claim_ids, ())
        terminal = ResearchTerminalRecord(
            record_id="terminal-unperformed-cuda", run_id=self.fixture.ledger_run_id,
            phase=TerminalPhase.COMPUTE, outcome=derivation.outcome,
            reason="Completing this frozen device-timing obligation requires GPU_CLOUD; execution and adequacy remain untested.",
            evidence_artifact_hashes=derivation.source_binding.required_evidence_artifact_hashes,
            derivation=derivation, producer=Role.SCIENTIFIC_REVIEWER,
            authority_scope=TerminalAuthorityScope.OPERATIONAL_BLOCKER,
            source_object_id=assessment.assessment_id, source_claim_ids=(),
            created_at=source.created_at,
        )
        materialized = materialize_terminal_outcome(terminal, repository)
        self.assertEqual(load_terminal_outcome(
            self.registry, materialized.terminal_artifact.sha256, repository=repository,
        ), terminal)
        self.assertEqual(self.require(source, inputs), assessment)

    def test_escalation_before_design_freeze_also_publishes_without_execution(self):
        inputs = self.fixture.prepare(escalation_first=True)
        assessment = self.require(self.register(inputs), inputs)
        self.assertLess(assessment.escalation_event_index, assessment.freeze_event_index)
        self.assertLess(assessment.freeze_event_index, assessment.ledger_event_index)

    def test_competing_assessment_identity_cannot_select_same_obligation_again(self):
        inputs = self.fixture.prepare()
        self.register(inputs)
        before = self.snapshots()
        with self.assertRaises(compute.ComputeTerminalError):
            self.register(inputs, assessment_id="competing-cuda-terminal")
        self.assertEqual(self.snapshots(), before)

    def test_actual_later_adverse_progress_revokes_stored_never_started_source(self):
        inputs = self.fixture.prepare()
        source = self.register(inputs)
        self.fixture.inert_progress(parents=(inputs["local_record"].sha256,))
        before = self.snapshots()
        with self.assertRaises(compute.ComputeTerminalError):
            self.require(source, inputs)
        with self.assertRaises(compute.ComputeTerminalError):
            self.register(inputs)
        self.assertEqual(self.snapshots(), before)

    def test_actual_assessment_event_correction_revokes_readback_without_writes(self):
        inputs = self.fixture.prepare()
        source = self.register(inputs)
        assessment = self.require(source, inputs)
        self.fixture.event({"inert-correction": True}, event_type="CORRECTION",
                           supersedes=assessment.ledger_event_id)
        before = self.snapshots()
        with self.assertRaises(compute.ComputeTerminalError):
            self.require(source, inputs)
        self.assertEqual(self.snapshots(), before)

    def test_real_event_first_io_failure_recovers_only_the_exact_publication(self):
        inputs = self.fixture.prepare()
        before = self.snapshots()
        original = self.registry._put_bytes_locked

        def fail_assessment(*args, **kwargs):
            if kwargs.get("logical_type") == compute.COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE:
                raise ArtifactError("injected assessment-artifact I/O failure")
            return original(*args, **kwargs)

        with patch.object(self.registry, "_put_bytes_locked", side_effect=fail_assessment):
            with self.assertRaises(ArtifactError):
                self.register(inputs)
        partial = self.snapshots()
        self.assertEqual(partial[0], before[0])
        self.assertEqual(partial[1].event_count, before[1].event_count + 1)
        with self.assertRaises(compute.ComputeTerminalError):
            self.register(inputs, assessment_id="different-recovery-slot")
        self.assertEqual(self.snapshots(), partial)
        source = self.register(inputs)
        recovered = self.snapshots()
        self.assertEqual(recovered[1], partial[1])
        self.assertEqual(recovered[0].count, before[0].count + 1)
        self.require(source, inputs)

    def test_registry_capacity_is_preflighted_before_any_assessment_event(self):
        inputs = self.fixture.prepare()
        before = self.snapshots()
        with patch.object(compute, "MAX_REGISTRY_RECORDS", before[0].count):
            with self.assertRaises(compute.ComputeTerminalError):
                self.register(inputs)
        self.assertEqual(self.snapshots(), before)

    def test_changed_source_pair_between_resolution_and_publication_is_not_adopted(self):
        inputs = self.fixture.prepare()
        before = self.snapshots()
        original = compute._publish_verified_compute_assessment

        def change_then_publish(*args, **kwargs):
            self.fixture.artifact(b"injected concurrent inert artifact", "inert_concurrent_input")
            return original(*args, **kwargs)

        with patch.object(compute, "_publish_verified_compute_assessment", side_effect=change_then_publish):
            with self.assertRaises(compute.ComputeTerminalError):
                self.register(inputs)
        after = self.snapshots()
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1], before[1])
        self.assertFalse(any(record.logical_type == compute.COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
                             for record in after[0].records))


if __name__ == "__main__":
    unittest.main()
