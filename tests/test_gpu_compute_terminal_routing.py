"""Real operational cross-family routing; no CUDA execution or science claim.

The existing wall fixture starts an actual temporary orchestrator and records
actual wall exhaustion. The existing GPU fixture publicly freezes prospective
inputs and an unspent escalation plan in that same registry/ledger. Its setUp
is deliberately not run. Only the wall fixture's existing temporary-root
routing is used; no successful source owner, clock, or authority is injected.
The freshness control delegates to the actual spec owner, then appends one
explicitly adverse inert record before the route's paired snapshot check.
Fixture modules, not TestCase classes, are imported to avoid duplicate discovery.
"""

from __future__ import annotations

from datetime import datetime
import unittest
from unittest.mock import patch

from scientist_one import compute_terminal as compute
from scientist_one import gpu_validation_requirement as gpu_owner
from scientist_one.orchestrator import require_resource_runtime_wall_budget_observation
from scientist_one.scientific_design import require_evaluation_contract_freeze_gate_receipt

from tests import test_compute_terminal as wall_sources
from tests import test_gpu_validation_requirement as gpu_sources
from tests.test_compute_prepared_fixture import prepared_compute_tests


_WALL_REFUSAL = "GPU_REQUIREMENT_POLICY_PRECLUDES_WALL_FALLBACK"


@prepared_compute_tests
class GpuComputeTerminalRoutingTests(unittest.TestCase):
    def setUp(self):
        self.wall = wall_sources.ComputeTerminalAuthorityTests(
            "test_owner_backed_compute_assessment_materializes_only_operational_scope")
        # Keep real clocks; allow actual prospective design publication before expiry.
        self.wall._real_wall_budget_seconds = 10
        self.wall.setUp()
        self.addCleanup(self.wall.tearDown)
        self.registry, self.ledger = self.wall.registry, self.wall.ledger
        self.gpu = gpu_sources.GpuValidationRequirementTests(
            "test_genuine_prospective_owners_establish_only_the_operational_requirement")
        self.gpu.root = self.wall.root
        self.gpu.registry, self.gpu.ledger = self.registry, self.ledger
        self.gpu.ledger_run_id = self.wall.run_id

    def snapshots(self):
        return self.registry.verify_all(), self.ledger.assert_valid()

    def prepare(self, **changes):
        inputs = self.gpu.prepare(**changes)
        freeze = require_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_artifact_sha256=inputs["freeze_record"].sha256,
            expected_run_id=self.wall.run_id,
            expected_contract_id=inputs["contract"].contract_id,
        )
        observation = self.wall._observe_exhaustion()
        self.assertEqual(observation.resource_config.maximum_wall_clock_seconds, 10)
        self.assertEqual(require_resource_runtime_wall_budget_observation(
            self.registry, self.ledger,
            observation_artifact_sha256=observation.observation_artifact_sha256,
            expected_run_id=self.wall.run_id,
        ), observation)
        events = self.ledger.events()
        freeze_event = events[freeze.design_freeze_event_index]
        self.assertEqual(freeze_event.event_hash, freeze.design_freeze_event_hash)
        self.assertLess(freeze.design_freeze_event_index, observation.ledger_event_index)
        deadline = (observation.runtime_state.wall_started_at_epoch_seconds
                    + observation.resource_config.maximum_wall_clock_seconds)
        self.assertLess(
            datetime.fromisoformat(freeze_event.timestamp).timestamp(), deadline,
            "The real configured fixture expired before design freeze; do not fake its clock.",
        )
        self.assertGreaterEqual(observation.runtime_state.wall_elapsed_seconds,
                                observation.resource_config.maximum_wall_clock_seconds)
        self.wall_arguments = dict(
            assessment_id="routing-wall-assessment",
            expected_ledger_run_id=self.wall.run_id,
            expected_execution_run_id=inputs["local"].run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256),
            wall_budget_observation_artifact_sha256=observation.observation_artifact_sha256,
        )
        self.gpu_arguments = dict(
            assessment_id="routing-gpu-assessment",
            expected_ledger_run_id=self.wall.run_id,
            expected_execution_run_id=inputs["local"].run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=inputs["freeze_record"].sha256,
            compute_escalation_plan_authority_artifact_sha256=inputs["escalation_record"].sha256,
        )
        return inputs

    def assert_wall_refused_without_delta(self):
        before = self.snapshots()
        resolution = compute.resolve_compute_terminal_assessment(
            self.registry, self.ledger, **self.wall_arguments)
        self.assertIs(resolution.status, compute.ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL)
        self.assertEqual(resolution.reason_code, _WALL_REFUSAL)
        self.assertIsNone(resolution.assessment)
        self.assertIsNone(resolution.assessment_artifact_sha256)
        self.assertEqual(self.snapshots(), before)
        with self.assertRaisesRegex(compute.ComputeTerminalError, _WALL_REFUSAL):
            compute.register_compute_terminal_assessment(
                self.registry, self.ledger, **self.wall_arguments)
        self.assertEqual(self.snapshots(), before)

    def require(self, record):
        before = self.snapshots()
        assessment = compute.require_compute_terminal_assessment(
            self.registry, self.ledger, assessment_artifact_sha256=record.sha256,
            expected_ledger_run_id=self.wall.run_id,
            expected_execution_run_id=self.gpu_arguments["expected_execution_run_id"],
        )
        self.assertEqual(self.snapshots(), before)
        self.assertEqual(assessment.authority_scope, "OPERATIONAL_BLOCKER")
        self.assertIs(assessment.scientific_evidence, False)
        return assessment

    def assert_exact_publication_delta(self, before, record):
        after = self.snapshots()
        expected = {item.sha256: item for item in before[0].records}
        self.assertNotIn(record.sha256, expected)
        expected[record.sha256] = record
        self.assertEqual({item.sha256: item for item in after[0].records}, expected)
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1].events[:-1], before[1].events)
        self.assertEqual(after[1].event_count, before[1].event_count + 1)
        self.assertEqual(tuple(item for item in after[0].records
                               if item.logical_type == compute.COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE),
                         (record,))

    def publish_gpu(self):
        before = self.snapshots()
        record = compute.register_gpu_requirement_compute_terminal_assessment(
            self.registry, self.ledger, **self.gpu_arguments)
        self.assert_exact_publication_delta(before, record)
        assessment = self.require(record)
        self.assertIs(type(assessment), compute.GpuRequirementComputeTerminalAssessment)
        self.assertEqual(assessment.factual_status, compute.GPU_PROTOCOL_REQUIRED_STATUS)
        self.assertEqual(assessment.external_validation_status, "UNTESTED")
        self.assertIs(assessment.spending_authorized, False)
        self.assertEqual(record.schema_version, "2.0")
        return record, assessment

    def assert_gpu_unavailable_without_delta(self, inputs, status, reason):
        before = self.snapshots()
        result = self.gpu.resolve(inputs)
        self.assertIs(result.status, status)
        self.assertEqual(result.reason_code, reason)
        self.assertIsNone(result.requirement)
        self.assertEqual(self.snapshots(), before)
        with self.assertRaisesRegex(compute.ComputeTerminalError, reason):
            compute.register_gpu_requirement_compute_terminal_assessment(
                self.registry, self.ledger, **self.gpu_arguments)
        self.assertEqual(self.snapshots(), before)

    def test_valid_policy_wall_first_cannot_reserve_slot_before_gpu_publication(self):
        self.prepare()
        self.assert_wall_refused_without_delta()
        record, assessment = self.publish_gpu()
        self.assertEqual(self.require(record), assessment)

    def test_valid_policy_gpu_first_leaves_wall_refused_and_exact_gpu_slot_current(self):
        self.prepare()
        record, assessment = self.publish_gpu()
        before = self.snapshots()
        self.assert_wall_refused_without_delta()
        self.assertEqual(self.require(record), assessment)
        self.assertEqual(self.snapshots(), before)

    def test_present_empty_malformed_policy_refuses_both_without_wall_fallback(self):
        inputs = self.prepare(policy={})
        self.assertIn(gpu_owner.GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY,
                      inputs["local"].metadata)
        self.assertFalse(inputs["local"].metadata[gpu_owner.GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY])
        before = self.snapshots()
        self.assert_wall_refused_without_delta()
        self.assert_gpu_unavailable_without_delta(
            inputs, gpu_owner.GpuValidationRequirementStatus.BLOCKED_LOCAL,
            "SOURCE_REQUIREMENT_UNAVAILABLE")
        self.assertEqual(self.snapshots(), before)

    def test_absent_policy_retains_owned_legacy_wall_and_gpu_not_applicable(self):
        inputs = self.prepare(omit_policy=True)
        self.assertNotIn(gpu_owner.GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY,
                         inputs["local"].metadata)
        self.assert_gpu_unavailable_without_delta(
            inputs, gpu_owner.GpuValidationRequirementStatus.NOT_APPLICABLE,
            "NO_DEVICE_REQUIREMENT_POLICY")
        before = self.snapshots()
        resolution = compute.resolve_compute_terminal_assessment(
            self.registry, self.ledger, **self.wall_arguments)
        self.assertIs(resolution.status, compute.ComputeTerminalAssessmentResolutionStatus.AUTHORIZED)
        self.assertEqual(resolution.reason_code, compute.WALL_BUDGET_EXHAUSTED_STATUS)
        self.assertEqual(self.snapshots(), before)
        record = compute.register_compute_terminal_assessment(
            self.registry, self.ledger, **self.wall_arguments)
        self.assert_exact_publication_delta(before, record)
        assessment = self.require(record)
        self.assertIs(type(assessment), compute.ComputeTerminalAssessment)
        self.assertEqual(assessment.factual_status, compute.WALL_BUDGET_EXHAUSTED_STATUS)
        self.assertEqual(record.schema_version, "1.0")
        self.assert_gpu_unavailable_without_delta(
            inputs, gpu_owner.GpuValidationRequirementStatus.NOT_APPLICABLE,
            "NO_DEVICE_REQUIREMENT_POLICY")
        self.assertEqual(self.require(record), assessment)

    def test_policy_route_refuses_actual_post_owner_registry_drift(self):
        inputs = self.prepare()
        before = self.snapshots()
        actual_owner = compute.require_scientific_execution_run_spec
        injected = []

        def actual_owner_then_inert_append(*args, **kwargs):
            # This is the real owner result, never a manufactured successful
            # DTO. The only introduced artifact is an adverse drift marker.
            result = actual_owner(*args, **kwargs)
            self.assertEqual(result, inputs["local"])
            injected.append(self.gpu.artifact(
                b'{"inert-concurrent-route-write":"no-execution-or-authority"}\n',
                "compute_route_inert_drift", validation_result="FAIL"))
            return result

        with patch.object(compute, "require_scientific_execution_run_spec",
                          new=actual_owner_then_inert_append):
            with self.assertRaisesRegex(compute.ComputeTerminalError, "compute route sources changed"):
                compute.resolve_compute_terminal_assessment(
                    self.registry, self.ledger, **self.wall_arguments)
        after = self.snapshots()
        self.assertEqual(len(injected), 1)
        self.assertEqual(injected[0].validation_result, "FAIL")
        expected = {record.sha256: record for record in before[0].records}
        expected[injected[0].sha256] = injected[0]
        self.assertEqual({record.sha256: record for record in after[0].records}, expected)
        self.assertEqual(after[0].count, before[0].count + 1)
        self.assertEqual(after[1], before[1])
        self.assertFalse(any(record.logical_type == compute.COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
                             for record in after[0].records))


if __name__ == "__main__":
    unittest.main()
