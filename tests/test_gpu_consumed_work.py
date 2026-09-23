"""Exact-work consumption regression tests; no live GPU transport is used."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.experiments import (
    ComputeEscalationBudget,
    ExperimentError,
    RunState,
    ScheduledGPUCloudBackend,
    ScheduledGPURecoveryBlocked,
    ScheduledGPURequest,
    ScheduledGPUStatus,
    make_gpu_cloud_submission_plan,
    register_compute_escalation_plan_authority,
    register_compute_escalation_submission_authorization,
)
from scientist_one.gates import (
    AutonomousDecisionRecord,
    HumanGate,
    HumanGatePolicy,
    HumanGateProfile,
)
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import thaw_json
from scientist_one.roles import Role
from tests import test_experiments as experiment_tests


class DispatchThenRaiseFixture(experiment_tests.StructuredSchedulerFixture):
    """Record a fixture dispatch, then lose its first response."""

    def __init__(self) -> None:
        super().__init__()
        self.lose_next_submit_response = True

    def submit(self, request: ScheduledGPURequest) -> ScheduledGPUStatus:
        status = super().submit(request)
        if self.lose_next_submit_response:
            self.lose_next_submit_response = False
            raise RuntimeError("fixture response lost after dispatch")
        return status


class GPUConsumedWorkTests(unittest.TestCase):
    run_id = "consumed-work-authority-run"

    def _runtime(
        self,
        root: Path,
        *,
        maximum_total_attempts: int = 1,
        initial_decision_label: str = "original-decision",
    ):
        transport = DispatchThenRaiseFixture()
        registry = ArtifactRegistry(root, f"runs/{self.run_id}/registry")
        ledger = EventLedger(root, f"runs/{self.run_id}/events.jsonl")
        local = experiment_tests.spec("consumed-work-local")
        cloud = experiment_tests.spec(
            "consumed-work-cloud",
            profile=experiment_tests.gpu_profile(),
            estimate=experiment_tests.gpu_estimate(),
        )
        budget = ComputeEscalationBudget(
            budget_id="consumed-work-budget",
            target_profile_sha256=cloud.compute_profile.sha256,
            target_estimate_sha256=cloud.resource_estimate.sha256,
            maximum_monetary_cost=2.5,
            maximum_total_attempts=maximum_total_attempts,
            maximum_cumulative_monetary_cost=2.5 * maximum_total_attempts,
            maximum_cumulative_wall_clock_seconds=600.0 * maximum_total_attempts,
        )
        # Match the existing authorized-backend harness: initialize the real
        # prospective plan and ledger before recovery inspects their namespace.
        # The first operation uses this authority; it is not a bootstrap record.
        decision, authority = self._authority(
            registry, ledger, local, cloud, budget, initial_decision_label
        )
        backend = ScheduledGPUCloudBackend(
            transport, artifact_registry=registry, event_ledger=ledger
        )
        return transport, backend, registry, ledger, local, cloud, budget, decision, authority

    def _authority(self, registry, ledger, local, cloud, budget, label):
        decision = experiment_tests.escalation_decision(local, cloud, label)
        plan = make_gpu_cloud_submission_plan(local, cloud, decision, budget)
        record = register_compute_escalation_plan_authority(
            registry,
            ledger,
            authority_id=f"caller-{label}",
            run_id=self.run_id,
            local_spec=local,
            cloud_spec=cloud,
            decision=decision,
            submission_plan=plan,
            budget=budget,
            human_gate_policy=HumanGatePolicy(HumanGateProfile.FULL_AUTONOMOUS),
        )
        autonomous = AutonomousDecisionRecord(
            decision_id=f"gate-{label}",
            gate=HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=record.sha256,
            alternatives=("SUBMIT", "STOP"),
            evidence_hashes=(record.sha256,),
            governing_rule="submit only the exact freshly authorized plan",
            uncertainty="fixture GPU execution remains untested",
            reason="exercise exact-work consumption without a live provider",
            downstream_consequences=("one fixture submission may occur",),
        )
        return decision, {
            "authority_artifact_sha256": record.sha256,
            "authority_run_id": self.run_id,
            "autonomous_decision": autonomous,
        }

    @staticmethod
    def _consumptions(ledger):
        return tuple(
            event for event in ledger.events()
            if "compute_escalation_submission_consumption" in event.metadata
        )

    def _lose_first_response(self, runtime):
        transport, backend, registry, ledger, local, cloud, budget, decision, authority = runtime
        with self.assertRaisesRegex(RuntimeError, "after dispatch"):
            backend.submit_planned(
                local, cloud, decision, idempotency_key="original-request", **authority
            )
        self.assertEqual(transport.submit_calls, 1)
        self.assertEqual(len(self._consumptions(ledger)), 1)
        self.assertEqual(backend._jobs, {})
        self.assertEqual(backend._spec_jobs, {})
        self.assertFalse(any(
            record.logical_type == "scheduled_gpu_recovery_snapshot"
            for record in registry.list_records()
        ))
        return decision, authority

    def _preissue(self, registry, ledger, local, cloud, decision, authority, key):
        record = register_compute_escalation_submission_authorization(
            registry,
            ledger,
            local_spec=local,
            cloud_spec=cloud,
            decision=decision,
            idempotency_key=key,
            **authority,
        )
        return {
            "authority_artifact_sha256": authority["authority_artifact_sha256"],
            "authority_run_id": authority["authority_run_id"],
            "submission_authorization_artifact_sha256": record.sha256,
        }

    def test_renamed_decision_cannot_resubmit_consumed_exact_work(self) -> None:
        for restart in (False, True):
            for key in ("original-request", "renamed-request"):
                for preissued in (False, True):
                    with self.subTest(restart=restart, key=key, preissued=preissued):
                        with tempfile.TemporaryDirectory() as directory:
                            runtime = self._runtime(Path(directory))
                            transport, backend, registry, ledger, local, cloud, budget, _, _ = runtime
                            _, original_authority = self._lose_first_response(runtime)
                            if restart:
                                backend = ScheduledGPUCloudBackend(
                                    transport, artifact_registry=registry, event_ledger=ledger
                                )
                            decision, authority = self._authority(
                                registry, ledger, local, cloud, budget, "renamed-decision"
                            )
                            self.assertNotEqual(
                                authority["authority_artifact_sha256"],
                                original_authority["authority_artifact_sha256"],
                            )
                            if preissued:
                                authority = self._preissue(
                                    registry, ledger, local, cloud, decision, authority, key
                                )
                            before = ledger.events()
                            with self.assertRaisesRegex(
                                ScheduledGPURecoveryBlocked, "exact work was already consumed"
                            ):
                                backend.submit_planned(
                                    local, cloud, decision, idempotency_key=key, **authority
                                )
                            self.assertEqual(ledger.events(), before)
                            self.assertEqual(len(self._consumptions(ledger)), 1)
                            self.assertEqual(transport.submit_calls, 1)
                            self.assertEqual(backend._jobs, {})
                            self.assertEqual(backend._spec_jobs, {})
                            self.assertEqual(backend._idempotency, {})

    def test_correcting_consumption_does_not_refund_exact_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            transport, _, registry, ledger, local, cloud, budget, _, _ = runtime
            self._lose_first_response(runtime)
            consumed = self._consumptions(ledger)[0]
            ledger.append_correction(
                consumed.event_id,
                actor_role=Role.CLAIM_VERIFIER,
                reason="fixture correction cannot prove dispatch did not occur",
                corrected_fields={"status": "REVOKED"},
            )
            backend = ScheduledGPUCloudBackend(
                transport, artifact_registry=registry, event_ledger=ledger
            )
            decision, authority = self._authority(
                registry, ledger, local, cloud, budget, "after-correction"
            )
            before = ledger.events()
            with self.assertRaisesRegex(ScheduledGPURecoveryBlocked, "exact work"):
                backend.submit_planned(
                    local, cloud, decision, idempotency_key="corrected-request", **authority
                )
            self.assertEqual(ledger.events(), before)
            self.assertEqual(len(self._consumptions(ledger)), 1)
            self.assertEqual(transport.submit_calls, 1)
            self.assertEqual(backend._jobs, {})

    def test_locked_consumption_rechecks_exact_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            transport, backend, registry, ledger, local, cloud, budget, _, _ = runtime
            self._lose_first_response(runtime)
            decision, authority = self._authority(
                registry, ledger, local, cloud, budget, "locked-decision"
            )
            guard = ScheduledGPUCloudBackend._require_unconsumed_submit_work
            calls = 0

            def omit_preliminary_check(events, **arguments):
                nonlocal calls
                calls += 1
                # Isolate the authoritative second check: diagnostics alone
                # must not be the only protection against a stale precheck.
                if calls > 1:
                    return guard(events, **arguments)
                return None

            before = ledger.events()
            with patch.object(
                ScheduledGPUCloudBackend,
                "_require_unconsumed_submit_work",
                side_effect=omit_preliminary_check,
            ):
                with self.assertRaisesRegex(ScheduledGPURecoveryBlocked, "exact work"):
                    backend.submit_planned(
                        local, cloud, decision, idempotency_key="locked-request", **authority
                    )
            self.assertEqual(calls, 2)
            self.assertEqual(ledger.events(), before)
            self.assertEqual(len(self._consumptions(ledger)), 1)
            self.assertEqual(transport.submit_calls, 1)
            self.assertEqual(backend._jobs, {})

    def test_distinct_cloud_spec_can_use_the_same_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            transport, backend, registry, ledger, local, cloud, budget, _, _ = runtime
            self._lose_first_response(runtime)
            distinct = replace(cloud, run_id="distinct-cloud-work")
            decision, authority = self._authority(
                registry, ledger, local, distinct, budget, "distinct-decision"
            )
            receipt = backend.submit_planned(
                local, distinct, decision, idempotency_key="distinct-request", **authority
            )
            self.assertEqual(transport.submit_calls, 2)
            self.assertEqual(receipt.state, RunState.QUEUED)
            self.assertFalse(receipt.scientific_evidence)
            consumptions = self._consumptions(ledger)
            self.assertEqual(len(consumptions), 2)
            bindings = tuple(
                thaw_json(event.metadata)["compute_escalation_submission_consumption"]
                for event in consumptions
            )
            self.assertEqual(
                {item["cloud_spec_sha256"] for item in bindings},
                {cloud.sha256, distinct.sha256},
            )
            self.assertEqual(bindings[0]["budget_sha256"], bindings[1]["budget_sha256"])

    def test_same_authority_replay_and_requeue_remain_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(
                Path(directory),
                maximum_total_attempts=2,
                initial_decision_label="successful-decision",
            )
            transport, backend, registry, ledger, local, cloud, budget, decision, authority = runtime
            transport.lose_next_submit_response = False
            receipt = backend.submit_planned(
                local, cloud, decision, idempotency_key="successful-request", **authority
            )
            restored = ScheduledGPUCloudBackend(
                transport, artifact_registry=registry, event_ledger=ledger
            )
            replay = restored.submit_planned(
                local, cloud, decision, idempotency_key="successful-request", **authority
            )
            self.assertEqual(replay.job_id, receipt.job_id)
            provider_id = next(iter(transport.requests))
            token = "fixture-checkpoint"
            transport.statuses[provider_id] = ScheduledGPUStatus(
                provider_id, RunState.PREEMPTED, checkpoint_token=token
            )
            restored.reconcile(receipt.job_id)
            resumed = restored.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(resumed.state, RunState.QUEUED)
            restarted = ScheduledGPUCloudBackend(
                transport, artifact_registry=registry, event_ledger=ledger
            )
            self.assertEqual(
                restarted.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token).state,
                RunState.QUEUED,
            )
            self.assertEqual(transport.submit_calls, 1)
            self.assertEqual(len(transport.requeue_calls), 1)
            self.assertEqual(len(self._consumptions(ledger)), 2)
            self.assertEqual(resumed.validation_status.value, "UNTESTED")
            self.assertFalse(resumed.scientific_evidence)

    def test_preissued_authorization_remains_request_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(
                Path(directory), initial_decision_label="preissued-decision"
            )
            transport, backend, registry, ledger, local, cloud, budget, decision, authority = runtime
            authorization = self._preissue(
                registry, ledger, local, cloud, decision, authority, "bound-request"
            )
            before = ledger.events()
            with self.assertRaisesRegex(ExperimentError, "not exactly bound"):
                backend.submit_planned(
                    local, cloud, decision, idempotency_key="different-request", **authorization
                )
            self.assertEqual(ledger.events(), before)
            self.assertEqual(transport.submit_calls, 0)
            self.assertEqual(self._consumptions(ledger), ())
            self.assertEqual(backend._jobs, {})

    def test_preissued_authorization_does_not_waive_fresh_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(
                Path(directory), initial_decision_label="stale-decision"
            )
            transport, backend, registry, ledger, local, cloud, budget, decision, authority = runtime
            authorization = self._preissue(
                registry, ledger, local, cloud, decision, authority, "stale-request"
            )
            last = ledger.events()[-1]
            ledger.append(LedgerEvent.create(
                run_id=self.run_id,
                actor_role=Role.EXPERIMENT_RUNNER,
                state_before=last.state_after,
                requested_state_after=last.state_after,
                artifact_hashes=(authority["authority_artifact_sha256"],),
                code_version=f"sha256:{cloud.code_sha256}",
                configuration_hash=cloud.configuration_sha256,
                dataset_identifiers=(cloud.data_sha256,),
                random_seeds=cloud.seeds,
                evaluator_outputs=(),
                reason="unrelated fixture checkpoint after authorization",
                event_type="CHECKPOINT",
                prior_event_hash=last.event_hash,
            ))
            before = ledger.events()
            with self.assertRaisesRegex(ExperimentError, "fresh ledger head"):
                backend.submit_planned(
                    local, cloud, decision, idempotency_key="stale-request", **authorization
                )
            self.assertEqual(ledger.events(), before)
            self.assertEqual(transport.submit_calls, 0)
            self.assertEqual(self._consumptions(ledger), ())
            self.assertEqual(backend._jobs, {})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
