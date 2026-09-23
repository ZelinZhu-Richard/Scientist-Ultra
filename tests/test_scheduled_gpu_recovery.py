"""Restart-boundary tests for the registry/ledger-native scheduled backend."""

from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path
from unittest.mock import patch

from scientist_one.experiments import (
    ExperimentIntegrityError,
    RunState,
    ScheduledGPUArtifactBundle,
    ScheduledGPURecoveryBlocked,
    ScheduledGPUStatus,
    StagedArtifact,
)
from scientist_one.ledger import LedgerEvent
from scientist_one.models import thaw_json
from scientist_one.roles import Role

# Reuse the accepted fixture and authority harness.  The fixture remains an
# UNTESTED transport boundary; these tests only exercise local durability.
from tests import test_experiments as experiment_tests


class ScheduledGPURecoveryTests(unittest.TestCase):
    def _authorized(
        self, root: Path, label: str
    ) -> tuple[object, object, object, object, object]:
        transport = experiment_tests.StructuredSchedulerFixture()
        local = experiment_tests.spec(f"{label}-local")
        cloud = experiment_tests.spec(
            f"{label}-cloud",
            profile=experiment_tests.gpu_profile(),
            estimate=experiment_tests.gpu_estimate(),
        )
        decision = experiment_tests.escalation_decision(local, cloud, f"{label}-decision")
        harness = experiment_tests.ScheduledGPUBackendTests("run")
        backend, registry, authority = harness._authorized_backend(
            transport, local, cloud, decision, root=root
        )
        return transport, backend, registry, (local, cloud, decision), authority

    @staticmethod
    def _append_unrelated_checkpoint(backend: object, authority: object, cloud: object) -> None:
        ledger = backend._ledger
        last = ledger.events()[-1]
        ledger.append(
            LedgerEvent.create(
                run_id=authority["authority_run_id"], actor_role=Role.EXPERIMENT_RUNNER,
                state_before=last.requested_state_after,
                requested_state_after=last.requested_state_after,
                artifact_hashes=(authority["authority_artifact_sha256"],),
                code_version=f"sha256:{cloud.code_sha256}",
                configuration_hash=cloud.configuration_sha256,
                dataset_identifiers=(cloud.data_sha256,), random_seeds=cloud.seeds,
                evaluator_outputs=(), reason="unrelated scheduler fixture checkpoint",
                event_type="CHECKPOINT", prior_event_hash=last.event_hash,
            )
        )

    def test_committed_submit_restarts_without_a_second_submit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "restart")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(
                local, cloud, decision, idempotency_key="restart-submit", **authority
            )
            restored = type(backend)(
                transport, artifact_registry=registry, event_ledger=backend._ledger
            )
            replay = restored.submit_planned(
                local, cloud, decision, idempotency_key="restart-submit", **authority
            )
            self.assertEqual(replay.job_id, receipt.job_id)
            self.assertEqual(transport.submit_calls, 1)
            self.assertEqual(replay.validation_status.value, "UNTESTED")
            self.assertFalse(replay.scientific_evidence)

    def test_consumed_unadmitted_submit_blocks_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "ambiguous")
            local, cloud, decision = inputs

            def interrupted(_request: object) -> object:
                raise RuntimeError("fixture response window lost")

            transport.submit = interrupted  # type: ignore[method-assign]
            with self.assertRaises(RuntimeError):
                backend.submit_planned(
                    local, cloud, decision, idempotency_key="ambiguous-submit", **authority
                )
            restored = type(backend)(
                transport, artifact_registry=registry, event_ledger=backend._ledger
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                restored.submit_planned(
                    local, cloud, decision, idempotency_key="ambiguous-submit", **authority
                )
            self.assertEqual(transport.submit_calls, 0)

    def test_consumed_unadmitted_requeue_blocks_same_process_and_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "requeue-ambiguous")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="rq-submit", **authority)
            provider_job_id = next(iter(transport.requests))
            token = "rq-checkpoint"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.PREEMPTED, checkpoint_token=token)
            backend.reconcile(receipt.job_id)
            def interrupted(*_args: object, **_kwargs: object) -> object:
                raise RuntimeError("fixture requeue response window lost")
            transport.requeue = interrupted  # type: ignore[method-assign]
            with self.assertRaises(RuntimeError):
                backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            restored = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                restored.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(transport.requeue_calls, [])

    def test_cancel_intent_is_reconciled_not_reissued_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "cancel")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="cancel-submit", **authority)
            calls = 0
            original = transport.cancel
            def counted(*args: object, **kwargs: object) -> object:
                nonlocal calls
                calls += 1
                return original(*args, **kwargs)
            transport.cancel = counted  # type: ignore[method-assign]
            self.assertEqual(backend.cancel(receipt.job_id).state, RunState.CANCELLED)
            restored = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            self.assertEqual(restored.cancel(receipt.job_id).state, RunState.CANCELLED)
            self.assertEqual(calls, 1)

    def test_ambiguous_cancel_allows_status_only_not_a_second_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "cancel-ambiguous")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="cancel-ambiguous-submit", **authority)
            def interrupted(*_args: object, **_kwargs: object) -> object:
                raise RuntimeError("fixture cancel response window lost")
            transport.cancel = interrupted  # type: ignore[method-assign]
            with self.assertRaises(RuntimeError):
                backend.cancel(receipt.job_id)
            restored = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            self.assertEqual(restored.reconcile(receipt.job_id).state, RunState.QUEUED)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                restored.cancel(receipt.job_id)

    def test_unrelated_shared_ledger_checkpoint_does_not_block_job_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "interleave")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="interleave-submit", **authority)
            self._append_unrelated_checkpoint(backend, authority, cloud)
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.RUNNING)
            self.assertEqual(backend.reconcile(receipt.job_id).state, RunState.RUNNING)

    def test_unchanged_polls_are_deduplicated_and_snapshot_ceiling_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "polls")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="poll-submit", **authority)
            provider_job_id = next(iter(transport.requests))
            before = len(registry.list_records())
            backend.reconcile(receipt.job_id)
            self.assertEqual(len(registry.list_records()), before)
            # The submission snapshot occupies one of the finite 64 slots.
            for position in range(1, 64):
                transport.statuses[provider_job_id] = ScheduledGPUStatus(
                    provider_job_id, RunState.QUEUED, queue_position=position
                )
                backend.reconcile(receipt.job_id)
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.QUEUED, queue_position=64
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.reconcile(receipt.job_id)

    def test_stale_backend_cannot_append_a_competing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "stale")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="stale-submit", **authority)
            stale = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.RUNNING)
            backend.reconcile(receipt.job_id)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                stale.reconcile(receipt.job_id)

    def test_stale_preempted_backend_cannot_requeue_after_newer_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "stale-preempt")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="stale-preempt", **authority)
            provider_job_id = next(iter(transport.requests))
            token = "stale-preempt-token"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.PREEMPTED, checkpoint_token=token)
            backend.reconcile(receipt.job_id)
            stale = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            backend.cancel(receipt.job_id)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                stale.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(transport.requeue_calls, [])

    def test_ambiguous_requeue_blocks_cancel_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "requeue-cancel")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="requeue-cancel", **authority)
            provider_job_id = next(iter(transport.requests))
            token = "requeue-cancel-token"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.PREEMPTED, checkpoint_token=token)
            backend.reconcile(receipt.job_id)
            def interrupted_requeue(*_args: object, **_kwargs: object) -> object:
                raise RuntimeError("fixture requeue response window lost")
            transport.requeue = interrupted_requeue  # type: ignore[method-assign]
            with self.assertRaises(RuntimeError):
                backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            cancel_calls = 0
            original_cancel = transport.cancel
            def counted_cancel(*args: object, **kwargs: object) -> object:
                nonlocal cancel_calls
                cancel_calls += 1
                return original_cancel(*args, **kwargs)
            transport.cancel = counted_cancel  # type: ignore[method-assign]
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.cancel(receipt.job_id)
            self.assertEqual(cancel_calls, 0)

    def test_pretransport_capacity_failure_never_submits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "capacity")
            local, cloud, decision = inputs
            backend._preflight_recovery_capacity = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
                ScheduledGPURecoveryBlocked("fixture capacity exhausted")
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.submit_planned(local, cloud, decision, idempotency_key="capacity-submit", **authority)
            self.assertEqual(transport.submit_calls, 0)

    def test_per_job_snapshot_exhaustion_blocks_requeue_before_consumption_or_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "requeue-ceiling")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="requeue-ceiling", **authority)
            provider_job_id = next(iter(transport.requests))
            token = "requeue-ceiling-token"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.PREEMPTED, checkpoint_token=token)
            backend.reconcile(receipt.job_id)
            events_before = tuple(backend._ledger.events())  # type: ignore[attr-defined]
            with patch("scientist_one.experiments._MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB", 2):
                with self.assertRaises(ScheduledGPURecoveryBlocked):
                    backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(transport.requeue_calls, [])
            self.assertEqual(tuple(backend._ledger.events()), events_before)  # type: ignore[attr-defined]

    def test_per_job_snapshot_exhaustion_blocks_cancel_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "cancel-ceiling")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="cancel-ceiling", **authority)
            cancel_calls = 0
            original_cancel = transport.cancel
            def counted_cancel(*args: object, **kwargs: object) -> object:
                nonlocal cancel_calls
                cancel_calls += 1
                return original_cancel(*args, **kwargs)
            transport.cancel = counted_cancel  # type: ignore[method-assign]
            with patch("scientist_one.experiments._MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB", 2):
                with self.assertRaises(ScheduledGPURecoveryBlocked):
                    backend.cancel(receipt.job_id)
            self.assertEqual(cancel_calls, 0)

    def test_post_transport_submit_admission_failure_blocks_same_process_replay(self) -> None:
        """A response not admitted to ledger/registry cannot become a live job."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "submit-admission")
            local, cloud, decision = inputs
            backend._persist_recovery_snapshot = lambda _job: (_ for _ in ()).throw(  # type: ignore[method-assign]
                ScheduledGPURecoveryBlocked("fixture post-transport admission failure")
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.submit_planned(local, cloud, decision, idempotency_key="submit-admission", **authority)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.submit_planned(local, cloud, decision, idempotency_key="submit-admission", **authority)
            self.assertEqual(transport.submit_calls, 1)

    def test_post_transport_requeue_admission_failure_blocks_same_process_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "requeue-admission")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="requeue-admission", **authority)
            provider_job_id = next(iter(transport.requests))
            token = "requeue-admission-token"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.PREEMPTED, checkpoint_token=token)
            backend.reconcile(receipt.job_id)
            backend._persist_recovery_snapshot = lambda _job: (_ for _ in ()).throw(  # type: ignore[method-assign]
                ScheduledGPURecoveryBlocked("fixture post-transport admission failure")
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(len(transport.requeue_calls), 1)

    def test_post_transport_cancel_admission_failure_blocks_same_process_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "cancel-admission")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="cancel-admission", **authority)
            original_persist = backend._persist_recovery_snapshot
            persistence_calls = 0
            def fail_response_only(job: object, **_kwargs: object) -> None:
                nonlocal persistence_calls
                persistence_calls += 1
                if persistence_calls == 1:
                    original_persist(job)
                    return
                raise ScheduledGPURecoveryBlocked("fixture post-transport admission failure")
            backend._persist_recovery_snapshot = fail_response_only  # type: ignore[method-assign]
            cancel_calls = 0
            original_cancel = transport.cancel
            def counted_cancel(*args: object, **kwargs: object) -> object:
                nonlocal cancel_calls
                cancel_calls += 1
                return original_cancel(*args, **kwargs)
            transport.cancel = counted_cancel  # type: ignore[method-assign]
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.cancel(receipt.job_id)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.cancel(receipt.job_id)
            self.assertEqual(cancel_calls, 1)

    def test_collect_admission_failure_never_exposes_cached_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "collect-admission")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="collect-admission", **authority)
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.SUCCEEDED)
            backend.reconcile(receipt.job_id)
            artifact_root = root / "collect-admission-return"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest=manifest,
                artifacts=tuple(StagedArtifact(item, (artifact_root / item.path).read_bytes()) for item in manifest.artifacts),
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id, spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256, attempt=1,
                resumed_checkpoint_sha256=None, requeue_history=(),
            )
            backend._persist_recovery_snapshot = lambda _job: (_ for _ in ()).throw(  # type: ignore[method-assign]
                ScheduledGPURecoveryBlocked("fixture collect admission failure")
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.collect(receipt.job_id)
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                backend.collect(receipt.job_id)

    def test_staged_artifacts_directly_collects_and_reads_current_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, _registry, inputs, authority = self._authorized(root, "direct-staged")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="direct-staged", **authority)
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.SUCCEEDED)
            artifact_root = root / "direct-staged-return"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            expected = tuple(
                StagedArtifact(item, (artifact_root / item.path).read_bytes())
                for item in manifest.artifacts
            )
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest=manifest, artifacts=expected,
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id, spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256, attempt=1,
                resumed_checkpoint_sha256=None, requeue_history=(),
            )
            self.assertEqual(backend.staged_artifacts(receipt.job_id), expected)
            self.assertEqual(
                backend._jobs[receipt.job_id].bundle.artifacts,  # type: ignore[attr-defined]
                expected,
            )

    def test_invalid_refetch_persists_invalid_output_and_restart_refuses_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "invalid-refetch")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(local, cloud, decision, idempotency_key="invalid-refetch", **authority)
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(provider_job_id, RunState.SUCCEEDED)
            artifact_root = root / "invalid-refetch-return"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            valid_bundle = ScheduledGPUArtifactBundle(
                manifest=manifest,
                artifacts=tuple(StagedArtifact(item, (artifact_root / item.path).read_bytes()) for item in manifest.artifacts),
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id, spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256, attempt=1,
                resumed_checkpoint_sha256=None, requeue_history=(),
            )
            transport.bundles[provider_job_id] = valid_bundle
            backend.collect(receipt.job_id)
            restored = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            transport.bundles[provider_job_id] = {}  # type: ignore[assignment]
            with self.assertRaises(ExperimentIntegrityError):
                restored.collect(receipt.job_id)
            self.assertEqual(restored.reconcile(receipt.job_id).state, RunState.INVALID_OUTPUT)
            restarted = type(backend)(transport, artifact_registry=registry, event_ledger=backend._ledger)
            with self.assertRaises(ExperimentIntegrityError):
                restarted.collect(receipt.job_id)

    def test_preemption_restores_only_a_matching_volatile_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "checkpoint")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(
                local, cloud, decision, idempotency_key="checkpoint-submit", **authority
            )
            provider_job_id = next(iter(transport.requests))
            token = "volatile-checkpoint-token"
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.PREEMPTED, checkpoint_token=token
            )
            backend.reconcile(receipt.job_id)
            for record in registry.list_records():
                if record.logical_type == "scheduled_gpu_recovery_snapshot":
                    self.assertNotIn(token.encode("utf-8"), registry.get_bytes(record.sha256))
            restored = type(backend)(
                transport, artifact_registry=registry, event_ledger=backend._ledger
            )
            self.assertIsNone(restored.preemption_checkpoint(receipt.job_id))
            resumed = restored.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            self.assertEqual(resumed.state, RunState.QUEUED)

    def test_restored_checkpoint_mismatch_blocks_without_requeue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "mismatch")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(
                local, cloud, decision, idempotency_key="mismatch-submit", **authority
            )
            provider_job_id = next(iter(transport.requests))
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.PREEMPTED, checkpoint_token="frozen-token"
            )
            backend.reconcile(receipt.job_id)
            restored = type(backend)(
                transport, artifact_registry=registry, event_ledger=backend._ledger
            )
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.PREEMPTED, checkpoint_token="substituted-token"
            )
            with self.assertRaises(ScheduledGPURecoveryBlocked):
                restored.requeue_from_checkpoint(
                    receipt.job_id, checkpoint_token="substituted-token"
                )
            self.assertEqual(transport.requeue_calls, [])

    def test_requeued_job_restart_retains_digest_and_collects_exact_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport, backend, registry, inputs, authority = self._authorized(root, "collect")
            local, cloud, decision = inputs
            receipt = backend.submit_planned(
                local, cloud, decision, idempotency_key="collect-submit", **authority
            )
            provider_job_id = next(iter(transport.requests))
            token = "resumed-checkpoint"
            checkpoint_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.PREEMPTED, checkpoint_token=token
            )
            backend.reconcile(receipt.job_id)
            backend.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token)
            restored = type(backend)(
                transport, artifact_registry=registry, event_ledger=backend._ledger
            )
            self.assertEqual(
                restored.requeue_from_checkpoint(receipt.job_id, checkpoint_token=token).resumed_from_checkpoint_sha256,
                checkpoint_sha256,
            )
            self.assertEqual(len(transport.requeue_calls), 1)
            artifact_root = root / "returned"
            artifact_root.mkdir()
            manifest = experiment_tests.write_manifest(cloud, artifact_root)
            transport.bundles[provider_job_id] = ScheduledGPUArtifactBundle(
                manifest=manifest,
                artifacts=tuple(
                    StagedArtifact(item, (artifact_root / item.path).read_bytes())
                    for item in manifest.artifacts
                ),
                manifest_bytes=(artifact_root / "output-manifest.json").read_bytes(),
                provider_job_id=provider_job_id,
                spec_sha256=cloud.sha256,
                submission_plan_sha256=receipt.execution_plan_sha256,
                attempt=2,
                resumed_checkpoint_sha256=checkpoint_sha256,
                requeue_history=restored.requeue_lineage(receipt.job_id),
            )
            transport.statuses[provider_job_id] = ScheduledGPUStatus(
                provider_job_id, RunState.SUCCEEDED, attempt=2
            )
            collected = restored.collect(receipt.job_id)
            self.assertEqual(collected.manifest_sha256, hashlib.sha256(collected.manifest_bytes).hexdigest())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
