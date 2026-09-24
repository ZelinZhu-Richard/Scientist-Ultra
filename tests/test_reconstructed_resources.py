"""Semantic reconstruction of frozen local resource-accounting guarantees.

These checks are newly authored against the recovered ``resources.py`` API;
they are not the missing historical test source.  All observations use
deterministic injected clocks and probes, and all filesystem work is confined
to per-test TemporaryDirectory fixtures.
"""

from __future__ import annotations

from collections import namedtuple
import json
import math
from pathlib import Path
import tempfile
import unittest

from scientist_one.resources import (
    GIB,
    MemoryObservation,
    PressureObservation,
    ResourceAction,
    ResourceConfig,
    ResourceConfigError,
    ResourceController,
    ResourceLimitError,
    ResourceRuntimeState,
    ResourceSnapshot,
    ValidityBudget,
    conservative_disk_reserve,
    parse_vm_stat,
)


DiskUsage = namedtuple("DiskUsage", "total used free")


class FakeClock:
    def __init__(self, monotonic: float = 0.0, wall: float = 1_000.0) -> None:
        self.monotonic_value = monotonic
        self.wall_value = wall

    def monotonic(self) -> float:
        return self.monotonic_value

    def wall(self) -> float:
        return self.wall_value


class FrozenResourceFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve() / "project"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def controller(
        self,
        *,
        config: ResourceConfig | None = None,
        clock: FakeClock | None = None,
        disk: DiskUsage = DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
        memory: MemoryObservation = MemoryObservation(1_000, 400, "AVAILABLE", "synthetic"),
        pressure: PressureObservation = PressureObservation(
            "nominal", "nominal", "AVAILABLE", "synthetic"
        ),
        artifact_roots: tuple[str, ...] = ("artifacts",),
        validity_budget_units: int | None = None,
        run_id: str = "resource-run",
    ) -> ResourceController:
        injected_clock = clock or FakeClock()
        return ResourceController(
            config or ResourceConfig(),
            self.root,
            clock=injected_clock.monotonic,
            wall_clock=injected_clock.wall,
            sleeper=lambda _delay: None,
            disk_usage_probe=lambda _path: disk,
            memory_probe=lambda: memory,
            pressure_probe=lambda: pressure,
            artifact_roots=artifact_roots,
            validity_budget_units=validity_budget_units,
            run_id=run_id,
        )

    @staticmethod
    def healthy_snapshot(**updates: object) -> ResourceSnapshot:
        values: dict[str, object] = {
            "monotonic_time": 10.0,
            "wall_elapsed_seconds": 10.0,
            "artifact_bytes": 100,
            "concurrent_experiments": 0,
            "cpu_workers": 0,
            "gpu_jobs": 0,
            "physical_memory_bytes": 1_000,
            "memory_used_bytes": 400,
            "disk_total_bytes": 500 * GIB,
            "disk_free_bytes": 100 * GIB,
        }
        values.update(updates)
        return ResourceSnapshot(**values)  # type: ignore[arg-type]


class ResourceConfigReconstructionTests(FrozenResourceFixtures):
    def test_config_round_trip_and_project_local_json_are_exact(self) -> None:
        config = ResourceConfig(
            maximum_wall_clock_seconds=120.0,
            maximum_concurrent_experiments=3,
            default_device="cpu",
        )
        self.assertEqual(ResourceConfig.from_mapping(config.to_dict()), config)
        path = self.root / "limits.json"
        path.write_bytes(json.dumps(config.to_dict(), sort_keys=True).encode("utf-8"))
        self.assertEqual(ResourceConfig.from_json(path, project_root=self.root), config)

    def test_config_invalid_values_fail_closed_individually(self) -> None:
        factories = (
            lambda: ResourceConfig(memory_soft_fraction=0.8, memory_hard_fraction=0.7),
            lambda: ResourceConfig(maximum_artifact_bytes=True),  # type: ignore[arg-type]
            lambda: ResourceConfig(maximum_wall_clock_seconds=math.inf),
            lambda: ResourceConfig(validity_reserve_fraction=0.29),
            lambda: ResourceConfig(default_device="cuda"),  # type: ignore[arg-type]
            lambda: ResourceConfig.from_mapping({"surprise": 1}),
        )
        for factory in factories:
            with self.assertRaises(ResourceConfigError):
                factory()

    def test_config_json_rejects_duplicate_nonfinite_and_escape_inputs(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"maximum_wall_clock_seconds":1,"maximum_wall_clock_seconds":2}',
            encoding="utf-8",
        )
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(duplicate, project_root=self.root)
        nonfinite = self.root / "nan.json"
        nonfinite.write_text('{"maximum_wall_clock_seconds":NaN}', encoding="utf-8")
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(nonfinite, project_root=self.root)
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json("../outside.json", project_root=self.root)
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(self.root.parent / "outside.json", project_root=self.root)

    def test_disk_reserve_uses_the_greater_configured_or_fractional_bound(self) -> None:
        self.assertEqual(conservative_disk_reserve(100 * GIB), 25 * GIB)
        self.assertEqual(conservative_disk_reserve(500 * GIB), 50 * GIB)
        with self.assertRaises(ResourceConfigError):
            conservative_disk_reserve(100, configured_fraction=0.0)

    def test_vm_stat_counts_reclaimable_pages_and_clamps_to_physical_memory(self) -> None:
        output = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                     6919.
Pages active:                                 549856.
Pages inactive:                               662839.
Pages speculative:                              2656.
Pages wired down:                             364714.
Pages purgeable:                                5634.
"""
        observation = parse_vm_stat(output, 48 * GIB)
        expected_available = (6919 + 662839 + 2656 + 5634) * 16384
        self.assertEqual(observation.status, "AVAILABLE")
        self.assertEqual(observation.used_bytes, 48 * GIB - expected_available)
        self.assertIn("clamp", observation.detail or "")
        overflowing = output.replace("6919.", "999999999999.")
        self.assertEqual(parse_vm_stat(overflowing, 48 * GIB).used_bytes, 0)

    def test_vm_stat_malformed_or_incomplete_input_is_unavailable(self) -> None:
        for output in (
            "garbage",
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 1.\n",
            "Mach Virtual Memory Statistics: (page size of x bytes)\nPages free: 1.\n",
        ):
            observation = parse_vm_stat(output, 48 * GIB)
            self.assertEqual(observation.status, "ERROR")
            self.assertIsNone(observation.used_bytes)

    def test_snapshot_validates_bounds_and_reports_memory_fraction(self) -> None:
        snapshot = self.healthy_snapshot()
        self.assertAlmostEqual(snapshot.memory_fraction or 0.0, 0.4)
        with self.assertRaises(ResourceConfigError):
            self.healthy_snapshot(memory_used_bytes=1_001)
        with self.assertRaises(ResourceConfigError):
            self.healthy_snapshot(disk_free_bytes=501 * GIB)
        with self.assertRaises(ResourceConfigError):
            self.healthy_snapshot(memory_pressure="unknown-value")


class ResourceDecisionReconstructionTests(FrozenResourceFixtures):
    def test_wall_artifact_and_disk_budget_breaches_stop_before_new_work(self) -> None:
        wall_controller = self.controller(config=ResourceConfig(maximum_wall_clock_seconds=20))
        wall = wall_controller.evaluate(self.healthy_snapshot(wall_elapsed_seconds=20))
        self.assertEqual(wall.action, ResourceAction.STOP_BUDGET)
        self.assertFalse(wall.allowed)
        self.assertIn("WALL_CLOCK_BUDGET_EXHAUSTED", wall.reasons)

        artifact_controller = self.controller(config=ResourceConfig(maximum_artifact_bytes=1_000))
        artifact = artifact_controller.evaluate(
            self.healthy_snapshot(artifact_bytes=900), estimated_artifact_bytes=100
        )
        self.assertIn("ARTIFACT_BUDGET_EXHAUSTED", artifact.reasons)

        disk_controller = self.controller()
        disk = disk_controller.evaluate(
            self.healthy_snapshot(disk_total_bytes=500 * GIB, disk_free_bytes=55 * GIB),
            estimated_artifact_bytes=5 * GIB,
        )
        self.assertEqual(disk.action, ResourceAction.STOP_BUDGET)
        self.assertIn("DISK_RESERVE_BREACH", disk.reasons)
        self.assertEqual(disk.effective_disk_reserve_bytes, 50 * GIB)

    def test_memory_pressure_crashes_stall_and_growth_pause_with_checkpoint(self) -> None:
        controller = self.controller(config=ResourceConfig(stall_timeout_seconds=30))
        decision = controller.evaluate(
            self.healthy_snapshot(
                memory_used_bytes=700,
                thermal_pressure="critical",
                worker_crashes=3,
                stalled_seconds=30,
                artifact_growth_bytes_per_second=64 * 1024**2,
            )
        )
        self.assertEqual(decision.action, ResourceAction.PAUSE)
        self.assertTrue(decision.checkpoint_required)
        self.assertFalse(decision.accept_new_work)
        for reason in (
            "MEMORY_HARD_LIMIT_REACHED",
            "SEVERE_THERMAL_PRESSURE",
            "REPEATED_WORKER_CRASHES",
            "WORK_STALLED",
            "ABNORMAL_ARTIFACT_GROWTH",
        ):
            self.assertIn(reason, decision.reasons)

    def test_cpu_and_gpu_slot_requests_refuse_overcommit(self) -> None:
        controller = self.controller(config=ResourceConfig(cpu_worker_limit=1, gpu_job_limit=1))
        decision = controller.evaluate(
            self.healthy_snapshot(cpu_workers=1, gpu_jobs=1),
            requested_cpu_workers=1,
            requested_gpu_jobs=1,
        )
        self.assertEqual(decision.action, ResourceAction.PAUSE)
        self.assertIn("CPU_WORKER_LIMIT_REACHED", decision.reasons)
        self.assertIn("GPU_JOB_LIMIT_REACHED", decision.reasons)
        self.assertFalse(decision.allowed)

    def test_unknown_memory_or_disk_probes_fail_closed_for_new_work(self) -> None:
        def fail() -> object:
            raise OSError("synthetic probe denied")

        controller = ResourceController(
            ResourceConfig(),
            self.root,
            clock=lambda: 0.0,
            wall_clock=lambda: 1_000.0,
            disk_usage_probe=lambda _path: fail(),
            memory_probe=fail,  # type: ignore[arg-type]
            pressure_probe=fail,  # type: ignore[arg-type]
            artifact_roots=(),
        )
        snapshot = controller.snapshot()
        self.assertIsNone(snapshot.memory_fraction)
        self.assertTrue(any("synthetic probe denied" in note for note in snapshot.probe_notes))
        decision = controller.evaluate(snapshot)
        self.assertEqual(decision.action, ResourceAction.PAUSE)
        self.assertIn("MEMORY_STATUS_UNAVAILABLE", decision.reasons)
        self.assertIn("DISK_STATUS_UNAVAILABLE", decision.reasons)

    def test_checkpoint_boundary_and_backoff_are_deterministic_and_bounded(self) -> None:
        clock = FakeClock()
        controller = self.controller(
            config=ResourceConfig(
                checkpoint_interval_seconds=10,
                backoff_initial_seconds=2,
                backoff_maximum_seconds=10,
            ),
            clock=clock,
        )
        decision = controller.evaluate(self.healthy_snapshot(monotonic_time=10, wall_elapsed_seconds=10))
        self.assertEqual(decision.action, ResourceAction.CHECKPOINT)
        self.assertTrue(decision.checkpoint_required)
        self.assertEqual(controller.backoff_seconds(0), 0.0)
        self.assertEqual(controller.backoff_seconds(1), 2.0)
        self.assertEqual(controller.backoff_seconds(10), 10.0)

    def test_artifact_usage_counts_regular_bytes_and_observes_growth(self) -> None:
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        payload = artifacts / "nested"
        payload.mkdir()
        data = payload / "result.bin"
        data.write_bytes(b"1234")
        (payload / "alias.bin").symlink_to(data)
        clock = FakeClock()
        controller = self.controller(clock=clock)
        first = controller.snapshot(now=0.0)
        self.assertEqual(first.artifact_bytes, 4)
        data.write_bytes(b"1234567890")
        second = controller.snapshot(now=2.0)
        self.assertEqual(second.artifact_bytes, 10)
        self.assertEqual(second.artifact_growth_bytes_per_second, 3.0)


class ResourceAccountingReconstructionTests(FrozenResourceFixtures):
    def test_leases_enforce_experiment_cpu_and_gpu_limits_and_release_once(self) -> None:
        controller = self.controller(
            config=ResourceConfig(
                maximum_concurrent_experiments=1,
                cpu_worker_limit=1,
                gpu_job_limit=1,
            )
        )
        lease = controller.acquire("one", cpu_workers=1, gpu_jobs=1)
        with self.assertRaises(ResourceLimitError):
            controller.acquire("two", cpu_workers=1, gpu_jobs=1)
        lease.release()
        with self.assertRaises(ResourceLimitError):
            lease.release()
        with controller.acquire("two", cpu_workers=1, gpu_jobs=1):
            pass

    def test_validity_budget_partitions_integer_reserve_without_exploration_invasion(self) -> None:
        budget = ValidityBudget(11, 0.40)
        initial = budget.snapshot()
        self.assertEqual((initial.exploratory_limit, initial.confirmatory_reserve), (6, 5))
        budget.charge("PILOT", 6)
        with self.assertRaises(ResourceLimitError):
            budget.charge("PILOT", 1)
        self.assertEqual(budget.snapshot().confirmatory_remaining, 5)
        budget.charge("CONFIRMATORY_RUN", 5)
        self.assertEqual(budget.snapshot().confirmatory_remaining, 0)
        with self.assertRaises(ResourceLimitError):
            budget.charge("CONFIRMATORY_RUN", 1)

    def test_validity_budget_rejects_unknown_stage_and_invalid_usage_without_partial_charge(self) -> None:
        budget = ValidityBudget(10, 0.40)
        with self.assertRaises(ResourceConfigError):
            budget.can_charge("unknown", 1)
        with self.assertRaises(ResourceConfigError):
            budget.charge("PILOT", -1)
        before = budget.snapshot()
        with self.assertRaises(ResourceLimitError):
            budget.charge("PILOT", before.exploratory_limit + 1)
        self.assertEqual(budget.snapshot(), before)

    def test_confirmatory_charge_remains_consumed_after_lease_release(self) -> None:
        controller = self.controller(validity_budget_units=10)
        with controller.acquire("confirm-1", validity_stage="CONFIRMATORY_RUN", validity_units=4):
            pass
        budget = controller.validity_budget
        self.assertIsNotNone(budget)
        self.assertEqual(budget.snapshot().confirmatory_used, 4)  # type: ignore[union-attr]
        with self.assertRaises(ResourceLimitError):
            controller.acquire("confirm-2", validity_stage="CONFIRMATORY_RUN", validity_units=1)
        self.assertEqual(budget.snapshot().confirmatory_used, 4)  # type: ignore[union-attr]

    def test_worker_crash_accounting_is_monotone_until_explicit_clear(self) -> None:
        controller = self.controller()
        self.assertEqual(controller.register_worker_crash("worker-a"), 1)
        self.assertEqual(controller.register_worker_crash("worker-a"), 2)
        self.assertEqual(controller.register_worker_crash("worker-b"), 1)
        snapshot = controller.snapshot()
        self.assertEqual(snapshot.worker_crashes, 2)
        controller.clear_worker_crashes("worker-a")
        self.assertEqual(controller.snapshot().worker_crashes, 1)
        with self.assertRaises(ResourceConfigError):
            controller.register_worker_crash("")

    def test_runtime_export_is_observational_and_preserves_validity_usage(self) -> None:
        clock = FakeClock()
        controller = self.controller(clock=clock, validity_budget_units=10, run_id="export-run")
        with controller.acquire("pilot", validity_stage="PILOT", validity_units=2):
            pass
        before = controller.export_state()
        after = controller.export_state()
        self.assertEqual(before, after)
        self.assertEqual(before.exploratory_used, 2)
        clock.monotonic_value = 5.0
        clock.wall_value = 1_005.0
        controller.record_progress()
        progressed = controller.export_state()
        self.assertEqual(progressed.wall_elapsed_seconds, 5.0)
        self.assertEqual(progressed.progress_elapsed_seconds, 5.0)
        with self.assertRaises(ResourceConfigError):
            controller.export_state(now=6.0)

    def test_runtime_resume_preserves_downtime_and_never_replenishes_budget(self) -> None:
        config = ResourceConfig(maximum_wall_clock_seconds=60)
        clock = FakeClock(100.0, 1_000.0)
        controller = self.controller(
            config=config,
            clock=clock,
            validity_budget_units=10,
            run_id="resume-run",
        )
        with controller.acquire("pilot", validity_stage="PILOT", validity_units=5):
            pass
        clock.monotonic_value = 150.0
        clock.wall_value = 1_050.0
        controller.snapshot()
        state = controller.export_state()
        self.assertEqual(state.wall_elapsed_seconds, 50.0)
        restored_clock = FakeClock(0.0, 1_060.0)
        restored = ResourceController.from_runtime_state(
            config,
            self.root,
            state,
            clock=restored_clock.monotonic,
            wall_clock=restored_clock.wall,
            sleeper=lambda _delay: None,
            disk_usage_probe=lambda _path: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1_000, 400, "AVAILABLE", "synthetic"),
            pressure_probe=lambda: PressureObservation(
                "nominal", "nominal", "AVAILABLE", "synthetic"
            ),
            artifact_roots=(),
        )
        resumed_snapshot = restored.snapshot(now=0.0)
        self.assertEqual(resumed_snapshot.wall_elapsed_seconds, 60.0)
        self.assertEqual(restored.validity_budget.snapshot().exploratory_used, 5)  # type: ignore[union-attr]
        self.assertEqual(restored.evaluate(resumed_snapshot).action, ResourceAction.STOP_BUDGET)
        rollback_clock = FakeClock(0.0, 1_049.0)
        with self.assertRaises(ResourceConfigError):
            ResourceController.from_runtime_state(
                config,
                self.root,
                state,
                clock=rollback_clock.monotonic,
                wall_clock=rollback_clock.wall,
                artifact_roots=(),
            )

    def test_runtime_state_schema_round_trip_and_inconsistent_values_fail_closed(self) -> None:
        state = ResourceRuntimeState(
            schema_version="1.0",
            run_id="run-state",
            config_sha256="a" * 64,
            wall_elapsed_seconds=10.0,
            checkpoint_elapsed_seconds=4.0,
            progress_elapsed_seconds=7.0,
            worker_crashes={"worker-b": 2, "worker-a": 1},
            wall_started_at_epoch_seconds=1_000.0,
            wall_observed_at_epoch_seconds=1_010.0,
            validity_total_units=10,
            exploratory_used=3,
            confirmatory_used=2,
        )
        self.assertEqual(ResourceRuntimeState.from_mapping(state.to_dict()), state)
        with self.assertRaises(ResourceConfigError):
            ResourceRuntimeState(
                **{
                    **state.to_dict(),
                    "checkpoint_elapsed_seconds": 11.0,
                }
            )
        with self.assertRaises(ResourceConfigError):
            ResourceRuntimeState(
                **{
                    **state.to_dict(),
                    "validity_total_units": None,
                    "exploratory_used": 1,
                }
            )
        with self.assertRaises(ResourceConfigError):
            ResourceRuntimeState.from_mapping({**state.to_dict(), "extra": True})

    def test_monotone_clock_is_required_for_snapshot_checkpoint_progress_and_export(self) -> None:
        clock = FakeClock()
        controller = self.controller(clock=clock)
        controller.snapshot(now=10.0)
        operations = (
            lambda: controller.snapshot(now=9.0),
            lambda: controller.export_state(now=9.0),
            lambda: controller.checkpoint_due(now=9.0),
            lambda: controller.mark_checkpoint(now=9.0),
            lambda: controller.record_progress(now=9.0),
        )
        for operation in operations:
            with self.assertRaises(ResourceConfigError):
                operation()


if __name__ == "__main__":
    unittest.main()
