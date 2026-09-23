"""Deterministic tests for local runtime, device, and recovery controls."""

from __future__ import annotations

from collections import namedtuple
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.device import (
    DeviceConfigurationError,
    DeviceExecutionError,
    DeviceManager,
    HardwareProfiler,
    ParityTolerance,
    _discover_torch_backend,
)
from scientist_one.recovery import (
    CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL,
    CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT,
    ConfirmatoryRevealAuthority,
    ConfirmatoryRerunError,
    LedgerValidationError,
    RecoveryError,
    RecoveryManager,
    ResumeAction,
    FreshCustodyEvidence,
    RegisteredArtifactSelector,
    confirmation_reveal_gate_object_id,
    event_digest,
    register_confirmation_reveal_gate_receipt,
    require_confirmation_reveal_gate_receipt,
)
from scientist_one.holdout import (
    ConfirmatoryEvaluatorSpec,
    HoldoutAccessViolation,
    HoldoutAlreadyRevealed,
    HoldoutCustodyError,
    HoldoutJournalError,
    RevealExecutionClass,
    SimulatedHoldoutCustody,
)
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import MacroState
from scientist_one.orchestrator import ScientistOneOrchestrator
from scientist_one.protocol import (
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ResearchProtocol,
    SeedPolicy,
    StatisticalTestSpec,
    StudyVersion,
    freeze_protocol,
    record_confirmatory_reveal,
    revise_study_version,
)
from scientist_one.roles import Role
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
    ValidityBudgetSnapshot,
    conservative_disk_reserve,
    parse_vm_stat,
)
from scientist_one.security import canonical_json_bytes


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_TMP_ROOT = PROJECT_ROOT / ".scientist-one-build" / "tmp"
TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
DiskUsage = namedtuple("DiskUsage", "total used free")


class ProjectTempCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(dir=TEST_TMP_ROOT)
        self.root = Path(self._temporary.name).resolve()

    def tearDown(self) -> None:
        self._temporary.cleanup()


def healthy_snapshot(**updates: object) -> ResourceSnapshot:
    values: dict[str, object] = {
        "monotonic_time": 10.0,
        "wall_elapsed_seconds": 10.0,
        "artifact_bytes": 100,
        "concurrent_experiments": 0,
        "cpu_workers": 0,
        "gpu_jobs": 0,
        "physical_memory_bytes": 1000,
        "memory_used_bytes": 500,
        "disk_total_bytes": 500 * GIB,
        "disk_free_bytes": 100 * GIB,
    }
    values.update(updates)
    return ResourceSnapshot(**values)  # type: ignore[arg-type]


def frozen_test_study(*, study_id: str = "study-1") -> StudyVersion:
    conditions = ExecutionConditions(
        "identity-v1",
        "frozen split",
        1,
        "deterministic",
        30.0,
        "scalar",
        True,
    )
    return freeze_protocol(
        ResearchProtocol(
            study_id=study_id,
            study_version=1,
            primary_hypothesis="treatment exceeds control",
            primary_estimand="mean difference",
            primary_metric="arithmetic mean difference",
            secondary_metrics=(),
            unit_of_analysis="subject",
            resampling_unit="subject",
            data_exclusions=(),
            data_roles=DataRoles(("train",), ("development",), ("validation",), ("holdout",)),
            candidate_conditions=conditions,
            baseline_set=(BaselineSpec("baseline", conditions),),
            ablation_set=("none",),
            negative_controls=("shuffled label",),
            domain_nulls=(
                DomainNullSpec(
                    "exchangeable-null",
                    "permutation",
                    "subject",
                    ("group size",),
                    ("subjects are exchangeable under the null",),
                    True,
                ),
            ),
            statistical_tests=(
                StatisticalTestSpec(
                    "primary-test", "permutation", "exchangeable-null", "greater"
                ),
            ),
            confidence_intervals=(ConfidenceIntervalSpec("bootstrap", 0.95, "subject"),),
            multiple_comparison_correction="Holm",
            seed_policy=SeedPolicy((7,), "frozen seed", "mechanical failure only"),
            compute_budget=ProtocolComputeBudget(1, 60.0, 1, 1),
            stopping_rules=("stop at frozen budget",),
            decision_ladder=("positive", "negative", "inconclusive"),
            claim_scope_contract="bounded synthetic study",
            interpretation_rules=InterpretationRules(
                "positive", "negative", "inconclusive", "invalid"
            ),
            validity_reserve_fraction=0.40,
            reserve_basis="data_and_compute",
        )
    )


class ResourceConfigTests(ProjectTempCase):
    def test_defaults_and_project_local_json_round_trip(self) -> None:
        path = self.root / "limits.json"
        path.write_text(json.dumps(ResourceConfig().to_dict()), encoding="utf-8")
        loaded = ResourceConfig.from_json(path, project_root=self.root)
        self.assertEqual(loaded.maximum_wall_clock_seconds, 28800)
        self.assertEqual(loaded.default_dtype, "float32")

    def test_rejects_invalid_fractions_bool_nonfinite_and_unknown(self) -> None:
        with self.assertRaises(ResourceConfigError):
            ResourceConfig(memory_soft_fraction=0.8, memory_hard_fraction=0.7)
        with self.assertRaises(ResourceConfigError):
            ResourceConfig(maximum_artifact_bytes=True)  # type: ignore[arg-type]
        with self.assertRaises(ResourceConfigError):
            ResourceConfig(maximum_wall_clock_seconds=math.inf)
        with self.assertRaises(ResourceConfigError):
            ResourceConfig(validity_reserve_fraction=0.29)
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_mapping({"surprise": 1})

    def test_json_rejects_duplicate_nonfinite_and_escape(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"maximum_wall_clock_seconds":1,"maximum_wall_clock_seconds":2}', encoding="utf-8")
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(duplicate, project_root=self.root)
        nonfinite = self.root / "nan.json"
        nonfinite.write_text('{"maximum_wall_clock_seconds":NaN}', encoding="utf-8")
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(nonfinite, project_root=self.root)
        outside = self.root.parent / "outside-config.json"
        # Do not write outside the project temp: confinement fails before access.
        with self.assertRaises(ResourceConfigError):
            ResourceConfig.from_json(outside, project_root=self.root)

    def test_conservative_disk_reserve_uses_greater_bound(self) -> None:
        self.assertEqual(conservative_disk_reserve(100 * GIB), 25 * GIB)
        self.assertEqual(conservative_disk_reserve(500 * GIB), 50 * GIB)

    def test_realistic_vm_stat_counts_reclaimable_pages_without_double_counting(self) -> None:
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

    def test_vm_stat_parser_fails_closed_on_malformed_or_missing_counters(self) -> None:
        for output in (
            "garbage",
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 1.\n",
            "Mach Virtual Memory Statistics: (page size of x bytes)\nPages free: 1.\n",
        ):
            observation = parse_vm_stat(output, 48 * GIB)
            self.assertEqual(observation.status, "ERROR")
            self.assertIsNone(observation.used_bytes)


class ResourceControllerTests(ProjectTempCase):
    def make_controller(self, **config_updates: object) -> ResourceController:
        config = ResourceConfig(**config_updates)
        return ResourceController(
            config,
            self.root,
            clock=lambda: 0.0,
            sleeper=lambda _: None,
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=("artifacts",),
        )

    def test_wall_artifact_and_allocation_aware_disk_stop_budget(self) -> None:
        controller = self.make_controller(maximum_wall_clock_seconds=20, maximum_artifact_bytes=1000)
        wall = controller.evaluate(healthy_snapshot(wall_elapsed_seconds=20))
        self.assertEqual(wall.action, ResourceAction.STOP_BUDGET)
        self.assertIn("WALL_CLOCK_BUDGET_EXHAUSTED", wall.reasons)
        artifact = controller.evaluate(healthy_snapshot(artifact_bytes=900), estimated_artifact_bytes=100)
        self.assertIn("ARTIFACT_BUDGET_EXHAUSTED", artifact.reasons)
        disk = controller.evaluate(
            healthy_snapshot(disk_total_bytes=500 * GIB, disk_free_bytes=55 * GIB),
            estimated_artifact_bytes=5 * GIB,
        )
        self.assertIn("DISK_RESERVE_BREACH", disk.reasons)
        self.assertEqual(disk.effective_disk_reserve_bytes, 50 * GIB)

    def test_memory_thermal_crash_growth_and_stall_pause_with_checkpoint(self) -> None:
        controller = self.make_controller(stall_timeout_seconds=30)
        decision = controller.evaluate(
            healthy_snapshot(
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
        self.assertIn("MEMORY_HARD_LIMIT_REACHED", decision.reasons)
        self.assertIn("SEVERE_THERMAL_PRESSURE", decision.reasons)
        self.assertIn("REPEATED_WORKER_CRASHES", decision.reasons)
        self.assertIn("WORK_STALLED", decision.reasons)
        self.assertIn("ABNORMAL_ARTIFACT_GROWTH", decision.reasons)

    def test_unknown_probes_fail_closed_for_new_work(self) -> None:
        controller = self.make_controller()
        decision = controller.evaluate(
            healthy_snapshot(
                physical_memory_bytes=None,
                memory_used_bytes=None,
                disk_total_bytes=None,
                disk_free_bytes=None,
            )
        )
        self.assertEqual(decision.action, ResourceAction.PAUSE)
        self.assertIn("MEMORY_STATUS_UNAVAILABLE", decision.reasons)
        self.assertIn("DISK_STATUS_UNAVAILABLE", decision.reasons)

    def test_probe_exceptions_become_fail_closed_observations(self) -> None:
        def fail() -> object:
            raise OSError("sandbox denied")

        controller = ResourceController(
            ResourceConfig(),
            self.root,
            clock=lambda: 0.0,
            disk_usage_probe=lambda _: fail(),
            memory_probe=fail,  # type: ignore[arg-type]
            pressure_probe=fail,  # type: ignore[arg-type]
            artifact_roots=(),
        )
        snapshot = controller.snapshot()
        self.assertIsNone(snapshot.memory_fraction)
        self.assertTrue(any("sandbox denied" in note for note in snapshot.probe_notes))
        self.assertEqual(controller.evaluate(snapshot).action, ResourceAction.PAUSE)

    def test_checkpoint_boundary_and_bounded_backoff(self) -> None:
        controller = self.make_controller(
            checkpoint_interval_seconds=10,
            backoff_initial_seconds=2,
            backoff_maximum_seconds=10,
        )
        decision = controller.evaluate(healthy_snapshot(monotonic_time=10))
        self.assertEqual(decision.action, ResourceAction.CHECKPOINT)
        self.assertEqual(controller.backoff_seconds(1), 2)
        self.assertEqual(controller.backoff_seconds(10), 10)

    def test_atomic_leases_enforce_and_release_limits(self) -> None:
        controller = self.make_controller(maximum_concurrent_experiments=1, cpu_worker_limit=1)
        lease = controller.acquire("one", cpu_workers=1)
        with self.assertRaises(ResourceLimitError):
            controller.acquire("two", cpu_workers=1)
        lease.release()
        with self.assertRaises(ResourceLimitError):
            lease.release()
        with controller.acquire("two", cpu_workers=1):
            pass

    def test_cpu_workers_clamp_to_half_detected_logical_cores(self) -> None:
        with patch("scientist_one.resources.os.cpu_count", return_value=6):
            controller = self.make_controller(cpu_worker_limit=20)
        self.assertEqual(controller.effective_cpu_worker_limit, 3)
        decision = controller.evaluate(
            healthy_snapshot(cpu_workers=3), requested_cpu_workers=1
        )
        self.assertIn("CPU_WORKER_LIMIT_REACHED", decision.reasons)

    def test_validity_reserve_is_integer_partition_and_pilot_cannot_consume_it(self) -> None:
        budget = ValidityBudget(11, 0.40)
        snap = budget.snapshot()
        self.assertEqual((snap.exploratory_limit, snap.confirmatory_reserve), (6, 5))
        budget.charge("PILOT", 6)
        with self.assertRaises(ResourceLimitError):
            budget.charge("PILOT", 1)
        budget.charge("CONFIRMATORY_RUN", 5)
        self.assertEqual(budget.snapshot().confirmatory_remaining, 0)

    def test_acquire_atomically_charges_validity_budget(self) -> None:
        controller = ResourceController(
            ResourceConfig(maximum_concurrent_experiments=2),
            self.root,
            clock=lambda: 0.0,
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=(),
            validity_budget_units=10,
        )
        with controller.acquire("pilot", validity_stage="PILOT", validity_units=6):
            pass
        self.assertEqual(controller.validity_budget.snapshot().exploratory_remaining, 0)  # type: ignore[union-attr]
        with self.assertRaises(ResourceLimitError):
            controller.acquire("over", validity_stage="PILOT", validity_units=1)
        self.assertEqual(controller.validity_budget.snapshot().exploratory_used, 6)  # type: ignore[union-attr]

    def test_runtime_state_restore_does_not_replenish_wall_or_validity_budget(self) -> None:
        ticks = iter((100.0, 150.0))
        wall_ticks = iter((1000.0, 1050.0))
        controller = ResourceController(
            ResourceConfig(maximum_wall_clock_seconds=60),
            self.root,
            clock=lambda: next(ticks),
            wall_clock=lambda: next(wall_ticks),
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=(),
            validity_budget_units=10,
            run_id="run-restore",
        )
        with controller.acquire("pilot", validity_stage="PILOT", validity_units=5):
            pass
        state = controller.export_state()
        self.assertEqual(state.wall_elapsed_seconds, 50)
        restored = ResourceController.from_runtime_state(
            controller.config,
            self.root,
            state,
            clock=lambda: 1000.0,
            wall_clock=lambda: 1050.0,
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=(),
        )
        self.assertEqual(restored.snapshot().wall_elapsed_seconds, 50)
        self.assertEqual(restored.validity_budget.snapshot().exploratory_used, 5)  # type: ignore[union-attr]
        exhausted = restored.evaluate(healthy_snapshot(wall_elapsed_seconds=60))
        self.assertEqual(exhausted.action, ResourceAction.STOP_BUDGET)

    def test_export_state_is_observational_and_consumes_neither_clock(self) -> None:
        calls = {"monotonic": 0, "wall": 0}

        def monotonic() -> float:
            calls["monotonic"] += 1
            return float(calls["monotonic"])

        def wall() -> float:
            calls["wall"] += 1
            return 1000.0 + calls["wall"]

        controller = ResourceController(
            ResourceConfig(),
            self.root,
            clock=monotonic,
            wall_clock=wall,
            artifact_roots=(),
            validity_budget_units=10,
            run_id="observational-export",
        )
        before = dict(calls)
        first = controller.export_state()
        second = controller.export_state()
        self.assertEqual(calls, before)
        self.assertEqual(first, second)

        controller.record_progress()
        observed = dict(calls)
        progressed = controller.export_state()
        self.assertEqual(calls, observed)
        self.assertGreater(progressed.wall_elapsed_seconds, first.wall_elapsed_seconds)

        with self.assertRaises(ResourceConfigError):
            controller.export_state(now=progressed.wall_elapsed_seconds + 100.0)

    def test_resource_state_preserves_cross_process_downtime_and_rejects_rollback(self) -> None:
        wall_ticks = iter((1000.0, 1000.0, 1010.0, 1010.0))
        controller = ResourceController(
            ResourceConfig(maximum_wall_clock_seconds=100),
            self.root,
            clock=lambda: 100.0,
            wall_clock=lambda: next(wall_ticks),
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=(),
            validity_budget_units=10,
            run_id="run-downtime",
        )
        with controller.acquire("pilot", validity_stage="PILOT", validity_units=2):
            pass
        controller.snapshot(now=110.0)
        state = controller.export_state()
        self.assertEqual(state.wall_elapsed_seconds, 10)
        restored = ResourceController.from_runtime_state(
            controller.config,
            self.root,
            state,
            clock=lambda: 500.0,
            wall_clock=lambda: 1060.0,
            disk_usage_probe=lambda _: DiskUsage(500 * GIB, 400 * GIB, 100 * GIB),
            memory_probe=lambda: MemoryObservation(1000, 400, "AVAILABLE", "fake"),
            pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "fake"),
            artifact_roots=(),
        )
        self.assertEqual(restored.snapshot(now=500.0).wall_elapsed_seconds, 60)
        self.assertEqual(restored.validity_budget.snapshot().exploratory_used, 2)  # type: ignore[union-attr]
        resumed_state = restored.export_state(now=500.0)
        twice = ResourceController.from_runtime_state(
            controller.config,
            self.root,
            resumed_state,
            clock=lambda: 900.0,
            wall_clock=lambda: 1070.0,
            artifact_roots=(),
        )
        self.assertEqual(twice.snapshot(now=900.0).wall_elapsed_seconds, 70)
        with self.assertRaises(ResourceConfigError):
            ResourceController.from_runtime_state(
                controller.config,
                self.root,
                resumed_state,
                clock=lambda: 900.0,
                wall_clock=lambda: 1059.0,
                artifact_roots=(),
            )

    def test_backward_monotonic_observations_are_rejected_everywhere(self) -> None:
        controller = self.make_controller()
        controller.snapshot(now=100.0)
        for operation in (
            lambda: controller.snapshot(now=99.0),
            lambda: controller.export_state(now=99.0),
            lambda: controller.checkpoint_due(now=99.0),
            lambda: controller.mark_checkpoint(now=99.0),
            lambda: controller.record_progress(now=99.0),
        ):
            with self.assertRaises(ResourceConfigError):
                operation()

    def test_symlinked_artifacts_are_not_followed_or_counted(self) -> None:
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        target = artifacts / "target.bin"
        target.write_bytes(b"1234")
        (artifacts / "alias.bin").symlink_to(target)
        controller = self.make_controller()
        self.assertEqual(controller.artifact_usage(), 4)

    def test_artifact_root_cannot_traverse_intermediate_symlink(self) -> None:
        (self.root / "real").mkdir()
        (self.root / "alias").symlink_to(self.root / "real", target_is_directory=True)
        with self.assertRaises(ResourceConfigError):
            ResourceController(
                ResourceConfig(), self.root, artifact_roots=("alias/artifacts",)
            )


class FakeBackend:
    name = "fake"
    version = "1.0"

    def __init__(
        self,
        *,
        built: bool = True,
        available: bool = True,
        supported: bool = True,
        mps_delta: float = 0.0,
        mps_value: object | None = None,
    ) -> None:
        self.built = built
        self.available = available
        self.supported = supported
        self.mps_delta = mps_delta
        self.mps_value = mps_value

    def is_mps_built(self) -> bool:
        return self.built

    def is_mps_available(self) -> bool:
        return self.available

    def supports_operation(self, operation: str) -> bool:
        return self.supported

    def run(self, *, device: str, operation: str, values: object, dtype: str) -> object:
        if device == "mps" and self.mps_value is not None:
            return self.mps_value

        def transform(value: object) -> object:
            if isinstance(value, tuple):
                return tuple(transform(item) for item in value)
            return float(value) + (self.mps_delta if device == "mps" else 0.0)

        return transform(values)


class EmptyOutputBackend(FakeBackend):
    def run(self, *, device: str, operation: str, values: object, dtype: str) -> object:
        return ()


class DeviceTests(ProjectTempCase):
    def test_cpu_is_default_safe_path_and_invalid_modes_are_rejected(self) -> None:
        selection = DeviceManager("cpu", backend=FakeBackend()).select()
        self.assertEqual(selection.selected, "cpu")
        with self.assertRaises(DeviceConfigurationError):
            DeviceManager("cuda", backend=FakeBackend())
        with self.assertRaises(DeviceConfigurationError):
            DeviceManager("mps", dtype="float16", backend=FakeBackend())

    def test_auto_selects_mps_only_after_float32_parity(self) -> None:
        selection = DeviceManager("auto", backend=FakeBackend()).select()
        self.assertEqual(selection.selected, "mps")
        self.assertTrue(selection.parity_passed)
        self.assertEqual(selection.dtype, "float32")
        self.assertIsNotNone(selection.parity)
        self.assertGreaterEqual(len(selection.capabilities.reproducibility_limitations), 3)
        self.assertEqual(
            selection.to_dict()["reproducibility_limitations"],
            list(selection.capabilities.reproducibility_limitations),
        )

    def test_mps_unavailable_unsupported_or_out_of_tolerance_falls_back(self) -> None:
        unavailable = DeviceManager("mps", backend=FakeBackend(available=False)).select()
        self.assertEqual(unavailable.selected, "cpu")
        self.assertEqual(unavailable.fallback_reason, "MPS_NOT_AVAILABLE")
        unsupported = DeviceManager("auto", backend=FakeBackend(supported=False)).select()
        self.assertEqual(unsupported.fallback_reason, "MPS_OPERATION_UNSUPPORTED")
        mismatch = DeviceManager(
            "mps", backend=FakeBackend(mps_delta=0.1), tolerance=ParityTolerance(1e-6, 1e-6)
        ).select()
        self.assertEqual(mismatch.selected, "cpu")
        self.assertEqual(mismatch.fallback_reason, "NUMERICAL_TOLERANCE_EXCEEDED")

    def test_nonfinite_and_shape_mismatch_parity_fail_closed(self) -> None:
        nan = DeviceManager("mps", backend=FakeBackend(mps_value=((math.nan,),))).select()
        self.assertEqual(nan.selected, "cpu")
        self.assertIn("PARITY_EXECUTION_FAILED", nan.fallback_reason or "")
        shape = DeviceManager("mps", backend=FakeBackend(mps_value=(1.0, 2.0))).select()
        self.assertEqual(shape.fallback_reason, "OUTPUT_SHAPE_MISMATCH")
        empty = DeviceManager("mps", backend=FakeBackend()).select(fixture=())
        self.assertEqual(empty.selected, "cpu")
        self.assertEqual(empty.fallback_reason, "EMPTY_PARITY_FIXTURE")

    def test_runtime_fallback_is_prohibited_for_confirmatory_execution(self) -> None:
        manager = DeviceManager("mps", backend=FakeBackend())
        selection = manager.select()
        with self.assertRaises(DeviceExecutionError):
            manager.execute(
                selection,
                cpu_callable=lambda: "cpu",
                mps_callable=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
                confirmatory=True,
            )
        pilot = manager.execute(
            selection,
            cpu_callable=lambda: "cpu",
            mps_callable=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            confirmatory=False,
        )
        self.assertEqual((pilot.value, pilot.device_used), ("cpu", "cpu"))

    def test_forged_mps_selection_without_evidence_is_rejected(self) -> None:
        manager = DeviceManager("mps", backend=FakeBackend())
        valid = manager.select()
        forged = type(valid)(
            requested="mps",
            selected="mps",
            dtype="float32",
            operation=valid.operation,
            parity_passed=True,
            fallback_reason=None,
            capabilities=valid.capabilities,
            parity=None,
        )
        with self.assertRaises(DeviceConfigurationError):
            manager.execute(
                forged,
                cpu_callable=lambda: "cpu",
                mps_callable=lambda: "mps",
            )

    def test_empty_parity_outputs_and_fully_copied_selection_fail_closed(self) -> None:
        empty = DeviceManager("mps", backend=EmptyOutputBackend()).select()
        self.assertEqual(empty.selected, "cpu")
        self.assertEqual(empty.fallback_reason, "EMPTY_PARITY_OUTPUT")
        manager = DeviceManager("mps", backend=FakeBackend())
        issued = manager.select()
        forged = replace(issued)
        with self.assertRaises(DeviceConfigurationError):
            manager.execute(
                forged,
                cpu_callable=lambda: "cpu",
                mps_callable=lambda: "mps",
            )

    def test_confirmatory_execution_is_bound_to_prepared_callable_identity(self) -> None:
        manager = DeviceManager("mps", backend=FakeBackend())
        cpu = lambda values: values
        mps = lambda values: values
        implementation = hashlib.sha256(b"frozen implementation").hexdigest()
        prepared = manager.prepare_execution(
            "basic_arithmetic",
            ((0.0, 1.0), (2.0, 3.0)),
            implementation_sha256=implementation,
            cpu_callable=cpu,
            mps_callable=mps,
        )
        executed = manager.execute(
            prepared,
            cpu_callable=cpu,
            mps_callable=mps,
            values=((4.0, 5.0),),
            confirmatory=True,
        )
        self.assertEqual((executed.value, executed.device_used), (((4.0, 5.0),), "mps"))
        with self.assertRaises(DeviceExecutionError):
            manager.execute(
                prepared,
                cpu_callable=cpu,
                mps_callable=lambda values: "different operation",
                values=((4.0, 5.0),),
                confirmatory=True,
            )
        with self.assertRaises(DeviceExecutionError):
            manager.execute(
                manager.select(),
                cpu_callable=cpu,
                mps_callable=mps,
                values=((4.0, 5.0),),
                confirmatory=True,
            )

    def test_prepared_mps_selection_parity_tests_the_exact_execution_callables(self) -> None:
        manager = DeviceManager("mps", backend=FakeBackend())
        cpu = lambda values: 0.0
        divergent_mps = lambda values: 999.0
        prepared = manager.prepare_execution(
            "basic_arithmetic",
            ((0.0, 1.0),),
            implementation_sha256=hashlib.sha256(b"divergent implementation").hexdigest(),
            cpu_callable=cpu,
            mps_callable=divergent_mps,
        )
        self.assertEqual(prepared.selected, "cpu")
        self.assertFalse(prepared.parity_passed)
        self.assertEqual(prepared.fallback_reason, "NUMERICAL_TOLERANCE_EXCEEDED")

    def test_system_profiler_json_is_bounded_and_strict(self) -> None:
        for payload in (
            '{"a":1,"a":2}',
            '{"a":NaN}',
            "[" * 200 + "0" + "]" * 200,
        ):
            profiler = HardwareProfiler(
                self.root,
                command_runner=lambda argv, payload=payload, **_: subprocess.CompletedProcess(
                    argv, 0, payload, ""
                ),
                executable_exists=lambda _: True,
                device_manager_factory=lambda: DeviceManager("cpu", backend=FakeBackend()),
            )
            parsed, status, _ = profiler._system_profiler()
            self.assertIsNone(parsed)
            self.assertEqual(status, "ERROR")

    def test_hardware_profile_existing_file_read_is_bounded(self) -> None:
        target = self.root / "state" / "HARDWARE_PROFILE.json"
        target.parent.mkdir()
        with target.open("wb") as handle:
            handle.truncate(8 * 1024**2 + 1)
        profiler = HardwareProfiler(
            self.root,
            command_runner=lambda argv, **_: subprocess.CompletedProcess(argv, 1, "", "denied"),
            executable_exists=lambda _: False,
            device_manager_factory=lambda: DeviceManager("cpu", backend=FakeBackend()),
        )
        with self.assertRaises(DeviceConfigurationError):
            profiler.write_json(target)

    def test_project_local_torch_shadow_is_rejected_without_import(self) -> None:
        shadow = self.root / "torch.py"
        shadow.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
        fake_spec = type("Spec", (), {"origin": str(shadow), "submodule_search_locations": None})()
        with patch("scientist_one.device.importlib.util.find_spec", return_value=fake_spec), patch(
            "scientist_one.device.importlib.import_module"
        ) as importer:
            backend, evidence = _discover_torch_backend(self.root)
        self.assertIsNone(backend)
        self.assertIn("inside project_root", evidence[0])
        importer.assert_not_called()

    def test_hardware_profile_records_denied_probes_without_fabricating_values(self) -> None:
        calls: list[tuple[str, ...]] = []

        def denied_runner(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 1, "", "Operation not permitted")

        profiler = HardwareProfiler(
            self.root,
            command_runner=denied_runner,
            executable_exists=lambda _: True,
            now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
            device_manager_factory=lambda: DeviceManager("cpu", backend=FakeBackend()),
        )
        profile = profiler.collect()
        self.assertEqual(profile.physical_cpu_count.status, "DENIED")
        self.assertIsNone(profile.physical_cpu_count.value)
        self.assertEqual(profile.gpu_description.status, "DENIED")
        self.assertTrue(all(call[0].startswith("/") for call in calls))
        self.assertGreaterEqual(
            len(profile.mps_capability["reproducibility_limitations"]), 3
        )
        output = profiler.write_json("state/profile.json", profile)
        self.assertTrue(output.is_file())
        self.assertEqual(json.loads(output.read_text())["timestamp"], "2026-01-01T00:00:00Z")
        previous = b'{"older":true}\n'
        output.write_bytes(previous)
        profiler.write_json("state/profile.json", profile)
        archived = list(
            (self.root / ".scientist-one-build/checkpoints/hardware-profile-history").glob("*.json")
        )
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0].read_bytes(), previous)

    def test_hardware_profile_falls_back_to_system_profiler_evidence(self) -> None:
        profiler_payload = {
            "SPHardwareDataType": [
                {
                    "number_processors": "proc 14:10 performance and 4 efficiency",
                    "physical_memory": "48 GB",
                }
            ],
            "SPDisplaysDataType": [
                {"sppci_model": "Apple M4 Pro", "sppci_cores": "20"}
            ],
        }

        def runner(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if argv[0] == "/usr/sbin/system_profiler":
                return subprocess.CompletedProcess(argv, 0, json.dumps(profiler_payload), "")
            return subprocess.CompletedProcess(argv, 1, "", "Operation not permitted")

        profile = HardwareProfiler(
            self.root,
            command_runner=runner,
            executable_exists=lambda _: True,
            device_manager_factory=lambda: DeviceManager("cpu", backend=FakeBackend()),
        ).collect()
        self.assertEqual(profile.physical_cpu_count.value, 14)
        self.assertEqual(profile.physical_cpu_count.source, "system_profiler")
        self.assertEqual(profile.physical_memory_bytes.value, 48 * GIB)
        self.assertIn("Apple M4 Pro", str(profile.gpu_description.value))

    def test_hardware_profile_omits_external_absolute_tool_paths(self) -> None:
        profiler = HardwareProfiler(
            self.root,
            command_runner=lambda argv, **_: subprocess.CompletedProcess(
                argv, 1, "", "denied"
            ),
            executable_exists=lambda _: True,
            device_manager_factory=lambda: DeviceManager("cpu", backend=FakeBackend()),
        )
        with patch("scientist_one.device.shutil.which", return_value="/opt/tools/bin/fake"):
            payload = profiler.collect().to_dict()
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn("/opt/tools/bin/fake", serialized)
        for evidence in payload["installed_toolchains"].values():
            self.assertFalse(str(evidence["value"]).startswith("/"))


_RECOVERY_EVENT_HEAD_STATES: dict[str, str] = {}


def make_event(run_id: str, event_id: str, prior: str | None, **extra: object) -> dict[str, object]:
    aliases = {"PILOT": "CANDIDATE", "MIDRUN_REVIEW": "CONFIRM", "VERIFY": "CLAIMS"}
    raw_after = str(extra.pop("state_after", "CONFIRM"))
    requested_after = aliases.get(raw_after, raw_after)
    event_type = str(extra.pop("event_type", "TRANSITION"))
    actor_role = extra.pop("actor_role", Role.ORCHESTRATOR)
    artifact_hashes = extra.pop("artifact_hashes", ())
    metadata = extra.pop("metadata", None)
    code_version = str(extra.pop("code_version", "test-code"))
    configuration_hash = str(extra.pop("configuration_hash", "c" * 64))
    inferred_before = _RECOVERY_EVENT_HEAD_STATES.get(str(prior))
    if event_type not in {"TRANSITION", "SECURITY_STOP"}:
        state_before = str(
            extra.pop("state_before", inferred_before or requested_after)
        )
        requested_after = state_before
    else:
        state_before = str(
            extra.pop("state_before", inferred_before or "CALIBRATE")
        )
    if extra:
        raise AssertionError(f"unsupported test event fields: {sorted(extra)}")
    event = LedgerEvent.create(
        run_id=run_id,
        event_id=event_id,
        timestamp="2026-01-01T00:00:00Z",
        actor_role=actor_role,  # type: ignore[arg-type]
        state_before=state_before,
        requested_state_after=requested_after,
        artifact_hashes=artifact_hashes,  # type: ignore[arg-type]
        code_version=code_version,
        configuration_hash=configuration_hash,
        dataset_identifiers=(),
        random_seeds=(),
        evaluator_outputs=(),
        reason="runtime recovery test",
        prior_event_hash=prior,
        event_type=event_type,
        metadata=metadata,  # type: ignore[arg-type]
    )
    serialized = event.to_dict()
    _RECOVERY_EVENT_HEAD_STATES[str(serialized["event_hash"])] = requested_after
    return serialized


def write_ledger(path: Path, events: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
        encoding="utf-8",
    )


def rewrite_custody_journal(path: Path, events: list[dict[str, object]]) -> None:
    """Rehash a deliberately forged journal so semantic checks are exercised."""

    prior = "0" * 64
    encoded: list[bytes] = []
    for index, event in enumerate(events):
        event["event_index"] = index
        event["prior_event_hash"] = prior
        unsigned = {key: value for key, value in event.items() if key != "event_hash"}
        digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        event["event_hash"] = digest
        prior = digest
        encoded.append(canonical_json_bytes(event) + b"\n")
    path.write_bytes(b"".join(encoded))


class RecoveryTests(ProjectTempCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = RecoveryManager(
            self.root, now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        self.ledger_path = self.root / "state" / "events.jsonl"

    def two_events(self) -> list[dict[str, object]]:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event("run-1", "e2", str(first["event_hash"]), state_after="MIDRUN_REVIEW")
        return [first, second]

    def custody_bundle(
        self,
        study: StudyVersion,
        events: list[dict[str, object]],
    ) -> tuple[
        ArtifactRegistry,
        SimulatedHoldoutCustody,
        FreshCustodyEvidence,
        list[dict[str, object]],
    ]:
        registry = ArtifactRegistry(self.root, f"registry-v{study.version}")
        protocol_parent = registry.put_json(
            {"protocol_hash": study.protocol_hash, "study_version": study.version},
            logical_type=f"frozen_protocol_v{study.version}",
            origin="runtime custody test",
            creator_role=Role.PROTOCOL_DESIGNER,
            validation_result="PASS",
            frozen=True,
        )
        provider = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=f"runs/custody-v{study.version}.jsonl",
        )
        seal = provider.seal(
            f"fresh holdout v{study.version}".encode(),
            split_manifest_hash=hashlib.sha256(
                f"split-v{study.version}".encode()
            ).hexdigest(),
            protocol_hash=study.protocol_hash,
            code_hash="d" * 64,
            configuration_hash="c" * 64,
            pre_unblinding_interpretation_hash="e" * 64,
            sealed_at="2026-01-01T00:00:00Z",
        )
        with provider.admission_guard() as live:
            receipt = {
                "schema_version": "1.0",
                "study_id": study.study_id,
                "study_version": study.version,
                "seal": asdict(live.seal),
                "status": asdict(live.status),
                "journal_head_hash": live.journal_head_hash,
                "journal_identity_sha256": live.journal_identity_sha256,
            }
        record = registry.put_json(
            receipt,
            logical_type="fresh_custody_receipt",
            origin="runtime custody test",
            creator_role=Role.HOLDOUT_CUSTODIAN,
            parent_artifacts=(protocol_parent.sha256,),
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        prior = str(events[-1]["event_hash"]) if events else None
        binding = {
            "artifact_sha256": record.sha256,
            "artifact_record_hash": record.record_hash,
            "journal_head_hash": receipt["journal_head_hash"],
            "journal_identity_sha256": receipt["journal_identity_sha256"],
            "protocol_hash": study.protocol_hash,
            "seal_hash": seal.seal_hash,
            "study_version": study.version,
        }
        receipt_event = make_event(
            "run-1",
            f"custody-v{study.version}",
            prior,
            state_after="CANDIDATE",
            event_type="CHECKPOINT",
            actor_role=Role.HOLDOUT_CUSTODIAN,
            artifact_hashes=(record.sha256,),
            code_version=seal.code_hash,
            configuration_hash=seal.configuration_hash,
            metadata={
                "artifact_types": ["fresh_custody_receipt"],
                "artifact_record_hashes": [record.record_hash],
                "fresh_custody": binding,
            },
        )
        all_events = [*events, receipt_event]
        return (
            registry,
            provider,
            FreshCustodyEvidence(
                record.sha256,
                str(record.record_hash),
                str(receipt_event["event_id"]),
            ),
            all_events,
        )

    def append_confirmatory_start(
        self,
        event_id: str,
        *,
        evidence: FreshCustodyEvidence,
        actor_role: Role = Role.ORCHESTRATOR,
        state_after: str = "CONFIRM",
    ) -> None:
        current = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(current.valid)
        event = make_event(
            "run-1",
            event_id,
            current.head_hash,
            state_after=state_after,
            event_type="CONFIRMATORY_STARTED",
            actor_role=actor_role,
            artifact_hashes=(evidence.receipt_artifact_sha256,),
            code_version="d" * 64,
            configuration_hash="c" * 64,
            metadata={
                "artifact_types": ["fresh_custody_receipt"],
                "artifact_record_hashes": [evidence.artifact_record_hash],
            },
        )
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    def reveal_authority_bundle(
        self,
        *,
        resource_run_id: str = "run-1",
        substitute_resource_parent: bool = False,
        corrupt_charge_checkpoint: bool = False,
        invalid_evaluator_payload: bool = False,
        substitute_evaluator_source: bool = False,
        scientific_confirmation: bool = False,
        ledger_state: str = "CONFIRM",
    ) -> dict[str, object]:
        study = frozen_test_study()
        registry = ArtifactRegistry(self.root, "reveal-registry")

        def put(
            payload: object,
            logical_type: str,
            role: Role,
            parents: tuple[str, ...] = (),
        ):
            return registry.put_json(
                payload,
                logical_type=logical_type,
                origin="runtime reveal authority test",
                creator_role=role,
                parent_artifacts=parents,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )

        protocol = put(
            {
                "kind": "FROZEN_SYNTHETIC_PROTOCOL",
                "frozen": True,
                "protocol": study.protocol.canonical_dict,
                "protocol_sha256": study.protocol_hash,
                "baseline_equivalence": [],
                "blind_patterns": ["positive", "null"],
                "reproduction_tolerance": 1e-12,
            },
            "frozen_protocol",
            Role.PROTOCOL_DESIGNER,
        )

        def inventory(
            kind: str,
            entries: list[dict[str, object]],
        ) -> dict[str, object]:
            entries = sorted(entries, key=lambda item: str(item["path"]))
            aggregate = hashlib.sha256(
                json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            ).hexdigest()
            return {
                "schema_version": "1.0",
                "kind": kind,
                "entries": entries,
                "aggregate_sha256": aggregate,
            }

        source_entries: list[dict[str, object]] = []
        for relative in (
            "src/scientist_one/holdout.py",
            "src/scientist_one/recovery.py",
        ):
            encoded = (PROJECT_ROOT / relative).read_bytes()
            copied = self.root / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(encoded)
            source_entries.append(
                {
                    "path": relative,
                    "sha256": (
                        "b" * 64
                        if substitute_evaluator_source
                        and relative == "src/scientist_one/holdout.py"
                        else hashlib.sha256(encoded).hexdigest()
                    ),
                    "size": len(encoded),
                }
            )
        source_payload = inventory("FROZEN_SOURCE_INVENTORY", source_entries)
        configuration_payload = inventory(
            "FROZEN_CONFIGURATION_INVENTORY",
            [{"path": "configs/test.json", "sha256": "a" * 64, "size": 1}],
        )
        source = put(
            source_payload, "frozen_source_inventory", Role.ORCHESTRATOR
        )
        configuration = put(
            configuration_payload,
            "frozen_configuration_inventory",
            Role.ORCHESTRATOR,
        )
        split_id = study.protocol.data_roles.holdout[0]
        split_hash = hashlib.sha256(
            json.dumps(
                {"id": split_id, "role": "holdout"},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            + b"\n"
        ).hexdigest()
        split = put(
            {
                "schema_version": "1.0",
                "kind": "FROZEN_CONFIRMATORY_SPLIT",
                "study_id": study.study_id,
                "study_version": study.version,
                "split_id": split_id,
                "role": "holdout",
                "split_manifest_hash": split_hash,
            },
            "frozen_confirmatory_split",
            Role.PROTOCOL_DESIGNER,
            (protocol.sha256,),
        )
        inventory_parents = (source.sha256, configuration.sha256)
        blind = put(
            {
                "kind": "FROZEN_BLIND_INTERPRETATION",
                "frozen_before_reveal": True,
                "source_inventory_sha256": source.sha256,
                "configuration_inventory_sha256": configuration.sha256,
                "patterns": {"positive": "bounded positive", "null": "NEGATIVE_RESULT"},
            },
            "blind_interpretation",
            Role.STATISTICIAN,
            inventory_parents,
        )
        midrun = put(
            {
                "kind": "FROZEN_MIDRUN_REVIEW",
                "passed": True,
                "drift": False,
                "leakage": False,
                "baseline_equivalent": True,
                "validity_reserve_intact": True,
                "code_fingerprint": source_payload["aggregate_sha256"],
                "configuration_sha256": configuration_payload["aggregate_sha256"],
                "source_inventory_sha256": source.sha256,
                "configuration_inventory_sha256": configuration.sha256,
            },
            "midrun_review",
            Role.SCIENTIFIC_REVIEWER,
            inventory_parents,
        )
        provider = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=".scientist-one-build/custody/run-1.jsonl",
        )
        seal = provider.seal(
            (
                b'{"control":[0,1,2],"treatment":[1,2,3]}'
                if invalid_evaluator_payload
                else b'{"control":[0,1,2,3],"treatment":[1,2,3,4]}'
            ),
            split_manifest_hash=split_hash,
            protocol_hash=study.protocol_hash,
            code_hash=str(source_payload["aggregate_sha256"]),
            configuration_hash=str(configuration_payload["aggregate_sha256"]),
            pre_unblinding_interpretation_hash=blind.sha256,
            sealed_at="2026-01-01T00:00:00Z",
        )
        with provider.admission_guard() as live:
            receipt_payload = {
                "schema_version": "1.0",
                "study_id": study.study_id,
                "study_version": study.version,
                "seal": asdict(live.seal),
                "status": asdict(live.status),
                "journal_head_hash": live.journal_head_hash,
                "journal_identity_sha256": live.journal_identity_sha256,
            }
        receipt = put(
            receipt_payload,
            "fresh_custody_receipt",
            Role.HOLDOUT_CUSTODIAN,
            (
                protocol.sha256,
                blind.sha256,
                source.sha256,
                configuration.sha256,
                split.sha256,
                midrun.sha256,
            ),
        )
        fresh_binding = {
            "artifact_sha256": receipt.sha256,
            "artifact_record_hash": receipt.record_hash,
            "journal_head_hash": live.journal_head_hash,
            "journal_identity_sha256": live.journal_identity_sha256,
            "protocol_hash": study.protocol_hash,
            "seal_hash": seal.seal_hash,
            "study_version": study.version,
        }
        initial_state = ResourceRuntimeState(
            schema_version="1.0",
            run_id=resource_run_id,
            config_sha256="b" * 64,
            wall_elapsed_seconds=10.0,
            checkpoint_elapsed_seconds=5.0,
            progress_elapsed_seconds=5.0,
            worker_crashes={},
            wall_started_at_epoch_seconds=100.0,
            wall_observed_at_epoch_seconds=110.0,
            validity_total_units=10,
            exploratory_used=2,
            confirmatory_used=0,
        )
        prior_resource = put(
            initial_state.to_dict(),
            "resource_runtime_pilot_completion",
            Role.ORCHESTRATOR,
        )
        charge_parent = prior_resource
        if substitute_resource_parent:
            substituted_state = ResourceRuntimeState(
                **{
                    **initial_state.to_dict(),
                    "progress_elapsed_seconds": 6.0,
                }
            )
            charge_parent = put(
                substituted_state.to_dict(),
                "resource_runtime_substituted_prior",
                Role.ORCHESTRATOR,
            )
        charged_state = ResourceRuntimeState(
            **{
                **initial_state.to_dict(),
                "confirmatory_used": 4,
            }
        )
        charge = put(
            charged_state.to_dict(),
            "resource_runtime_confirmatory_charge",
            Role.ORCHESTRATOR,
            (charge_parent.sha256,),
        )

        authority_directory = (
            self.root / ".scientist-one-build" / "resource-authority" / "run-1"
        )
        authority_directory.mkdir(parents=True)

        def persist_authority(
            sequence: int,
            logical_type: str,
            state: dict[str, object],
            prior_digest: str | None,
        ) -> tuple[str, dict[str, object]]:
            state_sha256 = hashlib.sha256(
                canonical_json_bytes(state) + b"\n"
            ).hexdigest()
            authority_record = {
                "schema_version": "1.0",
                "kind": "RESOURCE_RUNTIME_AUTHORITY",
                "run_id": "run-1",
                "sequence": sequence,
                "logical_type": logical_type,
                "state_sha256": state_sha256,
                "state": state,
                "prior_authority_sha256": prior_digest,
            }
            encoded = canonical_json_bytes(authority_record) + b"\n"
            digest = hashlib.sha256(encoded).hexdigest()
            (authority_directory / f"{sequence:04d}-{digest}.json").write_bytes(
                encoded
            )
            return digest, {
                "sequence": sequence,
                "logical_type": logical_type,
                "state_sha256": state_sha256,
                "authority_sha256": digest,
                "prior_authority_sha256": prior_digest,
            }

        prior_authority_digest, prior_authority_checkpoint = persist_authority(
            0,
            "resource_runtime_pilot_completion",
            initial_state.to_dict(),
            None,
        )
        _charge_authority_digest, authority_checkpoint = persist_authority(
            1,
            "resource_runtime_confirmatory_charge",
            charged_state.to_dict(),
            prior_authority_digest,
        )
        self.assertEqual(prior_authority_checkpoint["state_sha256"], prior_resource.sha256)
        self.assertEqual(authority_checkpoint["state_sha256"], charge.sha256)
        published_charge_checkpoint = dict(authority_checkpoint)
        if corrupt_charge_checkpoint:
            published_charge_checkpoint["authority_sha256"] = "f" * 64

        prior_resource_event = make_event(
            "run-1",
            "prior-resource",
            None,
            state_after=ledger_state,
            event_type="CHECKPOINT",
            artifact_hashes=(prior_resource.sha256,),
            code_version=seal.code_hash,
            configuration_hash=seal.configuration_hash,
            metadata={
                "artifact_types": ["resource_runtime_pilot_completion"],
                "artifact_record_hashes": [prior_resource.record_hash],
                "resource_authority_checkpoint": prior_authority_checkpoint,
            },
        )
        receipt_event = make_event(
            "run-1",
            "fresh-custody",
            str(prior_resource_event["event_hash"]),
            event_type="CHECKPOINT",
            actor_role=Role.HOLDOUT_CUSTODIAN,
            artifact_hashes=(receipt.sha256,),
            code_version=seal.code_hash,
            configuration_hash=seal.configuration_hash,
            metadata={
                "artifact_types": ["fresh_custody_receipt"],
                "artifact_record_hashes": [receipt.record_hash],
                "fresh_custody": fresh_binding,
            },
        )
        charge_event = make_event(
            "run-1",
            "confirmatory-charge",
            str(receipt_event["event_hash"]),
            event_type="CHECKPOINT",
            artifact_hashes=(charge.sha256,),
            code_version=seal.code_hash,
            configuration_hash=seal.configuration_hash,
            metadata={
                "artifact_types": ["resource_runtime_confirmatory_charge"],
                "artifact_record_hashes": [charge.record_hash],
                "resource_authority_checkpoint": published_charge_checkpoint,
            },
        )
        write_ledger(
            self.ledger_path,
            [prior_resource_event, receipt_event, charge_event],
        )

        def selector(record: object) -> RegisteredArtifactSelector:
            return RegisteredArtifactSelector(
                record.sha256, str(record.record_hash)  # type: ignore[attr-defined]
            )

        evidence = FreshCustodyEvidence(
            receipt.sha256, str(receipt.record_hash), "fresh-custody"
        )
        authority = ConfirmatoryRevealAuthority(
            selector(protocol),
            selector(source),
            selector(configuration),
            selector(split),
            selector(blind),
            selector(midrun),
            selector(charge),
            "confirmatory-charge",
            4,
        )

        selectors = (
            ("frozen_protocol", authority.protocol),
            ("frozen_source_inventory", authority.source_inventory),
            (
                "frozen_configuration_inventory",
                authority.configuration_inventory,
            ),
            ("frozen_confirmatory_split", authority.split_manifest),
            ("blind_interpretation", authority.blind_interpretation),
            ("midrun_review", authority.midrun_review),
            ("resource_runtime_confirmatory_charge", authority.resource_charge),
            ("fresh_custody_receipt", selector(receipt)),
        )
        start_event = LedgerEvent.from_dict(
            make_event(
                "run-1",
                "confirmatory-started",
                str(charge_event["event_hash"]),
                event_type=(
                    "CONFIRMATORY_STARTED"
                    if scientific_confirmation
                    else "CHECKPOINT"
                ),
                artifact_hashes=tuple(item.artifact_sha256 for _, item in selectors),
                code_version=seal.code_hash,
                configuration_hash=seal.configuration_hash,
                metadata={
                    "artifact_types": [name for name, _ in selectors],
                    "artifact_record_hashes": [
                        item.artifact_record_hash for _, item in selectors
                    ],
                    "fresh_custody": fresh_binding,
                    "resource_authority_checkpoint": authority_checkpoint,
                    "evidence_class": (
                        "SCIENTIFIC_EVIDENCE"
                        if scientific_confirmation
                        else "ARCHITECTURE_CONTROL"
                    ),
                    "execution_kind": (
                        "SCIENTIFIC_CONFIRMATION_STARTED"
                        if scientific_confirmation
                        else "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
                    ),
                },
            )
        )

        return {
            "study": study,
            "registry": registry,
            "provider": provider,
            "evidence": evidence,
            "authority": authority,
            "snapshot": ValidityBudgetSnapshot(10, 6, 4, 2, 4),
            "start_event": start_event,
            "pre_start_event_count": 3,
            "authority_directory": authority_directory,
            "journal_relative": ".scientist-one-build/custody/run-1.jsonl",
            "resource_authority": (prior_authority_checkpoint, authority_checkpoint),
        }

    def test_validates_hash_chain_and_rejects_mid_ledger_corruption(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        valid = self.manager.validate_ledger("state/events.jsonl")
        self.assertTrue(valid.valid)
        self.assertEqual(valid.event_count, 2)
        events[0]["requested_state_after"] = "CORRUPTED"
        write_ledger(self.ledger_path, events)
        invalid = self.manager.validate_ledger("state/events.jsonl")
        self.assertFalse(invalid.valid)
        self.assertEqual(invalid.error, "EVENT_HASH_MISMATCH")

    def test_recovery_rejects_state_discontinuity_and_derives_only_semantic_events(self) -> None:
        first = make_event("run-1", "e1", None, state_after="CANDIDATE")
        discontinuous = make_event(
            "run-1",
            "e2",
            str(first["event_hash"]),
            event_type="CHECKPOINT",
            state_before="CALIBRATE",
            state_after="CALIBRATE",
        )
        write_ledger(self.ledger_path, [first, discontinuous])
        validation = self.manager.validate_ledger(self.ledger_path)
        self.assertFalse(validation.valid)
        self.assertEqual(validation.error, "STATE_CONTINUITY_MISMATCH")

        self.assertEqual(
            RecoveryManager._derived_state(
                (
                    {
                        "event_type": "TRANSITION",
                        "state_before": "CALIBRATE",
                        "requested_state_after": "CHARTER",
                    },
                    {
                        "event_type": "CHECKPOINT",
                        "state_before": "CHARTER",
                        "requested_state_after": "RELEASE",
                    },
                )
            ),
            "CHARTER",
        )

    def test_persisted_terminal_stops_dominate_completed_and_new_study_paths(self) -> None:
        for terminal_state, event_type, expected_action in (
            ("STOP_SECURITY", "SECURITY_STOP", ResumeAction.STOP_SECURITY),
            (
                "STOP_SCIENTIFIC_INVALIDITY",
                "TRANSITION",
                ResumeAction.STOP_SCIENTIFIC_INVALIDITY,
            ),
        ):
            with self.subTest(terminal_state=terminal_state):
                checkpoint_dir = (
                    ".scientist-one-build/checkpoints/" + terminal_state.lower()
                )
                completed = make_event(
                    "run-1",
                    f"completed-{terminal_state}",
                    None,
                    event_type="CONFIRMATORY_COMPLETED",
                    state_before="CALIBRATE",
                )
                stopped = make_event(
                    "run-1",
                    f"stopped-{terminal_state}",
                    str(completed["event_hash"]),
                    event_type=event_type,
                    state_after=terminal_state,
                )
                write_ledger(self.ledger_path, [completed, stopped])
                self.manager.create_checkpoint(
                    {
                        "run_id": "run-1",
                        "event_id": completed["event_id"],
                        "ledger_head_hash": completed["event_hash"],
                        "state": "CALIBRATE",
                        "checkpoint_id": f"checkpoint-{terminal_state}",
                    },
                    checkpoint_dir=checkpoint_dir,
                )
                with patch.object(
                    self.manager, "_valid_new_study_protocol", return_value=True
                ) as new_study, patch.object(
                    self.manager,
                    "_valid_fresh_custody_evidence",
                    return_value=True,
                ) as custody:
                    report = self.manager.recover(
                        ledger_path="state/events.jsonl",
                        checkpoint_dir=checkpoint_dir,
                        new_study_protocol=object(),
                    )
                self.assertEqual(report.action, expected_action)
                self.assertFalse(report.resumable)
                self.assertEqual(report.derived_state, terminal_state)
                self.assertTrue(report.confirmatory_completed)
                new_study.assert_not_called()
                custody.assert_not_called()

    def test_ledger_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        event = make_event("run-1", "e1", None, state_after="PILOT")
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        encoded = encoded.replace('"event_id":"e1"', '"event_id":"wrong","event_id":"e1"')
        self.ledger_path.parent.mkdir(parents=True)
        self.ledger_path.write_text(encoded + "\n", encoding="utf-8")
        duplicate = self.manager.validate_ledger(self.ledger_path)
        self.assertFalse(duplicate.valid)
        self.assertIn("MALFORMED_LEDGER_JSON", duplicate.error or "")
        self.ledger_path.write_text('{"event_id":"e1","value":NaN}\n', encoding="utf-8")
        nonfinite = self.manager.validate_ledger(self.ledger_path)
        self.assertFalse(nonfinite.valid)
        self.assertIn("MALFORMED_LEDGER_JSON", nonfinite.error or "")

    def test_truncated_final_append_is_quarantined_and_prefix_restored(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events[:1])
        with self.ledger_path.open("ab") as handle:
            handle.write(b'{"run_id":"run-1","event_id"')
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertTrue(report.ledger_valid)
        self.assertEqual(report.ledger_event_count, 1)
        self.assertEqual(len(report.quarantined), 1)
        self.assertTrue(self.manager.validate_ledger(self.ledger_path).valid)

    def test_newline_terminated_malformed_append_is_fatal_and_not_repaired(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events[:1])
        with self.ledger_path.open("ab") as handle:
            handle.write(b"{bad}\n")
        original = self.ledger_path.read_bytes()
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertEqual(self.ledger_path.read_bytes(), original)

    def test_complete_confirmatory_event_without_newline_is_never_erased(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event(
            "run-1",
            "e2",
            str(first["event_hash"]),
            event_type="CONFIRMATORY_STARTED",
            state_after="CONFIRM",
        )
        events = [first, second]
        write_ledger(self.ledger_path, events[:1])
        with self.ledger_path.open("ab") as handle:
            handle.write(json.dumps(events[1], sort_keys=True, separators=(",", ":")).encode())
        original = self.ledger_path.read_bytes()
        validation = self.manager.validate_ledger(self.ledger_path)
        self.assertFalse(validation.valid)
        self.assertFalse(validation.recoverable_truncated_tail)
        self.assertEqual(validation.error, "AMBIGUOUS_FINAL_EVENT_WITHOUT_NEWLINE")
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.resumable)
        self.assertEqual(self.ledger_path.read_bytes(), original)

    def test_injected_foundation_validator_cannot_erase_complete_no_newline_event(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event(
            "run-1",
            "e2",
            str(first["event_hash"]),
            event_type="CONFIRMATORY_STARTED",
            state_after="CONFIRM",
        )
        write_ledger(self.ledger_path, [first])
        with self.ledger_path.open("ab") as handle:
            handle.write(json.dumps(second, sort_keys=True, separators=(",", ":")).encode())
        original = self.ledger_path.read_bytes()
        adapter_owner = type("AdapterOwner", (), {"root": self.root})()
        repair_lock_held = False
        validation_calls = 0

        def foundation_validation(path: Path):
            nonlocal validation_calls
            self.assertFalse(
                repair_lock_held,
                "the injected EventLedger validator must not re-enter the repair lock",
            )
            validation_calls += 1
            return ScientistOneOrchestrator._foundation_ledger_validation(
                adapter_owner, path
            )

        injected = RecoveryManager(self.root, ledger_validator=foundation_validation)
        open_repair_lock = injected._open_ledger_lock
        close_repair_lock = injected._close_ledger_lock

        def tracked_open(path: Path) -> int:
            nonlocal repair_lock_held
            descriptor = open_repair_lock(path)
            repair_lock_held = True
            return descriptor

        def tracked_close(descriptor: int) -> None:
            nonlocal repair_lock_held
            try:
                close_repair_lock(descriptor)
            finally:
                repair_lock_held = False

        with (
            patch.object(injected, "_open_ledger_lock", side_effect=tracked_open),
            patch.object(injected, "_close_ledger_lock", side_effect=tracked_close),
        ):
            external = injected.validate_ledger(self.ledger_path)
            self.assertTrue(external.recoverable_truncated_tail)
            report = injected.recover(ledger_path=self.ledger_path)
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.resumable)
        self.assertEqual(self.ledger_path.read_bytes(), original)
        self.assertIn(b'"event_type":"CONFIRMATORY_STARTED"', original)
        self.assertEqual(validation_calls, 3)

    def test_injected_foundation_validator_repairs_unambiguous_truncated_tail(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        write_ledger(self.ledger_path, [first])
        with self.ledger_path.open("ab") as handle:
            handle.write(b'{"run_id":"run-1","event_id"')
        adapter_owner = type("AdapterOwner", (), {"root": self.root})()
        repair_lock_held = False
        validation_calls = 0

        def foundation_validation(path: Path):
            nonlocal validation_calls
            self.assertFalse(
                repair_lock_held,
                "the injected EventLedger validator must not re-enter the repair lock",
            )
            validation_calls += 1
            return ScientistOneOrchestrator._foundation_ledger_validation(
                adapter_owner, path
            )

        injected = RecoveryManager(self.root, ledger_validator=foundation_validation)
        open_repair_lock = injected._open_ledger_lock
        close_repair_lock = injected._close_ledger_lock

        def tracked_open(path: Path) -> int:
            nonlocal repair_lock_held
            descriptor = open_repair_lock(path)
            repair_lock_held = True
            return descriptor

        def tracked_close(descriptor: int) -> None:
            nonlocal repair_lock_held
            try:
                close_repair_lock(descriptor)
            finally:
                repair_lock_held = False

        with (
            patch.object(injected, "_open_ledger_lock", side_effect=tracked_open),
            patch.object(injected, "_close_ledger_lock", side_effect=tracked_close),
        ):
            report = injected.recover(ledger_path=self.ledger_path)
        self.assertEqual(report.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertTrue(report.ledger_valid)
        self.assertEqual(report.ledger_event_count, 1)
        self.assertEqual(len(report.quarantined), 1)
        self.assertEqual(
            self.ledger_path.read_bytes(),
            (json.dumps(first, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        self.assertEqual(validation_calls, 4)

    def test_injected_repair_preserves_change_after_intrinsic_validation(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event(
            "run-1",
            "e2",
            str(first["event_hash"]),
            event_type="CONFIRMATORY_STARTED",
            state_after="CONFIRM",
        )
        write_ledger(self.ledger_path, [first])
        with self.ledger_path.open("ab") as handle:
            handle.write(b'{"run_id":"run-1","event_id"')
        adapter_owner = type("AdapterOwner", (), {"root": self.root})()
        injected = RecoveryManager(
            self.root,
            ledger_validator=lambda path: ScientistOneOrchestrator._foundation_ledger_validation(
                adapter_owner, path
            ),
        )
        read_regular_bytes = injected._read_regular_bytes
        read_calls = 0

        def change_after_intrinsic_validation(path: Path, *, maximum_bytes: int):
            nonlocal read_calls
            read_calls += 1
            if read_calls == 2:
                write_ledger(self.ledger_path, [first, second])
            return read_regular_bytes(path, maximum_bytes=maximum_bytes)

        with patch.object(
            injected,
            "_read_regular_bytes",
            side_effect=change_after_intrinsic_validation,
        ):
            report = injected.recover(ledger_path=self.ledger_path)
        replacement = self.ledger_path.read_bytes()
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.resumable)
        self.assertIn("changed after intrinsic validation", report.reasons[0])
        self.assertIn(b'"event_type":"CONFIRMATORY_STARTED"', replacement)
        self.assertEqual(read_calls, 2)

    def test_injected_repair_rejects_change_before_quarantine(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event(
            "run-1",
            "e2",
            str(first["event_hash"]),
            event_type="CONFIRMATORY_STARTED",
            state_after="CONFIRM",
        )
        write_ledger(self.ledger_path, [first])
        with self.ledger_path.open("ab") as handle:
            handle.write(b'{"run_id":"run-1","event_id"')
        adapter_owner = type("AdapterOwner", (), {"root": self.root})()
        injected = RecoveryManager(
            self.root,
            ledger_validator=lambda path: ScientistOneOrchestrator._foundation_ledger_validation(
                adapter_owner, path
            ),
        )
        quarantine_move = injected._quarantine_move

        def change_before_quarantine(
            source: Path,
            *,
            category: str,
            reason: str,
            expected_source: tuple[str, int, int, int] | None = None,
        ):
            write_ledger(self.ledger_path, [first, second])
            return quarantine_move(
                source,
                category=category,
                reason=reason,
                expected_source=expected_source,
            )

        with patch.object(
            injected,
            "_quarantine_move",
            side_effect=change_before_quarantine,
        ):
            report = injected.recover(ledger_path=self.ledger_path)
        replacement = self.ledger_path.read_bytes()
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.resumable)
        self.assertIn("differs from the validated repair input", report.reasons[0])
        self.assertIn(b'"event_type":"CONFIRMATORY_STARTED"', replacement)

    def test_recovery_rejects_minimal_schema_and_zero_hash_genesis(self) -> None:
        minimal = {"run_id": "run-1", "event_id": "e1", "prior_event_hash": None}
        minimal["event_hash"] = event_digest(minimal)
        write_ledger(self.ledger_path, [minimal])
        self.assertIn(
            "INVALID_EVENT_SCHEMA", self.manager.validate_ledger(self.ledger_path).error or ""
        )
        event = make_event("run-1", "e1", None, state_after="PILOT")
        event["prior_event_hash"] = "0" * 64
        event["event_hash"] = event_digest(event)
        write_ledger(self.ledger_path, [event])
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).error,
            "INVALID_GENESIS_PRIOR_HASH",
        )

    def test_stale_truncated_validation_cannot_overwrite_new_ledger(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events[:1])
        with self.ledger_path.open("ab") as handle:
            handle.write(b'{"torn"')
        stale = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(stale.recoverable_truncated_tail)
        write_ledger(self.ledger_path, events)
        replacement = self.ledger_path.read_bytes()
        with self.assertRaises(LedgerValidationError):
            self.manager.repair_truncated_ledger(self.ledger_path, stale)
        self.assertEqual(self.ledger_path.read_bytes(), replacement)

    def test_artifact_hash_size_and_frozen_corruption_fail_closed(self) -> None:
        artifact = self.root / "artifacts" / "result.json"
        artifact.parent.mkdir()
        artifact.write_bytes(b"result")
        record = {
            "path": "artifacts/result.json",
            "sha256": hashlib.sha256(b"result").hexdigest(),
            "size": 6,
            "frozen": True,
        }
        self.assertTrue(self.manager.validate_artifacts([record]).valid)
        artifact.write_bytes(b"tampered")
        result = self.manager.validate_artifacts([record])
        self.assertFalse(result.valid)
        self.assertTrue(result.has_frozen_failure)

    def test_artifact_registry_rejects_conflicting_alias_fields(self) -> None:
        result = self.manager.validate_artifacts(
            [
                {
                    "path": "artifacts/one",
                    "relative_path": "artifacts/two",
                    "sha256": "a" * 64,
                    "hash": "b" * 64,
                    "frozen": False,
                }
            ]
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.issues[0].code, "AMBIGUOUS_PATH_FIELDS")

    def test_partial_regular_file_is_quarantined_idempotently(self) -> None:
        partial = self.root / "runs" / "output.partial"
        partial.parent.mkdir()
        partial.write_bytes(b"partial")
        records = self.manager.quarantine_incomplete()
        self.assertEqual(len(records), 1)
        self.assertEqual(partial.read_bytes(), b"partial")
        self.assertTrue((self.root / records[0].quarantine_relative_path).is_file())
        self.assertTrue((self.root / records[0].metadata_relative_path).is_file())
        self.assertEqual(self.manager.quarantine_incomplete(), ())

    def test_same_basename_and_content_quarantine_to_distinct_paths(self) -> None:
        first = self.root / "runs" / "a" / "same.partial"
        second = self.root / "runs" / "b" / "same.partial"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(b"same")
        second.write_bytes(b"same")
        records = self.manager.quarantine_incomplete([first, second])
        self.assertEqual(len(records), 2)
        self.assertNotEqual(
            records[0].quarantine_relative_path, records[1].quarantine_relative_path
        )

    def test_quarantine_rejects_same_inode_mutation_during_sidecar_write(self) -> None:
        source = self.root / "runs" / "racy.partial"
        source.parent.mkdir()
        source.write_bytes(b"good")
        real_write = self.manager._write_sidecar

        def mutate(*args: object, **kwargs: object) -> Path:
            result = real_write(*args, **kwargs)  # type: ignore[arg-type]
            source.write_bytes(b"evil")
            return result

        with patch.object(self.manager, "_write_sidecar", side_effect=mutate):
            with self.assertRaises(RecoveryError):
                self.manager.quarantine_incomplete([source])
        self.assertEqual(source.read_bytes(), b"evil")
        quarantine = self.root / ".scientist-one-build" / "quarantine" / "partial"
        self.assertTrue(any(path.suffix == ".quarantine" for path in quarantine.glob("*")))

    def test_quarantine_never_unlinks_a_replacement_inode(self) -> None:
        source = self.root / "runs" / "replacement-race.partial"
        source.parent.mkdir()
        source.write_bytes(b"verified inode")
        replacement = source.with_name("replacement")
        replacement.write_bytes(b"replacement inode")
        real_write = self.manager._write_sidecar

        def replace_during_commit(*args: object, **kwargs: object) -> Path:
            sidecar = real_write(*args, **kwargs)  # type: ignore[arg-type]
            os.replace(replacement, source)
            return sidecar

        with patch.object(
            self.manager, "_write_sidecar", side_effect=replace_during_commit
        ):
            with self.assertRaises(RecoveryError):
                self.manager.quarantine_incomplete([source])
        self.assertEqual(source.read_bytes(), b"replacement inode")

    def test_incomplete_scan_and_partial_size_are_bounded(self) -> None:
        runs = self.root / "runs"
        runs.mkdir()
        (runs / "one").write_bytes(b"1")
        (runs / "two").write_bytes(b"2")
        limited = RecoveryManager(
            self.root, maximum_scan_entries=1, maximum_artifact_bytes=4
        )
        with self.assertRaises(RecoveryError):
            limited.quarantine_incomplete(scan_roots=("runs",))
        huge = runs / "huge.partial"
        huge.write_bytes(b"12345")
        with self.assertRaises(RecoveryError):
            limited.quarantine_incomplete([huge])
        self.assertTrue(huge.exists())

    def test_quarantine_rejects_symlink_and_outside_path(self) -> None:
        target = self.root / "runs" / "target"
        target.parent.mkdir()
        target.write_bytes(b"x")
        link = self.root / "runs" / "bad.partial"
        link.symlink_to(target)
        with self.assertRaises(RecoveryError):
            self.manager.quarantine_incomplete([link])
        with self.assertRaises(RecoveryError):
            self.manager.quarantine_incomplete([self.root.parent / "outside.partial"])

    def test_recovery_rejects_intermediate_symlink_even_when_target_is_inside_root(self) -> None:
        real = self.root / "runs" / "real"
        real.mkdir(parents=True)
        partial = real / "bad.partial"
        partial.write_bytes(b"x")
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(RecoveryError):
            self.manager.quarantine_incomplete(["alias/bad.partial"])

    def test_authoritative_ledger_cannot_be_quarantined_as_incomplete(self) -> None:
        ledger = self.root / "state" / "events.partial"
        event = make_event("run-1", "e1", None, state_after="PILOT")
        write_ledger(ledger, [event])
        report = self.manager.recover(
            ledger_path="state/events.partial",
            incomplete_paths=("state/events.partial",),
        )
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertTrue(ledger.exists())
        self.assertTrue(self.manager.validate_ledger(ledger).valid)

    def test_checkpoint_selection_uses_ledger_position_not_mtime(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        older = self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": events[0]["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "cp-e1",
            }
        )
        newer = self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e2",
                "ledger_head_hash": events[1]["event_hash"],
                "state": "CONFIRM",
                "checkpoint_id": "cp-e2",
            }
        )
        os.utime(older, (200, 200))
        os.utime(newer, (100, 100))
        selection = self.manager.select_checkpoint(
            ".scientist-one-build/checkpoints", self.manager.validate_ledger(self.ledger_path)
        )
        self.assertIsNotNone(selection)
        self.assertEqual(selection.checkpoint["event_id"], "e2")  # type: ignore[union-attr]

    def test_checkpoint_scan_is_bounded_before_cap_plus_one_name_retention(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        exact = RecoveryManager(self.root, maximum_checkpoint_entries=2)
        exact.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": events[0]["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "cp-e1",
            }
        )
        exact.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e2",
                "ledger_head_hash": events[1]["event_hash"],
                "state": "CONFIRM",
                "checkpoint_id": "cp-e2",
            }
        )
        selection = exact.select_checkpoint(
            ".scientist-one-build/checkpoints", exact.validate_ledger(self.ledger_path)
        )
        self.assertIsNotNone(selection)
        self.assertEqual(selection.checkpoint["event_id"], "e2")  # type: ignore[union-attr]

        class NamedEntry:
            name = "first.json"

        class SentinelEntry:
            @property
            def name(self) -> str:
                raise AssertionError("cap-plus-one checkpoint name must not be retained")

        class GuardedScandir:
            def __init__(self) -> None:
                self._entries = iter((NamedEntry(), SentinelEntry()))
                self.closed = False

            def __enter__(self) -> "GuardedScandir":
                return self

            def __exit__(self, *args: object) -> None:
                self.closed = True

            def __iter__(self) -> "GuardedScandir":
                return self

            def __next__(self) -> object:
                return next(self._entries)

        scans: list[GuardedScandir] = []

        def guarded_scandir(_directory_fd: int) -> GuardedScandir:
            scan = GuardedScandir()
            scans.append(scan)
            return scan

        limited = RecoveryManager(self.root, maximum_checkpoint_entries=1)
        with (
            patch(
                "scientist_one.recovery.os.listdir",
                side_effect=AssertionError("checkpoint scan must not materialize listdir"),
            ),
            patch("scientist_one.recovery.os.scandir", side_effect=guarded_scandir),
        ):
            with self.assertRaisesRegex(RecoveryError, "entry count exceeds"):
                limited.select_checkpoint(
                    ".scientist-one-build/checkpoints",
                    limited.validate_ledger(self.ledger_path),
                )
        self.assertTrue(scans)
        self.assertTrue(all(scan.closed for scan in scans))

    def test_checkpoint_aggregate_bound_is_admitted_before_body_retention(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        for event_id, state in (("e1", "CANDIDATE"), ("e2", "CONFIRM")):
            event = events[int(event_id[-1]) - 1]
            self.manager.create_checkpoint(
                {
                    "run_id": "run-1",
                    "event_id": event_id,
                    "ledger_head_hash": event["event_hash"],
                    "state": state,
                    "checkpoint_id": f"aggregate-{event_id}",
                }
            )
        checkpoint_dir = self.root / ".scientist-one-build" / "checkpoints"
        aggregate_bytes = sum(
            path.stat().st_size for path in checkpoint_dir.iterdir() if path.suffix == ".json"
        )
        ledger = self.manager.validate_ledger(self.ledger_path)

        exact = RecoveryManager(
            self.root,
            maximum_checkpoint_selection_bytes=aggregate_bytes,
        )
        selection = exact.select_checkpoint(
            ".scientist-one-build/checkpoints", ledger
        )
        self.assertIsNotNone(selection)
        self.assertEqual(selection.checkpoint["event_id"], "e2")  # type: ignore[union-attr]

        over_bound = RecoveryManager(
            self.root,
            maximum_checkpoint_selection_bytes=aggregate_bytes - 1,
        )
        with (
            patch(
                "scientist_one.recovery.os.read",
                side_effect=AssertionError(
                    "checkpoint bodies must not be read before aggregate admission"
                ),
            ),
            patch(
                "scientist_one.recovery.safe_json_loads",
                side_effect=AssertionError(
                    "checkpoint bodies must not be parsed before aggregate admission"
                ),
            ),
            patch(
                "scientist_one.recovery.CheckpointSelection",
                side_effect=AssertionError(
                    "checkpoint selections must not be retained before aggregate admission"
                ),
            ),
        ):
            with self.assertRaisesRegex(RecoveryError, "aggregate byte bound"):
                over_bound.select_checkpoint(
                    ".scientist-one-build/checkpoints", ledger
                )
        with self.assertRaisesRegex(RecoveryError, "no greater than"):
            RecoveryManager(
                self.root,
                maximum_checkpoint_selection_bytes=64 * 1024**2 + 1,
            )

    def test_newer_same_run_checkpoint_rejects_stale_ledger_rollback(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events[:1])
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": events[0]["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "01-surviving-older-checkpoint",
            }
        )
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e2",
                "ledger_head_hash": events[1]["event_hash"],
                "state": "CONFIRM",
                "checkpoint_id": "02-surviving-newer-checkpoint",
            }
        )

        stale_ledger = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(stale_ledger.valid)
        with self.assertRaisesRegex(
            LedgerValidationError, "event absent from the validated ledger"
        ):
            self.manager.select_checkpoint(
                ".scientist-one-build/checkpoints", stale_ledger
            )
        report = self.manager.recover(
            ledger_path="state/events.jsonl",
            checkpoint_dir=".scientist-one-build/checkpoints",
        )
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertIn(
            "event absent from the validated ledger", " ".join(report.reasons)
        )

    def test_empty_ledger_cannot_hide_expected_run_checkpoint_rollback(
        self,
    ) -> None:
        event = self.two_events()[0]
        write_ledger(self.ledger_path, [])
        self.manager.create_checkpoint(
            {
                "run_id": "foreign-run",
                "event_id": "foreign-event",
                "ledger_head_hash": "f" * 64,
                "state": "PILOT",
                "checkpoint_id": "00-foreign-checkpoint",
            }
        )
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": event["event_id"],
                "ledger_head_hash": event["event_hash"],
                "state": "PILOT",
                "checkpoint_id": "01-surviving-same-run-checkpoint",
            }
        )
        ledger = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(ledger.valid)
        self.assertIsNone(ledger.run_id)
        with self.assertRaisesRegex(
            LedgerValidationError,
            "no trusted expected run identity",
        ):
            self.manager.select_checkpoint(
                ".scientist-one-build/checkpoints",
                ledger,
            )
        implicit_report = self.manager.recover(
            ledger_path="state/events.jsonl",
            checkpoint_dir=".scientist-one-build/checkpoints",
        )
        self.assertEqual(implicit_report.action, ResumeAction.STOP_SECURITY)
        self.assertIn(
            "no trusted expected run identity",
            " ".join(implicit_report.reasons),
        )
        with self.assertRaisesRegex(
            LedgerValidationError,
            "event absent from the validated ledger",
        ):
            self.manager.select_checkpoint(
                ".scientist-one-build/checkpoints",
                ledger,
                expected_run_id="run-1",
            )
        report = self.manager.recover(
            ledger_path="state/events.jsonl",
            checkpoint_dir=".scientist-one-build/checkpoints",
            expected_run_id="run-1",
        )
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertIn(
            "event absent from the validated ledger",
            " ".join(report.reasons),
        )

        with tempfile.TemporaryDirectory() as empty_root:
            empty = RecoveryManager(empty_root)
            empty_ledger = Path(empty_root) / "runs" / "run-new" / "events.jsonl"
            write_ledger(empty_ledger, [])
            fresh = empty.recover(
                ledger_path="runs/run-new/events.jsonl",
                checkpoint_dir=(
                    ".scientist-one-build/checkpoints/run-new"
                ),
            )
            self.assertEqual(fresh.action, ResumeAction.START_FRESH)

    def test_checkpoint_is_retry_idempotent_and_state_bound_to_event(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        payload = {
            "run_id": "run-1",
            "event_id": "e1",
            "ledger_head_hash": events[0]["event_hash"],
            "state": "CANDIDATE",
            "checkpoint_id": "retry-stable",
        }
        first = self.manager.create_checkpoint(payload)
        first_bytes = first.read_bytes()
        second = self.manager.create_checkpoint(payload)
        self.assertEqual(first, second)
        self.assertEqual(second.read_bytes(), first_bytes)
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e2",
                "ledger_head_hash": events[1]["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "mismatched-state",
            }
        )
        selection = self.manager.select_checkpoint(
            ".scientist-one-build/checkpoints", self.manager.validate_ledger(self.ledger_path)
        )
        self.assertIsNotNone(selection)
        self.assertEqual(selection.checkpoint["checkpoint_id"], "retry-stable")  # type: ignore[union-attr]

    def test_checkpoint_requires_exact_schema_and_full_ledger_artifact_projection(self) -> None:
        artifact = self.root / "artifacts" / "runtime.json"
        artifact.parent.mkdir()
        artifact.write_bytes(b"runtime")
        digest = hashlib.sha256(b"runtime").hexdigest()
        record_hash = "b" * 64
        record = {
            "logical_type": "resource_runtime_initial",
            "path": "artifacts/runtime.json",
            "sha256": digest,
            "record_hash": record_hash,
            "size": 7,
            "frozen": True,
        }
        event = make_event(
            "run-1",
            "e1",
            None,
            state_after="PILOT",
            event_type="CHECKPOINT",
            artifact_hashes=(digest,),
            metadata={
                "artifact_types": ["resource_runtime_initial"],
                "artifact_record_hashes": [record_hash],
            },
        )
        write_ledger(self.ledger_path, [event])
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": event["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "bound",
                "artifact_hashes": {"resource_runtime_initial": digest},
                "artifact_record_hashes": {
                    "resource_runtime_initial": record_hash
                },
                "resource_runtime_artifact": "resource_runtime_initial",
            },
            checkpoint_dir="checkpoints-bound",
        )
        artifacts = self.manager.validate_artifacts([record])
        selected = self.manager.select_checkpoint(
            "checkpoints-bound", self.manager.validate_ledger(self.ledger_path), artifacts
        )
        self.assertIsNotNone(selected)
        with self.assertRaises(RecoveryError):
            self.manager.create_checkpoint(
                {
                    "schema_version": "999.0",
                    "run_id": "run-1",
                    "event_id": "e1",
                    "ledger_head_hash": event["event_hash"],
                    "state": "CANDIDATE",
                }
            )
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": event["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "unbound",
                "artifact_hashes": {},
                "artifact_record_hashes": {},
                "resource_runtime_artifact": None,
            },
            checkpoint_dir="checkpoints-unbound",
        )
        self.assertIsNone(
            self.manager.select_checkpoint(
                "checkpoints-unbound",
                self.manager.validate_ledger(self.ledger_path),
                artifacts,
            )
        )
        with self.assertRaises(RecoveryError):
            self.manager.create_checkpoint(
                {
                    "run_id": "run-1",
                    "event_id": "e1",
                    "ledger_head_hash": event["event_hash"],
                    "state": "CANDIDATE",
                    "resource_runtime_state": {"wall_elapsed_seconds": 0},
                }
            )

    def test_same_event_conflicting_checkpoints_fail_closed(self) -> None:
        artifact = self.root / "artifacts" / "runtime.json"
        artifact.parent.mkdir()
        artifact.write_bytes(b"runtime")
        digest = hashlib.sha256(b"runtime").hexdigest()
        record_hash = "b" * 64
        record = {
            "logical_type": "resource_runtime_initial",
            "path": "artifacts/runtime.json",
            "sha256": digest,
            "record_hash": record_hash,
            "size": 7,
            "frozen": True,
        }
        event = make_event(
            "run-1",
            "e1",
            None,
            state_after="PILOT",
            event_type="CHECKPOINT",
            artifact_hashes=(digest,),
            metadata={
                "artifact_types": ["resource_runtime_initial"],
                "artifact_record_hashes": [record_hash],
            },
        )
        write_ledger(self.ledger_path, [event])
        common = {
            "run_id": "run-1",
            "event_id": "e1",
            "ledger_head_hash": event["event_hash"],
            "state": "CANDIDATE",
            "artifact_hashes": {"resource_runtime_initial": digest},
            "artifact_record_hashes": {"resource_runtime_initial": record_hash},
        }
        self.manager.create_checkpoint(
            {**common, "checkpoint_id": "aa-valid", "resource_runtime_artifact": None},
            checkpoint_dir="ambiguous",
        )
        self.manager.create_checkpoint(
            {
                **common,
                "checkpoint_id": "zz-rollback",
                "resource_runtime_artifact": "resource_runtime_initial",
            },
            checkpoint_dir="ambiguous",
        )
        with self.assertRaises(RecoveryError):
            self.manager.select_checkpoint(
                "ambiguous",
                self.manager.validate_ledger(self.ledger_path),
                self.manager.validate_artifacts([record]),
            )

    def test_orchestrator_checkpoint_round_trip_selects_and_recovers(self) -> None:
        with (
            patch("scientist_one.orchestrator._safe_root", return_value=self.root),
            patch(
                "scientist_one.orchestrator._captured_project_root",
                return_value=None,
            ),
        ):
            orchestrator = ScientistOneOrchestrator(self.root)
        run_id = "run-checkpoint-integration"
        orchestrator._run_dir(run_id, create=True)
        manifest: dict[str, object] = {
            "run_id": run_id,
            "created_at": "2026-01-01T00:00:00Z",
            "current_state": "CALIBRATE",
            "terminal_state": None,
            "event_count": 0,
            "ledger_head_hash": None,
            "artifacts": {},
            "evaluator_decisions": {},
            "code_fingerprint": "d" * 64,
            "configuration_sha256": "c" * 64,
            "fixture_identifiers": ["fixture-v1"],
            "random_seeds": [7],
            "resource_runtime_artifact": None,
        }
        record = orchestrator._artifact(  # type: ignore[arg-type]
            manifest,
            "resource_runtime_initial",
            {"wall_elapsed_seconds": 0},
            creator=Role.ORCHESTRATOR.value,
        )
        (self.root / ".scientist-one-build" / "resource-authority" / run_id).mkdir()
        orchestrator._persist_resource_authority(  # type: ignore[arg-type]
            manifest,
            "resource_runtime_initial",
            {"wall_elapsed_seconds": 0},
        )
        manifest["resource_runtime_artifact"] = "resource_runtime_initial"
        orchestrator._append_event(  # type: ignore[arg-type]
            manifest,
            "INITIALIZED",
            "CALIBRATE",
            "checkpoint integration",
            ("resource_runtime_initial",),
            (),
        )
        orchestrator._checkpoint(manifest)  # type: ignore[arg-type]
        manager = RecoveryManager(self.root)
        ledger_path = Path("runs") / run_id / "events.jsonl"
        ledger = manager.validate_ledger(ledger_path)
        artifacts = manager.validate_artifacts([record])
        directory = Path(".scientist-one-build/checkpoints") / run_id
        selected = manager.select_checkpoint(directory, ledger, artifacts)
        self.assertIsNotNone(selected)
        self.assertEqual(
            selected.checkpoint["resource_runtime_artifact"],  # type: ignore[union-attr]
            "resource_runtime_initial",
        )
        recovered = manager.recover(
            ledger_path=ledger_path,
            artifact_registry=[record],
            checkpoint_dir=directory,
        )
        self.assertEqual(recovered.action, ResumeAction.RESUME_FROM_CHECKPOINT)

    def test_full_ledger_blocks_confirmatory_rerun_despite_old_checkpoint(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        second = make_event(
            "run-1", "e2", str(first["event_hash"]), event_type="CONFIRMATORY_STARTED"
        )
        write_ledger(self.ledger_path, [first, second])
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": first["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "pre-confirmatory",
            }
        )
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.NEW_STUDY_REQUIRED)
        self.assertTrue(report.confirmatory_touched)

    def test_resume_report_counts_ledger_events_after_checkpoint(self) -> None:
        events = self.two_events()
        write_ledger(self.ledger_path, events)
        self.manager.create_checkpoint(
            {
                "run_id": "run-1",
                "event_id": "e1",
                "ledger_head_hash": events[0]["event_hash"],
                "state": "CANDIDATE",
                "checkpoint_id": "cp-old",
            }
        )
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.RESUME_FROM_CHECKPOINT)
        self.assertEqual(report.replay_event_count, 1)

    def test_completed_confirmatory_is_skipped_not_rerun(self) -> None:
        first = make_event("run-1", "e1", None, event_type="CONFIRMATORY_STARTED")
        second = make_event(
            "run-1", "e2", str(first["event_hash"]), event_type="CONFIRMATORY_COMPLETED"
        )
        write_ledger(self.ledger_path, [first, second])
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.SKIP_COMPLETED)
        self.assertTrue(report.confirmatory_completed)
        with self.assertRaises(ConfirmatoryRerunError):
            self.manager.assert_confirmatory_run_allowed(ledger_path="state/events.jsonl")

    def test_downstream_verify_state_implies_confirmatory_completion(self) -> None:
        event = make_event("run-1", "e1", None, state_after="VERIFY")
        write_ledger(self.ledger_path, [event])
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.SKIP_COMPLETED)
        self.assertTrue(report.confirmatory_completed)

    def test_downstream_audit_state_implies_confirmatory_completion(self) -> None:
        event = make_event("run-1", "e1", None, state_after="AUDIT")
        write_ledger(self.ledger_path, [event])
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.SKIP_COMPLETED)
        self.assertTrue(report.confirmatory_touched)
        self.assertTrue(report.confirmatory_completed)

    def test_confirm_to_claims_transition_is_irreversible_completion(self) -> None:
        event = make_event("run-1", "e1", None, state_after="CLAIMS")
        write_ledger(self.ledger_path, [event])
        report = self.manager.recover(ledger_path="state/events.jsonl")
        self.assertEqual(report.action, ResumeAction.SKIP_COMPLETED)
        self.assertTrue(report.confirmatory_touched)
        self.assertTrue(report.confirmatory_completed)

    def test_confirmatory_admission_requires_explicit_trusted_custody_evidence(self) -> None:
        event = make_event("run-1", "e1", None, state_after="CANDIDATE")
        write_ledger(self.ledger_path, [event])
        with self.assertRaises(ConfirmatoryRerunError):
            self.manager.assert_confirmatory_run_allowed(ledger_path=self.ledger_path)
        with self.assertRaises(TypeError):
            self.manager.assert_confirmatory_run_allowed(
                ledger_path=self.ledger_path, custody_verified_unaccessed=True  # type: ignore[call-arg]
            )

    def test_scientific_confirmation_rejects_simulated_custody_without_mutation(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle(scientific_confirmation=True)
        provider = bundle["provider"]
        journal_head = provider.verify_journal()  # type: ignore[attr-defined]
        with provider._reveal_admission_guard() as session:  # type: ignore[attr-defined]
            with self.assertRaisesRegex(
                HoldoutAccessViolation,
                "cannot authorize scientific confirmation",
            ):
                session._release(
                    coordinator=self.manager,
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    execution_class=RevealExecutionClass.SCIENTIFIC_CONFIRMATION,
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="direct scientific simulation must fail",
                )
        with self.assertRaisesRegex(
            ConfirmatoryRerunError,
            "rejects non-independent custody",
        ):
            self.manager.run_confirmatory_authorized(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=provider,
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="scientific confirmation must reject simulated custody",
            )
        self.assertEqual(provider.verify_journal(), journal_head)  # type: ignore[attr-defined]
        self.assertFalse(provider.status.revealed)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

    def test_non_evidentiary_fixture_publishes_start_before_locked_release(self) -> None:
        bundle = self.reveal_authority_bundle()
        provider = bundle["provider"]
        initial_journal_head = provider.verify_journal()  # type: ignore[attr-defined]
        with provider._reveal_admission_guard() as direct_session:  # type: ignore[attr-defined]
            with self.assertRaisesRegex(HoldoutAccessViolation, "coordinator"):
                direct_session._release(
                    coordinator=object(),
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    execution_class=(
                        RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
                    ),
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="direct guard bypass must fail",
                )
        self.assertEqual(provider.verify_journal(), initial_journal_head)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

        cross_root = self.root / "cross-provider-root"
        cross_root.mkdir()
        cross_provider = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=cross_root,
            journal_path="cross-provider-custody.jsonl",
        )
        source_seal = provider.seal_record  # type: ignore[attr-defined]
        assert source_seal is not None
        cross_provider.seal(
            b'{"confirmatory":"cross-provider"}',
            split_manifest_hash=source_seal.split_manifest_hash,
            protocol_hash=source_seal.protocol_hash,
            code_hash=source_seal.code_hash,
            configuration_hash=source_seal.configuration_hash,
            pre_unblinding_interpretation_hash=(
                source_seal.pre_unblinding_interpretation_hash
            ),
            sealed_at="2026-01-01T00:00:00Z",
        )
        cross_head = cross_provider.verify_journal()
        with cross_provider._reveal_admission_guard() as cross_session:
            with self.assertRaisesRegex(HoldoutAccessViolation, "does not belong"):
                cross_session._release(
                    coordinator=self.manager,
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    execution_class=(
                        RevealExecutionClass.SIMULATED_ARCHITECTURE_CONTROL
                    ),
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="cross-provider splice must fail",
                )

        exfiltrated: list[bytes] = []

        def exfiltrate(payload: bytes) -> bytes:
            exfiltrated.append(payload)
            return payload

        with self.assertRaises(TypeError):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=provider,
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator=exfiltrate,  # type: ignore[call-arg]
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="arbitrary evaluator callback must not receive holdout bytes",
            )
        self.assertEqual(exfiltrated, [])
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )
        self.assertFalse(hasattr(provider, "_evaluate_confirmatory_payload"))
        with self.assertRaisesRegex(
            ConfirmatoryRerunError,
            "closed repository-owned spec",
        ):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=provider,
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=object(),  # type: ignore[arg-type]
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="substituted evaluator must fail",
            )
        with self.assertRaisesRegex(HoldoutCustodyError, "repository-owned"):
            ConfirmatoryEvaluatorSpec(evaluator_id="CALLER_EVALUATOR")
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

        release, result = self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=self.ledger_path,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=provider,
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="single content-bound confirmatory run",
            requested_at="2026-01-01T00:01:00Z",
        )
        self.assertEqual(result["primary_estimate"], 1.0)
        self.assertNotIn("fixture", result)
        self.assertNotIn("control", result)
        self.assertNotIn("treatment", result)
        self.assertEqual(release.authorized_access_count, 1)
        self.assertEqual(cross_provider.verify_journal(), cross_head)
        self.assertFalse(cross_provider.status.revealed)
        validated = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(validated.valid)
        self.assertEqual(
            validated.events[-1]["event_type"],
            "CHECKPOINT",
        )
        self.assertEqual(
            validated.events[-1]["metadata"]["execution_kind"],
            "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
        )
        self.assertTrue(provider.status.revealed)  # type: ignore[attr-defined]
        self.assertTrue(provider.status.invalidated)  # type: ignore[attr-defined]
        self.assertFalse(provider.status.confirmatory_claims_valid)  # type: ignore[attr-defined]
        self.assertEqual(provider.status.authorized_access_count, 1)  # type: ignore[attr-defined]
        release_head = provider.verify_journal()  # type: ignore[attr-defined]
        journal = provider.journal_path  # type: ignore[attr-defined]
        assert journal is not None
        journal_events = [
            json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [event["event_type"] for event in journal_events[-2:]],
            ["RELEASE", "EVALUATION_SUCCEEDED"],
        )
        self.assertEqual(
            journal_events[-2]["payload"]["authority"]["started_event_hash"],
            bundle["start_event"].event_hash,  # type: ignore[attr-defined]
        )
        self.assertEqual(
            journal_events[-2]["payload"]["authority"]["evidence_class"],
            "ARCHITECTURE_CONTROL",
        )
        self.assertEqual(
            journal_events[-2]["payload"]["record"]["detail"],
            "single non-evidentiary simulated fixture release",
        )
        self.assertEqual(
            journal_events[-1]["payload"]["evaluator_binding"][
                "implementation_sha256"
            ],
            journal_events[-2]["payload"]["authority"][
                "evaluator_implementation_sha256"
            ],
        )
        self.assertEqual(
            journal_events[-1]["payload"]["result"],
            result,
        )
        self.assertEqual(
            journal_events[-1]["payload"]["result_sha256"],
            hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
        )
        reloaded = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
        )
        self.assertTrue(reloaded.status.invalidated)
        self.assertFalse(reloaded.status.confirmatory_claims_valid)
        with self.assertRaises(HoldoutAlreadyRevealed):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=provider,
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="forbidden replay",
            )
        self.assertEqual(provider.verify_journal(), release_head)  # type: ignore[attr-defined]

    def test_non_evidentiary_fixture_preserves_candidate_ledger_head(self) -> None:
        bundle = self.reveal_authority_bundle(ledger_state="CANDIDATE")

        self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=self.ledger_path,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=bundle["provider"],
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="candidate-state architecture control",
            requested_at="2026-01-01T00:01:00Z",
        )

        validation = self.manager.validate_ledger(self.ledger_path)
        self.assertTrue(validation.valid)
        self.assertEqual(validation.events[-1]["event_type"], "CHECKPOINT")
        self.assertEqual(validation.events[-1]["state_before"], "CANDIDATE")
        self.assertEqual(
            validation.events[-1]["requested_state_after"], "CANDIDATE"
        )
        self.assertEqual(
            validation.events[-1]["metadata"]["evidence_class"],
            "ARCHITECTURE_CONTROL",
        )

    def test_scientific_start_requires_existing_confirm_state_before_append(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle(
            scientific_confirmation=True,
            ledger_state="CANDIDATE",
        )
        provider = bundle["provider"]
        journal_head = provider.verify_journal()  # type: ignore[attr-defined]

        with provider._reveal_admission_guard() as session:  # type: ignore[attr-defined]
            with self.assertRaisesRegex(
                ConfirmatoryRerunError,
                "scientific confirmation additionally requires CONFIRM",
            ):
                self.manager._admit_confirmatory_locked(
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],  # type: ignore[arg-type]
                    _locked_session=session,
                    _execution_class=(
                        RevealExecutionClass.SCIENTIFIC_CONFIRMATION
                    ),
                )

        self.assertEqual(provider.verify_journal(), journal_head)  # type: ignore[attr-defined]
        self.assertFalse(provider.status.revealed)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

    def test_scientific_readback_rejects_candidate_state_started_marker(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle(
            scientific_confirmation=True,
            ledger_state="CANDIDATE",
        )
        EventLedger(self.root, "state/events.jsonl").append(bundle["start_event"])

        with self.assertRaisesRegex(
            ConfirmatoryRerunError,
            "confirmation STARTED does not bind the frozen reveal design",
        ):
            register_confirmation_reveal_gate_receipt(
                bundle["registry"],
                EventLedger(self.root, "state/events.jsonl"),
                expected_run_id="run-1",
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                started_event_id="confirmatory-started",
            )

    def test_architecture_control_start_rejects_stale_head_without_append(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle()
        start_event = bundle["start_event"]
        candidates = (
            replace(
                start_event,
                state_before=MacroState.CANDIDATE,
                requested_state_after=MacroState.CANDIDATE,
                event_hash=None,
            ),
            replace(
                start_event,
                prior_event_hash="f" * 64,
                event_hash=None,
            ),
        )

        for candidate in candidates:
            with self.subTest(event_id=candidate.event_id), self.assertRaisesRegex(
                ConfirmatoryRerunError,
                "must preserve the exact current ledger head",
            ):
                self.manager.run_non_evidentiary_simulated_fixture(
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=bundle["provider"],
                    validity_snapshot=bundle["snapshot"],
                    start_event=candidate,
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="stale architecture-control start",
                )

        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

    def test_reveal_rejects_stale_validity_snapshot_before_start_or_release(self) -> None:
        bundle = self.reveal_authority_bundle()
        with self.assertRaisesRegex(ConfirmatoryRerunError, "validity snapshot"):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=ValidityBudgetSnapshot(10, 6, 4, 2, 0),
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="stale snapshot must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

    def test_reveal_rejects_substituted_closed_evaluator_source(self) -> None:
        bundle = self.reveal_authority_bundle(substitute_evaluator_source=True)
        with self.assertRaisesRegex(
            ConfirmatoryRerunError,
            "simulated evaluator implementation differs",
        ):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="substituted evaluator implementation must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]
        self.assertEqual(
            self.manager.validate_ledger(self.ledger_path).event_count,
            bundle["pre_start_event_count"],
        )

    def test_reveal_rejects_spliced_registered_selector_before_start(self) -> None:
        bundle = self.reveal_authority_bundle()
        authority = bundle["authority"]
        spliced = replace(
            authority,
            blind_interpretation=authority.source_inventory,  # type: ignore[attr-defined]
        )
        with self.assertRaisesRegex(ConfirmatoryRerunError, "blind_interpretation"):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=spliced,
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="spliced selector must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]

    def test_retired_admission_only_api_never_invokes_start_callback(self) -> None:
        study = frozen_test_study()
        registry, provider, evidence, events = self.custody_bundle(study, [])
        write_ledger(self.ledger_path, events)
        invoked = False

        def forbidden_callback() -> None:
            nonlocal invoked
            invoked = True

        with self.assertRaises(TypeError):
            self.manager.assert_confirmatory_run_allowed(
                ledger_path=self.ledger_path,
                new_study_protocol=study,
                fresh_custody_evidence=evidence,
                artifact_registry=registry,
                custody_provider=provider,
                admission_callback=forbidden_callback,  # type: ignore[call-arg]
            )
        self.assertFalse(invoked)
        # The retired API cannot publish STARTED and return before RELEASE.
        report = self.manager.recover(ledger_path=self.ledger_path)
        self.assertFalse(report.confirmatory_touched)

    def test_reveal_rejects_resource_charge_from_wrong_run(self) -> None:
        bundle = self.reveal_authority_bundle(resource_run_id="other-run")
        with self.assertRaisesRegex(ConfirmatoryRerunError, "different ledger run"):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="wrong resource run must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]

    def test_reveal_rejects_arbitrary_resource_authority_checkpoint(self) -> None:
        bundle = self.reveal_authority_bundle(corrupt_charge_checkpoint=True)
        with self.assertRaisesRegex(ConfirmatoryRerunError, "monotonic authority"):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="arbitrary resource checkpoint must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]

    def test_reveal_rejects_resource_parent_substitution(self) -> None:
        bundle = self.reveal_authority_bundle(substitute_resource_parent=True)
        with self.assertRaisesRegex(ConfirmatoryRerunError, "external authority head"):
            self.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=self.ledger_path,
                study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                artifact_registry=bundle["registry"],
                custody_provider=bundle["provider"],
                validity_snapshot=bundle["snapshot"],
                start_event=bundle["start_event"],  # type: ignore[arg-type]
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason="resource parent substitution must fail",
            )
        self.assertFalse(bundle["provider"].status.revealed)  # type: ignore[attr-defined]

    def test_confirmation_reveal_gate_receipt_replays_exact_blocked_boundary(self) -> None:
        bundle = self.reveal_authority_bundle(scientific_confirmation=True)
        EventLedger(self.root, "state/events.jsonl").append(bundle["start_event"])
        study = bundle["study"]
        object_id = confirmation_reveal_gate_object_id(
            "run-1",
            study.study_id,  # type: ignore[attr-defined]
            study.version,  # type: ignore[attr-defined]
        )
        record = register_confirmation_reveal_gate_receipt(
            bundle["registry"],
            EventLedger(self.root, "state/events.jsonl"),
            expected_run_id="run-1",
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            started_event_id="confirmatory-started",
        )
        receipt = require_confirmation_reveal_gate_receipt(
            bundle["registry"],
            EventLedger(self.root, "state/events.jsonl"),
            receipt_artifact_sha256=record.sha256,
            expected_run_id="run-1",
            expected_object_id=object_id,
        )
        self.assertEqual(
            receipt.evidence_class,
            CONFIRMATION_REVEAL_EVIDENCE_ARCHITECTURE_CONTROL,
        )
        self.assertEqual(
            receipt.verification_status,
            CONFIRMATION_REVEAL_STATUS_BLOCKED_NON_INDEPENDENT,
        )
        self.assertFalse(receipt.scientific_gate_passed)
        with self.assertRaises(RecoveryError):
            replace(receipt, custody_independence="HUMAN_INDEPENDENT")
        with self.assertRaisesRegex(ConfirmatoryRerunError, "another run"):
            require_confirmation_reveal_gate_receipt(
                bundle["registry"],
                EventLedger(self.root, "state/events.jsonl"),
                receipt_artifact_sha256=record.sha256,
                expected_run_id="other-run",
                expected_object_id=object_id,
            )

        current = self.manager.validate_ledger(self.ledger_path)
        terminal = LedgerEvent.from_dict(
            make_event(
                "run-1",
                "confirmatory-completed",
                current.head_hash,
                event_type="CONFIRMATORY_COMPLETED",
            )
        )
        EventLedger(self.root, "state/events.jsonl").append(terminal)
        with self.assertRaisesRegex(ConfirmatoryRerunError, "pre-reveal"):
            require_confirmation_reveal_gate_receipt(
                bundle["registry"],
                EventLedger(self.root, "state/events.jsonl"),
                receipt_artifact_sha256=record.sha256,
                expected_run_id="run-1",
                expected_object_id=object_id,
            )

    def test_confirmation_reveal_gate_rejects_wrong_protocol_selector(self) -> None:
        bundle = self.reveal_authority_bundle(scientific_confirmation=True)
        EventLedger(self.root, "state/events.jsonl").append(bundle["start_event"])
        authority = bundle["authority"]
        with self.assertRaisesRegex(ConfirmatoryRerunError, "frozen_protocol"):
            register_confirmation_reveal_gate_receipt(
                bundle["registry"],
                EventLedger(self.root, "state/events.jsonl"),
                expected_run_id="run-1",
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=replace(
                    authority,
                    protocol=authority.source_inventory,  # type: ignore[attr-defined]
                ),
                started_event_id="confirmatory-started",
            )

    def test_confirmation_reveal_gate_rejects_live_release_without_custody_record(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle()
        fixture_ledger = self.root / "state" / "fixture-events.jsonl"
        fixture_ledger.write_bytes(self.ledger_path.read_bytes())
        self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=fixture_ledger,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=bundle["provider"],
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="durable release before custody record",
        )
        self.assertFalse(
            any(
                record.logical_type == "custody_record"
                for record in bundle["registry"].list_records()  # type: ignore[attr-defined]
            )
        )
        scientific = bundle["start_event"].to_dict()  # type: ignore[attr-defined]
        scientific["event_type"] = "CONFIRMATORY_STARTED"
        scientific["metadata"] = {
            **scientific["metadata"],
            "evidence_class": "SCIENTIFIC_EVIDENCE",
            "execution_kind": "SCIENTIFIC_CONFIRMATION_STARTED",
        }
        scientific["event_hash"] = event_digest(scientific)
        EventLedger(self.root, "state/events.jsonl").append(
            LedgerEvent.from_dict(scientific)
        )
        with self.assertRaisesRegex(
            ConfirmatoryRerunError,
            "live custody journal is absent, stale, or released",
        ):
            register_confirmation_reveal_gate_receipt(
                bundle["registry"],
                EventLedger(self.root, "state/events.jsonl"),
                expected_run_id="run-1",
                fresh_custody_evidence=bundle["evidence"],
                reveal_authority=bundle["authority"],
                started_event_id="confirmatory-started",
            )

    def test_evaluator_failure_persists_failed_terminal_and_reloads_invalid(self) -> None:
        bundle = self.reveal_authority_bundle(invalid_evaluator_payload=True)
        provider = bundle["provider"]

        with patch.object(
            provider,
            "record_violation",
            side_effect=AssertionError("separate invalidation must not be required"),
        ) as invalidator:
            with self.assertRaisesRegex(HoldoutCustodyError, "evaluator failed"):
                self.manager.run_non_evidentiary_simulated_fixture(
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],  # type: ignore[arg-type]
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="failed evaluation must invalidate",
                )
        invalidator.assert_not_called()
        reloaded = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
        )
        self.assertTrue(reloaded.status.revealed)
        self.assertTrue(reloaded.status.invalidated)
        self.assertFalse(reloaded.status.confirmatory_claims_valid)
        journal = reloaded.journal_path
        assert journal is not None
        self.assertEqual(
            json.loads(journal.read_text(encoding="utf-8").splitlines()[-1])[
                "event_type"
            ],
            "EVALUATION_FAILED",
        )

    def test_failed_terminal_write_leaves_release_pending_and_reload_invalid(self) -> None:
        bundle = self.reveal_authority_bundle(invalid_evaluator_payload=True)
        provider = bundle["provider"]
        original_append = provider._append_journal_locked  # type: ignore[attr-defined]

        def fail_terminal(
            descriptor: int | None,
            event_type: str,
            payload: dict[str, object],
        ) -> object:
            if event_type == "EVALUATION_FAILED":
                raise HoldoutJournalError("forced terminal append failure")
            return original_append(descriptor, event_type, payload)

        with patch.object(
            provider,
            "_append_journal_locked",
            new=fail_terminal,
        ):
            with self.assertRaisesRegex(HoldoutJournalError, "invalidation is pending"):
                self.manager.run_non_evidentiary_simulated_fixture(
                    ledger_path=self.ledger_path,
                    study_version=bundle["study"],
                    fresh_custody_evidence=bundle["evidence"],
                    reveal_authority=bundle["authority"],
                    artifact_registry=bundle["registry"],
                    custody_provider=provider,
                    validity_snapshot=bundle["snapshot"],
                    start_event=bundle["start_event"],  # type: ignore[arg-type]
                    evaluator_spec=ConfirmatoryEvaluatorSpec(),
                    requester=Role.EXPERIMENT_RUNNER.value,
                    reason="missing terminal must remain invalid",
                )
        reloaded = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
        )
        self.assertTrue(reloaded.status.revealed)
        self.assertTrue(reloaded.status.invalidated)
        self.assertFalse(reloaded.status.confirmatory_claims_valid)
        self.assertIn("incomplete", reloaded.status.violation_reasons[-1])
        journal = reloaded.journal_path
        assert journal is not None
        self.assertEqual(
            json.loads(journal.read_text(encoding="utf-8").splitlines()[-1])[
                "event_type"
            ],
            "RELEASE",
        )

    def test_reload_rejects_rehashed_release_record_field_substitution(self) -> None:
        bundle = self.reveal_authority_bundle()
        self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=self.ledger_path,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=bundle["provider"],
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="release binding tamper test",
            requested_at="2026-01-01T00:01:00Z",
        )
        journal = bundle["provider"].journal_path  # type: ignore[attr-defined]
        assert journal is not None
        events = [
            json.loads(line)
            for line in journal.read_text(encoding="utf-8").splitlines()
        ]
        def omit_reason(payload: dict[str, object]) -> None:
            payload["release"].pop("reason")  # type: ignore[union-attr]

        def add_field(payload: dict[str, object]) -> None:
            payload["record"]["caller_attested_valid"] = True  # type: ignore[index]

        def mismatch_requester(payload: dict[str, object]) -> None:
            payload["record"]["requester"] = "substituted-runner"  # type: ignore[index]

        def mismatch_release_id(payload: dict[str, object]) -> None:
            payload["release"]["release_id"] = "0" * 64  # type: ignore[index]

        for name, mutate in (
            ("omission", omit_reason),
            ("addition", add_field),
            ("cross-field", mismatch_requester),
            ("canonical-id", mismatch_release_id),
        ):
            with self.subTest(name=name):
                forged = json.loads(json.dumps(events))
                release = next(
                    event for event in forged if event["event_type"] == "RELEASE"
                )
                mutate(release["payload"])
                rewrite_custody_journal(journal, forged)
                with self.assertRaises(HoldoutJournalError):
                    SimulatedHoldoutCustody(
                        (Role.EXPERIMENT_RUNNER.value,),
                        journal_root=self.root,
                        journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
                    )

    def test_reload_rejects_terminal_implementation_and_result_substitution(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle()
        self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=self.ledger_path,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=bundle["provider"],
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="terminal binding tamper test",
        )
        journal = bundle["provider"].journal_path  # type: ignore[attr-defined]
        assert journal is not None
        original = [
            json.loads(line)
            for line in journal.read_text(encoding="utf-8").splitlines()
        ]

        def implementation(events: list[dict[str, object]]) -> None:
            events[-1]["payload"]["evaluator_binding"][  # type: ignore[index]
                "implementation_sha256"
            ] = "0" * 64

        def release_implementation(events: list[dict[str, object]]) -> None:
            events[-2]["payload"]["authority"][  # type: ignore[index]
                "evaluator_implementation_sha256"
            ] = "0" * 64

        def result_content(events: list[dict[str, object]]) -> None:
            events[-1]["payload"]["result"]["primary_estimate"] = 2.0  # type: ignore[index]

        def result_digest(events: list[dict[str, object]]) -> None:
            events[-1]["payload"]["result_sha256"] = "0" * 64  # type: ignore[index]

        for name, mutate in (
            ("terminal-implementation", implementation),
            ("release-implementation", release_implementation),
            ("result-content", result_content),
            ("result-digest", result_digest),
        ):
            with self.subTest(name=name):
                forged = json.loads(json.dumps(original))
                mutate(forged)
                rewrite_custody_journal(journal, forged)
                with self.assertRaises(HoldoutJournalError):
                    SimulatedHoldoutCustody(
                        (Role.EXPERIMENT_RUNNER.value,),
                        journal_root=self.root,
                        journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
                    )

    def test_reload_rejects_rehashed_non_independent_scientific_promotion(
        self,
    ) -> None:
        bundle = self.reveal_authority_bundle()
        self.manager.run_non_evidentiary_simulated_fixture(
            ledger_path=self.ledger_path,
            study_version=bundle["study"],
            fresh_custody_evidence=bundle["evidence"],
            reveal_authority=bundle["authority"],
            artifact_registry=bundle["registry"],
            custody_provider=bundle["provider"],
            validity_snapshot=bundle["snapshot"],
            start_event=bundle["start_event"],  # type: ignore[arg-type]
            evaluator_spec=ConfirmatoryEvaluatorSpec(),
            requester=Role.EXPERIMENT_RUNNER.value,
            reason="evidence-class promotion tamper test",
        )
        journal = bundle["provider"].journal_path  # type: ignore[attr-defined]
        assert journal is not None
        original = [
            json.loads(line)
            for line in journal.read_text(encoding="utf-8").splitlines()
        ]
        forged = json.loads(json.dumps(original))
        release = next(
            event for event in forged if event["event_type"] == "RELEASE"
        )
        release["payload"]["authority"]["evidence_class"] = (  # type: ignore[index]
            "SCIENTIFIC_EVIDENCE"
        )
        release["payload"]["record"]["detail"] = (  # type: ignore[index]
            "single authorized confirmatory reveal"
        )
        rewrite_custody_journal(journal, forged)

        with self.assertRaisesRegex(HoldoutJournalError, "provider independence"):
            SimulatedHoldoutCustody(
                (Role.EXPERIMENT_RUNNER.value,),
                journal_root=self.root,
                journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
            )

        forged = json.loads(json.dumps(original))
        forged[0]["payload"]["seal"]["custody_independence"] = (  # type: ignore[index]
            "HUMAN_INDEPENDENT"
        )
        rewrite_custody_journal(journal, forged)
        with self.assertRaisesRegex(
            HoldoutJournalError,
            "seal differs from provider independence",
        ):
            SimulatedHoldoutCustody(
                (Role.EXPERIMENT_RUNNER.value,),
                journal_root=self.root,
                journal_path=bundle["journal_relative"],  # type: ignore[arg-type]
            )

    def test_new_study_recovery_requires_fresh_registry_ledger_and_live_custody(self) -> None:
        parent = frozen_test_study()
        revealed = record_confirmatory_reveal(
            parent,
            release_hash="a" * 64,
            revealed_at="2026-01-01T00:00:00Z",
        )
        child = revise_study_version(
            revealed,
            revision_reason="new preregistered hypothesis",
            changes={"primary_hypothesis": "revised treatment hypothesis"},
        )
        touched = make_event(
            "run-1", "old-confirm", None, event_type="CONFIRMATORY_STARTED"
        )
        registry, provider, evidence, events = self.custody_bundle(child, [touched])
        write_ledger(self.ledger_path, events)
        old_custody = {
            "study_id": parent.study_id,
            "study_version": parent.version,
            "protocol_hash": parent.protocol_hash,
            "access_count": 1,
            "holdout_identity_hash": "1" * 64,
            "split_manifest_hash": "2" * 64,
            "seal_hash": "3" * 64,
        }
        blocked = self.manager.recover(
            ledger_path=self.ledger_path,
            artifact_registry=registry,
            custody_record=old_custody,
            new_study_protocol=child,
        )
        self.assertEqual(blocked.action, ResumeAction.NEW_STUDY_REQUIRED)
        accepted = self.manager.recover(
            ledger_path=self.ledger_path,
            artifact_registry=registry,
            custody_record=old_custody,
            new_study_protocol=child,
            fresh_custody_evidence=evidence,
            custody_provider=provider,
        )
        self.assertEqual(accepted.action, ResumeAction.START_NEW_STUDY)
        self.assertTrue(accepted.new_study_protocol_accepted)

    def test_missing_ledger_returns_observable_stop_security(self) -> None:
        report = self.manager.recover(ledger_path="state/missing.jsonl")
        self.assertEqual(report.action, ResumeAction.STOP_SECURITY)
        self.assertFalse(report.ledger_valid)

    def test_custody_access_rejects_minimal_new_study_mapping(self) -> None:
        first = make_event("run-1", "e1", None, state_after="PILOT")
        write_ledger(self.ledger_path, [first])
        custody = {
            "study_id": "study-1",
            "protocol_hash": "a" * 64,
            "access_count": 1,
        }
        blocked = self.manager.recover(
            ledger_path="state/events.jsonl", custody_record=custody
        )
        self.assertEqual(blocked.action, ResumeAction.NEW_STUDY_REQUIRED)
        rejected = self.manager.recover(
            ledger_path="state/events.jsonl",
            custody_record=custody,
            new_study_protocol={
                "study_id": "study-2",
                "parent_study_id": "study-1",
                "protocol_hash": "b" * 64,
                "frozen": True,
                "fresh_confirmatory_reserve": True,
            },
        )
        self.assertEqual(rejected.action, ResumeAction.NEW_STUDY_REQUIRED)

    def test_frozen_registered_partial_is_preserved_and_not_auto_quarantined(self) -> None:
        event = make_event("run-1", "e1", None, state_after="PILOT")
        write_ledger(self.ledger_path, [event])
        partial = self.root / "artifacts" / "registered.partial"
        partial.parent.mkdir()
        partial.write_bytes(b"valid")
        record = {
            "path": "artifacts/registered.partial",
            "sha256": hashlib.sha256(b"valid").hexdigest(),
            "size": 5,
            "frozen": True,
        }
        report = self.manager.recover(
            ledger_path="state/events.jsonl", artifact_registry=[record]
        )
        self.assertEqual(report.action, ResumeAction.RESUME_FROM_LEDGER)
        self.assertEqual(report.quarantined, ())
        self.assertTrue(partial.exists())


if __name__ == "__main__":
    unittest.main()
