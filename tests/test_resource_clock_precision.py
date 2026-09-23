"""Native clock accounting at epoch-float boundaries, not execution authority."""

import math
from pathlib import Path
import tempfile
import unittest

from scientist_one.orchestrator import _validate_monotonic_resource_states
from scientist_one.resources import ResourceConfig, ResourceController


class ResourceClockPrecisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="resource-clock-precision-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_progress_and_checkpoint_never_exceed_epoch_rounded_elapsed(self):
        for epoch in (1000.0, 1_000_000_000.0, 1_800_000_000.0, 1_000_000_000_000.0):
            for observer in ("record_progress", "mark_checkpoint"):
                with self.subTest(epoch=epoch, observer=observer):
                    start = 100.0
                    observed = start + math.ulp(epoch) / 4
                    monotonic = iter((start, observed))
                    wall = iter((epoch, epoch))
                    controller = ResourceController(
                        ResourceConfig(), self.root, artifact_roots=(),
                        clock=lambda: next(monotonic),
                        wall_clock=lambda: next(wall),
                        validity_budget_units=40,
                    )
                    initial = controller.export_state()
                    getattr(controller, observer)()
                    result = controller.export_state()
                    self.assertEqual(controller.export_state(), result)
                    self.assertGreaterEqual(result.wall_elapsed_seconds, observed - start)
                    self.assertLessEqual(
                        result.wall_elapsed_seconds, observed - start + math.ulp(epoch)
                    )
                    self.assertEqual(
                        result.wall_elapsed_seconds,
                        result.wall_observed_at_epoch_seconds
                        - result.wall_started_at_epoch_seconds,
                    )
                    self.assertEqual(result.exploratory_used, 0)
                    self.assertEqual(result.confirmatory_used, 0)
                    self.assertEqual(
                        _validate_monotonic_resource_states(
                            tuple({"state": item.to_dict()} for item in (initial, result))
                        ),
                        (initial, result),
                    )

    def test_rounded_epoch_start_and_accounting_survive_restart_without_refund(self):
        epoch = 1_800_000_000.0
        monotonic = iter((100.0, 100.00000006))
        wall = iter((epoch, epoch))
        controller = ResourceController(
            ResourceConfig(), self.root, artifact_roots=(), run_id="clock-restart",
            clock=lambda: next(monotonic), wall_clock=lambda: next(wall),
            validity_budget_units=40,
        )
        controller.validity_budget.charge("CONFIRMATORY", 8)
        controller.record_progress()
        saved = controller.export_state()
        restored = ResourceController.from_runtime_state(
            controller.config, self.root, saved, artifact_roots=(),
            clock=lambda: 1000.0, wall_clock=lambda: epoch,
        )
        replay = restored.export_state()
        self.assertEqual(replay.wall_started_at_epoch_seconds, saved.wall_started_at_epoch_seconds)
        self.assertGreaterEqual(replay.wall_elapsed_seconds, saved.wall_elapsed_seconds)
        self.assertEqual(replay.confirmatory_used, 8)
        self.assertEqual(replay.progress_elapsed_seconds, saved.progress_elapsed_seconds)

    def test_exact_offsets_survive_lower_upward_and_exact_rebases(self):
        epoch = 1_800_000_000.0
        monotonic = iter((100.0, 100.00000003, 100.00000006))
        controller = ResourceController(
            ResourceConfig(), self.root, artifact_roots=(),
            clock=lambda: next(monotonic), wall_clock=lambda: epoch,
            validity_budget_units=40,
        )
        controller.mark_checkpoint()
        controller.record_progress()
        saved = controller.export_state()
        for base in (0.0, 1.0, 100.0, 1000.0, 10000.0, 1_000_000.0, 1_000_000_000.0):
            with self.subTest(base=base):
                ticks = iter((base, base + 1.0, base + 2.0))
                walls = iter((epoch, epoch + 1.0, epoch + 2.0))
                restored = ResourceController.from_runtime_state(
                    controller.config, self.root, saved, artifact_roots=(),
                    clock=lambda: next(ticks), wall_clock=lambda: next(walls),
                )
                replay = restored.export_state()
                self.assertEqual(replay.checkpoint_elapsed_seconds, saved.checkpoint_elapsed_seconds)
                self.assertEqual(replay.progress_elapsed_seconds, saved.progress_elapsed_seconds)
                restored.mark_checkpoint()
                checkpoint = restored.export_state()
                restored.record_progress()
                progressed = restored.export_state()
                sequence = (saved, replay, checkpoint, progressed)
                self.assertEqual(
                    _validate_monotonic_resource_states(
                        tuple({"state": item.to_dict()} for item in sequence)
                    ),
                    sequence,
                )
