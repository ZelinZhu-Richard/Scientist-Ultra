from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from scientist_one.experiments import (
    ExperimentIntegrityError,
    FrozenRunSpec,
    LocalMacBackend,
    RunState,
    default_local_cpu_profile,
    default_resource_estimate,
)


WORKER_SOURCE = """\
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

child = subprocess.Popen(
    [sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(60)"],
    close_fds=True,
)

def handle_term(_signum, _frame):
    try:
        child.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass

signal.signal(signal.SIGTERM, handle_term)
with Path(sys.argv[1]).open("w", encoding="utf-8") as stream:
    stream.write(f"{os.getpid()}\\n{child.pid}\\n")
    stream.flush()
    os.fsync(stream.fileno())
while True:
    time.sleep(1)
"""
DATA_BYTES = b'{"fixture":"process-tree-data"}\n'
CONFIGURATION_BYTES = b'{"fixture":"process-tree-configuration"}\n'
EVALUATOR_BYTES = b'{"fixture":"process-tree-evaluator"}\n'


def _spec(run_id: str, *, timeout_seconds: float) -> FrozenRunSpec:
    return FrozenRunSpec(
        run_id=run_id,
        experiment_id="process-tree-termination",
        hypothesis_id="bounded-local-process-tree",
        phase="EXPLORATORY",
        argv=(
            sys.executable,
            "-I",
            "-S",
            "-B",
            "worker.py",
            "pids.txt",
        ),
        working_directory=".",
        code_sha256=hashlib.sha256(WORKER_SOURCE.encode("utf-8")).hexdigest(),
        data_sha256=hashlib.sha256(DATA_BYTES).hexdigest(),
        configuration_sha256=hashlib.sha256(CONFIGURATION_BYTES).hexdigest(),
        evaluator_sha256=hashlib.sha256(EVALUATOR_BYTES).hexdigest(),
        seeds=(1,),
        timeout_seconds=timeout_seconds,
        compute_profile=default_local_cpu_profile(),
        resource_estimate=replace(
            default_resource_estimate(),
            wall_clock_seconds=min(0.25, timeout_seconds),
        ),
    )


class LocalProcessTreeTerminationTests(unittest.TestCase):
    def _backend(self, root: Path) -> LocalMacBackend:
        (root / "worker.py").write_text(WORKER_SOURCE, encoding="utf-8")
        (root / "data.json").write_bytes(DATA_BYTES)
        (root / "configuration.json").write_bytes(CONFIGURATION_BYTES)
        (root / "evaluator.json").write_bytes(EVALUATOR_BYTES)
        return LocalMacBackend(
            root,
            allowed_executables=(sys.executable,),
        )

    @staticmethod
    def _input_artifact_paths() -> dict[str, str]:
        return {
            "code": "worker.py",
            "data": "data.json",
            "configuration": "configuration.json",
            "evaluator": "evaluator.json",
        }

    def _wait_for_pids(self, root: Path) -> tuple[int, int]:
        path = root / "pids.txt"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                values = tuple(
                    int(value) for value in path.read_text(encoding="utf-8").splitlines()
                )
            except (FileNotFoundError, ValueError):
                time.sleep(0.01)
                continue
            if len(values) == 2 and all(value > 1 for value in values):
                return values
            time.sleep(0.01)
        self.fail("worker did not publish its process identities")

    @staticmethod
    def _observe_process_state(pid: int) -> str:
        """Return gone/zombie/live/unknown without treating observer failure as gone."""
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "gone"
        except OSError:
            return "unknown"
        try:
            status = subprocess.run(
                ("/bin/ps", "-o", "stat=", "-p", str(pid)),
                check=False,
                capture_output=True,
                text=True,
                timeout=1.0,
            )
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        state = status.stdout.strip()
        if status.returncode != 0 or not state:
            return "unknown"
        if state.startswith("Z"):
            return "zombie"
        return "live"

    def _assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            observation = self._observe_process_state(pid)
            if observation in {"gone", "zombie"}:
                return
            if observation == "unknown":
                self.fail(f"process {pid} could not be inspected after backend termination")
            time.sleep(0.02)
        self.fail(f"process {pid} remained live after backend termination")

    def test_timeout_terminates_exact_process_group_and_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = self._backend(root)
            receipt = backend.submit(
                _spec("timeout-process-tree", timeout_seconds=0.5),
                idempotency_key="timeout-process-tree",
                input_artifact_paths=self._input_artifact_paths(),
            )
            parent_pid, child_pid = self._wait_for_pids(root)

            self.assertEqual(receipt.state, RunState.FAILED)
            self.assertEqual(receipt.job_id, f"local-{receipt.spec_sha256[:20]}")
            self.assertEqual(backend.reconcile(receipt.job_id).reason, "WALL_CLOCK_TIMEOUT")
            self._assert_process_gone(parent_pid)
            self._assert_process_gone(child_pid)
            with self.assertRaises(ProcessLookupError):
                os.killpg(parent_pid, 0)

    def test_cancel_terminates_running_process_group_and_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = self._backend(root)
            spec = _spec("cancel-process-tree", timeout_seconds=30.0)
            receipts = []
            worker = threading.Thread(
                target=lambda: receipts.append(
                    backend.submit(
                        spec,
                        idempotency_key="cancel-process-tree",
                        input_artifact_paths=self._input_artifact_paths(),
                    )
                )
            )
            worker.start()
            parent_pid, child_pid = self._wait_for_pids(root)
            job_id = f"local-{spec.sha256[:20]}"

            cancelled = backend.cancel(job_id)
            worker.join(timeout=5.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(cancelled.state, RunState.CANCELLED)
            self.assertEqual(cancelled.reason, "CANCELLED_BY_CALLER")
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0].state, RunState.CANCELLED)
            self.assertEqual(backend.reconcile(job_id).state, RunState.CANCELLED)
            self._assert_process_gone(parent_pid)
            self._assert_process_gone(child_pid)
            with self.assertRaises(ProcessLookupError):
                os.killpg(parent_pid, 0)

    def test_termination_refuses_the_callers_process_group(self) -> None:
        caller_process_group = os.getpgrp()
        active = SimpleNamespace(
            process=SimpleNamespace(pid=caller_process_group),
            process_group_id=caller_process_group,
            session_id=caller_process_group,
            termination_lock=threading.Lock(),
        )

        with mock.patch("scientist_one.experiments.os.killpg") as kill_group:
            with self.assertRaisesRegex(
                ExperimentIntegrityError,
                "refusing to terminate",
            ):
                LocalMacBackend._terminate_process_group(active)
        kill_group.assert_not_called()

    def test_post_spawn_internal_error_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = self._backend(root)
            published_pids: list[tuple[int, int]] = []

            def fail_log_capture_start() -> None:
                published_pids.append(self._wait_for_pids(root))
                raise RuntimeError("injected log-capture startup failure")

            with mock.patch(
                "scientist_one.experiments.threading.Thread.start",
                side_effect=fail_log_capture_start,
            ):
                receipt = backend.submit(
                    _spec("error-process-tree", timeout_seconds=30.0),
                    idempotency_key="error-process-tree",
                    input_artifact_paths=self._input_artifact_paths(),
                )

            self.assertEqual(receipt.state, RunState.FAILED)
            self.assertEqual(
                backend.reconcile(receipt.job_id).reason,
                "EXECUTION_EXCEPTION:RuntimeError",
            )
            self.assertEqual(len(published_pids), 1)
            parent_pid, child_pid = published_pids[0]
            self._assert_process_gone(parent_pid)
            self._assert_process_gone(child_pid)
            with self.assertRaises(ProcessLookupError):
                os.killpg(parent_pid, 0)

    def test_observer_accepts_missing_pid(self) -> None:
        with (
            mock.patch(
                "scientist_one.experiments.os.kill",
                side_effect=ProcessLookupError,
            ) as kill,
            mock.patch("scientist_one.experiments.subprocess.run") as run,
        ):
            self.assertEqual(self._observe_process_state(12345), "gone")
        kill.assert_called_once_with(12345, 0)
        run.assert_not_called()

    def test_observer_accepts_observed_zombie(self) -> None:
        status = SimpleNamespace(returncode=0, stdout=" Z\n")
        with (
            mock.patch("scientist_one.experiments.os.kill") as kill,
            mock.patch("scientist_one.experiments.subprocess.run", return_value=status) as run,
        ):
            self.assertEqual(self._observe_process_state(12345), "zombie")
        kill.assert_called_once_with(12345, 0)
        run.assert_called_once()

    def test_observer_rejects_unavailable_inspection_while_pid_exists(self) -> None:
        for status in (
            SimpleNamespace(returncode=1, stdout="STAT\n"),
            SimpleNamespace(returncode=0, stdout=""),
        ):
            with (
                mock.patch("scientist_one.experiments.os.kill") as kill,
                mock.patch("scientist_one.experiments.subprocess.run", return_value=status),
            ):
                self.assertEqual(self._observe_process_state(12345), "unknown")
            kill.assert_called_once_with(12345, 0)

    def test_assert_process_gone_rejects_unknown_observation(self) -> None:
        with (
            mock.patch.object(self, "_observe_process_state", return_value="unknown") as observe,
            mock.patch("scientist_one.experiments.time.monotonic", return_value=0.0),
            mock.patch("scientist_one.experiments.time.sleep") as sleep,
        ):
            with self.assertRaises(self.failureException):
                self._assert_process_gone(12345)
        observe.assert_called_once_with(12345)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
