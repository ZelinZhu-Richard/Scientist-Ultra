from __future__ import annotations

import inspect
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import scientist_one.orchestrator as orchestration


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    rows: list[tuple[object, ...]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        stat_result = path.lstat()
        row: tuple[object, ...] = (
            relative,
            stat_result.st_mode,
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_nlink,
            stat_result.st_size,
        )
        if path.is_file():
            row += (path.read_bytes(),)
        rows.append(row)
    return tuple(rows)


def _holder_program() -> str:
    return """
import fcntl
import os
from pathlib import Path
import sys
import time

kind, target_text, ready_text, release_text = sys.argv[1:]
target = Path(target_text)
ready = Path(ready_text)
release = Path(release_text)
if kind == 'parent':
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
else:
    flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
fd = os.open(target, flags)
try:
    fcntl.flock(fd, fcntl.LOCK_EX)
    ready.write_text('ready', encoding='utf-8')
    deadline = time.monotonic() + 8.0
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not release.exists():
        raise SystemExit(7)
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
"""


def _reentry_program() -> str:
    return """
import importlib.util
from pathlib import Path
import sys

source_path = Path(sys.argv[1])
dependency_path = sys.argv[2]
root = Path(sys.argv[3])
sys.path.insert(0, dependency_path)
spec = importlib.util.spec_from_file_location(
    'scientist_one.orchestrator', source_path
)
if spec is None or spec.loader is None:
    raise SystemExit('could not load orchestrator source')
module = importlib.util.module_from_spec(spec)
sys.modules['scientist_one.orchestrator'] = module
spec.loader.exec_module(module)
from scientist_one.orchestrator import (
    OrchestrationError,
    _project_resource_execution_lock,
)
with _project_resource_execution_lock(root):
    try:
        with _project_resource_execution_lock(root, nonblocking=True):
            raise SystemExit('unexpected same-process reentry acquisition')
    except OrchestrationError as exc:
        if str(exc) != 'project resource execution lock failed':
            raise
        if not isinstance(exc.__cause__, BlockingIOError):
            raise
        print('bounded reentry refusal')
"""


class ProjectResourceLockNonblockingTests(unittest.TestCase):
    def _start_holder(
        self,
        kind: str,
        target: Path,
        marker_dir: Path,
    ) -> tuple[subprocess.Popen[str], Path, Path]:
        ready = marker_dir / f"{kind}-ready"
        release = marker_dir / f"{kind}-release"
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-c",
                _holder_program(),
                kind,
                str(target),
                str(ready),
                str(release),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 3.0
        while not ready.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                process.wait(timeout=2.0)
                self.fail(f"{kind} holder did not become ready")
            time.sleep(0.01)
        if not ready.exists():
            stdout, stderr = process.communicate(timeout=2.0)
            self.fail(
                f"{kind} holder exited before readiness: "
                f"status={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
        return process, ready, release

    def _release_holder(
        self,
        process: subprocess.Popen[str],
        release: Path,
    ) -> None:
        release.write_text("release", encoding="utf-8")
        try:
            stdout, stderr = process.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2.0)
            self.fail(
                f"lock holder did not release: stdout={stdout!r} stderr={stderr!r}"
            )
        self.assertEqual(
            process.returncode,
            0,
            f"lock holder failed: stdout={stdout!r} stderr={stderr!r}",
        )

    def test_signature_and_native_default_false_true_all_acquire(self) -> None:
        parameter = inspect.signature(
            orchestration._project_resource_execution_lock
        ).parameters["nonblocking"]
        self.assertIs(parameter.default, False)
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project"
            root.mkdir()
            for kwargs in ({}, {"nonblocking": False}, {"nonblocking": True}):
                with orchestration._project_resource_execution_lock(root, **kwargs):
                    self.assertTrue(root.is_dir())
            lock_path = root / ".scientist-one-resource-execution.lock"
            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_non_boolean_values_refuse_before_any_filesystem_delta(self) -> None:
        truthiness_calls: list[str] = []

        class Truthy:
            def __bool__(self) -> bool:
                truthiness_calls.append("called")
                return True

        invalid_values = (0, 1, 0.0, 1.0, None, "false", Truthy())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project"
            root.mkdir()
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"preserve")
            before = _tree_snapshot(root)
            for value in invalid_values:
                with self.subTest(value=repr(value)):
                    with self.assertRaisesRegex(
                        orchestration.OrchestrationError,
                        "nonblocking must be an exact boolean",
                    ):
                        with orchestration._project_resource_execution_lock(
                            root, nonblocking=value
                        ):
                            self.fail("invalid nonblocking value acquired a lock")
                    self.assertEqual(_tree_snapshot(root), before)
            self.assertEqual(truthiness_calls, [])

    def test_same_process_reentry_refuses_bounded_nonblocking_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project"
            root.mkdir()
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            source_path = str(Path(orchestration.__file__).resolve())
            dependency_path = str(Path(source_path).parent.parent)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    _reentry_program(),
                    source_path,
                    dependency_path,
                    str(root),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                try:
                    stdout, stderr = process.communicate(timeout=3.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=2.0)
                    self.fail(
                        "same-process reentry probe hung; "
                        f"stdout={stdout!r} stderr={stderr!r}"
                    )
                self.assertEqual(
                    process.returncode,
                    0,
                    f"reentry probe failed: stdout={stdout!r} stderr={stderr!r}",
                )
                self.assertIn("bounded reentry refusal", stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2.0)
            with orchestration._project_resource_execution_lock(
                root, nonblocking=True
            ):
                pass

    def test_held_parent_contends_and_parent_is_released_afterwards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "namespace"
            root = parent / "Project"
            parent.mkdir()
            root.mkdir()
            with self.subTest(lock="parent"):
                process, _ready, release = self._start_holder(
                    "parent", parent, parent
                )
                try:
                    with self.assertRaisesRegex(
                        orchestration.OrchestrationError,
                        "project resource execution lock failed",
                    ) as raised:
                        with orchestration._project_resource_execution_lock(
                            root, nonblocking=True
                        ):
                            self.fail("held parent unexpectedly acquired")
                    self.assertIsInstance(raised.exception.__cause__, BlockingIOError)
                finally:
                    self._release_holder(process, release)
                with orchestration._project_resource_execution_lock(
                    root, nonblocking=True
                ):
                    pass

    def test_held_leaf_contends_and_parent_is_released_afterwards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "namespace"
            root = parent / "Project"
            parent.mkdir()
            root.mkdir()
            lock_path = root / ".scientist-one-resource-execution.lock"
            lock_path.touch(mode=0o600)
            lock_path.chmod(0o600)
            process, _ready, release = self._start_holder(
                "leaf", lock_path, parent
            )
            try:
                with self.assertRaisesRegex(
                    orchestration.OrchestrationError,
                    "project resource execution lock failed",
                ) as raised:
                    with orchestration._project_resource_execution_lock(
                        root, nonblocking=True
                    ):
                        self.fail("held leaf unexpectedly acquired")
                self.assertIsInstance(raised.exception.__cause__, BlockingIOError)
            finally:
                self._release_holder(process, release)
            with orchestration._project_resource_execution_lock(
                root, nonblocking=True
            ):
                pass

    def test_exception_cleanup_permits_later_nonblocking_acquisition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project"
            root.mkdir()
            with self.assertRaisesRegex(RuntimeError, "body failure"):
                with orchestration._project_resource_execution_lock(root):
                    raise RuntimeError("body failure")
            with orchestration._project_resource_execution_lock(
                root, nonblocking=True
            ):
                pass

    def test_replaced_root_and_leaf_refuse_on_context_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "Project"
            root.mkdir()
            moved_root = parent / "Project-held"
            with self.assertRaisesRegex(
                orchestration.OrchestrationError,
                "project resource namespace changed",
            ):
                with orchestration._project_resource_execution_lock(root):
                    root.rename(moved_root)
                    root.mkdir()
            self.assertTrue(root.is_dir())
            self.assertTrue(moved_root.is_dir())
            with orchestration._project_resource_execution_lock(
                root, nonblocking=True
            ):
                pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "Project"
            root.mkdir()
            lock_path = root / ".scientist-one-resource-execution.lock"
            moved_lock = root / ".scientist-one-resource-execution.lock-held"
            with self.assertRaisesRegex(
                orchestration.OrchestrationError,
                "project resource namespace changed",
            ):
                with orchestration._project_resource_execution_lock(root):
                    lock_path.rename(moved_lock)
                    lock_path.touch(mode=0o600)
                    lock_path.chmod(0o600)
            with orchestration._project_resource_execution_lock(
                root, nonblocking=True
            ):
                pass


if __name__ == "__main__":
    unittest.main()
