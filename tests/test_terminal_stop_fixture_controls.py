"""NEW_TEST_FIXTURE controls of actual Option B helpers, not scientific runs."""

from contextlib import contextmanager
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

# Module import only: do not expose its TestCase class to this module's discovery.
from tests import test_terminal_stop_verification as subject


@contextmanager
def owned_tree():
    with tempfile.TemporaryDirectory(prefix="terminal-stop-helper-control-") as raw:
        root = Path(raw).resolve() / "ScientistOne"
        for relative in ("runs", ".scientist-one-build/custody",
                         ".scientist-one-build/resource-authority",
                         ".scientist-one-build/checkpoints"):
            (root / relative).mkdir(parents=True, exist_ok=True)
        yield root


def helper_case(start=None):
    # Deliberately do not call TestCase.__init__, setUp, run, or a subject owner.
    case = object.__new__(subject.TerminalStopVerificationTests)
    case._owned_run_ids = []
    case._cleanup_incomplete = False
    case.orchestrator = SimpleNamespace(start=start)
    return case


def add_owned_run(root, run_id="run-owned"):
    (root / "runs" / run_id).mkdir()
    (root / "runs" / run_id / "manifest-fixture.txt").write_bytes(b"fake run\n")
    build = root / ".scientist-one-build"
    (build / "custody" / (run_id + ".jsonl")).write_bytes(b"fake custody\n")
    (build / "resource-authority" / run_id).mkdir()
    (build / "resource-authority" / run_id / "record.txt").write_bytes(b"fake resource\n")
    (build / "checkpoints" / run_id).mkdir()
    (build / "checkpoints" / run_id / "checkpoint.txt").write_bytes(b"retained checkpoint\n")


def tree_bytes(root):
    """Only this control's owned tree; preserve symlink labels without following."""
    result = {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = ("symlink", str(path.readlink()))
        elif path.is_dir():
            result[name] = ("dir",)
        else:
            result[name] = ("file", path.read_bytes())
    return result


class NewTerminalStopFixtureControls(unittest.TestCase):
    """Eight new helper controls, separate from the original three tests."""

    def test_real_helper_tracks_only_valid_returned_ids(self):
        start = mock.Mock(return_value={"run_id": "run-owned"})
        case = helper_case(start)
        self.assertEqual(case.start_run(), "run-owned")
        start.assert_called_once_with()
        self.assertEqual(case._owned_run_ids, ["run-owned"])
        with mock.patch.object(subject.sys, "stderr", io.StringIO()):
            with self.assertRaisesRegex(AssertionError, "duplicate"):
                case.start_run()
        self.assertEqual(case._owned_run_ids, ["run-owned"])
        for result in (None, [], {}, {"run_id": ""}, {"run_id": "../other"},
                       {"run_id": "/other"}, {"run_id": "."}, {"run_id": 4}):
            with self.subTest(result=result):
                start = mock.Mock(return_value=result)
                case = helper_case(start)
                with mock.patch.object(subject.sys, "stderr", io.StringIO()):
                    with self.assertRaisesRegex(AssertionError, "unsafe"):
                        case.start_run()
                start.assert_called_once_with()
                self.assertEqual(case._owned_run_ids, [])
                self.assertTrue(case._cleanup_incomplete)

    def test_real_start_helper_preserves_exact_failure_without_ownership(self):
        for error in (RuntimeError("fake ordinary start error"),
                      KeyboardInterrupt("fake interrupted start"),
                      SystemExit("fake exiting start")):
            with self.subTest(error=type(error).__name__), owned_tree() as root:
                add_owned_run(root, "run-unreturned")
                before = tree_bytes(root)
                start = mock.Mock(side_effect=error)
                case = helper_case(start)
                stream = io.StringIO()
                with mock.patch.object(subject.sys, "stderr", stream):
                    with self.assertRaises(type(error)) as caught:
                        case.start_run()
                self.assertIs(caught.exception, error)
                start.assert_called_once_with()
                self.assertEqual(case._owned_run_ids, [])
                with mock.patch.object(subject, "PROJECT_ROOT", root):
                    case._archive_owned_runs()
                self.assertEqual(tree_bytes(root), before)
                if isinstance(error, Exception):
                    self.assertTrue(case._cleanup_incomplete)
                    self.assertIn("START_RETURN_ID_UNAVAILABLE", stream.getvalue())
                else:
                    self.assertEqual(stream.getvalue(), "")

    def test_real_archive_moves_exact_targets_and_retains_unrelated_checkpoint(self):
        with owned_tree() as root:
            add_owned_run(root)
            add_owned_run(root, "run-unrelated")
            before = tree_bytes(root)
            case = helper_case()
            case._owned_run_ids = ["run-owned"]
            with mock.patch.object(subject, "PROJECT_ROOT", root):
                case._archive_owned_runs()
            archive = root / ".scientist-one-build/test-runs/run-owned"
            self.assertEqual((archive / "manifest-fixture.txt").read_bytes(), b"fake run\n")
            self.assertEqual((archive / "external-authority/custody.jsonl").read_bytes(),
                             b"fake custody\n")
            self.assertEqual((archive / "external-authority/resource/record.txt").read_bytes(),
                             b"fake resource\n")
            after = tree_bytes(root)
            for path, value in before.items():
                if "run-unrelated" in path or path.startswith(".scientist-one-build/checkpoints"):
                    self.assertEqual(after[path], value)
            self.assertFalse((root / "runs/run-owned").exists())
            self.assertFalse((root / ".scientist-one-build/custody/run-owned.jsonl").exists())
            self.assertFalse((root / ".scientist-one-build/resource-authority/run-owned").exists())
            self.assertFalse(case._cleanup_incomplete)

    def test_real_archive_rejects_source_reserved_subtree_before_moves(self):
        for kind in ("custody", "resource", "file", "symlink", "dangling"):
            with self.subTest(kind=kind), owned_tree() as root:
                add_owned_run(root)
                reserved = root / "runs/run-owned/external-authority"
                if kind in {"custody", "resource"}:
                    reserved.mkdir()
                    if kind == "custody":
                        (reserved / "custody.jsonl").write_bytes(b"must not overwrite\n")
                    else:
                        (reserved / "resource").mkdir()
                        (reserved / "resource/retained.txt").write_bytes(b"keep\n")
                elif kind == "file":
                    reserved.write_bytes(b"wrong kind\n")
                else:
                    target = root / ("runs" if kind == "symlink" else "absent")
                    reserved.symlink_to(target, target_is_directory=True)
                before = tree_bytes(root)
                case = helper_case()
                case._owned_run_ids = ["run-owned"]
                with mock.patch.object(subject, "PROJECT_ROOT", root):
                    with self.assertRaisesRegex(AssertionError, "conflict"):
                        case._archive_owned_runs()
                self.assertTrue(case._cleanup_incomplete)
                self.assertEqual(tree_bytes(root), before)

    def test_real_archive_rejects_unsafe_paths_and_destination_conflicts(self):
        bad_paths = (
            "runs", ".scientist-one-build", ".scientist-one-build/test-runs",
            ".scientist-one-build/custody", ".scientist-one-build/resource-authority",
            "runs/run-owned", ".scientist-one-build/custody/run-owned.jsonl",
            ".scientist-one-build/resource-authority/run-owned",
            ".scientist-one-build/test-runs/run-owned",
        )
        for relative in bad_paths:
            for kind in ("file", "symlink", "dangling", "directory"):
                if kind == "directory" and relative != ".scientist-one-build/test-runs/run-owned":
                    continue
                with self.subTest(path=relative, kind=kind), owned_tree() as root:
                    add_owned_run(root)
                    path = root / relative
                    if path.exists():
                        path.rename(root / "saved-fixture-path")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    # A custody regular file is its valid kind; use a directory.
                    if kind == "directory":
                        path.mkdir()
                    elif kind == "file" and relative.endswith(".jsonl"):
                        path.mkdir()
                    elif kind == "file":
                        path.write_bytes(b"conflicting fixture bytes\n")
                    else:
                        target = root / ("runs" if kind == "symlink" else "absent")
                        path.symlink_to(target, target_is_directory=True)
                    before = tree_bytes(root)
                    case = helper_case()
                    case._owned_run_ids = ["run-owned"]
                    with mock.patch.object(subject, "PROJECT_ROOT", root):
                        with self.assertRaises(AssertionError):
                            case._archive_owned_runs()
                    self.assertEqual(tree_bytes(root), before)
        for ids in (["../other"], ["run-owned", "run-owned"]):
            with self.subTest(ids=ids), owned_tree() as root:
                add_owned_run(root)
                case = helper_case()
                case._owned_run_ids = ids
                before = tree_bytes(root)
                with mock.patch.object(subject, "PROJECT_ROOT", root):
                    with self.assertRaisesRegex(AssertionError, "owned run ID"):
                        case._archive_owned_runs()
                self.assertEqual(tree_bytes(root), before)

    def test_real_archive_keeps_actual_partial_moves_when_later_move_fails(self):
        with owned_tree() as root:
            add_owned_run(root)
            case = helper_case()
            case._owned_run_ids = ["run-owned"]
            real_replace = subject.os.replace
            error = OSError("synthetic resource archival failure")
            calls = []

            def fail_resource(source, destination):
                calls.append((source, destination))
                if source == root / ".scientist-one-build/resource-authority/run-owned":
                    raise error
                return real_replace(source, destination)

            with mock.patch.object(subject, "PROJECT_ROOT", root), mock.patch.object(
                subject.os, "replace", side_effect=fail_resource
            ):
                with self.assertRaises(OSError) as caught:
                    case._archive_owned_runs()
            self.assertIs(caught.exception, error)
            self.assertEqual(len(calls), 3)
            self.assertTrue(case._cleanup_incomplete)
            archived = root / ".scientist-one-build/test-runs/run-owned"
            self.assertEqual((archived / "external-authority/custody.jsonl").read_bytes(),
                             b"fake custody\n")
            self.assertFalse((root / "runs/run-owned").exists())
            self.assertEqual((root / ".scientist-one-build/resource-authority/run-owned/record.txt").read_bytes(),
                             b"fake resource\n")
            self.assertEqual((root / ".scientist-one-build/checkpoints/run-owned/checkpoint.txt").read_bytes(),
                             b"retained checkpoint\n")
            self.assertFalse((archived / "external-authority/resource").exists())

    def test_real_archive_rechecks_actual_moved_destination(self):
        with owned_tree() as root:
            add_owned_run(root)
            case = helper_case()
            case._owned_run_ids = ["run-owned"]
            real_replace = subject.os.replace
            moves = []

            def insert_conflict(source, destination):
                result = real_replace(source, destination)
                moves.append((source, destination))
                if source == root / "runs/run-owned":
                    (destination / "external-authority").mkdir()
                    (destination / "external-authority/custody.jsonl").write_bytes(b"new conflict\n")
                return result

            with mock.patch.object(subject, "PROJECT_ROOT", root), mock.patch.object(
                subject.os, "replace", side_effect=insert_conflict
            ):
                with self.assertRaisesRegex(AssertionError, "conflict"):
                    case._archive_owned_runs()
            self.assertEqual(len(moves), 1)
            archived = root / ".scientist-one-build/test-runs/run-owned"
            self.assertEqual((archived / "external-authority/custody.jsonl").read_bytes(),
                             b"new conflict\n")
            self.assertEqual((root / ".scientist-one-build/custody/run-owned.jsonl").read_bytes(),
                             b"fake custody\n")
            self.assertTrue(case._cleanup_incomplete)

    def test_real_metadata_helper_contains_ordinary_errors_not_interrupts(self):
        for operation in ("write", "flush"):
            for error in (OSError("fake diagnostic write failure"),
                          KeyboardInterrupt("fake diagnostic interrupt"),
                          SystemExit("fake diagnostic exit")):
                with self.subTest(operation=operation, error=type(error).__name__):
                    case = helper_case()
                    stream = mock.Mock()
                    getattr(stream, operation).side_effect = error
                    with mock.patch.object(subject.sys, "stderr", stream):
                        if isinstance(error, Exception):
                            self.assertIsNone(case._emit_cleanup_incomplete("START_RETURN_ID_UNAVAILABLE"))
                        else:
                            with self.assertRaises(type(error)) as caught:
                                case._emit_cleanup_incomplete("START_RETURN_ID_UNAVAILABLE")
                            self.assertIs(caught.exception, error)
                    self.assertTrue(case._cleanup_incomplete)
        case = helper_case(mock.Mock(side_effect=RuntimeError("original fake start")))
        original = case.orchestrator.start.side_effect
        stream = mock.Mock()
        stream.write.side_effect = OSError("ordinary stderr failure")
        with mock.patch.object(subject.sys, "stderr", stream):
            with self.assertRaises(RuntimeError) as caught:
                case.start_run()
        self.assertIs(caught.exception, original)
        self.assertEqual(case._owned_run_ids, [])
        stream = io.StringIO()
        with mock.patch.object(subject.sys, "stderr", stream):
            case._emit_cleanup_incomplete("RETURNED_RUN_ID_INVALID")
        self.assertLessEqual(len(stream.getvalue().encode("utf-8")), 512)
        self.assertIn("TERMINAL_STOP_CLEANUP_INCOMPLETE", stream.getvalue())
