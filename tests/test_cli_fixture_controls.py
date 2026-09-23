"""NEW_REGRESSION_TEST: actual CLI fixture helper, synthetic bookkeeping only."""

import hashlib
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from tests import test_cli as subject


class NewCliFixtureControls(unittest.TestCase):
    def tree(self, *, run_only=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        for relative in (
            "runs", ".scientist-one-build/custody",
            ".scientist-one-build/resource-authority",
            ".scientist-one-build/checkpoints", "artifacts/release_candidates",
        ):
            (root / relative).mkdir(parents=True, exist_ok=True)
        return root, subject._CliFixtureOwner(root, run_only=run_only)

    def returned(self, root, owner, run_id="run-owned"):
        (root / "runs" / run_id).mkdir()
        (root / "runs" / run_id / "marker").write_bytes(b"run evidence")
        result = {"run_id": run_id}
        controller = types.SimpleNamespace(start=mock.Mock(return_value=result))
        self.assertIs(owner.start(controller), result)
        return result

    def authority(self, root, run_id="run-owned"):
        custody = root / ".scientist-one-build/custody" / (run_id + ".jsonl")
        custody.write_bytes(b"synthetic custody bytes")
        resource = root / ".scientist-one-build/resource-authority" / run_id
        resource.mkdir()
        (resource / "marker").write_bytes(b"synthetic resource bytes")
        checkpoint = root / ".scientist-one-build/checkpoints" / run_id
        checkpoint.mkdir()
        (checkpoint / "marker").write_bytes(b"retained checkpoint bytes")

    def package(self, root, run_id="run-owned"):
        result = {"run_id": run_id}
        for path_key, hash_key, suffix, data in (
            ("archive_path", "archive_sha256", ".zip", b"synthetic archive"),
            ("envelope_path", "envelope_sha256", ".final-envelope.json", b"synthetic envelope"),
        ):
            digest = hashlib.sha256(data).hexdigest()
            relative = "artifacts/release_candidates/" + run_id + "-" + digest[:20] + suffix
            (root / relative).write_bytes(data)
            result[path_key] = relative
            result[hash_key] = digest
        return result

    def test_start_forwards_once_and_returns_identical_result_for_multiple_ids(self):
        root, owner = self.tree()
        first, second = {"run_id": "run-one"}, {"run_id": "run-two"}
        primary = types.SimpleNamespace(start=mock.Mock(return_value=first))
        local = types.SimpleNamespace(start=mock.Mock(return_value=second))
        self.assertIs(owner.start(primary, "brief", mode="brief"), first)
        self.assertIs(owner.start(local, synthetic_scenario="null"), second)
        primary.start.assert_called_once_with("brief", mode="brief")
        local.start.assert_called_once_with(synthetic_scenario="null")
        self.assertEqual(owner._run_ids, ["run-one", "run-two"])
        self.assertEqual(owner._packages, {})
        self.assertTrue((root / ".scientist-one-build/test-runs").is_dir())

    def test_start_rejects_invalid_and_duplicate_ids_without_adoption(self):
        _, owner = self.tree()
        for result in (None, {}, {"run_id": 1}, {"run_id": "../outside"},
                       {"run_id": ""}, {"run_id": "x/y"}, {"run_id": "x\n"},
                       {"run_id": "."}, {"run_id": ".."}, {"run_id": "a" * 129}):
            with self.subTest(result=result):
                controller = types.SimpleNamespace(start=mock.Mock(return_value=result))
                with self.assertRaises(AssertionError):
                    owner.start(controller)
                controller.start.assert_called_once_with()
                self.assertEqual(owner._run_ids, [])
        valid = {"run_id": "run-one"}
        controller = types.SimpleNamespace(start=mock.Mock(return_value=valid))
        self.assertIs(owner.start(controller), valid)
        with self.assertRaisesRegex(AssertionError, "duplicate"):
            owner.start(controller)
        self.assertEqual(owner._run_ids, ["run-one"])

    def test_start_and_demo_propagate_exact_exceptions_without_partial_adoption(self):
        for method in ("start", "demo"):
            for failure in (RuntimeError("partial"), KeyboardInterrupt(), SystemExit(7)):
                with self.subTest(method=method, failure=type(failure).__name__):
                    root, owner = self.tree()
                    partial = root / "runs/run-unreturned"
                    def operation(**kwargs):
                        partial.mkdir()
                        (partial / "marker").write_bytes(b"unknown partial evidence")
                        raise failure
                    fake = mock.Mock(side_effect=operation)
                    controller = types.SimpleNamespace(**{method: fake})
                    with self.assertRaises(type(failure)) as caught:
                        getattr(owner, method)(controller, synthetic_scenario="positive")
                    self.assertIs(caught.exception, failure)
                    fake.assert_called_once_with(synthetic_scenario="positive")
                    self.assertEqual(owner._run_ids, [])
                    self.assertEqual(owner._packages, {})
                    with mock.patch.object(subject.os, "replace") as move:
                        owner.archive()
                    move.assert_not_called()
                    self.assertEqual((partial / "marker").read_bytes(), b"unknown partial evidence")

    def test_demo_is_one_genuine_call_with_same_result_and_immutable_package_tuples(self):
        root, owner = self.tree()
        package = self.package(root)
        original_paths = (package["archive_path"], package["envelope_path"])
        result = {"run_id": "run-owned", "package": package}
        fake = types.SimpleNamespace(demo=mock.Mock(return_value=result),
                                     start=mock.Mock(side_effect=AssertionError("no decomposition")))
        self.assertIs(owner.demo(fake, synthetic_scenario="positive"), result)
        fake.demo.assert_called_once_with(synthetic_scenario="positive")
        fake.start.assert_not_called()
        recorded = owner._packages["run-owned"]
        self.assertIs(type(recorded), tuple)
        self.assertTrue(all(type(item) is tuple for item in recorded))
        package["archive_path"] = "runs/foreign"
        package["envelope_sha256"] = "0" * 64
        result["package"] = None
        self.assertEqual(tuple(value[0] for value in recorded), original_paths)
        self.assertEqual(owner._packages["run-owned"], recorded)

    def test_negative_demo_has_no_package_and_bad_package_retains_returned_id(self):
        for package in (None, {"run_id": "foreign"}):
            with self.subTest(package=package):
                _, owner = self.tree()
                result = {"run_id": "run-negative", "package": package}
                controller = types.SimpleNamespace(demo=mock.Mock(return_value=result))
                if package is None:
                    self.assertIs(owner.demo(controller, synthetic_scenario="null"), result)
                else:
                    with self.assertRaises(AssertionError):
                        owner.demo(controller, synthetic_scenario="null")
                self.assertEqual(owner._run_ids, ["run-negative"])
                self.assertEqual(owner._packages, {})
                controller.demo.assert_called_once_with(synthetic_scenario="null")

    def test_package_records_require_owned_exact_paths_hashes_and_profile(self):
        mutations = (
            {"run_id": "foreign"}, {"archive_path": "/tmp/foreign"},
            {"archive_path": "artifacts/release_candidates/../foreign"},
            {"archive_path": "artifacts/release_candidates/run-owned-extra.zip"},
            {"archive_sha256": "X" * 64}, {"archive_sha256": 42},
            {"envelope_sha256": "a" * 63}, {"envelope_path": None},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                root, owner = self.tree()
                self.returned(root, owner)
                package = self.package(root)
                package.update(changes)
                with self.assertRaises(AssertionError):
                    owner.record_package("run-owned", package)
                self.assertEqual(owner._packages, {})
        root, owner = self.tree()
        package = self.package(root)
        with self.assertRaises(AssertionError):
            owner.record_package("run-owned", package)
        self.returned(root, owner)
        owner.record_package("run-owned", package)
        with self.assertRaises(AssertionError):
            owner.record_package("run-owned", package)
        root, run_only = self.tree(run_only=True)
        self.returned(root, run_only)
        with self.assertRaises(AssertionError):
            run_only.record_package("run-owned", self.package(root))

    def test_full_archive_moves_only_exact_recorded_targets_and_preserves_current_bytes(self):
        root, owner = self.tree()
        self.returned(root, owner)
        self.authority(root)
        package = self.package(root)
        owner.record_package("run-owned", package)
        # Recording binds returned names/hashes, not a later immutable byte claim.
        (root / package["archive_path"]).write_bytes(b"intentionally changed evidence")
        unrelated = (
            root / "runs/run-unrelated",
            root / ".scientist-one-build/test-runs/run-owned-completed-before-rollback",
            root / ".scientist-one-build/test-runs/run-owned-combined-complete",
            root / ".scientist-one-build/tmp/unknown-partial",
        )
        for directory in unrelated:
            directory.mkdir(parents=True)
            (directory / "marker").write_bytes(b"retain")
        stray = root / "artifacts/release_candidates/run-owned-unrecorded.zip"
        stray.write_bytes(b"unknown output")
        owner.archive()
        archived = root / ".scientist-one-build/test-runs/run-owned"
        self.assertFalse((root / "runs/run-owned").exists())
        self.assertEqual((archived / "marker").read_bytes(), b"run evidence")
        self.assertEqual((archived / "external-authority/custody.jsonl").read_bytes(), b"synthetic custody bytes")
        self.assertEqual((archived / "external-authority/resource/marker").read_bytes(), b"synthetic resource bytes")
        self.assertEqual((archived / "release-candidates" / Path(package["archive_path"]).name).read_bytes(),
                         b"intentionally changed evidence")
        self.assertEqual((archived / "release-candidates" / Path(package["envelope_path"]).name).read_bytes(),
                         b"synthetic envelope")
        self.assertFalse((root / package["archive_path"]).exists())
        self.assertFalse((root / package["envelope_path"]).exists())
        for directory in unrelated:
            self.assertEqual((directory / "marker").read_bytes(), b"retain")
        self.assertEqual(stray.read_bytes(), b"unknown output")
        self.assertEqual((root / ".scientist-one-build/checkpoints/run-owned/marker").read_bytes(),
                         b"retained checkpoint bytes")

    def test_run_only_archive_retains_all_external_evidence(self):
        root, owner = self.tree(run_only=True)
        self.returned(root, owner)
        self.authority(root)
        package = self.package(root)
        # Run-only never writes into this subtree; preserve its existing content.
        reserved = root / "runs/run-owned/external-authority"
        reserved.mkdir()
        (reserved / "marker").write_bytes(b"already in run")
        owner.archive()
        archive = root / ".scientist-one-build/test-runs/run-owned"
        self.assertEqual((archive / "external-authority/marker").read_bytes(), b"already in run")
        for relative in (
            ".scientist-one-build/custody/run-owned.jsonl",
            ".scientist-one-build/resource-authority/run-owned/marker",
            ".scientist-one-build/checkpoints/run-owned/marker",
            package["archive_path"], package["envelope_path"],
        ):
            self.assertTrue((root / relative).is_file(), relative)

    def test_reserved_subtrees_and_later_id_conflicts_preflight_before_any_move(self):
        for reserved in ("external-authority", "release-candidates"):
            for kind in ("file", "directory", "symlink"):
                with self.subTest(reserved=reserved, kind=kind):
                    root, owner = self.tree()
                    self.returned(root, owner, "run-first")
                    self.returned(root, owner, "run-second")
                    path = root / "runs/run-second" / reserved
                    if kind == "file":
                        path.write_bytes(b"do not overwrite")
                    elif kind == "directory":
                        path.mkdir()
                    else:
                        path.symlink_to(root / "missing")
                    with mock.patch.object(subject.os, "replace") as move, mock.patch.object(subject.sys, "stderr", io.StringIO()):
                        with self.assertRaises(AssertionError):
                            owner.archive()
                    move.assert_not_called()
                    self.assertTrue((root / "runs/run-first/marker").is_file())
                    self.assertTrue(owner.cleanup_incomplete)

    def test_unsafe_parents_sources_and_destination_conflicts_refuse_before_move(self):
        cases = ("destination-directory", "destination-file", "destination-symlink",
                 "run-symlink", "custody-directory", "resource-symlink", "parent-symlink")
        for case in cases:
            with self.subTest(case=case):
                root, owner = self.tree()
                self.returned(root, owner)
                destination = root / ".scientist-one-build/test-runs/run-owned"
                if case == "destination-directory":
                    destination.mkdir()
                elif case == "destination-file":
                    destination.write_bytes(b"no overwrite")
                elif case == "destination-symlink":
                    destination.symlink_to(root / "missing")
                elif case == "run-symlink":
                    os.replace(root / "runs/run-owned", root / "runs/preserved")
                    (root / "runs/run-owned").symlink_to(root / "runs/preserved")
                elif case == "custody-directory":
                    (root / ".scientist-one-build/custody/run-owned.jsonl").mkdir()
                elif case == "resource-symlink":
                    (root / ".scientist-one-build/resource-authority/run-owned").symlink_to(root / "missing")
                else:
                    os.replace(root / ".scientist-one-build/custody", root / ".scientist-one-build/custody-preserved")
                    (root / ".scientist-one-build/custody").symlink_to(root / ".scientist-one-build/custody-preserved")
                with mock.patch.object(subject.os, "replace") as move, mock.patch.object(subject.sys, "stderr", io.StringIO()):
                    with self.assertRaises(AssertionError):
                        owner.archive()
                move.assert_not_called()

    def test_missing_or_symlink_package_is_not_silently_absent(self):
        for kind in ("missing", "symlink", "directory"):
            with self.subTest(kind=kind):
                root, owner = self.tree()
                self.returned(root, owner)
                package = self.package(root)
                owner.record_package("run-owned", package)
                path = root / package["archive_path"]
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(root / package["envelope_path"])
                elif kind == "directory":
                    path.mkdir()
                with mock.patch.object(subject.os, "replace") as move, mock.patch.object(subject.sys, "stderr", io.StringIO()):
                    with self.assertRaises((AssertionError, FileNotFoundError)):
                        owner.archive()
                move.assert_not_called()

    def test_archive_rechecks_moved_run_reserved_destination(self):
        root, owner = self.tree()
        self.returned(root, owner)
        self.authority(root)
        real_replace = os.replace
        archive = root / ".scientist-one-build/test-runs/run-owned"
        def mutate_after_run(source, destination):
            real_replace(source, destination)
            if Path(destination) == archive:
                (archive / "external-authority").mkdir()
                (archive / "external-authority/custody.jsonl").write_bytes(b"collision")
        with mock.patch.object(subject.os, "replace", side_effect=mutate_after_run) as move, mock.patch.object(subject.sys, "stderr", io.StringIO()):
            with self.assertRaises(AssertionError):
                owner.archive()
        self.assertEqual(move.call_count, 1)
        self.assertEqual((archive / "external-authority/custody.jsonl").read_bytes(), b"collision")
        self.assertEqual((root / ".scientist-one-build/custody/run-owned.jsonl").read_bytes(),
                         b"synthetic custody bytes")

    def test_archive_rechecks_later_ancillary_and_package_targets(self):
        for kind in ("resource", "package"):
            with self.subTest(kind=kind):
                root, owner = self.tree()
                self.returned(root, owner)
                self.authority(root)
                package = self.package(root)
                owner.record_package("run-owned", package)
                real_replace = os.replace
                archive = root / ".scientist-one-build/test-runs/run-owned"
                resource_target = archive / "external-authority/resource"
                package_target = archive / "release-candidates" / Path(package["archive_path"]).name
                def collide(source, destination):
                    real_replace(source, destination)
                    if Path(destination) == archive / "external-authority/custody.jsonl" and kind == "resource":
                        resource_target.mkdir()
                        (resource_target / "marker").write_bytes(b"collision")
                    if Path(destination) == resource_target and kind == "package":
                        package_target.write_bytes(b"collision")
                with mock.patch.object(subject.os, "replace", side_effect=collide), mock.patch.object(subject.sys, "stderr", io.StringIO()):
                    with self.assertRaises(AssertionError):
                        owner.archive()
                if kind == "resource":
                    self.assertEqual((resource_target / "marker").read_bytes(), b"collision")
                    self.assertEqual((root / ".scientist-one-build/resource-authority/run-owned/marker").read_bytes(),
                                     b"synthetic resource bytes")
                else:
                    self.assertEqual(package_target.read_bytes(), b"collision")
                    self.assertEqual((root / package["archive_path"]).read_bytes(), b"synthetic archive")

    def test_partial_archival_preserves_actual_moves_and_exact_failure(self):
        root, owner = self.tree()
        self.returned(root, owner)
        self.authority(root)
        real_replace = os.replace
        failure = OSError("synthetic second move failure")
        calls = []
        def fail_after_run(source, destination):
            calls.append((source, destination))
            if len(calls) == 2:
                raise failure
            real_replace(source, destination)
        with mock.patch.object(subject.os, "replace", side_effect=fail_after_run), mock.patch.object(subject.sys, "stderr", io.StringIO()):
            with self.assertRaises(OSError) as caught:
                owner.archive()
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(calls), 2)
        self.assertFalse((root / "runs/run-owned").exists())
        self.assertEqual((root / ".scientist-one-build/test-runs/run-owned/marker").read_bytes(), b"run evidence")
        self.assertTrue((root / ".scientist-one-build/custody/run-owned.jsonl").is_file())
        self.assertTrue(owner.cleanup_incomplete)

    def test_diagnostic_is_bounded_and_contains_only_ordinary_emission_failures(self):
        _, owner = self.tree()
        stream = io.StringIO()
        with mock.patch.object(subject.sys, "stderr", stream):
            owner._diagnose_cleanup()
        self.assertEqual(stream.getvalue(), "CLI_FIXTURE_CLEANUP_INCOMPLETE reason=ARCHIVE_FAILED\n")
        self.assertLess(len(stream.getvalue().encode()), 128)
        for position in ("write", "flush"):
            for failure in (OSError("emission failed"), KeyboardInterrupt(), SystemExit(9)):
                with self.subTest(position=position, failure=type(failure).__name__):
                    stream = mock.Mock()
                    getattr(stream, position).side_effect = failure
                    with mock.patch.object(subject.sys, "stderr", stream):
                        if isinstance(failure, Exception):
                            owner._diagnose_cleanup()
                        else:
                            with self.assertRaises(type(failure)) as caught:
                                owner._diagnose_cleanup()
                            self.assertIs(caught.exception, failure)
        self.assertTrue(owner.cleanup_incomplete)
