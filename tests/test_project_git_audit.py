"""Project-audit integration using real, explicitly synthetic Git history."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import unittest
from unittest import mock

import scientist_one.audit as audit_module
import scientist_one.git_audit as git_module
from scientist_one.errors import PathSecurityError
from scientist_one.security import canonical_json_bytes
import tests.test_git_audit as fixtures
import tests.test_isolated_launchers as launcher_fixtures


class ProjectGitAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GitAuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root.resolve()
        self.git = self.fixture.git

    def test_absent_git_preserves_original_report_bytes(self):
        root = self.root.parent / "without-git"
        root.mkdir()
        (root / "note.txt").write_text("Inert text.\n", encoding="utf-8")
        result = audit_module.audit_project(root)
        expected = {
            "project_root": str(root.resolve()),
            "snapshot_digest": result.snapshot_digest,
            "file_count": result.file_count,
            "total_bytes": result.total_bytes,
            "files": [asdict(item) for item in result.files],
            "findings": [], "lockfiles": [], "passed": True,
        }
        self.assertEqual(result.as_json(), canonical_json_bytes(expected).decode() + "\n")
        self.assertIsNone(getattr(result, "git", None))

    def test_real_loose_git_remains_in_complete_raw_snapshot(self):
        records, findings = audit_module.inventory(self.root)
        self.assertFalse(findings)
        result = audit_module.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        self.assertTrue(result.git.passed)
        self.assertEqual(result.snapshot_digest, audit_module.snapshot_digest(records))
        self.assertEqual(result.files, tuple(records))
        raw = sorted((item for item in records if item.path.startswith(".git/")), key=lambda item: item.path)
        self.assertEqual(result.git.raw_file_count, len(raw))
        self.assertEqual(result.git.raw_inventory_sha256, hashlib.sha256(canonical_json_bytes([asdict(item) for item in raw])).hexdigest())
        self.assertTrue(json.loads(result.as_json())["git"]["passed"])
        self.assertNotIn("_binding", result.as_json())

    def test_real_packed_history_and_tag_are_decoded(self):
        self.git("tag", "-a", "synthetic-integration", "-m", "Synthetic integration tag")
        self.git("repack", "-ad")
        self.git("pack-refs", "--all")
        result = audit_module.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        self.assertTrue(any(path.endswith(".pack") for path in result.git.binary_waiver_paths))

    def test_unreachable_secret_blocks_project_without_echo(self):
        marker = b"api" + b"_key = " + b"r" * 24
        oid = self.git("hash-object", "-w", "--stdin", payload=marker).decode().strip()
        result = audit_module.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertTrue(any(oid in item.path and "secret_pattern" in item.detail for item in result.findings))
        self.assertNotIn(marker.decode(), result.as_json())

    def test_git_file_aba_after_native_validation_refuses(self):
        original_run = git_module.GitAuditSession._run
        changed = False

        def forward(session, arguments, **kwargs):
            nonlocal changed
            output = original_run(session, arguments, **kwargs)
            if arguments[0] == "fsck" and not changed:
                target = self.root / ".git" / "config"
                original = target.read_bytes()
                target.write_bytes(original + b"\n")
                target.write_bytes(original)
                changed = True
            return output

        with mock.patch.object(git_module.GitAuditSession, "_run", new=forward):
            result = audit_module.audit_project(self.root)
        self.assertTrue(changed)
        self.assertFalse(result.passed)
        self.assertTrue(any(item.check == "changed_during_audit" for item in result.findings))
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())

    def test_git_change_after_audit_prevents_publication(self):
        (self.root / "reports").mkdir()
        result = audit_module.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        config = self.root / ".git" / "config"
        config.write_bytes(config.read_bytes() + b"\n")
        with self.assertRaises(PathSecurityError):
            audit_module.require_current_audit(result, self.root)
        target = self.root / "reports" / "final_audit.json"
        with self.assertRaises(ValueError):
            audit_module.write_audit(result, target, self.root)
        self.assertFalse(target.exists())

    def test_git_specific_exclusions_cannot_hide_dangling_objects(self):
        marker = b"api" + b"_key = " + b"s" * 24
        oid = self.git("hash-object", "-w", "--stdin", payload=marker).decode().strip()
        result = audit_module.audit_project(self.root, excluded_files=(f".git/objects/{oid[:2]}/{oid[2:]}",))
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)
        hidden = audit_module.audit_project(self.root, excludes=(".git",))
        self.assertFalse(hidden.passed)
        self.assertFalse(hidden.git.passed)

    def test_empty_git_and_gitfile_are_not_absent_git(self):
        for label in ("empty", "gitfile", "symlink"):
            with self.subTest(label=label):
                root = self.root.parent / label
                root.mkdir()
                marker = root / ".git"
                if label == "empty":
                    marker.mkdir()
                elif label == "gitfile":
                    marker.write_text("gitdir: ../synthetic-repository/.git\n", encoding="utf-8")
                else:
                    marker.symlink_to(self.root / ".git", target_is_directory=True)
                result = audit_module.audit_project(root)
                self.assertFalse(result.passed)
                self.assertFalse(result.git.passed)
                self.assertEqual(result.git.binary_waiver_paths, ())
                self.assertIsNone(result.git.tool_version)

    def test_unknown_git_zip_does_not_gain_raw_encoding_waiver(self):
        target = self.root / ".git" / "unknown.zip"
        target.write_bytes(b"\xff\x00not-a-git-format")
        result = audit_module.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertTrue(any(item.check == "invalid_text_encoding" and item.path == ".git/unknown.zip" for item in result.findings))

    def test_worktree_aba_during_real_parser_is_not_hidden(self):
        original_run = git_module.GitAuditSession._run
        changed = False

        def forward(session, arguments, **kwargs):
            nonlocal changed
            output = original_run(session, arguments, **kwargs)
            if arguments[0] == "fsck" and not changed:
                target = self.root / "README.md"
                original = target.read_bytes()
                target.write_bytes(original + b"\n")
                target.write_bytes(original)
                changed = True
            return output

        with mock.patch.object(git_module.GitAuditSession, "_run", new=forward):
            result = audit_module.audit_project(self.root)
        self.assertTrue(changed)
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)

    def test_parser_image_io_failure_is_bounded_and_cleaned(self):
        images = []

        def fail_put(session, *_args):
            images.append(session._image)
            raise OSError("synthetic-private-diagnostic-must-not-be-reported")

        with mock.patch.object(git_module.GitAuditSession, "_put", new=fail_put):
            result = audit_module.audit_project(self.root)
        self.assertTrue(images)
        self.assertTrue(all(not path.exists() for path in images))
        self.assertFalse(result.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertNotIn("synthetic-private-diagnostic", result.as_json())

    def test_report_substitution_cannot_reuse_identity_binding(self):
        self.git("hash-object", "-w", "--stdin", payload=b"api" + b"_key = " + b"t" * 24)
        result = audit_module.audit_project(self.root)
        self.assertFalse(result.passed)
        for substituted in (
            replace(result, findings=()),
            replace(result, git=replace(result.git, findings=())),
            replace(result, findings=(), git=None),
            replace(result, findings=(), git=None, _binding=None),
        ):
            with self.subTest(git_absent=substituted.git is None):
                with self.assertRaises(PathSecurityError):
                    audit_module.require_current_audit(substituted, self.root)

    def test_new_git_after_no_git_audit_requires_a_new_audit(self):
        root = self.root.parent / "new-git-after-audit"
        root.mkdir()
        result = audit_module.audit_project(root)
        self.assertTrue(result.passed)
        (root / ".git").mkdir()
        with self.assertRaises(PathSecurityError):
            audit_module.require_current_audit(result, root)

    def test_exact_staged_report_is_the_only_extra_allowed_file(self):
        (self.root / "reports").mkdir()
        result = audit_module.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        scratch = "reports/.final_audit.json." + "a" * 32 + ".partial"
        target = self.root / scratch
        target.write_bytes(result.as_json().encode("utf-8"))
        target.chmod(0o600)
        audit_module.require_current_audit(result, self.root, staged_report_path=scratch)
        target.write_bytes(b"unreviewed material")
        with self.assertRaises(PathSecurityError):
            audit_module.require_current_audit(result, self.root, staged_report_path=scratch)

    def test_staged_report_does_not_hide_sibling_file_aba(self):
        (self.root / "reports").mkdir()
        sibling = self.root / "reports" / "other.txt"
        sibling.write_text("Original.\n", encoding="utf-8")
        result = audit_module.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        scratch = "reports/.final_audit.json." + "b" * 32 + ".partial"
        target = self.root / scratch
        target.write_bytes(result.as_json().encode("utf-8"))
        target.chmod(0o600)
        original = sibling.read_bytes()
        sibling.write_bytes(b"changed\n")
        sibling.write_bytes(original)
        with self.assertRaises(PathSecurityError):
            audit_module.require_current_audit(result, self.root, staged_report_path=scratch)

    def test_captured_launcher_publishes_real_git_coverage(self):
        launcher_fixtures._single_test_project(
            self.root,
            "import unittest\nclass ProbeTests(unittest.TestCase):\n    def test_probe(self): self.assertTrue(True)\n",
        )
        result = launcher_fixtures._run_launcher(self.root, "audit-project", timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads((self.root / "reports" / "final_audit.json").read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertTrue(report["git"]["passed"])
        self.assertIn(".git/index", report["git"]["binary_waiver_paths"])
        self.assertTrue(any(item["path"].startswith(".git/objects/") for item in report["files"]))
        self.assertFalse(tuple((self.root / "reports").glob("*.partial")))

    def test_captured_launcher_refuses_git_aba_at_publication(self):
        package, _ = launcher_fixtures._single_test_project(
            self.root,
            "import unittest\nclass ProbeTests(unittest.TestCase):\n    def test_probe(self): self.assertTrue(True)\n",
        )
        source = package / "audit.py"
        original = source.read_text(encoding="utf-8")
        needle = "    binding = audit._binding\n"
        self.assertEqual(original.count(needle), 1)
        source.write_text(original.replace(needle, needle + (
            "    if staged_report_path is not None:\n"
            "        _probe_path = root / '.git' / 'config'\n"
            "        _probe_original = _probe_path.read_bytes()\n"
            "        _probe_path.write_bytes(_probe_original + b'\\n')\n"
            "        _probe_path.write_bytes(_probe_original)\n"
        )), encoding="utf-8")
        result = launcher_fixtures._run_launcher(self.root, "audit-project", timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inventory changed after audit", result.stderr)
        self.assertFalse((self.root / "reports" / "final_audit.json").exists())
        self.assertFalse(tuple((self.root / "reports").glob("*.partial")))

    def test_final_staged_attestation_rejects_mode_and_read_aba(self):
        observed = launcher_fixtures._isolated_launcher_probe('''
            import os, tempfile
            from pathlib import Path
            outcomes = {}
            for scenario in ("unchanged", "mode", "read-aba"):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "reports").mkdir()
                    staged = namespace["_StagedEvidence"](root, "final_audit.json", b"inert report")
                    target = root / "reports" / staged.temporary_name
                    original_read = os.read
                    changed = False
                    def forward(descriptor, size):
                        global changed
                        data = original_read(descriptor, size)
                        if descriptor == staged.descriptor and data and not changed:
                            changed = True
                            target.write_bytes(b"different!!")
                            target.write_bytes(b"inert report")
                        return data
                    try:
                        if scenario == "mode":
                            target.chmod(0o644)
                        if scenario == "read-aba":
                            os.read = forward
                        try:
                            staged.commit(root)
                        except SystemExit:
                            outcomes[scenario] = "refused"
                        else:
                            outcomes[scenario] = "published"
                    finally:
                        os.read = original_read
                        staged.close()
            print(json.dumps(outcomes))
        ''')
        self.assertEqual(observed, {"unchanged": "published", "mode": "refused", "read-aba": "refused"})

    def test_staged_cleanup_preserves_preexisting_and_replacement_files(self):
        observed = launcher_fixtures._isolated_launcher_probe('''
            import tempfile
            from pathlib import Path
            stage_type = namespace["_StagedEvidence"]
            outcomes = {}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "reports").mkdir()
                staged = stage_type(root, "final_audit.json", b"inert report")
                target = root / "reports" / staged.temporary_name
                target.rename(root / "reports" / "held-original")
                target.write_bytes(b"replacement sentinel")
                staged.close()
                outcomes["replacement"] = target.read_bytes() == b"replacement sentinel"
                secrets_module = stage_type.__init__.__globals__["secrets"]
                original_hex = secrets_module.token_hex
                secrets_module.token_hex = lambda _count: "c" * 32
                existing = root / "reports" / (".final_audit.json." + "c" * 32 + ".partial")
                existing.write_bytes(b"preexisting sentinel")
                try:
                    try:
                        stage_type(root, "final_audit.json", b"inert report")
                    except FileExistsError:
                        outcomes["collision_refused"] = True
                finally:
                    secrets_module.token_hex = original_hex
                outcomes["preexisting"] = existing.read_bytes() == b"preexisting sentinel"
            print(json.dumps(outcomes))
        ''')
        self.assertEqual(observed, {"replacement": True, "collision_refused": True, "preexisting": True})

    def test_publication_reinventory_does_not_accept_post_read_aba_or_secret(self):
        reports = self.root / "reports"
        reports.mkdir()
        report = reports / "final_audit.json"
        report.write_bytes(b"previous report sentinel")
        target = self.root / "README.md"
        original = target.read_bytes()
        real_read = audit_module._read_inventory_file
        for scenario in ("aba", "content"):
            with self.subTest(scenario=scenario):
                target.write_bytes(original)
                result = audit_module.audit_project(self.root)
                self.assertTrue(result.passed, result.findings)
                changed = False

                def read_then_change(descriptor, name):
                    nonlocal changed
                    observed = real_read(descriptor, name)
                    if name == "README.md" and not changed:
                        changed = True
                        target.write_bytes(original + b"api" + b"_key = " + b"z" * 24 + b"\n")
                        if scenario == "aba":
                            target.write_bytes(original)
                    return observed

                with mock.patch.object(audit_module, "_read_inventory_file", new=read_then_change):
                    with self.assertRaises(ValueError):
                        audit_module.write_audit(result, report, self.root)
                self.assertTrue(changed)
                self.assertEqual(report.read_bytes(), b"previous report sentinel")

    def test_post_native_reinventory_checks_files_after_last_read(self):
        real_read = audit_module._read_inventory_file
        reads = 0
        changed = False
        target = self.root / ".git" / "config"
        original = target.read_bytes()

        def read_then_change(descriptor, name):
            nonlocal reads, changed
            observed = real_read(descriptor, name)
            if name == "config":
                reads += 1
                if reads == 3:
                    target.write_bytes(original + b"\n")
                    target.write_bytes(original)
                    changed = True
            return observed

        with mock.patch.object(audit_module, "_read_inventory_file", new=read_then_change):
            result = audit_module.audit_project(self.root)
        self.assertTrue(changed)
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
