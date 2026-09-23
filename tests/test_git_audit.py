"""Real disposable Git-format controls; never project or scientific history."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import scientist_one.git_audit as git_audit
from scientist_one.git_audit import GitAuditError, GitAuditFile, GitAuditSession


_GIT = "/Library/Developer/CommandLineTools/usr/bin/git"
if not Path(_GIT).is_file():
    _GIT = "/usr/bin/git"


class GitAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="git-audit-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "synthetic-repository"
        self.root.mkdir()
        self.git("init", "-b", "main", "--template=")
        for key, value in (
            ("user.name", "Synthetic Git Audit Fixture"),
            ("user.email", "synthetic-git-audit@example.invalid"),
            ("gc.auto", "0"),
            ("maintenance.auto", "false"),
            ("pack.writeReverseIndex", "false"),
            ("index.version", "2"),
        ):
            self.git("config", key, value)
        (self.root / "README.md").write_text(
            "Disposable operational Git parser fixture. No scientific evidence.\n",
            encoding="utf-8",
        )
        (self.root / "nested").mkdir()
        (self.root / "nested" / "fixture.py").write_text("FIXTURE_ONLY = True\n", encoding="utf-8")
        self.git("add", "--", "README.md", "nested/fixture.py")
        # Explicit synthetic identity and native current timestamps only.
        self.git("commit", "-m", "Create disposable Git audit fixture")

    def git(self, *arguments: str, payload: bytes | None = None) -> bytes:
        environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1",
        }
        result = subprocess.run(
            [_GIT, "--no-pager", "--no-optional-locks", "-c", "protocol.allow=never", "-c", "core.hooksPath=/dev/null", "-C", str(self.root), *arguments],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, "synthetic Git fixture command failed")
        return result.stdout

    def files(self):
        payloads = {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in (self.root / ".git").rglob("*") if path.is_file()
        }
        manifest = tuple(
            GitAuditFile(path, len(payload), hashlib.sha256(payload).hexdigest())
            for path, payload in sorted(payloads.items())
        )
        return manifest, payloads

    def audit(self):
        manifest, payloads = self.files()
        with GitAuditSession(manifest) as session:
            image = session._image
            for path, payload in payloads.items():
                session.observe(path, payload)
            coverage = session.finalize()
        if image is not None:
            self.assertFalse(image.exists())
        if not coverage.passed:
            self.assertEqual(coverage.binary_waiver_paths, ())
        return coverage

    def assert_refuses(self, code=None):
        result = self.audit()
        self.assertFalse(result.passed)
        self.assertEqual(result.binary_waiver_paths, ())
        if code is not None:
            self.assertIn(code, {finding.code for finding in result.findings})
        return result

    def mutate_index(self, transform):
        path = self.root / ".git" / "index"
        original = path.read_bytes()
        body = bytearray(original[:-20])
        transformed = transform(body)
        if transformed is not None:
            body = transformed
        path.write_bytes(bytes(body) + hashlib.sha1(body).digest())

    def test_real_loose_objects_index_and_tool_are_verified(self):
        result = self.audit()
        self.assertTrue(result.passed, result.findings)
        self.assertEqual(result.index_entry_count, 2)
        expected_objects = self.git("cat-file", "--batch-all-objects", "--batch-check").splitlines()
        self.assertEqual(result.decoded_object_count, len(expected_objects))
        self.assertGreaterEqual(result.decoded_object_count, 5)
        self.assertIn(".git/index", result.binary_waiver_paths)
        self.assertNotIn(".git/config", result.binary_waiver_paths)
        self.assertTrue(result.tool_version.startswith("git version "))
        self.assertEqual(len(result.tool_sha256), 64)
        self.assertEqual(len(result.raw_inventory_sha256), 64)
        self.assertEqual(len(result.decoded_inventory_sha256), 64)
        self.assertEqual(len(result.index_inventory_sha256), 64)
        with self.assertRaises(FrozenInstanceError):
            result.profile = "forged"

    def test_real_packed_history_and_annotated_tag_decode(self):
        (self.root / "README.md").write_text("Second disposable revision.\n", encoding="utf-8")
        self.git("add", "--", "README.md")
        self.git("commit", "-m", "Second disposable Git parser revision")
        self.git("tag", "-a", "synthetic-fixture", "-m", "Synthetic parser fixture tag")
        self.git("repack", "-ad")
        self.git("pack-refs", "--all")
        result = self.audit()
        self.assertTrue(result.passed, result.findings)
        self.assertTrue(any(path.endswith(".pack") for path in result.binary_waiver_paths))
        self.assertTrue(any(path.endswith(".idx") for path in result.binary_waiver_paths))
        self.assertGreater(result.decoded_object_count, 5)

    def test_default_repack_reverse_index_is_not_silently_exempted(self):
        self.git("config", "--unset", "pack.writeReverseIndex")
        self.git("repack", "-ad")
        self.assertTrue(tuple((self.root / ".git" / "objects" / "pack").glob("*.rev")))
        result = self.assert_refuses("unsupported_git_metadata")
        self.assertIsNone(result.tool_version)

    def test_real_empty_unborn_repository_is_explicitly_unsupported(self):
        original_root = self.root
        self.root = original_root.parent / "synthetic-unborn-repository"
        self.root.mkdir()
        try:
            self.git("init", "-b", "main", "--template=")
            result = self.assert_refuses("incomplete_git_inventory")
            self.assertIsNone(result.tool_version)
            self.git("read-tree", "--empty")
            self.assert_refuses("incomplete_object_headers")
        finally:
            self.root = original_root

    def test_unreachable_blob_secret_is_found_without_echo(self):
        marker = b"api" + b"_key = " + b"z" * 24
        oid = self.git("hash-object", "-w", "--stdin", payload=marker).decode().strip()
        result = self.assert_refuses("secret_pattern_secret_assignment")
        self.assertIn(oid, result.findings[0].path)
        self.assertNotIn(marker.decode(), str(result.to_dict()))

    def test_unreachable_packed_secret_is_decoded_and_refused(self):
        marker = b"api" + b"_key = " + b"z" * 24
        oid = self.git("hash-object", "-w", "--stdin", payload=marker).decode().strip()
        packed = self.git("pack-objects", "--stdout", payload=(oid + "\n").encode("ascii"))
        self.git("index-pack", "--stdin", payload=packed)
        loose = self.root / ".git" / "objects" / oid[:2] / oid[2:]
        loose.unlink()
        result = self.assert_refuses("secret_pattern_secret_assignment")
        self.assertIn(oid, result.findings[0].path)
        self.assertNotIn(marker.decode(), str(result.to_dict()))

    def test_unreachable_binary_blob_is_unsupported(self):
        self.git("hash-object", "-w", "--stdin", payload=b"\xff\xfe\x00inert binary")
        self.assert_refuses("unsupported_decoded_encoding")

    def test_archive_name_does_not_authorize_decoded_binary(self):
        (self.root / "fixture.zip").write_bytes(b"PK\xff\x00synthetic-not-a-zip")
        self.git("add", "--", "fixture.zip")
        self.assert_refuses("unsupported_decoded_encoding")

    def test_malformed_object_and_pack_refuse(self):
        paths = [path for path in (self.root / ".git" / "objects").rglob("*") if path.is_file()]
        target = paths[0]
        original = target.read_bytes()
        target.chmod(0o600)
        target.write_bytes(b"not a Git object")
        result = self.assert_refuses()
        self.assertIn(result.findings[0].code, {"native_git_validation_failed", "malformed_object_frame"})
        target.write_bytes(original)
        self.git("repack", "-ad")
        pack = next((self.root / ".git" / "objects" / "pack").glob("*.pack"))
        pack.chmod(0o600)
        pack.write_bytes(pack.read_bytes()[:-10])
        result = self.assert_refuses()
        self.assertIn(result.findings[0].code, {"native_git_validation_failed", "malformed_object_frame"})

    def test_unpaired_pack_refuses_before_tool(self):
        self.git("repack", "-ad")
        next((self.root / ".git" / "objects" / "pack").glob("*.idx")).unlink()
        result = self.assert_refuses("incomplete_pack_pair")
        self.assertIsNone(result.tool_version)

    def test_index_checksum_drift_refuses(self):
        path = self.root / ".git" / "index"
        path.write_bytes(path.read_bytes()[:-1] + b"!")
        self.assert_refuses("invalid_index_checksum_or_header")

    def test_unknown_index_extension_refuses_despite_valid_checksum(self):
        self.mutate_index(lambda body: body + b"ABCD" + struct.pack("!I", 4) + b"test")
        self.assert_refuses("unsupported_index_extension")

    def test_validly_rehashed_index_mode_and_stage_refuse(self):
        path = self.root / ".git" / "index"
        original = path.read_bytes()
        self.mutate_index(lambda body: body.__setitem__(slice(36, 40), struct.pack("!I", 0o120000)))
        self.assert_refuses("unsupported_index_path_mode_or_stage")
        path.write_bytes(original)
        self.mutate_index(lambda body: body.__setitem__(72, body[72] | 0x10))
        self.assert_refuses("unsupported_index_path_mode_or_stage")

    def test_index_path_traversal_refuses(self):
        self.mutate_index(lambda body: body.__setitem__(slice(74, 83), b"../bad.md"))
        self.assert_refuses("invalid_index_path")

    def test_index_v4_refuses(self):
        self.git("update-index", "--index-version=4")
        self.assert_refuses("unsupported_index_version_or_count")

    def test_tree_cache_identity_mismatch_refuses(self):
        path = self.root / ".git" / "index"
        self.assertIn(b"TREE", path.read_bytes())
        self.mutate_index(lambda body: body.__setitem__(-1, body[-1] ^ 1))
        self.assert_refuses("index_tree_cache_identity_mismatch")

    def test_index_without_tree_cache_rejects_directory_aliases_and_collisions(self):
        oid = bytes.fromhex(self.git("rev-parse", "HEAD:README.md").decode().strip())
        for names, accepted in (
            (("Dir/one.txt", "other/two.txt"), True),
            (("Dir/one.txt", "dir/two.txt"), False),
            (("dir", "dir/two.txt"), False),
        ):
            with self.subTest(paths=names):
                body = bytearray(b"DIRC" + struct.pack("!II", 2, len(names)))
                for name in names:
                    encoded = name.encode("ascii")
                    entry = bytes(24) + struct.pack("!I", 0o100644) + bytes(12)
                    entry += oid + struct.pack("!H", len(encoded)) + encoded + b"\0"
                    body.extend(entry + bytes((-len(entry)) % 8))
                (self.root / ".git" / "index").write_bytes(body + hashlib.sha1(body).digest())
                if accepted:
                    result = self.audit()
                    self.assertTrue(result.passed, result.findings)
                else:
                    self.assert_refuses("index_path_collision")

    def test_unsafe_configuration_never_invokes_git(self):
        path = self.root / ".git" / "config"
        original = path.read_bytes()
        for extra in (
            b"\n[include]\npath = /outside/private-configuration\n",
            b"\n[core]\nfsmonitor = /outside/execute-this\n",
            b"\n[filter \"unsafe\"]\nsmudge = execute-this\n",
            b"\n[extensions]\npartialClone = origin\n",
            b"\n[fsck]\nskipList = /outside/object-list\n",
        ):
            with self.subTest(extra=extra.splitlines()[1]):
                path.write_bytes(original + extra)
                with mock.patch.object(git_audit.subprocess, "Popen", side_effect=AssertionError("unsafe configuration invoked Git")):
                    result = self.assert_refuses("unsafe_or_unsupported_config")
                self.assertNotIn("/outside/", str(result.to_dict()))
                self.assertIsNone(result.tool_version)

    def test_unknown_metadata_hooks_and_indirections_refuse_before_tool(self):
        for relative in (
            "hooks/pre-push", "objects/info/alternates", "commondir", "shallow",
            "objects/info/commit-graph", "objects/pack/multi-pack-index",
            "refs/replace/" + "1" * 40, "index.lock", "config.worktree",
        ):
            with self.subTest(path=relative):
                path = self.root / ".git" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"inert unsupported control\n")
                result = self.assert_refuses()
                self.assertIsNone(result.tool_version)
                path.unlink()

    def test_sample_hook_is_scanned_but_never_executed_or_waived(self):
        path = self.root / ".git" / "hooks" / "pre-push.sample"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"#!/bin/sh\nexit 71\n")
        path.chmod(0o700)
        result = self.audit()
        self.assertTrue(result.passed, result.findings)
        self.assertNotIn(".git/hooks/pre-push.sample", result.binary_waiver_paths)
        path.write_bytes(b"password = " + b"z" * 24)
        self.assert_refuses("secret_pattern_secret_assignment")

    def test_manifest_observation_hash_drift_and_duplicates_refuse(self):
        manifest, payloads = self.files()
        for bad in ("drift", "duplicate", "unplanned", "missing"):
            with self.subTest(case=bad), GitAuditSession(manifest) as session:
                image = session._image
                first = manifest[0].path
                if bad == "unplanned":
                    session.observe(".git/not-planned", b"inert")
                else:
                    for path, payload in payloads.items():
                        if bad == "missing" and path == first:
                            continue
                        session.observe(path, payload + b"drift" if bad == "drift" and path == first else payload)
                    if bad == "duplicate":
                        session.observe(first, payloads[first])
                result = session.finalize()
                self.assertFalse(result.passed)
                self.assertEqual(result.binary_waiver_paths, ())
                self.assertFalse(image.exists())

    def test_incomplete_git_image_and_invalid_manifest_refuse(self):
        manifest, _payloads = self.files()
        with self.assertRaises(GitAuditError):
            GitAuditSession(())
        with self.assertRaises(GitAuditError):
            GitAuditSession((manifest[0], manifest[0]))
        with self.assertRaises(GitAuditError):
            replace(manifest[0], path=".git")
        with self.assertRaises(GitAuditError):
            replace(manifest[0], path=".git/../outside")
        with self.assertRaises(GitAuditError):
            replace(manifest[0], size=git_audit.MAX_RAW_FILE_BYTES + 1)
        with mock.patch.object(git_audit, "MAX_RAW_FILES", 1):
            with self.assertRaises(GitAuditError):
                GitAuditSession(manifest)
        with mock.patch.object(git_audit, "MAX_RAW_TOTAL_BYTES", 1):
            with self.assertRaises(GitAuditError):
                GitAuditSession(manifest)
        with GitAuditSession((manifest[0],)) as session:
            result = session.finalize()
        self.assertFalse(result.passed)
        self.assertEqual(result.binary_waiver_paths, ())

    def test_manifest_dtos_are_revalidated_and_detached(self):
        manifest, payloads = self.files()
        original = manifest[0]
        detached = replace(original)
        with GitAuditSession(manifest) as session:
            object.__setattr__(original, "sha256", "0" * 64)
            for path, payload in payloads.items():
                session.observe(path, payload)
            result = session.finalize()
        self.assertTrue(result.passed, result.findings)
        expected = (detached, *manifest[1:])
        with GitAuditSession(expected) as session:
            for path, payload in payloads.items():
                session.observe(path, payload)
            self.assertEqual(session.finalize(), result)
        object.__setattr__(original, "path", ".git/../outside")
        with self.assertRaises(GitAuditError):
            GitAuditSession(manifest)

    def test_exception_cleanup_does_not_return_waiver(self):
        manifest, payloads = self.files()
        session = GitAuditSession(manifest)
        image = session._image
        with mock.patch.object(git_audit, "_index", side_effect=RuntimeError("injected test fault")):
            with self.assertRaises(RuntimeError), session:
                for path, payload in payloads.items():
                    session.observe(path, payload)
        self.assertFalse(image.exists())

    def test_decoded_count_size_and_time_limits_cleanup(self):
        for name, limit, code in (
            ("MAX_INDEX_ENTRIES", 1, "unsupported_index_version_or_count"),
            ("MAX_OBJECTS", 1, "decoded_object_limit"),
            ("MAX_OBJECT_BYTES", 1, "decoded_object_limit"),
            ("MAX_DECODED_BYTES", 1, "decoded_object_limit"),
            ("MAX_COMMAND_SECONDS", 0.0, "git_command_timeout"),
        ):
            with self.subTest(bound=name), mock.patch.object(git_audit, name, limit):
                self.assert_refuses(code)

    def test_session_time_limit_includes_observation_and_cleans_image(self):
        with mock.patch.object(git_audit, "MAX_SESSION_SECONDS", 0.0):
            self.assert_refuses("git_session_timeout")

    def test_declared_size_preflight_refuses_before_fsck_or_full_decode(self):
        commands = []
        original_run = GitAuditSession._run

        def record_run(session, arguments, **kwargs):
            commands.append(arguments)
            return original_run(session, arguments, **kwargs)

        with mock.patch.object(GitAuditSession, "_run", new=record_run):
            with mock.patch.object(git_audit, "MAX_OBJECT_BYTES", 1):
                result = self.assert_refuses("decoded_object_limit")
        self.assertIsNotNone(result.tool_version)
        self.assertIn(("cat-file", "--batch-all-objects", "--batch-check"), commands)
        self.assertFalse(any(command[0] == "fsck" for command in commands))
        self.assertNotIn(("cat-file", "--batch-all-objects", "--batch"), commands)

    def test_real_decoding_must_match_preflight_object_headers(self):
        original_finish = git_audit._ObjectHeaders.finish

        def changed_header_projection(headers):
            original_finish(headers)
            oid = next(iter(headers.objects))
            kind, size = headers.objects[oid]
            headers.objects[oid] = (kind, size + 1)

        # Corrupt only the intermediate expectation. Native header discovery,
        # fsck and full decoding still run; no successful tool result is mocked.
        with mock.patch.object(git_audit._ObjectHeaders, "finish", new=changed_header_projection):
            self.assert_refuses("object_header_content_mismatch")

    def test_host_git_configuration_is_not_inherited(self):
        with mock.patch.dict(os.environ, {
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "/outside/host-hook",
            "GIT_DIR": "/outside/repository", "GIT_WORK_TREE": "/outside/worktree",
            "GIT_OBJECT_DIRECTORY": "/outside/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/outside/alternates",
        }):
            result = self.audit()
        self.assertTrue(result.passed, result.findings)

    def test_repeated_audit_is_deterministic_and_live_git_is_unchanged(self):
        before = self.files()
        first = self.audit()
        self.assertTrue(first.passed, first.findings)
        self.assertEqual(self.audit(), first)
        self.assertEqual(self.files(), before)


if __name__ == "__main__":
    unittest.main()
