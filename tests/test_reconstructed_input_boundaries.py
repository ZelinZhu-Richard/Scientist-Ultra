"""SEMANTIC_RECONSTRUCTION of frozen B-01 local data-handling guarantees.

Synthetic temporary paths and inert bytes only; no commands are executed.
These tests do not exercise vNext experiment isolation or stopped work.
"""
import os
from pathlib import Path
import tempfile
import unittest

from scientist_one.errors import (
    CommandSecurityError, PathSecurityError, UnsafeSerializationError,
)
from scientist_one.security import (
    atomic_write_bytes, canonical_json_bytes, read_confined_bytes,
    resolve_confined, safe_json_loads, secure_directory, validate_command,
)


class ReconstructedInputBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.root = self.parent / "synthetic-project"
        self.root.mkdir()

    def test_regular_read_exact_bound_and_oversize_refusal(self):
        (self.root / "data").write_bytes(b"1234")
        self.assertEqual(read_confined_bytes(self.root, "data", max_bytes=4), b"1234")
        with self.assertRaises(PathSecurityError):
            read_confined_bytes(self.root, "data", max_bytes=3)

    def test_lexical_traversal_is_rejected_even_when_target_would_be_inside(self):
        (self.root / "inside").mkdir()
        with self.assertRaises(PathSecurityError):
            resolve_confined(self.root, "inside/../inside", expected_kind="directory")

    def test_outside_and_symlink_reads_are_refused(self):
        outside = self.parent / "synthetic-outside"
        outside.write_bytes(b"synthetic sentinel")
        (self.root / "link").symlink_to(outside)
        for name in (outside, "link"):
            with self.subTest(name=str(name)), self.assertRaises(PathSecurityError):
                read_confined_bytes(self.root, name)
        self.assertEqual(outside.read_bytes(), b"synthetic sentinel")

    def test_hardlinked_evidence_is_refused_when_unique_identity_required(self):
        source = self.root / "source"
        source.write_bytes(b"synthetic")
        os.link(source, self.root / "alias")
        with self.assertRaises(PathSecurityError):
            read_confined_bytes(self.root, "source", reject_hardlinks=True)

    def test_parent_symlink_cannot_create_external_directory(self):
        outside = self.parent / "other"
        outside.mkdir()
        (self.root / "outputs").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(PathSecurityError):
            secure_directory(self.root, "outputs/new", create=True)
        self.assertEqual(list(outside.iterdir()), [])

    def test_immutable_publication_is_exactly_idempotent(self):
        target = atomic_write_bytes(self.root, "frozen", b"original", immutable=True)
        self.assertEqual(atomic_write_bytes(self.root, "frozen", b"original", immutable=True), target)
        with self.assertRaises(PathSecurityError):
            atomic_write_bytes(self.root, "frozen", b"different", immutable=True)
        self.assertEqual(target.read_bytes(), b"original")

    def test_write_does_not_follow_symlink(self):
        outside = self.parent / "synthetic-target"
        outside.write_bytes(b"original")
        (self.root / "output").symlink_to(outside)
        with self.assertRaises(PathSecurityError):
            atomic_write_bytes(self.root, "output", b"different", overwrite=True)
        self.assertEqual(outside.read_bytes(), b"original")

    def test_duplicate_nonfinite_and_malformed_json_are_refused(self):
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                        b'{"a":', b'\xff', b'{"a":1e999}'):
            with self.subTest(payload=payload), self.assertRaises(UnsafeSerializationError):
                safe_json_loads(payload)

    def test_json_byte_item_and_depth_limits_are_independent(self):
        self.assertEqual(safe_json_loads(b"[1]", max_bytes=3, max_items=2), [1])
        with self.assertRaises(UnsafeSerializationError):
            safe_json_loads(b"[1]", max_bytes=2)
        with self.assertRaises(UnsafeSerializationError):
            safe_json_loads(b"[1]", max_items=1)
        with self.assertRaises(UnsafeSerializationError):
            safe_json_loads(b"[[[1]]]", max_depth=1)

    def test_canonical_json_preserves_identity_and_rejects_invalid_values(self):
        self.assertEqual(canonical_json_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')
        for value in ({"v": float("nan")}, {"v": float("inf")}, {1: "non-string key"}):
            with self.subTest(value=value), self.assertRaises(UnsafeSerializationError):
                canonical_json_bytes(value)

    def test_command_validation_requires_argv_and_explicit_allowlist(self):
        argv = ("python3", "-m", "scientist_one")
        self.assertEqual(validate_command(argv, allowed_executables=("python3",)), argv)
        for command in ("python3 -m scientist_one", (), ("unlisted",), ("python3", "-c", "pass")):
            with self.subTest(command=command), self.assertRaises(CommandSecurityError):
                validate_command(command, allowed_executables=("python3",))

    def test_shell_network_and_dependency_commands_are_never_executed(self):
        for command in (("sh", "script"), ("curl", "https://example.invalid"),
                        ("pip", "install", "synthetic"), ("python3", "-m", "unlisted")):
            with self.subTest(command=command), self.assertRaises(CommandSecurityError):
                validate_command(command, allowed_executables=(command[0],))


if __name__ == "__main__":
    unittest.main()
