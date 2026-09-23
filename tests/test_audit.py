from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from scientist_one import audit as audit_module

from scientist_one.audit import (
    audit_project,
    inventory,
    outside_root_paths_in_json,
    snapshot_digest,
    write_audit,
)
from scientist_one.domains import (
    SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME,
)


ROOT = Path(__file__).resolve().parents[1]
TMP = ROOT / ".scientist-one-build" / "tmp"


class AuditTests(unittest.TestCase):
    def test_private_gateway_trust_root_is_absent_from_audit_inventory(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            registry = root / "runs" / "run-audit" / "registry"
            registry.mkdir(parents=True)
            key_name = "." + "gateway-execution-" + "authority.key"
            (registry / key_name).write_bytes(bytes(range(32)))
            (registry / key_name).chmod(0o600)
            (registry / "public.json").write_text("{}", encoding="utf-8")

            records, findings = inventory(root, excludes=())
            report = audit_project(root, excludes=())

            self.assertFalse(findings)
            self.assertIn(
                "runs/run-audit/registry/public.json",
                {record.path for record in records},
            )
            self.assertNotIn(
                f"runs/run-audit/registry/{key_name}",
                {record.path for record in records},
            )
            self.assertNotIn(key_name, report.as_json())

    def test_private_gateway_trust_root_basename_cannot_hide_source(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            source = root / "src" / "nested"
            source.mkdir(parents=True)
            key_name = "." + "gateway-execution-" + "authority.key"
            private_file = source / key_name
            private_file.write_bytes(bytes(reversed(range(32))))
            private_file.chmod(0o600)

            records, findings = inventory(root, excludes=())
            report = audit_project(root, excludes=())

            self.assertNotIn(
                f"src/nested/{key_name}",
                {record.path for record in records},
            )
            self.assertTrue(
                any(
                    finding.check
                    == "private_runtime_secret_outside_registry"
                    and finding.path == "src/nested"
                    for finding in findings
                )
            )
            self.assertIn(
                "private_runtime_secret_outside_registry",
                report.as_json(),
            )
            self.assertNotIn(key_name, report.as_json())

    def test_private_domain_trust_root_is_absent_from_audit_inventory(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            registry = root / "runs" / "run-domain-audit" / "registry"
            registry.mkdir(parents=True)
            key_name = SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
            (registry / key_name).write_bytes(bytes(range(32)))
            (registry / key_name).chmod(0o600)
            (registry / "public.json").write_text("{}", encoding="utf-8")

            records, findings = inventory(root, excludes=())
            report = audit_project(root, excludes=())

            self.assertFalse(findings)
            self.assertIn(
                "runs/run-domain-audit/registry/public.json",
                {record.path for record in records},
            )
            self.assertNotIn(
                f"runs/run-domain-audit/registry/{key_name}",
                {record.path for record in records},
            )
            self.assertNotIn(key_name, report.as_json())

    def test_private_domain_trust_root_basename_cannot_hide_source(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            source = root / "src" / "nested"
            source.mkdir(parents=True)
            key_name = SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
            private_file = source / key_name
            private_file.write_bytes(bytes(reversed(range(32))))
            private_file.chmod(0o600)

            records, findings = inventory(root, excludes=())
            report = audit_project(root, excludes=())

            self.assertNotIn(
                f"src/nested/{key_name}",
                {record.path for record in records},
            )
            self.assertTrue(
                any(
                    finding.check == "private_runtime_secret_outside_registry"
                    and finding.path == "src/nested"
                    for finding in findings
                )
            )
            self.assertIn(
                "private_runtime_secret_outside_registry",
                report.as_json(),
            )
            self.assertNotIn(key_name, report.as_json())

    def test_unsafe_private_domain_trust_root_is_never_read_or_inventoried(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            registry = root / "runs" / "run-domain-audit" / "registry"
            registry.mkdir(parents=True)
            key_name = SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
            private_file = registry / key_name
            private_file.write_bytes(bytes(range(31)))
            private_file.chmod(0o644)

            records, findings = inventory(root, excludes=())
            report = audit_project(root, excludes=())

            self.assertNotIn(
                f"runs/run-domain-audit/registry/{key_name}",
                {record.path for record in records},
            )
            self.assertTrue(
                any(
                    finding.check == "unsafe_private_runtime_secret"
                    and finding.path == "runs/run-domain-audit/registry"
                    for finding in findings
                )
            )
            self.assertNotIn(key_name, report.as_json())

    def test_snapshot_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "b.txt").write_text("two")
            (root / "a.txt").write_text("one")
            first, findings = inventory(root)
            second, _ = inventory(root)
            self.assertFalse(findings)
            self.assertEqual(snapshot_digest(first), snapshot_digest(second))

    def test_symlink_is_reported_and_not_followed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "inside.txt").write_text("safe")
            (root / "escape").symlink_to(Path("/tmp"))
            _, findings = inventory(root)
            self.assertTrue(any(item.check == "symlink_rejected" for item in findings))

    def test_directory_swap_cannot_enumerate_outside_names(self) -> None:
        with (
            tempfile.TemporaryDirectory(dir=TMP) as directory,
            tempfile.TemporaryDirectory(dir=TMP) as outside_directory,
        ):
            root = Path(directory)
            outside = Path(outside_directory)
            child = root / "child"
            child.mkdir()
            (child / "inside.txt").write_text("inside")
            (outside / "outside-secret-name.txt").write_text("outside")
            held = root / "held-child"
            swapped = False

            def swap(relative: Path) -> None:
                nonlocal swapped
                if relative == Path("child") and not swapped:
                    child.rename(held)
                    child.symlink_to(outside, target_is_directory=True)
                    swapped = True

            with mock.patch.object(
                audit_module, "_inventory_before_descend", side_effect=swap
            ):
                records, findings = inventory(root)
            self.assertTrue(swapped)
            self.assertNotIn(
                "child/outside-secret-name.txt", {record.path for record in records}
            )
            self.assertTrue(
                any(
                    item.check == "unsafe_directory" and item.path == "child"
                    for item in findings
                )
            )

    def test_queued_directory_replacement_is_rejected_by_identity(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir()
            (child / "original.txt").write_text("original")
            replacement = root / "replacement"
            replacement.mkdir()
            (replacement / "replacement.txt").write_text("replacement")
            held = root / "held-child"
            swapped = False

            def swap(relative: Path) -> None:
                nonlocal swapped
                if relative == Path("child") and not swapped:
                    child.rename(held)
                    replacement.rename(child)
                    swapped = True

            with mock.patch.object(
                audit_module,
                "_inventory_before_directory_reopen",
                side_effect=swap,
            ):
                records, findings = inventory(root)

            self.assertTrue(swapped)
            self.assertNotIn(
                "child/replacement.txt", {record.path for record in records}
            )
            self.assertTrue(
                any(
                    item.check == "unsafe_directory" and item.path == "child"
                    for item in findings
                )
            )

    def test_outside_root_manifest_path_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"input": "/outside/file.json", "local": str(root / "ok.json")}))
            self.assertEqual(outside_root_paths_in_json(manifest, root), ["/outside/file.json"])

    def test_secret_assignment_and_lockfile_block_audit(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            synthetic_secret = "api" + "_key = " + ("a" * 24)
            (root / "notes.txt").write_text(synthetic_secret)
            (root / "package-lock.json").write_text("{}")
            audit = audit_project(root)
            self.assertFalse(audit.passed)
            self.assertEqual(audit.lockfiles, ("package-lock.json",))
            self.assertTrue(any(item.check == "secret_pattern" for item in audit.findings))

    def test_malformed_utf8_is_reported_and_does_not_hide_ascii_marker(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            marker = ("access" + "_" + "token").encode("ascii")
            synthetic_value = ("r" * 24).encode("ascii")
            (root / "malformed.txt").write_bytes(
                b"\xff\n" + marker + b"=" + synthetic_value
            )

            audit = audit_project(root)

            self.assertFalse(audit.passed)
            self.assertTrue(
                any(
                    item.check == "invalid_text_encoding"
                    and item.detail == "invalid_utf8"
                    for item in audit.findings
                )
            )
            self.assertTrue(
                any(
                    item.check == "secret_pattern"
                    and item.detail == "secret_assignment"
                    for item in audit.findings
                )
            )
            self.assertNotIn(
                synthetic_value.decode("ascii"), repr(audit.findings)
            )

    def test_zip_binary_encoding_is_accepted_but_ascii_secrets_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            benign_buffer = io.BytesIO()
            with zipfile.ZipFile(
                benign_buffer, "w", compression=zipfile.ZIP_STORED
            ) as archive:
                archive.writestr("payload.bin", b"\xff\x00\x80")
            benign_payload = benign_buffer.getvalue()
            with self.assertRaises(UnicodeDecodeError):
                benign_payload.decode("utf-8")
            (root / "benign.zip").write_bytes(benign_payload)

            benign_audit = audit_project(root)

            self.assertTrue(benign_audit.passed)
            self.assertFalse(
                any(
                    item.check == "invalid_text_encoding"
                    and item.path == "benign.zip"
                    for item in benign_audit.findings
                )
            )

            marker = ("access" + "_" + "token").encode("ascii")
            synthetic_value = ("z" * 24).encode("ascii")
            marked_buffer = io.BytesIO()
            with zipfile.ZipFile(
                marked_buffer, "w", compression=zipfile.ZIP_STORED
            ) as archive:
                archive.writestr(
                    "payload.bin", b"\xff\n" + marker + b"=" + synthetic_value
                )
            (root / "marked.zip").write_bytes(marked_buffer.getvalue())

            marked_audit = audit_project(root)

            self.assertTrue(
                any(
                    item.check == "secret_pattern"
                    and item.path == "marked.zip"
                    and item.detail == "secret_assignment"
                    for item in marked_audit.findings
                )
            )
            self.assertFalse(
                any(
                    item.check == "invalid_text_encoding"
                    and item.path in {"benign.zip", "marked.zip"}
                    for item in marked_audit.findings
                )
            )
            self.assertNotIn(
                synthetic_value.decode("ascii"), repr(marked_audit.findings)
            )

    def test_invalid_json_in_run_manifest_is_reported(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "runs").mkdir()
            (root / "runs" / "bad.json").write_text("{")
            audit = audit_project(root)
            self.assertTrue(any(item.check == "invalid_manifest_json" for item in audit.findings))

    def test_duplicate_and_nonfinite_manifest_json_are_reported(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "runs").mkdir()
            (root / "runs" / "duplicate.json").write_text('{"path":"a","path":"b"}')
            (root / "runs" / "nan.json").write_text('{"value":NaN}')
            audit = audit_project(root)
            invalid = {item.path for item in audit.findings if item.check == "invalid_manifest_json"}
            self.assertEqual(invalid, {"runs/duplicate.json", "runs/nan.json"})

    def test_leaf_swap_cannot_separate_snapshot_from_security_checks(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "runs").mkdir()
            manifest = root / "runs" / "manifest.json"
            manifest.write_text('{"local":"safe"}')
            swapped = False

            def swap(record: audit_module.FileRecord) -> None:
                nonlocal swapped
                if record.path == "runs/manifest.json" and not swapped:
                    replacement = root / "runs" / "replacement.json"
                    replacement.write_text('{"path":"/outside/changed.json"}')
                    replacement.replace(manifest)
                    swapped = True

            with mock.patch.object(
                audit_module, "_audit_before_record_validation", side_effect=swap
            ):
                audit = audit_project(root)
            self.assertTrue(swapped)
            self.assertFalse(audit.passed)
            self.assertTrue(
                any(
                    item.check == "changed_during_audit"
                    and item.path == "runs/manifest.json"
                    for item in audit.findings
                )
            )

    def test_hardlinked_evidence_is_reported(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            original = root / "original.json"
            original.write_text("{}")
            linked = root / "linked.json"
            linked.hardlink_to(original)
            audit = audit_project(root)
            self.assertFalse(audit.passed)
            self.assertEqual(
                {item.path for item in audit.findings if item.check == "hardlink_rejected"},
                {"original.json", "linked.json"},
            )

    def test_audit_file_and_total_size_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "first.bin").write_bytes(b"1234")
            (root / "large.bin").write_bytes(b"12345")
            with mock.patch.object(audit_module, "MAX_AUDIT_FILE_BYTES", 4):
                audit = audit_project(root)
            self.assertTrue(
                any(item.check == "audit_file_size_limit" for item in audit.findings)
            )

            with (
                mock.patch.object(audit_module, "MAX_AUDIT_FILE_BYTES", 16),
                mock.patch.object(audit_module, "MAX_AUDIT_TOTAL_BYTES", 4),
            ):
                audit = audit_project(root)
            self.assertTrue(
                any(item.check == "audit_total_size_limit" for item in audit.findings)
            )

    def test_audit_entry_count_and_report_output_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            for index in range(3):
                (root / f"empty-{index}.txt").write_bytes(b"")
            with mock.patch.object(audit_module, "MAX_AUDIT_FILES", 2):
                audit = audit_project(root)
            self.assertFalse(audit.passed)
            self.assertLessEqual(audit.file_count, 2)
            self.assertTrue(
                any(
                    item.check == "audit_file_count_limit"
                    for item in audit.findings
                )
            )
            with mock.patch.object(audit_module, "MAX_AUDIT_REPORT_BYTES", 8):
                with self.assertRaises(audit_module.UnsafeSerializationError):
                    audit.as_json()

    def test_entry_limit_stops_before_unbounded_directory_retention(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            consumed = 0

            class SyntheticScandir:
                def __enter__(self) -> SyntheticScandir:
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

                def __iter__(self) -> SyntheticScandir:
                    return self

                def __next__(self) -> object:
                    nonlocal consumed
                    consumed += 1
                    if consumed > 3:
                        raise AssertionError("audit consumed beyond limit plus one")
                    return type("Entry", (), {"name": f"entry-{consumed}"})()

            with (
                mock.patch.object(audit_module.os, "scandir", return_value=SyntheticScandir()),
                mock.patch.object(audit_module, "MAX_AUDIT_FILES", 2),
            ):
                records, findings = inventory(root)

            self.assertEqual(consumed, 3)
            self.assertEqual(records, [])
            self.assertTrue(
                any(item.check == "audit_file_count_limit" for item in findings)
            )

    def test_final_audit_report_excludes_itself_from_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            (root / "reports").mkdir()
            (root / "source.txt").write_text("stable")
            first = audit_project(root)
            (root / "reports" / "final_audit.json").write_text(first.as_json())
            second = audit_project(root)
            self.assertEqual(first.snapshot_digest, second.snapshot_digest)

    def test_audit_writer_rejects_preplanted_target_symlink(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP) as directory:
            root = Path(directory)
            outside = TMP / "audit-symlink-sentinel.txt"
            if outside.exists():
                outside.unlink()
            target = root / "audit.json"
            target.symlink_to(outside)
            audit = audit_project(root)
            with self.assertRaises(ValueError):
                write_audit(audit, target, root)
            self.assertFalse(outside.exists())
            target.unlink()

    def test_machine_test_report_does_not_follow_preplanted_partial_symlink(self) -> None:
        """The evidence runner must use the shared no-follow atomic writer."""

        script = (ROOT / "scripts" / "run_test_suite.py").read_text(encoding="utf-8")
        self.assertIn("atomic_write_json", script)
        self.assertNotIn("REPORT.with_suffix", script)
        self.assertNotIn("partial.write_text", script)


if __name__ == "__main__":
    unittest.main()
