"""Bounded parser-admission controls; no scientific or release authority."""

import hashlib
import io
import struct
import unittest
from unittest.mock import patch
import zipfile

from scientist_one import packaging


class PackageDirectoryAdmissionTests(unittest.TestCase):
    def stored(self, count=3):
        return packaging._zip_bytes({f"member-{i}.txt": b"x" for i in range(count)})

    def directory(self, data):
        return struct.unpack_from("<4s4H2LH", data, len(data) - 22)[6]

    def changed(self, data, offset, fmt, value):
        changed = bytearray(data)
        struct.pack_into(fmt, changed, offset, value)
        return bytes(changed)

    def alternate_zip64_directory(self):
        # A 444-byte directory-selection fixture, not a release package. The
        # third alternate filename contains the complete classic header. Its
        # classic filename then spans the ZIP64 end record and locator (76
        # bytes). Neither directory's counts/sizes use classic sentinels.
        # Only directory parsing is exercised; no member is opened here.
        def central(name_length, local_offset):
            return struct.pack(
                "<4s6H3L5H2L", b"PK\x01\x02", 20, 20, 0, 0, 0, 33,
                0, 0, 0, name_length, 0, 0, 0, 0, 0, local_offset,
            )

        classic_header = central(56 + 20, 0)
        names = (b"a", b"b", b"alternate-c" + classic_header)
        local_bytes = bytearray()
        offsets = []
        for name in names:
            offsets.append(len(local_bytes))
            local_bytes.extend(struct.pack(
                "<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 33,
                0, 0, 0, len(name), 0,
            ))
            local_bytes.extend(name)
        alternate_offset = len(local_bytes)
        alternate = b"".join(
            central(len(name), offset) + name
            for name, offset in zip(names, offsets, strict=True)
        )
        zip64_offset = alternate_offset + len(alternate)
        classic_offset = zip64_offset - len(classic_header)
        zip64_record = struct.pack(
            "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
            3, 3, len(alternate), alternate_offset,
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, zip64_offset, 1)
        footer_offset = zip64_offset + len(zip64_record) + len(locator)
        footer = struct.pack(
            "<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1,
            footer_offset - classic_offset, classic_offset, 0,
        )
        return bytes(local_bytes) + alternate + zip64_record + locator + footer

    def test_actual_builder_ascii_unicode_empty_contents_and_empty_archive(self):
        for members in ({}, {"zero.txt": b""}, {"nested/alpha.txt": b"one", "nested/\u03b2.txt": b"two"}):
            with self.subTest(members=tuple(members)):
                archive = packaging._zip_bytes(members)
                packaging._admit_finalized_archive_directory(archive)
                with zipfile.ZipFile(io.BytesIO(archive)) as packet:
                    self.assertEqual({name: packet.read(name) for name in packet.namelist()}, members)

    def test_exact_admission_ceiling_and_one_over(self):
        exact, excess = self.stored(2), self.stored(3)
        with patch.object(packaging, "MAX_PACKAGE_FILES", 2):
            packaging._admit_finalized_archive_directory(exact)
            with self.assertRaises(packaging.PackagingError):
                packaging._admit_finalized_archive_directory(excess)

    def test_forged_low_footer_count_does_not_hide_actual_entry_count(self):
        archive = self.stored(3)
        archive = self.changed(archive, len(archive) - 14, "<H", 1)
        archive = self.changed(archive, len(archive) - 12, "<H", 1)
        with patch.object(packaging, "MAX_PACKAGE_FILES", 2):
            with self.assertRaises(packaging.PackagingError):
                packaging._admit_finalized_archive_directory(archive)

    def test_footer_count_must_equal_actual_count(self):
        archive = self.stored(3)
        for declared in (0, 1, 4):
            with self.subTest(declared=declared):
                candidate = self.changed(archive, len(archive) - 14, "<H", declared)
                candidate = self.changed(candidate, len(candidate) - 12, "<H", declared)
                with self.assertRaises(packaging.PackagingError):
                    packaging._admit_finalized_archive_directory(candidate)

    def test_truncated_and_trailing_archives_rejected(self):
        archive = self.stored()
        for candidate in (b"", archive[:21], archive[:-1], archive + b"trailing"):
            with self.subTest(size=len(candidate)):
                with self.assertRaises(packaging.PackagingError):
                    packaging._admit_finalized_archive_directory(candidate)

    def test_spanned_zip64_comments_and_offset_mismatch_rejected(self):
        archive = self.stored()
        footer = len(archive) - 22
        for offset, fmt, value in ((4, "<H", 1), (6, "<H", 1), (8, "<H", 65535),
                                   (10, "<H", 65535), (12, "<L", 0xffffffff),
                                   (16, "<L", 0xffffffff), (20, "<H", 1)):
            with self.subTest(offset=offset):
                with self.assertRaises(packaging.PackagingError):
                    packaging._admit_finalized_archive_directory(self.changed(archive, footer + offset, fmt, value))

    def test_member_profile_and_truncated_fields_rejected(self):
        archive = self.stored()
        start = self.directory(archive)
        for offset, fmt, value in ((0, "<L", 0), (6, "<H", 45), (8, "<H", 1),
                                   (10, "<H", 8), (20, "<L", 2), (28, "<H", 0xffff),
                                   (30, "<H", 1), (32, "<H", 1), (34, "<H", 1),
                                   (42, "<L", start)):
            with self.subTest(offset=offset):
                with self.assertRaises(packaging.PackagingError):
                    packaging._admit_finalized_archive_directory(self.changed(archive, start + offset, fmt, value))

    def test_aggregate_declared_bytes_rejected_before_member_reads(self):
        archive = self.stored(2)
        start = self.directory(archive)
        second = start + 46 + len("member-0.txt")
        for entry in (start, second):
            archive = self.changed(archive, entry + 20, "<L", packaging.MAX_PACKAGE_INPUT_BYTES)
            archive = self.changed(archive, entry + 24, "<L", packaging.MAX_PACKAGE_INPUT_BYTES)
        with self.assertRaises(packaging.PackagingError):
            packaging._admit_finalized_archive_directory(archive)

    def test_declared_byte_ceiling_is_checked_before_structure(self):
        archive = self.stored()
        with patch.object(packaging, "MAX_PACKAGE_INPUT_BYTES", len(archive) - 1):
            with self.assertRaises(packaging.PackagingError):
                packaging._admit_finalized_archive_directory(archive)

    def test_finalized_verifier_rejects_before_eager_parser_control_flow_only(self):
        self.assert_finalized_refusal_before_parser(self.stored(3), file_count=3)

    def assert_finalized_refusal_before_parser(self, archive, *, file_count, message=None):
        # Stub only earlier I/O to reach actual parser admission. This is not
        # a real registry/ledger/custody or successful release integration.
        envelope = b"{}"
        digest = hashlib.sha256(envelope).hexdigest()
        manifest = dict.fromkeys(packaging.RUN_MANIFEST_KEYS)
        manifest["package"] = {
            "run_id": "unit-run", "status": "PASS", "package_kind": "DEMO_RESEARCH_PACKAGE",
            "review_state": "READY_FOR_HUMAN_REVIEW", "e4_required": True,
            "archive_path": "artifacts/release_candidates/unit.zip",
            "archive_sha256": hashlib.sha256(archive).hexdigest(), "file_count": file_count,
            "envelope_path": f"artifacts/release_candidates/unit-run-{digest[:20]}.final-envelope.json",
            "envelope_sha256": digest,
        }
        with (patch.object(packaging, "ArtifactRegistry"),
              patch.object(packaging, "_resource_authority_bytes", return_value={}),
              patch.object(packaging, "_confined_bytes", side_effect=[archive, envelope]),
              patch.object(packaging, "MAX_PACKAGE_FILES", 2),
              patch.object(packaging.zipfile, "ZipFile", side_effect=AssertionError("parser reached")) as parser):
            expectation = (
                self.assertRaises(packaging.PackagingError)
                if message is None
                else self.assertRaisesRegex(packaging.PackagingError, message)
            )
            with expectation:
                packaging._verify_finalized_package(None, "unit-run", manifest)
            parser.assert_not_called()

    def test_alternate_directory_layout_has_ordinary_classic_counts(self):
        archive = self.alternate_zip64_directory()
        self.assertEqual(len(archive), 444)
        footer_offset = len(archive) - 22
        footer = struct.unpack_from("<4s4H2LH", archive, footer_offset)
        self.assertEqual(footer, (b"PK\x05\x06", 0, 0, 1, 1, 122, 300, 0))
        self.assertEqual(footer[5] + footer[6], footer_offset)
        locator = struct.unpack_from("<4sLQL", archive, footer_offset - 20)
        self.assertEqual(locator, (b"PK\x06\x07", 0, 346, 1))
        zip64 = struct.unpack_from("<4sQ2H2L4Q", archive, locator[2])
        self.assertEqual(zip64, (b"PK\x06\x06", 44, 45, 45, 0, 0, 3, 3, 197, 149))
        self.assertEqual(zip64[8] + zip64[9], locator[2])
        self.assertEqual(locator[2] + 56 + 20, footer_offset)
        classic = struct.unpack_from("<4s6H3L5H2L", archive, footer[6])
        self.assertEqual(classic[0], b"PK\x01\x02")
        self.assertEqual(classic[10], 76)
        self.assertEqual(footer[6] + 46 + classic[10], footer_offset)
        # Disabling only the exact dispatch marker leaves the classic record's
        # opaque filename and every framing/count field intact. This exercises
        # the original classic-admission predicates without copying V1 code or
        # executing a V1 helper. It does not make the original archive safe.
        classic_only = self.changed(archive, footer_offset - 20, "<4s", b"NO64")
        with patch.object(packaging, "MAX_PACKAGE_FILES", 2):
            packaging._admit_finalized_archive_directory(classic_only)

    def test_dependency_selects_alternate_directory_without_classic_sentinels(self):
        # Intentionally use the actual runtime dependency, not a stub/sentinel.
        # When separately run, three small ZipInfo objects prove which directory
        # the dependency selected. This is not an allocation stress test.
        archive = self.alternate_zip64_directory()
        with zipfile.ZipFile(io.BytesIO(archive)) as packet:
            self.assertEqual(packet.start_dir, 149)
            self.assertEqual(len(packet.infolist()), 3)
            self.assertEqual(packet.namelist()[:2], ["a", "b"])
            self.assertEqual([info.header_offset for info in packet.infolist()], [0, 31, 62])
        classic_only = self.changed(archive, len(archive) - 42, "<4s", b"NO64")
        with zipfile.ZipFile(io.BytesIO(classic_only)) as packet:
            self.assertEqual(packet.start_dir, 300)
            self.assertEqual(len(packet.infolist()), 1)

    def test_finalized_verifier_refuses_alternate_dispatch_before_parser_control_flow_only(self):
        self.assert_finalized_refusal_before_parser(
            self.alternate_zip64_directory(), file_count=1,
            message="final archive ZIP64 dispatch is unsupported",
        )

    def test_locator_with_malformed_metadata_is_refused_before_parser_control_flow_only(self):
        archive = self.alternate_zip64_directory()
        locator_offset = len(archive) - 42
        zip64_offset = locator_offset - 56
        cases = (
            ("locator disk", locator_offset + 4, "<L", 1),
            ("locator offset", locator_offset + 8, "<Q", locator_offset),
            ("record signature", zip64_offset, "<4s", b"BAD!"),
            ("record size", zip64_offset + 4, "<Q", 43),
            ("directory offset", zip64_offset + 48, "<Q", 150),
        )
        for label, offset, fmt, value in cases:
            with self.subTest(metadata=label):
                self.assert_finalized_refusal_before_parser(
                    self.changed(archive, offset, fmt, value), file_count=1,
                    message="final archive ZIP64 dispatch is unsupported",
                )

    def test_locator_magic_in_non_dispatch_filename_position_is_allowed(self):
        name = "prefix-PK\x06\x07-" + "tail" * 8 + ".txt"
        archive = packaging._zip_bytes({name: b"small"})
        self.assertIn(b"PK\x06\x07", archive[self.directory(archive):])
        self.assertNotEqual(archive[-42:-38], b"PK\x06\x07")
        packaging._admit_finalized_archive_directory(archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as packet:
            self.assertEqual(packet.namelist(), [name])
            self.assertEqual(packet.read(name), b"small")
