"""Owner-reviewed decoded fixture only; never read the developer's Git objects.

Reconstruct the approved bytes from pinned public source by one exact deletion.
The result is inert parser input, never imported or executed. Internal match
tests isolate location/context checks without mocking hashes or granting a seal.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import scientist_one.audit as audit
import scientist_one.git_audit as git_audit
from scientist_one.errors import PathSecurityError
import tests.test_git_audit as fixtures


OID = "eed1d57e7b1645f7498dbab679859d95e37a54e9"
CONTENT_SHA256 = "de1d966155aec9441bf3c0c4bd3a0227ff433c927aaa333571932ff5350f0b7e"
DECODED_PATH = ".git/decoded-objects/" + OID
RULE = "secret_pattern_secret_assignment"


def approved_payload():
    current = Path(__file__).with_name("test_external_providers.py").read_bytes()
    assert len(current) == 139137
    assert hashlib.sha256(current).hexdigest() == "d0e59a5f285498633b98c7c152e62b0ae1e0ed856b9d3f910af997e6ffdfceab"
    payload = current[:133905] + current[137943:]
    assert len(payload) == 135099
    assert hashlib.sha256(payload).hexdigest() == CONTENT_SHA256
    assert hashlib.sha1(b"blob 135099\0" + payload).hexdigest() == OID
    return payload


class ExactBlobIdentityTests(unittest.TestCase):
    def setUp(self):
        self.payload = approved_payload()

    def classified(self, payload):
        return git_audit.is_reviewed_synthetic_fixture(DECODED_PATH, payload, blob_oid=OID)

    def test_exact_approved_bytes_and_context(self):
        self.assertTrue(self.classified(self.payload))
        self.assertEqual(git_audit.reviewed_synthetic_fixture_sha256(OID), CONTENT_SHA256)
        context = self.payload[20808:22229]
        self.assertEqual(len(context), 1421)
        self.assertEqual(hashlib.sha256(context).hexdigest(), "cc3084799e4e6efbb0589a1f836c70983a387edbed187aa3ac62454914227967")
        self.assertEqual(hashlib.sha256(self.payload[21865:21889]).hexdigest(), "2c66730fbffaa076361f7c3d291251c8243143bbd4c2e462e0386a026cc295df")
        self.assertEqual(self.payload[:21865].count(b"\n") + 1, 584)

    def test_wrong_oid_or_path_or_raw_source_cannot_inherit(self):
        for path, oid in (
            (DECODED_PATH, "0" * 40), (DECODED_PATH, None),
            (DECODED_PATH, 1), (".git/decoded-objects/" + "0" * 40, OID),
            ("tests/test_external_providers.py", OID),
            ("tests/test_external_providers.py", None), ("copy.py", None),
        ):
            with self.subTest(path=path, oid=oid):
                self.assertFalse(git_audit.is_reviewed_synthetic_fixture(path, self.payload, blob_oid=oid))
        self.assertIsNone(git_audit.reviewed_synthetic_fixture_sha256("0" * 40))

    def test_wrong_size_or_payload_type_is_refused(self):
        for payload in (self.payload + b"\n", self.payload[:-1], bytearray(self.payload)):
            with self.subTest(size=len(payload), kind=type(payload).__name__):
                self.assertFalse(self.classified(payload))

    def test_same_size_changed_full_content_hash_is_refused(self):
        changed = self.payload[:-1] + b"!"
        self.assertEqual(len(changed), len(self.payload))
        self.assertNotEqual(hashlib.sha256(changed).hexdigest(), CONTENT_SHA256)
        # Match/context alone are not whole-object authority.
        self.assertTrue(git_audit._has_reviewed_rejection_match(changed))
        self.assertFalse(self.classified(changed))

    def test_changed_matched_bytes_are_refused_by_match_guard(self):
        replacement = b"Z" if self.payload[21888:21889] != b"Z" else b"Y"
        changed = self.payload[:21888] + replacement + self.payload[21889:]
        self.assertFalse(git_audit._has_reviewed_rejection_match(changed))
        self.assertFalse(self.classified(changed))

    def test_changed_byte_location_is_refused_by_match_guard(self):
        changed = b" " + self.payload
        self.assertFalse(git_audit._has_reviewed_rejection_match(changed))
        self.assertFalse(self.classified(changed))

    def test_changed_line_without_byte_shift_is_refused_by_match_guard(self):
        first_newline = self.payload.index(b"\n")
        changed = self.payload[:first_newline] + b" " + self.payload[first_newline + 1:]
        self.assertEqual(changed[21865:21889], self.payload[21865:21889])
        self.assertFalse(git_audit._has_reviewed_rejection_match(changed))
        self.assertFalse(self.classified(changed))

    def test_changed_context_outside_match_is_refused_by_context_guard(self):
        changed = self.payload[:20812] + b"X" + self.payload[20813:]
        self.assertEqual(changed[21865:21889], self.payload[21865:21889])
        self.assertEqual(changed[:21865].count(b"\n"), self.payload[:21865].count(b"\n"))
        self.assertFalse(git_audit._has_reviewed_rejection_match(changed))
        self.assertFalse(self.classified(changed))

    def test_additional_match_or_other_rule_cannot_inherit(self):
        for addition in (
            b"\npassword = " + b"z" * 24,
            b"\nghp_" + b"x" * 30,
        ):
            changed = self.payload + addition
            self.assertFalse(git_audit._has_reviewed_rejection_match(changed))
            self.assertFalse(self.classified(changed))
        with mock.patch.object(git_audit, "detect_secret_patterns_in_bytes", return_value=("github_token",)):
            self.assertFalse(self.classified(self.payload))

    def test_wrong_object_type_never_reaches_fixture_classifier(self):
        for oid in (OID, git_audit._object_hash("tag", self.payload)):
            stream = git_audit._ObjectStream({oid: ("tag", len(self.payload))})
            frame = f"{oid} tag {len(self.payload)}\n".encode() + self.payload + b"\n"
            with mock.patch.object(git_audit, "is_reviewed_synthetic_fixture", side_effect=AssertionError("non-blob classified")):
                with self.assertRaises(git_audit._Refusal) as raised:
                    stream.feed(frame)
            expected = "decoded_object_identity_mismatch" if oid == OID else RULE
            self.assertEqual(raised.exception.code, expected)
            self.assertEqual(stream.reviewed_findings, [])

    def test_wrong_size_or_hash_frame_is_refused_before_classification(self):
        cases = (
            (f"{OID} blob {len(self.payload) + 1}\n".encode() + self.payload + b"\n", "object_header_content_mismatch"),
            (f"{OID} blob {len(self.payload)}\n".encode() + self.payload[:-1] + b"!\n", "decoded_object_identity_mismatch"),
        )
        for frame, expected in cases:
            stream = git_audit._ObjectStream({OID: ("blob", len(self.payload))})
            with mock.patch.object(git_audit, "is_reviewed_synthetic_fixture", side_effect=AssertionError("unverified object classified")):
                with self.assertRaises(git_audit._Refusal) as raised:
                    stream.feed(frame)
            self.assertEqual(raised.exception.code, expected)
            self.assertEqual(stream.reviewed_findings, [])


class ExactBlobDispositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GitAuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root.resolve()
        self.git = self.fixture.git
        self.payload = approved_payload()
        # Only this disposable test repository is mutated; never the real .git.
        oid = self.git("hash-object", "-w", "--stdin", payload=self.payload).decode().strip()
        self.assertEqual(oid, OID)

    def test_real_decoded_blob_keeps_raw_finding_and_exact_sealed_rationale(self):
        result = audit.audit_project(self.root)
        self.assertTrue(result.git.passed, result.git.findings)
        self.assertTrue(result.passed, result.findings)
        raw = audit.AuditFinding("git_validation", DECODED_PATH, RULE)
        self.assertEqual(result.findings, (raw,))
        self.assertEqual(result.unresolved_finding_count, 0)
        self.assertEqual(result.git.reviewed_findings, (git_audit.GitAuditFinding(RULE, DECODED_PATH),))
        disposition, = result.reviewed_dispositions
        self.assertEqual(disposition.finding, raw)
        self.assertEqual(disposition.classification, "REVIEWED_SYNTHETIC_REJECTION_FIXTURE")
        self.assertEqual(disposition.content_sha256, CONTENT_SHA256)
        self.assertEqual(disposition.blob_oid, OID)
        wire = json.loads(result.as_json())
        self.assertEqual(wire["disposition_policy"], "AUDIT001_REVIEWED_DISPOSITIONS_V1")
        self.assertEqual(wire["findings"], [wire["reviewed_dispositions"][0]["finding"]])
        self.assertTrue(wire["reviewed_dispositions"][0]["nonblocking"])
        audit.require_current_audit(result, self.root)

    def test_later_git_failure_retains_observation_without_waivers(self):
        original = git_audit.GitAuditSession._run

        def wrong_projection(session, arguments, **kwargs):
            result = original(session, arguments, **kwargs)
            return b"invalid projection" if arguments[0] == "ls-files" else result

        with mock.patch.object(git_audit.GitAuditSession, "_run", new=wrong_projection):
            result = audit.audit_project(self.root)
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertFalse(result.passed)
        self.assertEqual(result.unresolved_finding_count, len(result.findings))
        self.assertIn(audit.AuditFinding("git_validation", DECODED_PATH, RULE), result.findings)
        self.assertEqual(result.reviewed_dispositions[0].content_sha256, CONTENT_SHA256)
        self.assertFalse(json.loads(result.as_json())["reviewed_dispositions"][0]["nonblocking"])

    def test_missing_or_stale_seal_cannot_apply_classification(self):
        result = audit.audit_project(self.root)
        self.assertTrue(result.passed)
        disposition, = result.reviewed_dispositions
        for changed in (
            replace(result, _binding=None),
            replace(result, total_bytes=result.total_bytes + 1),
            replace(result, reviewed_dispositions=(replace(disposition, content_sha256="0" * 64),)),
            replace(result, reviewed_dispositions=(replace(disposition, classification="UNREVIEWED"),)),
        ):
            self.assertFalse(changed.passed)
            self.assertFalse(json.loads(changed.as_json())["reviewed_dispositions"][0]["nonblocking"])
            with self.assertRaises(PathSecurityError):
                audit.require_current_audit(changed, self.root)

    def test_filesystem_drift_blocks_publication(self):
        result = audit.audit_project(self.root)
        self.assertTrue(result.passed)
        (self.root / "README.md").write_text("Changed after captured audit\n")
        with self.assertRaises(PathSecurityError):
            audit.require_current_audit(result, self.root)

    def test_approved_decoded_blob_does_not_exempt_raw_copy(self):
        path = self.root / "tests" / "test_external_providers.py"
        path.parent.mkdir()
        path.write_bytes(self.payload)
        result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertEqual(result.unresolved_finding_count, 1)
        self.assertIn(audit.AuditFinding("secret_pattern", "tests/test_external_providers.py", "secret_assignment"), result.findings)
        self.assertEqual(len(result.reviewed_dispositions), 1)  # Decoded only.

    def test_no_git_remains_strict(self):
        root = self.root.parent / "without-git"
        path = root / "tests" / "test_external_providers.py"
        path.parent.mkdir(parents=True)
        path.write_bytes(self.payload)
        result = audit.audit_project(root)
        self.assertFalse(result.passed)
        self.assertEqual(result.unresolved_finding_count, 1)
        self.assertFalse(result.reviewed_dispositions)
        self.assertNotIn("reviewed_dispositions", json.loads(result.as_json()))

    def test_similar_modified_blob_is_not_classified(self):
        changed = self.payload + b"\npassword = " + b"z" * 24
        oid = self.git("hash-object", "-w", "--stdin", payload=changed).decode().strip()
        result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertIn(git_audit.GitAuditFinding(RULE, ".git/decoded-objects/" + oid), result.git.findings)


if __name__ == "__main__":
    unittest.main()
