"""Narrow AUDIT-001 dispositions, not exemptions for arbitrary fixtures.

P's typed-parser tests use a synthetic pinned payload explicitly patched only
within the test. They do not authenticate the private historical manifest.
S tests read the unchanged, public rejection-test source itself.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import scientist_one.audit as audit
from scientist_one.errors import PathSecurityError, UnsafeSerializationError
from scientist_one.security import canonical_json_bytes
import tests.test_git_audit as fixtures
import tests.test_external_providers as provider_fixtures


def fixture_bytes():
    payload = Path(__file__).with_name("test_external_providers.py").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == "d0e59a5f285498633b98c7c152e62b0ae1e0ed856b9d3f910af997e6ffdfceab"
    return payload


def provenance_fixture():
    return {
        "schema_version": "scientist-one-functional-source-inventory/v1",
        "generated_at": "2026-09-24T00:00:00Z",
        "interpreter_path": "/synthetic-unavailable/interpreter",
        "interpreter_version": "3.14.0", "selection_rule": "Synthetic parser test only",
        "file_count": 1, "total_bytes": 2, "aggregate_sha256": "a" * 64,
        "entries": [{"path": "source.py", "size": 2, "sha256": "b" * 64}],
    }


class DispositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GitAuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root.resolve()
        self.git = self.fixture.git

    def install_fixture(self, relative="tests/test_external_providers.py", payload=None):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_bytes() if payload is None else payload)
        return path

    def test_unchanged_provider_rejection_case_still_refuses_before_transport(self):
        case = provider_fixtures.ExternalPolicyTests(
            "test_idempotency_keys_cannot_expose_credentials_or_secret_patterns"
        )
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertTrue(result.wasSuccessful(), "unchanged provider rejection case failed")
        self.assertFalse(result.skipped)

    def test_exact_raw_and_decoded_fixture_keep_raw_findings_and_sealed_classification(self):
        self.install_fixture()
        self.git("add", "--", "tests/test_external_providers.py")
        self.git("commit", "-m", "Public synthetic rejection fixture")
        result = audit.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.unresolved_finding_count, 0)
        self.assertEqual(len(result.git.reviewed_findings), 1)
        self.assertEqual(len(result.reviewed_dispositions), 2)
        self.assertTrue(all(item["nonblocking"] for item in json.loads(result.as_json())["reviewed_dispositions"]))
        audit.require_current_audit(result, self.root)

    def test_same_bytes_elsewhere_are_blocking(self):
        self.install_fixture("copied.py")
        result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertEqual(result.unresolved_finding_count, 1)
        self.assertFalse(result.reviewed_dispositions)

    def test_changed_or_additional_match_cannot_inherit_review(self):
        payload = fixture_bytes()
        for changed in (payload + b"\n", payload + b"\napi" + b"_key = " + b"x" * 24):
            with self.subTest(additional=len(changed) != len(payload) + 1):
                self.install_fixture(payload=changed)
                result = audit.audit_project(self.root)
                self.assertFalse(result.passed)
                self.assertFalse(result.reviewed_dispositions)

    def test_exact_fixture_does_not_excuse_new_unreachable_secret(self):
        self.install_fixture()
        self.git("hash-object", "-w", "--stdin", payload=b"api" + b"_key = " + b"z" * 24)
        result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertFalse(result.git.passed)
        self.assertEqual(result.git.binary_waiver_paths, ())
        self.assertEqual(result.unresolved_finding_count, len(result.findings))

    def test_no_git_keeps_fixture_strict_and_original_wire_format(self):
        root = self.root.parent / "no-git"
        path = root / "tests" / "test_external_providers.py"
        path.parent.mkdir(parents=True)
        path.write_bytes(fixture_bytes())
        result = audit.audit_project(root)
        self.assertFalse(result.passed)
        self.assertEqual(result.unresolved_finding_count, 1)
        self.assertNotIn("reviewed_dispositions", json.loads(result.as_json()))
        self.assertNotIn("disposition_policy", json.loads(result.as_json()))

    def test_mutation_or_absent_seal_cannot_authorize_dispositions(self):
        self.install_fixture()
        result = audit.audit_project(self.root)
        self.assertTrue(result.passed)
        disposition = result.reviewed_dispositions[0]
        for changed in (
            replace(result, _binding=None),
            replace(result, reviewed_dispositions=(replace(disposition, content_sha256="0" * 64),)),
            replace(result, reviewed_dispositions=()),
            replace(result, findings=()),
            replace(result, total_bytes=result.total_bytes + 1),
        ):
            with self.subTest(binding=changed._binding is not None):
                with self.assertRaises(PathSecurityError):
                    audit.require_current_audit(changed, self.root)
        self.assertFalse(replace(result, _binding=None).passed)

    def test_classified_report_still_requires_publication_freshness(self):
        self.install_fixture()
        result = audit.audit_project(self.root)
        self.assertTrue(result.passed)
        (self.root / "README.md").write_text("Changed after audit\n")
        with self.assertRaises(PathSecurityError):
            audit.require_current_audit(result, self.root)

    def test_typed_provenance_is_lexical_only_and_nonblocking_only_with_git_seal(self):
        data = provenance_fixture()
        payload = canonical_json_bytes(data)
        relative = audit._REVIEWED_MANIFEST_PATH
        path = self.root / relative
        path.parent.mkdir()
        path.write_bytes(payload)
        original_resolve = Path.resolve

        def guarded_resolve(value, *args, **kwargs):
            self.assertNotEqual(str(value), data["interpreter_path"], "provenance target was resolved")
            return original_resolve(value, *args, **kwargs)

        with mock.patch.object(audit, "_REVIEWED_MANIFEST_SHA256", hashlib.sha256(payload).hexdigest()), mock.patch.object(Path, "resolve", new=guarded_resolve):
            result = audit.audit_project(self.root)
        self.assertTrue(result.passed, result.findings)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.reviewed_dispositions[0].field_pointer, "/interpreter_path")
        self.assertEqual(result.reviewed_dispositions[0].target_access, "NOT_PERMITTED")
        audit.require_current_audit(result, self.root)

    def test_unpinned_provenance_and_operational_fields_remain_blocking(self):
        data = provenance_fixture()
        path = self.root / audit._REVIEWED_MANIFEST_PATH
        path.parent.mkdir()
        path.write_bytes(canonical_json_bytes(data))
        result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertFalse(result.reviewed_dispositions)
        data["output_path"] = "/synthetic-unavailable/output"
        payload = canonical_json_bytes(data)
        path.write_bytes(payload)
        with mock.patch.object(audit, "_REVIEWED_MANIFEST_SHA256", hashlib.sha256(payload).hexdigest()):
            result = audit.audit_project(self.root)
        self.assertFalse(result.passed)
        self.assertFalse(result.reviewed_dispositions)

    def test_closed_typed_manifest_rejects_malformed_or_lookalike_records(self):
        good = provenance_fixture()
        bad = [
            {**good, "schema_version": "other/v1"}, {**good, "file_count": True},
            {**good, "total_bytes": 3}, {**good, "extra": "field"},
            {**good, "entries": [*good["entries"], *good["entries"]], "file_count": 2, "total_bytes": 4},
            {**good, "entries": [{"path": "../outside", "size": 2, "sha256": "b" * 64}]},
            {**good, "entries": [{"path": "source.py", "size": True, "sha256": "b" * 64}]},
            {**good, "interpreter_path": "relative/path"},
            {**good, "interpreter_path": "/synthetic\x00/path"},
            {"nested": good},
        ]
        for data in bad:
            payload = canonical_json_bytes(data)
            with self.subTest(keys=sorted(data)), mock.patch.object(audit, "_REVIEWED_MANIFEST_SHA256", hashlib.sha256(payload).hexdigest()):
                self.assertIsNone(audit._reviewed_interpreter_provenance(audit._REVIEWED_MANIFEST_PATH, payload, data))
        payload = canonical_json_bytes(good)
        with mock.patch.object(audit, "_REVIEWED_MANIFEST_SHA256", hashlib.sha256(payload).hexdigest()):
            self.assertIsNone(audit._reviewed_interpreter_provenance("reports/other.json", payload, good))
        with self.assertRaises(UnsafeSerializationError):
            audit._outside_root_paths_in_payload(b'{"interpreter_path":"a","interpreter_path":"b"}', self.root)
