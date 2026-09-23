"""Deterministic validation for the frozen architecture evaluation.

This test intentionally does not import Scientist-One implementation code.  It
checks that the evaluation packet is complete, remains bound to the frozen
suite, and points only at hash-verified project-local evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "configs" / "architecture_evaluation.json"
REPORT_PATH = ROOT / "reports" / "architecture_evaluation.json"
HEX = frozenset("0123456789abcdef")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _load_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"unsafe JSON evidence path: {path.name}")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path.name}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX for character in value)
    )


def _confined_regular_file(relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AssertionError("evidence path must be a non-empty string")
    raw = Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise AssertionError(f"evidence path is not project-relative: {relative!r}")
    candidate = ROOT
    for index, component in enumerate(raw.parts):
        candidate = candidate / component
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise AssertionError(f"evidence path contains a link: {relative!r}")
        if index < len(raw.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError(f"evidence parent is not a directory: {relative!r}")
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AssertionError(
            f"evidence path is not a unique regular non-link file: {relative!r}"
        )
    resolved = candidate.resolve(strict=True)
    if ROOT != resolved and ROOT not in resolved.parents:
        raise AssertionError(f"evidence path escapes the project: {relative!r}")
    return resolved


class ArchitectureEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = _load_json(SUITE_PATH)
        cls.report = _load_json(REPORT_PATH)

    def test_report_schema_and_frozen_suite_binding(self) -> None:
        self.assertEqual(self.report.get("schema_version"), "1.0")
        self.assertEqual(
            self.report.get("kind"),
            "SCIENTIST_ONE_ARCHITECTURE_EVALUATION",
        )
        suite_binding = self.report.get("suite")
        self.assertIsInstance(suite_binding, dict)
        assert isinstance(suite_binding, dict)
        self.assertEqual(suite_binding.get("path"), "configs/architecture_evaluation.json")
        self.assertEqual(suite_binding.get("sha256"), _sha256(SUITE_PATH))
        self.assertEqual(
            suite_binding.get("frozen_at_utc"), self.suite.get("frozen_at_utc")
        )
        self.assertFalse(suite_binding.get("changed_after_freeze"))

        baseline = self.report.get("baseline")
        configured_baseline = self.suite.get("baseline")
        self.assertIsInstance(baseline, dict)
        self.assertIsInstance(configured_baseline, dict)
        assert isinstance(baseline, dict) and isinstance(configured_baseline, dict)
        self.assertEqual(baseline.get("kind"), configured_baseline.get("kind"))
        self.assertEqual(baseline.get("status"), "ABSENT")
        self.assertEqual(
            baseline.get("scoring_policy"), configured_baseline.get("scoring_policy")
        )
        source = _confined_regular_file(baseline.get("source"))
        self.assertEqual(baseline.get("source_sha256"), _sha256(source))

        method = self.report.get("method")
        self.assertIsInstance(method, dict)
        assert isinstance(method, dict)
        self.assertFalse(method.get("numeric_scoring_used"))
        self.assertEqual(method.get("retention_rule"), self.suite.get("retention_rule"))
        self.assertEqual(method.get("stop_rules"), self.suite.get("stop_rules"))

    def test_every_frozen_check_has_a_complete_honest_comparison(self) -> None:
        configured = self.suite.get("checks")
        evaluated = self.report.get("checks")
        self.assertIsInstance(configured, list)
        self.assertIsInstance(evaluated, list)
        assert isinstance(configured, list) and isinstance(evaluated, list)
        self.assertEqual(
            [item["id"] for item in evaluated],
            [item["id"] for item in configured],
        )

        for expected, observed in zip(configured, evaluated, strict=True):
            with self.subTest(check=expected["id"]):
                self.assertEqual(observed.get("mandatory"), expected.get("mandatory"))
                self.assertEqual(observed.get("criterion"), expected.get("criterion"))
                self.assertEqual(observed.get("baseline_status"), "ABSENT")
                self.assertIsInstance(observed.get("defect_or_hypothesis"), str)
                self.assertGreaterEqual(len(observed["defect_or_hypothesis"].strip()), 24)
                self.assertIn(
                    observed.get("final_status"),
                    {"PASS", "FAIL", "PARTIAL", "BLOCKED", "PENDING"},
                )
                self.assertIsInstance(observed.get("after"), str)
                self.assertGreaterEqual(len(observed["after"].strip()), 24)
                self.assertIsInstance(observed.get("tradeoffs"), list)
                self.assertTrue(observed["tradeoffs"])
                self.assertTrue(all(isinstance(item, str) and item.strip() for item in observed["tradeoffs"]))
                self.assertIsInstance(observed.get("residual_limitations"), list)
                self.assertIn(
                    observed.get("retention_decision"),
                    {"RETAIN", "REJECT", "PENDING"},
                )
                if observed.get("final_status") == "PASS":
                    self.assertEqual(observed.get("retention_decision"), "RETAIN")
                    self.assertTrue(observed.get("evidence"))
                if observed.get("final_status") == "PENDING":
                    self.assertEqual(observed.get("retention_decision"), "PENDING")
                if observed.get("retention_decision") == "REJECT":
                    self.assertNotEqual(observed.get("final_status"), "PASS")

                adr = observed.get("adr")
                self.assertIsInstance(adr, dict)
                assert isinstance(adr, dict)
                self._assert_evidence_record(
                    adr,
                    allow_pending_hash=(
                        self.report.get("evaluation_state")
                        == "PROVISIONAL_AWAITING_FRESH_DEMO_AND_FINAL_PACKET"
                    ),
                )
                self.assertIn(
                    expected["id"],
                    adr.get("locators", []),
                    f"ADR locator does not address check: {expected['id']}",
                )

    def _assert_evidence_record(
        self, record: object, *, allow_pending_hash: bool = False
    ) -> None:
        self.assertIsInstance(record, dict)
        assert isinstance(record, dict)
        path = _confined_regular_file(record.get("path"))
        self.assertNotEqual(path, REPORT_PATH.resolve())
        digest = record.get("sha256")
        if allow_pending_hash and digest == "PENDING_FINAL_HASH":
            pass
        elif digest == "PENDING_FINAL_HASH":
            self.fail("a final report cannot contain a pending evidence hash")
        else:
            self.assertTrue(_is_sha256(digest))
            self.assertEqual(digest, _sha256(path))
        support = record.get("supports")
        self.assertIsInstance(support, str)
        self.assertTrue(support.strip())
        locators = record.get("locators")
        self.assertIsInstance(locators, list)
        self.assertTrue(locators)
        text = path.read_text(encoding="utf-8")
        for locator in locators:
            self.assertIsInstance(locator, str)
            self.assertTrue(locator)
            self.assertIn(locator, text)

    def test_evidence_is_confined_hash_bound_and_locator_addressable(self) -> None:
        evaluated = self.report["checks"]
        assert isinstance(evaluated, list)
        for check in evaluated:
            with self.subTest(check=check["id"]):
                evidence = check.get("evidence")
                self.assertIsInstance(evidence, list)
                self.assertTrue(evidence)
                for record in evidence:
                    self._assert_evidence_record(record)

    def test_summary_is_derived_from_check_records_without_a_score(self) -> None:
        checks = self.report["checks"]
        summary = self.report.get("summary")
        self.assertIsInstance(checks, list)
        self.assertIsInstance(summary, dict)
        assert isinstance(checks, list) and isinstance(summary, dict)
        mandatory = [item for item in checks if item["mandatory"]]
        passed = [item for item in mandatory if item["final_status"] == "PASS"]
        failed = [item for item in mandatory if item["final_status"] != "PASS"]
        retained = [item for item in checks if item["retention_decision"] == "RETAIN"]
        pending = [item for item in checks if item["final_status"] == "PENDING"]
        self.assertEqual(summary.get("configured_checks"), len(self.suite["checks"]))
        self.assertEqual(summary.get("evaluated_checks"), len(checks))
        self.assertEqual(summary.get("mandatory_checks"), len(mandatory))
        self.assertEqual(summary.get("mandatory_passed"), len(passed))
        self.assertEqual(summary.get("mandatory_not_passed"), len(failed))
        self.assertEqual(summary.get("retained_changes"), len(retained))
        self.assertEqual(
            summary.get("pending_check_ids"),
            [item["id"] for item in pending],
        )
        self.assertIsNone(summary.get("numeric_score"))
        self.assertEqual(
            summary.get("final_status"),
            "PASS" if not failed else "NOT_ALL_MANDATORY_CHECKS_PASS",
        )
        if failed:
            self.assertEqual(
                self.report.get("evaluation_state"),
                "PROVISIONAL_AWAITING_FRESH_DEMO_AND_FINAL_PACKET",
            )
        else:
            self.assertEqual(self.report.get("evaluation_state"), "FINAL")
            for check in checks:
                if check.get("final_status") != "PASS":
                    continue
                executable = [
                    record
                    for record in check.get("evidence", [])
                    if isinstance(record, dict)
                    and isinstance(record.get("path"), str)
                    and record["path"].startswith(("tests/", "runs/", "reports/"))
                ]
                self.assertTrue(
                    executable,
                    f"final PASS lacks executable or run evidence: {check.get('id')}",
                )
            reopened = {
                "negative_result_handling",
                "claim_traceability",
                "crash_recovery",
                "deterministic_reproduction",
                "resource_control",
                "review_packet_usability",
                "drift_and_stall_detection",
            }
            for check in checks:
                if check.get("id") not in reopened:
                    continue
                adversarial = check.get("adversarial_evidence")
                self.assertIsInstance(adversarial, list)
                self.assertTrue(adversarial)
                for record in adversarial:
                    self._assert_evidence_record(record)
                    assert isinstance(record, dict)
                    self.assertTrue(
                        record["path"].startswith(("tests/", "runs/")),
                        f"adversarial evidence is not executable/run evidence: {check.get('id')}",
                    )
            verification_runs = self.report.get("verification_runs")
            self.assertIsInstance(verification_runs, list)
            assert isinstance(verification_runs, list)
            fresh = [
                item
                for item in verification_runs
                if item.get("scope") == "authoritative_fresh_demo_replay_packet"
            ]
            self.assertEqual(len(fresh), 1)
            self.assertEqual(fresh[0].get("status"), "PASS")
            self.assertIsInstance(fresh[0].get("command"), str)
            self.assertTrue(fresh[0]["command"].strip())
            fresh_evidence = fresh[0].get("evidence")
            self.assertIsInstance(fresh_evidence, list)
            self.assertTrue(fresh_evidence)
            for record in fresh_evidence:
                self._assert_evidence_record(record)


if __name__ == "__main__":
    unittest.main()
