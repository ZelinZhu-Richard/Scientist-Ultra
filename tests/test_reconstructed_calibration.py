"""SEMANTIC_RECONSTRUCTION of B-08/B-14 using hash-recovered inert fixtures.

New 2026-09-19 test bytes; not the missing historical 364-test source.
Fixtures match the SHA-256 constants in the unchanged frozen calibration owner.
Known answers are synthetic diagnostics, never external scientific evidence.
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest

from scientist_one.calibration import (
    CalibrationError, CalibrationGateError, CalibrationReport,
    FROZEN_CALIBRATION_REPORT_SHA256, FROZEN_WORKFLOW_REPORT_SHA256,
    MANDATORY_CASE_KINDS, assert_calibrated, evaluate_case,
    load_calibration_cases, run_calibration, run_synthetic_workflow_benchmark,
)


class ReconstructedCalibrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_calibration_cases()
        cls.report = run_calibration()

    def test_exact_recovered_fixture_identity_and_twelve_kinds(self):
        root = Path(__file__).resolve().parents[1] / "fixtures/calibration"
        expected = {
            "calibration_cases.json": "c5697cc4207bfc3c2c93287274fe0c87cfed43f74ed5f4dffe60d8c7730ef543",
            "synthetic_workflow_tasks.json": "3bef85d9e02ca5a532ecedb0bbabd7b537aeb60509f318d485d170e4e927153d",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(len(self.cases), 12)
        self.assertEqual({case.kind for case in self.cases}, set(MANDATORY_CASE_KINDS))
        self.assertTrue(all(case.mandatory for case in self.cases))

    def test_all_known_answers_and_finding_codes_are_reproduced(self):
        self.assertEqual(self.report.report_sha256, FROZEN_CALIBRATION_REPORT_SHA256)
        self.assertTrue(self.report.integrity_valid)
        self.assertTrue(self.report.passed)
        for case, result in zip(self.cases, self.report.results, strict=True):
            with self.subTest(kind=case.kind):
                self.assertEqual(result.case_id, case.case_id)
                self.assertEqual(result.decision, case.expected_decision)
                self.assertTrue(result.passed)
                self.assertTrue(set(case.expected_finding_codes).issubset(
                    {finding.code for finding in result.findings}))

    def test_canonical_gate_reexecutes_same_known_answers(self):
        self.assertIs(assert_calibrated(self.report), self.report)
        self.assertEqual(run_calibration().to_dict(), self.report.to_dict())

    def test_gate_rejects_omitted_case_and_changed_result(self):
        omitted = CalibrationReport(self.report.results[1:], self.report.report_sha256)
        changed = replace(self.report.results[0], decision="UNSUPPORTED_POSITIVE")
        altered = CalibrationReport((changed, *self.report.results[1:]), self.report.report_sha256)
        for candidate in (omitted, altered, replace(self.report, report_sha256="0" * 64)):
            with self.subTest(candidate=candidate.report_sha256):
                self.assertFalse(candidate.integrity_valid)
                with self.assertRaises(CalibrationGateError):
                    assert_calibrated(candidate)

    def test_known_signal_and_null_are_not_collapsed(self):
        values = {result.kind: result for result in self.report.results}
        self.assertEqual(values["planted_positive"].statistics["observed_difference"], 1.0)
        self.assertEqual(values["planted_positive"].statistics["two_sided_p_value"], 1 / 4097)
        self.assertEqual(values["true_null"].statistics["observed_difference"], 0.0)
        self.assertEqual(values["true_null"].statistics["two_sided_p_value"], 1.0)
        self.assertNotEqual(values["planted_positive"].decision, values["true_null"].decision)

    def test_signal_detector_rejects_unmet_effect_threshold(self):
        case = next(case for case in self.cases if case.kind == "planted_positive")
        changed = case.to_dict()
        changed["payload"]["minimum_effect"] = 2.0
        result = evaluate_case(changed)
        self.assertFalse(result.passed)
        self.assertEqual(result.decision, "SIGNAL_NOT_RECOVERED")

    def test_fixture_byte_drift_is_rejected(self):
        source = Path(__file__).resolve().parents[1] / "fixtures/calibration/calibration_cases.json"
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "calibration_cases.json"
            changed.write_bytes(source.read_bytes() + b"\n")
            with self.assertRaises(CalibrationError):
                load_calibration_cases(directory)

    def test_workflow_known_answers_keep_negative_and_invalid_outcomes(self):
        report = run_synthetic_workflow_benchmark()
        self.assertTrue(report.passed)
        self.assertEqual(report.report_sha256, FROZEN_WORKFLOW_REPORT_SHA256)
        self.assertEqual({row.scenario: row.terminal_state for row in report.results}, {
            "signal": "DEMO_RESEARCH_PACKAGE", "null": "NEGATIVE_RESULT",
            "reversal": "INCONCLUSIVE", "leakage": "STOP_SCIENTIFIC_INVALIDITY",
            "invalid-analysis": "STOP_SCIENTIFIC_INVALIDITY",
            "corrupted-evidence": "STOP_SCIENTIFIC_INVALIDITY",
        })
        self.assertTrue(all(row.passed for row in report.results))
        with self.assertRaises(CalibrationError):
            run_synthetic_workflow_benchmark(seed=1)


if __name__ == "__main__":
    unittest.main()
