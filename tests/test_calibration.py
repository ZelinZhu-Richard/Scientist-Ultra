from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import MappingProxyType
import unittest
from unittest import mock

from scientist_one.calibration import (
    CalibrationGateError,
    CalibrationReport,
    FROZEN_CALIBRATION_REPORT_SHA256,
    FROZEN_WORKFLOW_REPORT_SHA256,
    MANDATORY_CASE_KINDS,
    SYNTHETIC_WORKFLOW_SCENARIOS,
    assert_calibrated,
    canonical_json_sha256,
    evaluate_case,
    generate_synthetic_workflow_tasks,
    holm_adjust,
    load_calibration_cases,
    load_synthetic_workflow_tasks,
    run_calibration,
    run_synthetic_workflow_benchmark,
    scan_untrusted_research_text,
    seeded_permutation_test,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CalibrationFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_calibration_cases()
        cls.by_kind = {case.kind: case for case in cls.cases}

    def test_mandatory_coverage_is_exact(self) -> None:
        self.assertEqual(12, len(self.cases))
        self.assertEqual(set(MANDATORY_CASE_KINDS), set(self.by_kind))
        self.assertTrue(all(case.mandatory for case in self.cases))

    def test_known_answers_pass_with_distinct_decisions(self) -> None:
        expected = {
            "planted_positive": "PLANTED_SIGNAL_RECOVERED",
            "true_null": "TRUE_NULL_RETAINED",
            "leakage_trap": "LEAKAGE_DETECTED",
            "regime_reversal_shift": "REGIME_REVERSAL_DETECTED",
            "invalid_resampling_unit": "INVALID_RESAMPLING_UNIT_DETECTED",
            "multiple_comparisons": "MULTIPLE_COMPARISONS_DETECTED",
            "baseline_implementation_mismatch": "BASELINE_MISMATCH_DETECTED",
            "corrupted_provenance": "CORRUPTED_PROVENANCE_DETECTED",
            "unsupported_claim": "UNSUPPORTED_CLAIM_REJECTED",
            "holdout_access_violation": "HOLDOUT_ACCESS_VIOLATION_DETECTED",
            "prompt_injection_artifact": "PROMPT_INJECTION_QUARANTINED",
            "domain_invalid_permutation": "DOMAIN_INVALID_PERMUTATION_REJECTED",
        }
        report = run_calibration()
        actual = {result.kind: result.decision for result in report.results}
        self.assertEqual(expected, actual)
        self.assertTrue(report.passed)
        self.assertTrue(report.mandatory_passed)
        self.assertIs(report, assert_calibrated(report))

    def test_report_is_deterministic_and_frozen(self) -> None:
        first = run_calibration()
        second = run_calibration()
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.integrity_valid)
        self.assertEqual(
            "34428db4cef7e70c0531ae546f424af7d7bf8ba1f1654632287482bbfed41441",
            FROZEN_CALIBRATION_REPORT_SHA256,
        )
        self.assertEqual(FROZEN_CALIBRATION_REPORT_SHA256, first.report_sha256)

    def test_seeded_signal_and_true_null_statistics(self) -> None:
        signal = evaluate_case(self.by_kind["planted_positive"])
        null = evaluate_case(self.by_kind["true_null"])
        self.assertEqual(1.0, signal.statistics["observed_difference"])
        self.assertEqual(0, signal.statistics["extreme_count"])
        self.assertEqual(1 / 4097, signal.statistics["two_sided_p_value"])
        self.assertEqual(0.0, null.statistics["observed_difference"])
        self.assertEqual(1.0, null.statistics["two_sided_p_value"])

    def test_seeded_permutation_is_order_invariant(self) -> None:
        case = self.by_kind["planted_positive"]
        observations = case.payload["observations"]
        forward = seeded_permutation_test(observations, seed=case.seed, iterations=257)
        backward = seeded_permutation_test(
            list(reversed(observations)), seed=case.seed, iterations=257
        )
        self.assertEqual(forward, backward)
        self.assertEqual("stable_sha256_monte_carlo_permutation_v1", forward["method"])

    def test_each_trap_emits_its_required_machine_code(self) -> None:
        for case in self.cases:
            with self.subTest(kind=case.kind):
                result = evaluate_case(case)
                codes = {finding.code for finding in result.findings}
                self.assertTrue(set(case.expected_finding_codes).issubset(codes))

    def test_each_detector_has_a_clean_specificity_control(self) -> None:
        controls: dict[str, tuple[dict[str, object], str]] = {}

        signal = self.by_kind["planted_positive"].to_dict()
        signal["payload"]["minimum_effect"] = 2.0
        controls["planted_positive"] = (signal, "SIGNAL_NOT_RECOVERED")

        null = self.by_kind["true_null"].to_dict()
        for observation in null["payload"]["observations"]:
            if observation["group"] == "treatment":
                observation["outcome"] += 1.0
        controls["true_null"] = (null, "NULL_MISCLASSIFIED")

        leakage = self.by_kind["leakage_trap"].to_dict()
        leakage["payload"]["splits"] = {
            "training": ["p01"],
            "holdout": ["p02"],
        }
        leakage["payload"]["features"] = [
            {"name": "age", "lineage": ["input"], "timing": "pre_outcome"}
        ]
        controls["leakage_trap"] = (leakage, "NO_LEAKAGE_DETECTED")

        reversal = self.by_kind["regime_reversal_shift"].to_dict()
        confirmatory = reversal["payload"]["regimes"][1]
        for observation in confirmatory["observations"]:
            if observation["group"] == "treatment":
                observation["outcome"] += 2.0
        controls["regime_reversal_shift"] = (
            reversal,
            "NO_REGIME_REVERSAL_DETECTED",
        )

        resampling = self.by_kind["invalid_resampling_unit"].to_dict()
        resampling["payload"]["resampling_unit"] = "subject_id"
        controls["invalid_resampling_unit"] = (resampling, "RESAMPLING_UNIT_VALID")

        multiplicity = self.by_kind["multiple_comparisons"].to_dict()
        multiplicity["payload"]["reported_significant"] = []
        controls["multiple_comparisons"] = (multiplicity, "MULTIPLICITY_HANDLED")

        baseline = self.by_kind["baseline_implementation_mismatch"].to_dict()
        baseline["payload"]["contender"] = dict(baseline["payload"]["baseline"])
        controls["baseline_implementation_mismatch"] = (
            baseline,
            "BASELINE_EQUIVALENT",
        )

        provenance = self.by_kind["corrupted_provenance"].to_dict()
        artifact = provenance["payload"]["artifacts"][0]
        artifact["declared_sha256"] = canonical_json_sha256(artifact["content"])
        artifact["parent_artifact_ids"] = []
        controls["corrupted_provenance"] = (provenance, "PROVENANCE_VALID")

        claim = self.by_kind["unsupported_claim"].to_dict()
        claim["payload"]["evidence"][0]["eligible"] = True
        claim["payload"]["claims"][0]["evidence_ids"] = ["pilot-only"]
        controls["unsupported_claim"] = (claim, "CLAIMS_SUPPORTED")

        holdout = self.by_kind["holdout_access_violation"].to_dict()
        holdout["payload"]["protocol_frozen"] = True
        holdout["payload"]["accesses"] = [
            {
                "requester": "experiment-runner",
                "authorized": True,
                "requires_frozen_protocol": True,
                "purpose": "confirmatory-evaluation",
            }
        ]
        controls["holdout_access_violation"] = (holdout, "HOLDOUT_ACCESS_VALID")

        prompt = self.by_kind["prompt_injection_artifact"].to_dict()
        prompt["payload"]["untrusted_text"] = "Benign research note."
        prompt["payload"]["recorded_actions"] = []
        controls["prompt_injection_artifact"] = (
            prompt,
            "NO_PROMPT_INJECTION_PATTERN",
        )

        domain = self.by_kind["domain_invalid_permutation"].to_dict()
        domain["payload"]["proposed_permutation_scheme"] = domain["payload"][
            "allowed_permutation_schemes"
        ][0]
        controls["domain_invalid_permutation"] = (
            domain,
            "PERMUTATION_SCHEME_DOMAIN_VALID",
        )

        self.assertEqual(set(MANDATORY_CASE_KINDS), set(controls))
        for kind, (control, expected_decision) in controls.items():
            with self.subTest(kind=kind):
                result = evaluate_case(control)
                self.assertEqual(expected_decision, result.decision)
                self.assertNotEqual(self.by_kind[kind].expected_decision, result.decision)

    def test_prompt_injection_artifact_remains_inert_data(self) -> None:
        marker = PROJECT_ROOT / "fixtures" / "calibration" / "SHOULD_NOT_EXIST"
        case = self.by_kind["prompt_injection_artifact"]
        original_text = case.payload["untrusted_text"]
        self.assertFalse(marker.exists())
        result = evaluate_case(case)
        self.assertEqual("PROMPT_INJECTION_QUARANTINED", result.decision)
        self.assertEqual("inert_untrusted_data", result.statistics["handling"])
        self.assertGreaterEqual(len(scan_untrusted_research_text(original_text)), 3)
        self.assertEqual((), case.payload["recorded_actions"])
        self.assertEqual(original_text, case.payload["untrusted_text"])
        self.assertFalse(marker.exists())

    def test_malformed_case_fails_closed(self) -> None:
        malformed = replace(self.by_kind["planted_positive"], payload={})
        result = evaluate_case(malformed)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        self.assertFalse(result.passed)
        self.assertEqual("MALFORMED_CALIBRATION_CASE", result.findings[0].code)

    def test_wrong_known_answer_fails_gate(self) -> None:
        wrong = replace(
            self.by_kind["planted_positive"],
            expected_decision="TRUE_NULL_RETAINED",
        )
        result = evaluate_case(wrong)
        report = CalibrationReport(
            results=(result,),
            report_sha256=canonical_json_sha256([result.to_dict()]),
        )
        self.assertFalse(result.passed)
        self.assertFalse(report.mandatory_passed)
        with self.assertRaises(CalibrationGateError):
            assert_calibrated(report)

    def test_tampered_or_forged_report_hash_fails_gate(self) -> None:
        import scientist_one.calibration as calibration_module

        report = run_calibration()
        forged = CalibrationReport(report.results, "0" * 64)
        self.assertFalse(forged.integrity_valid)
        with self.assertRaises(CalibrationGateError):
            assert_calibrated(forged)
        fabricated_results = tuple(
            replace(
                result,
                expected_decision="FORGED_PASS",
                expected_finding_codes=(),
                decision="FORGED_PASS",
                passed=True,
                findings=(),
                statistics={},
                fixture_sha256="0" * 64,
            )
            for result in report.results
        )
        fabricated = CalibrationReport(
            fabricated_results,
            calibration_module._calibration_report_sha256(fabricated_results),
        )
        self.assertFalse(fabricated.integrity_valid)
        with self.assertRaises(CalibrationGateError):
            assert_calibrated(fabricated)

    def test_calibration_statistics_are_deeply_immutable(self) -> None:
        result = evaluate_case(self.by_kind["multiple_comparisons"])
        with self.assertRaises(TypeError):
            result.statistics["family_size"] = 1  # type: ignore[index]
        with self.assertRaises(AttributeError):
            result.statistics["raw_significant"].append("forged")  # type: ignore[union-attr]

    def test_declared_correction_cannot_waive_unsupported_discovery(self) -> None:
        case = self.by_kind["multiple_comparisons"]
        payload = case.to_dict()
        payload["payload"]["correction_method"] = "holm"
        result = evaluate_case(payload)
        self.assertEqual("MULTIPLE_COMPARISONS_DETECTED", result.decision)

    def test_nonsignificant_opposite_signs_do_not_prove_reversal(self) -> None:
        case = self.by_kind["regime_reversal_shift"].to_dict()
        for regime in case["payload"]["regimes"]:
            controls = [row for row in regime["observations"] if row["group"] == "control"][:2]
            treated = [row for row in regime["observations"] if row["group"] == "treatment"][:2]
            regime["observations"] = controls + treated
        case["payload"]["minimum_abs_effect"] = 0.1
        result = evaluate_case(case)
        self.assertEqual("NO_REGIME_REVERSAL_DETECTED", result.decision)
        self.assertIn("REGIME_REVERSAL_NOT_STATISTICALLY_SUPPORTED", {x.code for x in result.findings})

    def test_regime_contract_and_frozen_pair_multiplicity(self) -> None:
        duplicate_name = self.by_kind["regime_reversal_shift"].to_dict()
        duplicate_name["payload"]["regimes"][1]["name"] = "development_regime"
        self.assertEqual(
            "CALIBRATION_CASE_INVALID", evaluate_case(duplicate_name).decision
        )

        negative_threshold = self.by_kind["regime_reversal_shift"].to_dict()
        negative_threshold["payload"]["minimum_abs_effect"] = -0.1
        self.assertEqual(
            "CALIBRATION_CASE_INVALID", evaluate_case(negative_threshold).decision
        )

        missing_pairs = self.by_kind["regime_reversal_shift"].to_dict()
        del missing_pairs["payload"]["predeclared_regime_pairs"]
        self.assertEqual("CALIBRATION_CASE_INVALID", evaluate_case(missing_pairs).decision)

        duplicate_pairs = self.by_kind["regime_reversal_shift"].to_dict()
        duplicate_pairs["payload"]["predeclared_regime_pairs"].append(
            ["confirmatory_regime", "development_regime"]
        )
        self.assertEqual(
            "CALIBRATION_CASE_INVALID", evaluate_case(duplicate_pairs).decision
        )

        excessive_work = self.by_kind["regime_reversal_shift"].to_dict()
        excessive_work["payload"]["permutation_iterations"] = 4096
        for regime in excessive_work["payload"]["regimes"]:
            regime["observations"] = [{} for _ in range(3000)]
        excessive_result = evaluate_case(excessive_work)
        self.assertEqual("CALIBRATION_CASE_INVALID", excessive_result.decision)
        self.assertIn("regime permutation work budget", excessive_result.findings[0].detail)

        case = self.by_kind["regime_reversal_shift"].to_dict()
        cloned_regime = json.loads(
            json.dumps(case["payload"]["regimes"][1], sort_keys=True)
        )
        cloned_regime["name"] = "confirmatory_clone"
        case["payload"]["regimes"].append(cloned_regime)
        case["payload"]["predeclared_regime_pairs"] = [
            ["development_regime", "confirmatory_regime"],
            ["development_regime", "confirmatory_clone"],
        ]
        result = evaluate_case(case)
        self.assertEqual("NO_REGIME_REVERSAL_DETECTED", result.decision)
        self.assertEqual(
            "holm_over_predeclared_intersection_union_pairs",
            result.statistics["multiplicity_method"],
        )
        for pair in result.statistics["predeclared_pair_results"]:
            self.assertLessEqual(pair["intersection_union_p_value"], 0.05)
            self.assertGreater(pair["holm_adjusted_p_value"], 0.05)
            self.assertFalse(pair["significant_reversal"])

    def test_extreme_number_fails_closed(self) -> None:
        case = self.by_kind["multiple_comparisons"].to_dict()
        case["payload"]["family_alpha"] = 10**400
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        signal = self.by_kind["planted_positive"].to_dict()
        signal["payload"]["alpha"] = 2.0
        self.assertEqual("CALIBRATION_CASE_INVALID", evaluate_case(signal).decision)
        signal["payload"]["alpha"] = 0.05
        signal["payload"]["expected_direction"] = "sideways"
        self.assertEqual("CALIBRATION_CASE_INVALID", evaluate_case(signal).decision)

    def test_deep_programmatic_mapping_fails_closed(self) -> None:
        nested: dict[str, object] = {}
        cursor = nested
        for _ in range(2000):
            child: dict[str, object] = {}
            cursor["child"] = child
            cursor = child
        result = evaluate_case(nested)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)

    def test_generic_mapping_and_sequence_depth_fails_closed(self) -> None:
        deep_mapping: object = "leaf"
        deep_sequence: object = "leaf"
        for _ in range(40):
            deep_mapping = MappingProxyType({"child": deep_mapping})
            deep_sequence = (deep_sequence,)
        for name, nested in (
            ("generic_mapping", deep_mapping),
            ("non_string_sequence", deep_sequence),
        ):
            with self.subTest(container=name):
                case = self.by_kind["planted_positive"].to_dict()
                case["payload"]["unused_nested_value"] = nested
                result = evaluate_case(case)
                self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
                self.assertIn("JSON depth", result.findings[0].detail)

    def test_split_role_identifier_and_work_caps_fail_closed(self) -> None:
        case = self.by_kind["leakage_trap"].to_dict()
        case["payload"] = {
            "splits": {f"role-{index}": [f"p-{index}"] for index in range(65)},
            "features": [],
        }
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        self.assertIn("exceeds 64 roles", result.findings[0].detail)

        case["payload"]["splits"] = {
            f"role-{index}": [f"p-{index}"] for index in range(47)
        }
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        self.assertIn("pair comparison budget", result.findings[0].detail)

        shared_identifiers = [f"p-{index}" for index in range(200)]
        case["payload"]["splits"] = {
            f"role-{index}": list(shared_identifiers) for index in range(21)
        }
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        self.assertIn("intersection work budget", result.findings[0].detail)

        case["payload"]["splits"] = {
            "training": [f"p-{index}" for index in range(4097)]
        }
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        self.assertIn("exceeds 4096 identifiers", result.findings[0].detail)

    def test_permutation_work_is_bounded(self) -> None:
        case = self.by_kind["planted_positive"].to_dict()
        case["payload"]["permutation_iterations"] = 16_385
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)
        case["payload"]["permutation_iterations"] = True
        result = evaluate_case(case)
        self.assertEqual("CALIBRATION_CASE_INVALID", result.decision)

    def test_missing_baseline_dimensions_fail_equivalence(self) -> None:
        case = self.by_kind["baseline_implementation_mismatch"].to_dict()
        case["payload"]["baseline"] = {}
        case["payload"]["contender"] = {}
        result = evaluate_case(case)
        self.assertEqual("BASELINE_MISMATCH_DETECTED", result.decision)
        self.assertTrue(result.statistics["missing_dimensions"])

    def test_holdout_access_cannot_opt_out_of_protocol_freeze(self) -> None:
        case = self.by_kind["holdout_access_violation"].to_dict()
        case["payload"]["accesses"] = [{
            "requester": "experiment-runner",
            "authorized": True,
            "requires_frozen_protocol": False,
            "purpose": "confirmatory-evaluation",
        }]
        case["payload"]["protocol_frozen"] = False
        result = evaluate_case(case)
        self.assertEqual("HOLDOUT_ACCESS_VIOLATION_DETECTED", result.decision)
        self.assertIn("custody_policy_opt_out_rejected", result.statistics["violations"][0]["reasons"])

    def test_duplicate_or_cyclic_provenance_is_corrupt(self) -> None:
        content = {"value": 1}
        digest = canonical_json_sha256(content)
        base = self.by_kind["corrupted_provenance"].to_dict()
        base["payload"]["artifacts"] = [
            {"artifact_id": "a", "content": content, "declared_sha256": digest, "parent_artifact_ids": ["a"]},
            {"artifact_id": "a", "content": content, "declared_sha256": digest, "parent_artifact_ids": []},
        ]
        result = evaluate_case(base)
        self.assertEqual("CORRUPTED_PROVENANCE_DETECTED", result.decision)
        codes = {finding.code for finding in result.findings}
        self.assertIn("DUPLICATE_ARTIFACT_ID", codes)
        self.assertIn("PROVENANCE_CYCLE", codes)

    def test_long_provenance_chain_does_not_recurse(self) -> None:
        case = self.by_kind["corrupted_provenance"].to_dict()
        artifacts = []
        for index in range(1500):
            content = {"index": index}
            artifacts.append({
                "artifact_id": f"a{index}",
                "content": content,
                "declared_sha256": canonical_json_sha256(content),
                "parent_artifact_ids": [] if index == 0 else [f"a{index-1}"],
            })
        case["payload"]["artifacts"] = artifacts
        result = evaluate_case(case)
        self.assertEqual("PROVENANCE_VALID", result.decision)

    def test_loader_rejects_symlink_traversal_duplicate_nonfinite_and_oversize(self) -> None:
        from scientist_one.calibration import (
            CalibrationError,
            _safe_json_document,
            load_calibration_cases,
        )

        project_tmp = PROJECT_ROOT / ".scientist-one-build" / "tmp"
        with tempfile.TemporaryDirectory(dir=project_tmp) as directory:
            base = Path(directory)
            fixture = base / "calibration_cases.json"
            fixture.symlink_to(PROJECT_ROOT / "fixtures" / "calibration" / "calibration_cases.json")
            with self.assertRaises(CalibrationError):
                load_calibration_cases(base)
            fixture.unlink()

            fixture.write_text('{"schema_version":"1.0","schema_version":"1.0"}')
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            with self.assertRaisesRegex(CalibrationError, "duplicate JSON key"):
                _safe_json_document(fixture, expected_file_sha256=digest)

            fixture.write_text('{"schema_version":"1.0","value":NaN}')
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
            with self.assertRaisesRegex(CalibrationError, "non-finite JSON number"):
                _safe_json_document(fixture, expected_file_sha256=digest)

            fixture.write_text("{}")
            with self.assertRaisesRegex(CalibrationError, "frozen fixture file hash mismatch"):
                load_calibration_cases(base)
            (base / "nested").mkdir()
            with self.assertRaisesRegex(CalibrationError, "traversal rejected"):
                _safe_json_document(
                    base / "nested" / ".." / fixture.name,
                    expected_file_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                )

            fixture.unlink()
            hard_link_target = base / "hard-link-target.json"
            hard_link_target.write_text("{}")
            os.link(hard_link_target, fixture)
            with self.assertRaisesRegex(CalibrationError, "hard-link count rejected"):
                _safe_json_document(
                    fixture,
                    expected_file_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                )
            fixture.unlink()
            hard_link_target.unlink()

            fixture.write_bytes(b" " * 1_048_577)
            with self.assertRaisesRegex(CalibrationError, "exceeds 1048576 bytes"):
                _safe_json_document(
                    fixture,
                    expected_file_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                )

    def test_loader_uses_descriptor_pinned_confined_reader(self) -> None:
        import scientist_one.calibration as calibration_module
        from scientist_one.calibration import _safe_json_document

        project_tmp = PROJECT_ROOT / ".scientist-one-build" / "tmp"
        with tempfile.TemporaryDirectory(dir=project_tmp) as directory:
            fixture = Path(directory) / "fixture.json"
            raw = b'{"fixture_type":"descriptor-pinned"}'
            fixture.write_bytes(raw)
            with mock.patch.object(
                calibration_module,
                "read_confined_bytes",
                wraps=calibration_module.read_confined_bytes,
            ) as reader:
                document = _safe_json_document(
                    fixture,
                    expected_file_sha256=hashlib.sha256(raw).hexdigest(),
                )

        self.assertEqual("descriptor-pinned", document["fixture_type"])
        reader.assert_called_once_with(
            PROJECT_ROOT,
            fixture.relative_to(PROJECT_ROOT),
            reject_hardlinks=True,
            max_bytes=1_048_576,
        )

    def test_holm_correction_rejects_raw_false_discovery(self) -> None:
        adjusted = holm_adjust([0.02, 0.07, 0.09, 0.11])
        for expected, actual in zip((0.08, 0.21, 0.21, 0.21), adjusted, strict=True):
            self.assertAlmostEqual(expected, actual)
        result = evaluate_case(self.by_kind["multiple_comparisons"])
        self.assertEqual(("h07",), result.statistics["raw_significant"])
        self.assertEqual((), result.statistics["holm_significant"])

    def test_corrupted_provenance_reports_computed_hash(self) -> None:
        result = evaluate_case(self.by_kind["corrupted_provenance"])
        computed = result.statistics["computed_sha256"]["result-001"]
        self.assertEqual(64, len(computed))
        self.assertNotEqual("f" * 64, computed)
        self.assertEqual(
            {"result-001": ["protocol-that-is-absent"]},
            {key: list(value) for key, value in result.statistics["missing_parents"].items()},
        )

    def test_domain_invalid_permutation_is_not_treated_as_generic_null(self) -> None:
        result = evaluate_case(self.by_kind["domain_invalid_permutation"])
        self.assertEqual("DOMAIN_INVALID_PERMUTATION_REJECTED", result.decision)
        self.assertFalse(result.statistics["exchangeability"])
        self.assertEqual(
            "global-label-permutation",
            result.statistics["proposed_permutation_scheme"],
        )


class SyntheticWorkflowBenchmarkTests(unittest.TestCase):
    def test_manifest_materializes_required_seeded_task_set(self) -> None:
        loaded = load_synthetic_workflow_tasks()
        generated = generate_synthetic_workflow_tasks(20260812)
        self.assertEqual(
            [task.to_dict() for task in generated],
            [task.to_dict() for task in loaded],
        )
        self.assertEqual(
            list(SYNTHETIC_WORKFLOW_SCENARIOS),
            [task.scenario for task in loaded],
        )
        self.assertEqual(6, len({task.seed for task in loaded}))

    def test_task_generation_is_seed_deterministic(self) -> None:
        first = generate_synthetic_workflow_tasks(1234)
        second = generate_synthetic_workflow_tasks(1234)
        different = generate_synthetic_workflow_tasks(1235)
        first_payload = [task.to_dict() for task in first]
        self.assertEqual(first_payload, [task.to_dict() for task in second])
        self.assertNotEqual(first_payload, [task.to_dict() for task in different])

    def test_six_scenarios_produce_expected_honest_outcomes(self) -> None:
        report = run_synthetic_workflow_benchmark()
        self.assertTrue(report.passed)
        self.assertEqual(
            {
                "signal": "POSITIVE_SIGNAL",
                "null": "NEGATIVE_RESULT",
                "reversal": "SIGN_REVERSAL",
                "leakage": "INVALID_LEAKAGE",
                "invalid-analysis": "INVALID_ANALYSIS",
                "corrupted-evidence": "CORRUPTED_EVIDENCE",
            },
            {result.scenario: result.decision for result in report.results},
        )
        task_states = {
            task.scenario: task.expected_terminal_state
            for task in generate_synthetic_workflow_tasks()
        }
        self.assertEqual("DEMO_RESEARCH_PACKAGE", task_states["signal"])
        self.assertEqual("NEGATIVE_RESULT", task_states["null"])
        self.assertEqual("INCONCLUSIVE", task_states["reversal"])
        for invalid in ("leakage", "invalid-analysis", "corrupted-evidence"):
            self.assertEqual("STOP_SCIENTIFIC_INVALIDITY", task_states[invalid])
        self.assertEqual(
            task_states,
            {result.scenario: result.terminal_state for result in report.results},
        )

    def test_benchmark_rejects_nonmanifest_seed_and_terminal_tampering(self) -> None:
        from scientist_one.calibration import CalibrationError, evaluate_synthetic_workflow_task

        with self.assertRaises(CalibrationError):
            run_synthetic_workflow_benchmark(1234)
        task = generate_synthetic_workflow_tasks()[0]
        tampered = replace(task, expected_terminal_state="STOP_SECURITY")
        result = evaluate_synthetic_workflow_task(tampered)
        self.assertFalse(result.passed)

    def test_benchmark_report_is_deterministic_and_frozen(self) -> None:
        import scientist_one.calibration as calibration_module

        first = run_synthetic_workflow_benchmark()
        second = run_synthetic_workflow_benchmark()
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.integrity_valid)
        self.assertEqual(
            "ffdfb300cbebbe04c8e0885a50b7b1d931afba4149d3c5f002e6d82d054ccfa7",
            FROZEN_WORKFLOW_REPORT_SHA256,
        )
        self.assertEqual(FROZEN_WORKFLOW_REPORT_SHA256, first.report_sha256)

        forged_results = (
            replace(first.results[0], decision="FORGED_DECISION"),
            *first.results[1:],
        )
        self_consistently_rehashed = replace(
            first,
            results=forged_results,
            report_sha256=calibration_module._workflow_report_sha256(
                first.seed, forged_results
            ),
        )
        self.assertFalse(self_consistently_rehashed.integrity_valid)


if __name__ == "__main__":
    unittest.main()
