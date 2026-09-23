"""Native external envelope identity is byte-exact, not JSON-value equality."""

import json
import hashlib
import math
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from scientist_one import orchestrator
from scientist_one import simulated_reserve
from scientist_one.security import canonical_json_bytes, sha256_bytes
from tests import test_shared_resource_authority as native_fixtures
from tests import test_simulated_resource as initial_fixtures


_CHILD_TEST_TEMPLATE = '''
import unittest
from pathlib import Path
from tests.test_resource_authority_canonical_bytes import _run_prepared_scenario


class PreparedScenarioTests(unittest.TestCase):
    def test_prepared_scenario(self):
        _run_prepared_scenario(Path.cwd(), {scenario!r})
'''


def _copy_child_project(root, scenario):
    root.mkdir(parents=True, exist_ok=False)
    (root / "scripts").mkdir()
    (root / "src" / "scientist_one").mkdir(parents=True)
    (root / "tests").mkdir()
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "scripts/scientist_one_cli.py",
        root / "scripts/scientist_one_cli.py",
    )
    source_root = Path(__file__).resolve().parents[1] / "src/scientist_one"
    for source in source_root.glob("*.py"):
        shutil.copyfile(source, root / "src/scientist_one" / source.name)
    test_root = Path(__file__).resolve().parent
    for name in (
        "__init__.py",
        "test_resource_authority_canonical_bytes.py",
        "test_simulated_resource.py",
        "test_resource_prepared_cases.py",
        "test_shared_resource_authority.py",
        "test_scientific_design.py",
        "test_protocol_contract_crosswalk.py",
        "test_scientific_core.py",
    ):
        shutil.copyfile(test_root / name, root / "tests" / name)
    (root / "tests/test_prepared_scenario.py").write_text(
        _CHILD_TEST_TEMPLATE.format(scenario=scenario), encoding="utf-8"
    )
    config = root / "configs/resource_limits.json"
    config.parent.mkdir()
    config.write_bytes(
        canonical_json_bytes(initial_fixtures.ResourceConfig().to_dict()) + b"\n"
    )
    # The simulated population is pinned to this public known-answer fixture;
    # production verifies its exact digest before deriving the population.
    calibration = root / "fixtures/calibration/calibration_cases.json"
    calibration.parent.mkdir(parents=True)
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "fixtures/calibration/calibration_cases.json",
        calibration,
    )
    (root / ".prepared-resource-fixture").write_text(
        "prepared-root-fixture-20260920\n", encoding="utf-8"
    )
    (root / "reports").mkdir()


def _run_prepared_child(scenario):
    from tests import test_isolated_launchers as launcher_fixtures

    with tempfile.TemporaryDirectory(prefix="prepared-resource-child-") as raw:
        root = Path(raw) / "ScientistOne"
        _copy_child_project(root, scenario)
        before = {
            path.relative_to(root).as_posix(): (
                path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
                path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
            )
            for path in root.rglob("*")
            if path.is_file()
        }
        with mock.patch.object(launcher_fixtures, "PYTHON", sys.executable):
            result = launcher_fixtures._run_launcher(
                root,
                "__captured-test-module__",
                "tests.test_prepared_scenario",
                timeout=90,
            )
        lines = result.stdout.splitlines()
        protocol = "SCIENTIST_ONE_CAPTURED_TEST_MODULE_V1="
        payloads = [line[len(protocol):] for line in lines if line.startswith(protocol)]
        if result.returncode != 0 or len(payloads) != 1:
            raise AssertionError(result.stderr or result.stdout)
        report = json.loads(payloads[0])
        self_ids = ["tests.test_prepared_scenario.PreparedScenarioTests.test_prepared_scenario"]
        expected_worker_fields = {
            "schema_version", "module_name", "module_sha256", "test_ids",
            "tests_run", "failures", "errors", "skipped", "expected_failures",
            "unexpected_successes", "successful", "failure_details", "error_details",
            "output", "elapsed_seconds", "loaded_test_modules",
            "project_source_attestation", "test_source_attestation",
        }
        counters = ("tests_run", "failures", "errors", "skipped",
                    "expected_failures", "unexpected_successes")
        if (
            set(report) != expected_worker_fields
            or any(type(report.get(key)) is not int for key in counters)
            or type(report.get("elapsed_seconds")) not in (int, float)
            or not math.isfinite(report["elapsed_seconds"])
            or report["elapsed_seconds"] < 0
            or type(report.get("output")) is not str
            or not report["output"].strip()
            or report.get("schema_version") != "captured-test-module/v1"
            or report.get("module_name") != "tests.test_prepared_scenario"
            or report.get("module_sha256") != hashlib.sha256(
                (root / "tests/test_prepared_scenario.py").read_bytes()
            ).hexdigest()
            or report.get("successful") is not True
            or report.get("test_ids") != self_ids
            or report.get("tests_run") != 1
            or report.get("failures") != 0
            or report.get("errors") != 0
            or report.get("skipped") != 0
            or report.get("expected_failures") != 0
            or report.get("unexpected_successes") != 0
            or report.get("failure_details") != []
            or report.get("error_details") != []
            or not report.get("loaded_test_modules")
            or report.get("project_source_attestation", {}).get("entries") is None
            or report.get("test_source_attestation", {}).get("entries") is None
        ):
            raise AssertionError(f"invalid captured child report: {report!r}")
        if Path.cwd().resolve() == root:
            raise AssertionError("parent unexpectedly changed into child root")
        if (
            Path.cwd().resolve() != Path(__file__).resolve().parents[1]
            or root.name != "ScientistOne"
            or not root.parent.name.startswith("prepared-resource-child-")
            or (root / ".prepared-resource-fixture").read_text(encoding="utf-8")
            != "prepared-root-fixture-20260920\n"
        ):
            raise AssertionError("prepared child root ownership/layout is invalid")
        for attestation_key, schema in (
            ("project_source_attestation", "SCIENTIST_ONE_CAPTURED_SOURCE_V1"),
            ("test_source_attestation", "SCIENTIST_ONE_CAPTURED_TESTS_V1"),
        ):
            entries = report[attestation_key]["entries"]
            if not entries:
                raise AssertionError(f"empty {attestation_key}")
            if (
                set(report[attestation_key]) != {"schema_version", "entries"}
                or report[attestation_key]["schema_version"] != schema
            ):
                raise AssertionError(f"invalid {attestation_key} schema")
            if len({entry["path"] for entry in entries}) != len(entries):
                raise AssertionError(f"duplicate {attestation_key} paths")
            for entry in entries:
                if (
                    set(entry) != {"path", "sha256", "size"}
                    or type(entry["size"]) is not int
                ):
                    raise AssertionError(f"invalid {attestation_key} entry")
                relative = entry["path"]
                payload = before.get(relative)
                if payload is None or hashlib.sha256(payload[0]).hexdigest() != entry["sha256"] or len(payload[0]) != entry["size"]:
                    raise AssertionError(f"{attestation_key} identity mismatch: {relative}")
        project_paths = {
            entry["path"] for entry in report["project_source_attestation"]["entries"]
        }
        expected_project_paths = {
            relative for relative in before
            if relative == "scripts/scientist_one_cli.py"
            or relative.startswith("src/scientist_one/")
        }
        if project_paths != expected_project_paths:
            raise AssertionError("project source closure differs from copied inputs")
        test_entries = {
            entry["path"]: entry["sha256"]
            for entry in report["test_source_attestation"]["entries"]
        }
        expected_test_paths = {
            relative for relative in before if relative.startswith("tests/")
        }
        if set(test_entries) != expected_test_paths:
            raise AssertionError("test source closure differs from copied inputs")
        expected_loaded = {
            "tests", "tests.test_prepared_scenario",
            "tests.test_resource_authority_canonical_bytes", "tests.test_simulated_resource",
            "tests.test_resource_prepared_cases",
            "tests.test_shared_resource_authority", "tests.test_scientific_design",
            "tests.test_protocol_contract_crosswalk", "tests.test_scientific_core",
        }
        loaded_names = [loaded["module_name"] for loaded in report["loaded_test_modules"]]
        if set(loaded_names) != expected_loaded or len(loaded_names) != len(expected_loaded):
            raise AssertionError(f"loaded test closure mismatch: {loaded_names!r}")
        for loaded in report["loaded_test_modules"]:
            if set(loaded) != {"module_name", "sha256"}:
                raise AssertionError("invalid loaded test module record")
            module_name = loaded["module_name"]
            if module_name == "tests":
                relative = "tests/__init__.py"
            else:
                relative = module_name.replace(".", "/") + ".py"
            if test_entries.get(relative) != loaded["sha256"]:
                raise AssertionError(f"loaded test closure mismatch: {module_name}")
        after = {
            path.relative_to(root).as_posix(): (
                path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
                path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
            )
            for path in root.rglob("*")
            if path.is_file()
        }
        def controlled_paths(inventory):
            return {
                relative for relative in inventory
                if relative.startswith(("src/", "scripts/", "tests/", "configs/", "fixtures/"))
                or relative == ".prepared-resource-fixture"
            }
        controlled = controlled_paths(before)
        if controlled_paths(after) != controlled:
            raise AssertionError("child controlled input path set changed")
        for relative in controlled:
            if after.get(relative) != before[relative]:
                raise AssertionError(f"child input changed: {relative}")
        return report


def _run_prepared_scenario(root, scenario):
    if Path.cwd().resolve() != Path(root).resolve():
        raise AssertionError("prepared scenario did not use the captured child cwd")
    if scenario not in {
        *(f"format:{label}" for label, _encode in ResourceAuthorityCanonicalBytesTests().formats()),
        "completed:false", "completed:true",
    }:
        raise ValueError(f"unknown prepared scenario: {scenario}")
    if (Path(root) / "runs").exists() or (
        Path(root) / ".scientist-one-build/resource-authority"
    ).exists():
        raise AssertionError("prepared child has preexisting run/resource state")
    case = initial_fixtures.SimulatedResourceTests()
    owner = ResourceAuthorityCanonicalBytesTests()
    case.prepare(prepared_root=root)
    if scenario.startswith("format:"):
        label = scenario.split(":", 1)[1]
        initial = case.initialize()
        encode = dict(owner.formats())[label]
        owner.rewrite_initial(case.root, case.run, encode)
        before, external = case.snapshot(), case.files()
        with unittest.TestCase().assertRaises(orchestrator.OrchestrationError):
            case.require(initial)
        if case.snapshot() != before or case.files() != external:
            raise AssertionError("refusal changed prepared child state")
        return
    completed = scenario == "completed:true"
    initial = case.initialize()
    if completed:
        owner.publish_reserve(case, initial)
    owner.rewrite_initial(case.root, case.run, owner.formats()[0][1])
    before, external = case.snapshot(), case.files()
    with unittest.TestCase().assertRaises(simulated_reserve.SimulatedReserveError):
        owner.publish_reserve(case, initial)
    if case.snapshot() != before or case.files() != external:
        raise AssertionError("refusal changed prepared child state")


class ResourceAuthorityCanonicalBytesTests(unittest.TestCase):
    def native_fixture(self):
        case = native_fixtures.SharedResourceAuthorityTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        value = case.publish("resource_runtime_initial", 0)
        return case, value

    def initial_fixture(self):
        case = initial_fixtures.SimulatedResourceTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        return case, case.initialize()

    def rewrite_initial(self, root, run_id, encode):
        directory = root / ".scientist-one-build/resource-authority" / run_id
        old, = directory.glob("*.json")
        previous = old.read_bytes()
        raw = encode(json.loads(previous))
        self.assertNotEqual(raw, previous)
        replacement = directory / f"0000-{sha256_bytes(raw)}.json"
        self.assertNotEqual(replacement, old)
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        old.unlink()
        return replacement

    def formats(self):
        return (
            ("indent", lambda value: json.dumps(value, indent=2).encode() + b"\n"),
            ("missing-LF", canonical_json_bytes),
            ("extra-LF", lambda value: canonical_json_bytes(value) + b"\n\n"),
            ("boolean-sequence", lambda value: canonical_json_bytes(
                {**value, "sequence": False}
            ) + b"\n"),
            ("float-sequence", lambda value: canonical_json_bytes(
                {**value, "sequence": 0.0}
            ) + b"\n"),
        )

    def publish_reserve(self, case, initial):
        return simulated_reserve.register_simulated_confirmatory_reserve(
            case.registry,
            case.ledger,
            expected_run_id=case.run,
            protocol_artifact_sha256=case.protocol_record.sha256,
            contract_artifact_sha256=case.contract_record.sha256,
            population_artifact_sha256=case.population.sha256,
            window_index=1,
            initialization_artifact_sha256=initial.record.sha256,
        )

    def test_native_reader_rejects_noncanonical_or_noninteger_envelopes(self):
        for label, encode in self.formats():
            with self.subTest(label=label):
                case, _ = self.native_fixture()
                self.rewrite_initial(case.root, native_fixtures.RUN_ID, encode)
                before = case.filesystem_snapshot()
                with self.assertRaises(orchestrator.OrchestrationError):
                    case.history()
                self.assertEqual(case.filesystem_snapshot(), before)

    def test_next_native_append_refuses_before_poisoning_existing_history(self):
        case, _ = self.native_fixture()
        self.rewrite_initial(case.root, native_fixtures.RUN_ID, self.formats()[0][1])
        before = case.filesystem_snapshot()
        with self.assertRaises(orchestrator.OrchestrationError):
            orchestrator._persist_resource_authority_for(
                case.root, native_fixtures.RUN_ID,
                "resource_runtime_pilot_charge", case.state(1),
            )
        self.assertEqual(case.filesystem_snapshot(), before)

    def test_current_initialization_requires_its_exact_native_envelope(self):
        for label, _encode in self.formats():
            with self.subTest(label=label):
                _run_prepared_child(f"format:{label}")

    def test_new_and_completed_reserves_refuse_reformatted_external_head(self):
        for completed in (False, True):
            with self.subTest(completed=completed):
                _run_prepared_child(f"completed:{str(completed).lower()}")


if __name__ == "__main__":
    unittest.main()
