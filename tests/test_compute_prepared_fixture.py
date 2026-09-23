"""Test-only prepared-root dispatch for three existing compute fixture classes.

This is not evidence or dispatch authority. Every child uses the unchanged normal
captured launcher, then runs one original TestCase (including setup and cleanup).
Only the parent owns the copied project lifetime. No unrelated suite is selected.
"""

from functools import wraps
import hashlib
import importlib
import io
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MARKER = ".prepared-compute-fixture.json"
_BOOTSTRAP = "state/APP_SESSION_BOOTSTRAP.json"
_WRAPPER_MODULE = "tests.test_prepared_compute_case"
_WRAPPER_ID = _WRAPPER_MODULE + ".PreparedComputeCaseTests.test_original_case"
_NESTED_PROTOCOL = "SCIENTIST_ONE_PREPARED_COMPUTE_CASE_V1="
_WORKER_PROTOCOL = "SCIENTIST_ONE_CAPTURED_TEST_MODULE_V1="
_ACTIVE = None
_CLASS_MODULES = {
    "ComputeTerminalAuthorityTests": "tests.test_compute_terminal",
    "GpuComputeTerminalRoutingTests": "tests.test_gpu_compute_terminal_routing",
    "OperationalSeedWallProgressTests": "tests.test_operational_seed_exposure",
}
_BASE_MODULES = {"tests", "tests.test_compute_prepared_fixture",
                 "tests.test_compute_terminal", "tests.test_scientific_design"}
_EXPOSURE_IMPORTS = {
    "tests.test_evaluation_contract_amendment", "tests.test_gpu_validation_requirement",
    "tests.test_scientific_execution_authority", "tests.test_runtime",
}
_CONFIG_DRIFT_ID = (
    "tests.test_compute_terminal.ComputeTerminalAuthorityTests."
    "test_wall_observation_rejects_live_config_drift_without_writes"
)
_FAILURE_SETUP_ID = (
    "tests.test_compute_terminal.ComputeTerminalAuthorityTests."
    "test_scheduled_setup_failure_restores_clock_patches_for_default_fixture"
)

_PROSPECTIVE_COMPUTE_CASES = frozenset(
    "tests.test_compute_terminal.ComputeTerminalAuthorityTests." + name
    for name in (
        "test_any_external_consumption_key_blocks_without_writes",
        "test_assessment_event_before_wall_observation_is_rejected_without_write",
        "test_assessment_recovery_preflights_same_bytes_metadata_collision",
        "test_event_first_assessment_crash_recovers_only_exact_identity",
        "test_owner_backed_compute_assessment_materializes_only_operational_scope",
        "test_progress_and_legacy_map_cannot_upgrade_to_compute_authority",
    )
)


def _selection(test_id):
    module, class_name, method = test_id.rsplit(".", 2)
    if (_CLASS_MODULES.get(class_name) != module
            or not method.startswith("test_") or not method.isidentifier()):
        raise AssertionError("unknown prepared compute case")
    budget = (5.0 if class_name == "OperationalSeedWallProgressTests" else
              10 if class_name == "GpuComputeTerminalRoutingTests"
              or test_id in _PROSPECTIVE_COMPUTE_CASES else 1)
    return module, class_name, method, budget


def prepared_prospective_compute_profile():
    """Select only the genuine captured outer case, never an inner fixture ID."""
    if _ACTIVE is None:
        raise AssertionError("prospective compute profile requires a prepared child")
    _root, test_id = _ACTIVE
    if test_id not in _PROSPECTIVE_COMPUTE_CASES:
        return None
    return test_id, _selection(test_id)[3]


def _modules(test_id):
    module, class_name, _method, _budget = _selection(test_id)
    names = _BASE_MODULES | {module, _WRAPPER_MODULE}
    if class_name == "GpuComputeTerminalRoutingTests":
        names |= {"tests.test_gpu_validation_requirement"}
    elif class_name == "OperationalSeedWallProgressTests":
        names |= _EXPOSURE_IMPORTS
    return names


def _module_path(name):
    return "tests/__init__.py" if name == "tests" else name.replace(".", "/") + ".py"


def prepared_compute_tests(cls):
    """Keep static test IDs/bodies; route the parent call into one captured child."""
    if _CLASS_MODULES.get(cls.__name__) != cls.__module__:
        raise AssertionError("prepared decorator used by another class")
    original_setup, original_teardown = cls.setUp, cls.tearDown

    @wraps(original_setup)
    def setup(self):
        if _ACTIVE is not None:
            original_setup(self)

    @wraps(original_teardown)
    def teardown(self):
        if _ACTIVE is not None:
            original_teardown(self)

    def wrap(method):
        @wraps(method)
        def dispatched(self):
            if _ACTIVE is None:
                _run_prepared_child(self.id())
            else:
                if self.id() != _ACTIVE[1]:
                    raise AssertionError("child attempted another original test body")
                method(self)
        return dispatched

    cls.setUp, cls.tearDown = setup, teardown
    for name, method in tuple(vars(cls).items()):
        if name.startswith("test_") and callable(method):
            setattr(cls, name, wrap(method))
    return cls


def prepared_fixture_root(case):
    """Return owned captured cwd, except the explicit pre-start failure fixture."""
    if _ACTIVE is None:
        raise AssertionError("compute setup requires a prepared captured child")
    root, test_id = _ACTIVE
    if getattr(case, "_prepared_failure_copy", False):
        if test_id != _FAILURE_SETUP_ID:
            raise AssertionError("temporary setup exception is limited to cleanup test")
        return None
    if root != Path.cwd().resolve(strict=True) or root != _PROJECT_ROOT:
        raise AssertionError("prepared fixture root differs from captured child cwd")
    return root


def _snapshot(root):
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
            path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
        )
        for path in root.rglob("*")
        if path.is_file() and (
            path.relative_to(root).parts[0] in {"src", "scripts", "tests", "configs"}
            or path.relative_to(root).as_posix() in {_MARKER, _BOOTSTRAP}
        )
    }


def _bootstrap_payload(root):
    return {
        "app_session_bootstrap": "PASS",
        "canonical_project_root": str(root.resolve(strict=True)),
        "classification": "NEW_TEST_FIXTURE",
        "historical_authority": False,
        "scientific_evidence": False,
        "app_approval_claimed": False,
        "human_e4_authority": False,
        "provider_authority": False,
        "bootstrap_checks": [{
            "check": "fresh_owned_root_and_exact_prepared_input_identities",
            "result": "PASS",
            "scope": "Measured local test preparation only; no app approval, human/E4, provider, historical or scientific authority.",
            "input_sha256": {
                relative: hashlib.sha256(identity[0]).hexdigest()
                for relative, identity in sorted(_snapshot(root).items())
                if relative != _BOOTSTRAP
            },
        }],
    }


def _prepare(root, test_id):
    _module, _class, _method, budget = _selection(test_id)
    root.mkdir()
    for directory in ("src/scientist_one", "scripts", "tests", "reports", "state",
                      ".scientist-one-build/tmp"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for source in (_PROJECT_ROOT / "src/scientist_one").glob("*.py"):
        shutil.copyfile(source, root / "src/scientist_one" / source.name)
    shutil.copyfile(_PROJECT_ROOT / "scripts/scientist_one_cli.py",
                    root / "scripts/scientist_one_cli.py")
    for name in _modules(test_id) - {_WRAPPER_MODULE}:
        relative = _module_path(name)
        shutil.copyfile(_PROJECT_ROOT / relative, root / relative)
    shutil.copytree(_PROJECT_ROOT / "configs", root / "configs")
    config_path = root / "configs/resource_limits.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["maximum_wall_clock_seconds"] = budget
    config_path.write_text(json.dumps(config), encoding="utf-8")
    (root / _MARKER).write_text(json.dumps({"test_id": test_id, "budget": budget}),
                                encoding="utf-8")
    (root / _module_path(_WRAPPER_MODULE)).write_text(
        "import unittest\n"
        "from tests.test_compute_prepared_fixture import run_original_case\n\n"
        "class PreparedComputeCaseTests(unittest.TestCase):\n"
        "    def test_original_case(self):\n"
        f"        run_original_case({test_id!r})\n", encoding="utf-8",
    )
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True).name != "ScientistOne":
        raise AssertionError("prepared root is not a fresh physical named directory")
    generated = {_MARKER, "configs/resource_limits.json", _module_path(_WRAPPER_MODULE)}
    for relative, identity in _snapshot(root).items():
        path = root / relative
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise AssertionError("prepared input is not a unique regular file")
        if relative not in generated and identity[0] != (_PROJECT_ROOT / relative).read_bytes():
            raise AssertionError("prepared copy differs from original input")
    # New fixture receipt follows existing normal runtime-project tests. It is
    # not a copied real receipt or a claim that app/human authority was granted.
    (root / _BOOTSTRAP).write_text(json.dumps(_bootstrap_payload(root), sort_keys=True),
                                   encoding="utf-8")


def _require_success(value, *, test_id, nested):
    counters = {"tests_run", "failures", "errors", "skipped", "expected_failures",
                "unexpected_successes"}
    if (not isinstance(value, dict)
            or any(type(value.get(key)) is not int for key in counters)
            or value["tests_run"] != 1
            or any(value[key] != 0 for key in counters - {"tests_run"})
            or value.get("successful") is not True
            or value.get("test_ids") != [test_id]
            or value.get("failure_details") != [] or value.get("error_details") != []
            or type(value.get("output")) is not str or not value["output"].strip()):
        raise AssertionError(f"prepared child did not pass exact original scope: {value!r}")
    common = counters | {"schema_version", "test_ids", "successful", "failure_details",
                         "error_details", "output"}
    if nested:
        expected = common
        schema = "prepared-compute-case/v1"
    else:
        expected = common | {"module_name", "module_sha256", "elapsed_seconds",
                             "loaded_test_modules", "project_source_attestation",
                             "test_source_attestation"}
        schema = "captured-test-module/v1"
    if set(value) != expected or value["schema_version"] != schema:
        raise AssertionError("prepared child report schema mismatch")


def run_original_case(test_id):
    """Called only by the static, normally captured one-case child wrapper."""
    global _ACTIVE
    module_name, class_name, method, budget = _selection(test_id)
    root = Path.cwd().resolve(strict=True)
    if (_ACTIVE is not None or root != _PROJECT_ROOT or root.name != "ScientistOne"
            or not root.parent.name.startswith("prepared-compute-child-")
            or root.parent.parent != Path(tempfile.gettempdir()).resolve()
            or (root / "runs").exists()
            or (root / ".scientist-one-build/resource-authority").exists()
            or json.loads((root / _MARKER).read_text(encoding="utf-8"))
            != {"test_id": test_id, "budget": budget}):
        raise AssertionError("original case requires its fresh prepared child")
    if json.loads((root / _BOOTSTRAP).read_text(encoding="utf-8")) != _bootstrap_payload(root):
        raise AssertionError("test preparation receipt differs from exact fresh input identities")
    _ACTIVE = (root, test_id)
    try:
        module = importlib.import_module(module_name)
        case = getattr(module, class_name)(method)
        if case.id() != test_id:
            raise AssertionError("selected original TestCase identity differs")
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(
            unittest.TestSuite((case,))
        )
        report = {
            "schema_version": "prepared-compute-case/v1", "test_ids": [case.id()],
            "tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "successful": result.wasSuccessful(), "output": output.getvalue(),
            "failure_details": [{"test": item.id(), "traceback": detail}
                                for item, detail in result.failures],
            "error_details": [{"test": item.id(), "traceback": detail}
                              for item, detail in result.errors],
        }
        print(_NESTED_PROTOCOL + json.dumps(report, sort_keys=True))
        _require_success(report, test_id=test_id, nested=True)
    finally:
        _ACTIVE = None


def _run_prepared_child(test_id):
    with tempfile.TemporaryDirectory(prefix="prepared-compute-child-") as directory:
        root = Path(directory) / "ScientistOne"
        _prepare(root, test_id)
        before = _snapshot(root)
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py",
                 "__captured-test-module__", _WRAPPER_MODULE], cwd=root,
                check=False, capture_output=True, text=True, timeout=180,
            )
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(
                f"captured compute child timed out: {exc.stdout!r}\n{exc.stderr!r}"
            ) from exc
        if completed.returncode != 0 or completed.stderr:
            raise AssertionError(f"captured compute child failed:\n{completed.stdout}\n{completed.stderr}")
        lines = completed.stdout.splitlines()
        reports = []
        for protocol in (_NESTED_PROTOCOL, _WORKER_PROTOCOL):
            matches = [line[len(protocol):] for line in lines if line.startswith(protocol)]
            if len(matches) != 1:
                raise AssertionError(f"child must emit exactly one {protocol}: {completed.stdout}")
            reports.append(json.loads(matches[0]))
        nested, worker = reports
        _require_success(nested, test_id=test_id, nested=True)
        _require_success(worker, test_id=_WRAPPER_ID, nested=False)
        if (worker["module_name"] != _WRAPPER_MODULE
                or worker["module_sha256"] != hashlib.sha256(before[_module_path(_WRAPPER_MODULE)][0]).hexdigest()
                or type(worker["elapsed_seconds"]) not in (int, float)
                or not math.isfinite(worker["elapsed_seconds"])
                or worker["elapsed_seconds"] < 0):
            raise AssertionError("child module or elapsed time differs")
        for key, schema, expected_paths in (
            ("project_source_attestation", "SCIENTIST_ONE_CAPTURED_SOURCE_V1",
             {p for p in before if p.startswith(("src/", "scripts/"))}),
            ("test_source_attestation", "SCIENTIST_ONE_CAPTURED_TESTS_V1",
             {p for p in before if p.startswith("tests/")}),
        ):
            attestation = worker[key]
            if (type(attestation) is not dict or set(attestation) != {"schema_version", "entries"}
                    or attestation["schema_version"] != schema
                    or type(attestation["entries"]) is not list):
                raise AssertionError("child attestation schema differs")
            entries = attestation["entries"]
            if (any(type(e) is not dict or set(e) != {"path", "sha256", "size"}
                    or type(e["size"]) is not int for e in entries)
                    or len(entries) != len(expected_paths)
                    or {e["path"] for e in entries} != expected_paths):
                raise AssertionError("child attestation closure differs")
            for entry in entries:
                raw = before[entry["path"]][0]
                if entry["sha256"] != hashlib.sha256(raw).hexdigest() or entry["size"] != len(raw):
                    raise AssertionError("child attestation content differs")
        loaded = worker["loaded_test_modules"]
        expected_modules = _modules(test_id)
        if (type(loaded) is not list or len(loaded) != len(expected_modules)
                or any(type(e) is not dict or set(e) != {"module_name", "sha256"} for e in loaded)
                or {e["module_name"] for e in loaded} != expected_modules):
            raise AssertionError("child loaded test closure differs")
        for entry in loaded:
            if entry["sha256"] != hashlib.sha256(before[_module_path(entry["module_name"])][0]).hexdigest():
                raise AssertionError("child loaded test identity differs")
        after = _snapshot(root)
        if set(after) != set(before):
            raise AssertionError("child changed controlled input path set")
        for relative, identity in before.items():
            if test_id == _CONFIG_DRIFT_ID and relative == "configs/resource_limits.json":
                changed = json.loads(identity[0])
                changed["cpu_worker_limit"] = int(changed["cpu_worker_limit"]) + 1
                if after[relative][0] != json.dumps(changed).encode("utf-8"):
                    raise AssertionError("config drift differs from the exact original adverse mutation")
                if after[relative][1:3] != identity[1:3]:
                    raise AssertionError("config drift replaced physical file identity")
            elif after[relative] != identity:
                raise AssertionError(f"child changed controlled input: {relative}")
        # Retain the already validated child reports in the enclosing captured
        # worker log before the owned physical fixture is cleaned up. These are
        # test records, not additional test IDs or scientific authority.
        print("SCIENTIST_ONE_PREPARED_COMPUTE_VALIDATION_V1=" + json.dumps({
            "schema_version": "prepared-compute-validation/v1",
            "test_id": test_id,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "controlled_inputs_verified": True,
            "permitted_config_drift": test_id == _CONFIG_DRIFT_ID,
        }, sort_keys=True), flush=True)
