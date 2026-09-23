"""Regression tests for the captured-source isolated launch boundary."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = PROJECT_ROOT / "scripts" / "scientist_one_cli.py"
TEST_RUNNER_SHIM = PROJECT_ROOT / "scripts" / "run_test_suite.py"
AUDIT_RUNNER_SHIM = PROJECT_ROOT / "scripts" / "audit_project.py"
SOURCE_PACKAGE = PROJECT_ROOT / "src" / "scientist_one"
PINNED_PYTHON = Path("/opt/anaconda3/bin/python3")
TEST_PYTHON_OVERRIDE = os.environ.get("SCIENTIST_ONE_TEST_PYTHON")
PYTHON = TEST_PYTHON_OVERRIDE or str(
    PINNED_PYTHON if PINNED_PYTHON.is_file() else Path(sys.executable)
)


def _run_launcher(
    root: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
    timeout: int = 15,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, "-I", "-S", "-B", "scripts/scientist_one_cli.py", *arguments],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _compile_pyc_with_launcher_python(
    source: Path,
    mode: py_compile.PycInvalidationMode,
) -> None:
    """Create poison fixtures with the interpreter used by their control run."""

    result = subprocess.run(
        [
            PYTHON,
            "-I",
            "-S",
            "-B",
            "-c",
            (
                "import py_compile,sys;"
                "py_compile.compile("
                "sys.argv[1],doraise=True,"
                "invalidation_mode=py_compile.PycInvalidationMode[sys.argv[2]]"
                ")"
            ),
            str(source),
            mode.name,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            "failed to compile poisoned bytecode with launcher interpreter: "
            f"{result.stderr}"
        )


def _minimal_project(root: Path, cli_source: str) -> tuple[Path, Path]:
    scripts = root / "scripts"
    package = root / "src" / "scientist_one"
    scripts.mkdir(parents=True)
    package.mkdir(parents=True)
    shutil.copyfile(LAUNCHER, scripts / LAUNCHER.name)
    (package / "__init__.py").write_text("", encoding="utf-8")
    cli = package / "cli.py"
    cli.write_text(textwrap.dedent(cli_source), encoding="utf-8")
    return package, cli


def _runtime_project(root: Path) -> Path:
    scripts = root / "scripts"
    package = root / "src" / "scientist_one"
    configs = root / "configs"
    state = root / "state"
    scripts.mkdir(parents=True)
    package.mkdir(parents=True)
    configs.mkdir()
    state.mkdir()
    shutil.copyfile(LAUNCHER, scripts / LAUNCHER.name)
    shutil.copyfile(TEST_RUNNER_SHIM, scripts / TEST_RUNNER_SHIM.name)
    shutil.copyfile(AUDIT_RUNNER_SHIM, scripts / AUDIT_RUNNER_SHIM.name)
    for source in SOURCE_PACKAGE.glob("*.py"):
        shutil.copyfile(source, package / source.name)
    for config in (PROJECT_ROOT / "configs").glob("*.json"):
        shutil.copyfile(config, configs / config.name)
    (state / "APP_SESSION_BOOTSTRAP.json").write_text(
        json.dumps(
            {
                "app_session_bootstrap": "PASS",
                "canonical_project_root": str(root.resolve()),
            }
        ),
        encoding="utf-8",
    )
    return package


def _vnext_runtime_project(root: Path) -> Path:
    package = _runtime_project(root)
    fixtures = root / "fixtures"
    fixtures.mkdir()
    shutil.copyfile(
        PROJECT_ROOT / "fixtures" / "vnext_research_dataset.json",
        fixtures / "vnext_research_dataset.json",
    )
    shutil.copyfile(
        PROJECT_ROOT / "scripts" / "vnext_fixture_experiment.py",
        root / "scripts" / "vnext_fixture_experiment.py",
    )
    return package


def _single_test_project(root: Path, test_source: str) -> tuple[Path, Path]:
    package = _runtime_project(root)
    tests = root / "tests"
    tests.mkdir()
    (root / "reports").mkdir()
    (tests / "__init__.py").write_text(
        '"""Captured test package fixture."""\n', encoding="utf-8"
    )
    test_path = tests / "test_probe.py"
    test_path.write_text(textwrap.dedent(test_source), encoding="utf-8")
    return package, test_path


def _pad_source(source: str, size: int) -> str:
    encoded = source.encode("utf-8")
    if len(encoded) > size:
        raise AssertionError("source cannot be padded to a smaller size")
    remaining = size - len(encoded)
    if remaining == 0:
        return source
    if remaining == 1:
        return source + "\n"
    return source + "#" + (" " * (remaining - 2)) + "\n"


def _isolated_launcher_probe(source: str, *arguments: str) -> dict[str, object]:
    """Introspect launcher helpers only under its required startup contract."""

    program = (
        "import json,runpy,sys\n"
        "namespace=runpy.run_path(sys.argv[1])\n"
        + textwrap.dedent(source)
    )
    result = subprocess.run(
        [PYTHON, "-I", "-S", "-B", "-c", program, str(LAUNCHER), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError("isolated launcher probe did not emit an object")
    return value


class IsolatedLauncherTests(unittest.TestCase):
    def test_directory_name_enumeration_stops_before_retaining_cap_plus_one(
        self,
    ) -> None:
        observed = _isolated_launcher_probe(
            '''
            import os
            bounded_names = namespace["_bounded_directory_names"]
            observations = {"name_reads": 0, "successful_yields": 0, "comparisons": 0}
            class ObservedName:
                def __init__(self, value): self.value = value
                def __lt__(self, other):
                    observations["comparisons"] += 1
                    return self.value < other.value
            class Entry:
                def __init__(self, value): self.value = value
                @property
                def name(self):
                    observations["name_reads"] += 1
                    return ObservedName(self.value)
            class Scan:
                def __init__(self, values): self._entries = iter(Entry(value) for value in values); self.exited = False
                def __enter__(self): return self
                def __exit__(self, *_args): self.exited = True
                def __iter__(self): return self
                def __next__(self):
                    entry = next(self._entries); observations["successful_yields"] += 1; return entry
            original_scandir, original_listdir = os.scandir, os.listdir
            overflowing = Scan(("d", "c", "b", "a", "never-read"))
            os.scandir = lambda _path: overflowing
            os.listdir = lambda _path: (_ for _ in ()).throw(AssertionError("full directory materialization used"))
            try:
                try: bounded_names(91, maximum=3, overflow_message="bounded overflow")
                except SystemExit as error: overflow = str(error)
            finally: os.scandir, os.listdir = original_scandir, original_listdir
            overflow_result = dict(observations, exited=overflowing.exited, error=overflow)
            observations.update(name_reads=0, successful_yields=0, comparisons=0)
            exact = Scan(("z", "a", "m"))
            os.scandir = lambda _path: exact
            os.listdir = lambda _path: (_ for _ in ()).throw(AssertionError("full directory materialization used"))
            try: names = [name.value for name in bounded_names(92, maximum=3, overflow_message="bounded overflow")]
            finally: os.scandir, os.listdir = original_scandir, original_listdir
            print(json.dumps({"overflow": overflow_result, "exact": dict(observations, exited=exact.exited, names=names)}))
            '''
        )
        overflow = observed["overflow"]
        exact = observed["exact"]
        self.assertEqual(overflow["successful_yields"], 4)
        self.assertEqual(overflow["name_reads"], 3)
        self.assertEqual(overflow["comparisons"], 0)
        self.assertTrue(overflow["exited"])
        self.assertEqual(overflow["error"], "bounded overflow")
        self.assertEqual(exact["names"], ["a", "m", "z"])
        self.assertEqual(exact["successful_yields"], 3)
        self.assertEqual(exact["name_reads"], 3)
        self.assertGreater(exact["comparisons"], 0)
        self.assertTrue(exact["exited"])

    def test_capture_and_reattest_share_bounded_directory_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        self.assertTrue(True)
                """,
            )
            root = root.resolve(strict=True)
            observed = _isolated_launcher_probe(
                '''
                from pathlib import Path
                canonical_regular_file = namespace["_canonical_regular_file"]
                captured_tree = namespace["_CapturedTree"]
                launcher_globals = captured_tree.__init__.__globals__
                original = launcher_globals["_bounded_directory_names"]
                calls = []
                def observed(descriptor, *, maximum, overflow_message):
                    calls.append([maximum, overflow_message])
                    return original(descriptor, maximum=maximum, overflow_message=overflow_message)
                launcher_globals["_bounded_directory_names"] = observed
                root = Path(sys.argv[2]).resolve(strict=True)
                launcher, source, identity = canonical_regular_file(root / "scripts" / "scientist_one_cli.py")
                tree = captured_tree(root, launcher, source, identity, capture_tests=True)
                initial = list(calls)
                calls.clear()
                tree.attest_live_tree()
                print(json.dumps({"initial": initial, "reattest": calls, "max_source": launcher_globals["_MAX_SOURCE_ENTRIES"], "max_tests": launcher_globals["_MAX_TEST_ENTRIES"]}))
                ''',
                str(root),
            )

        self.assertEqual(
            observed["initial"],
            [
                [1, "unexpected top-level entry in the Scientist-One source root"],
                [
                    observed["max_source"],
                    "Scientist-One captured source inventory is invalid",
                ],
                [
                    observed["max_tests"] + 1,
                    "Scientist-One captured test inventory is invalid",
                ],
            ],
        )
        self.assertEqual(
            observed["reattest"],
            [
                [1, "Scientist-One source directory names changed after capture"],
                [
                    observed["max_source"],
                    "Scientist-One package names changed after capture",
                ],
                [
                    observed["max_tests"] + 1,
                    "Scientist-One test names changed after capture",
                ],
            ],
        )

    def test_real_launcher_requires_all_isolation_flags(self) -> None:
        cases = (
            ([PYTHON, "-S", "-B", str(LAUNCHER), "--help"], "-I -S -B"),
            ([PYTHON, "-I", "-B", str(LAUNCHER), "--help"], "-I -S -B"),
            ([PYTHON, "-I", "-S", str(LAUNCHER), "--help"], "-I -S -B"),
            (
                [PYTHON, "-O", "-I", "-S", "-B", str(LAUNCHER), "--help"],
                "-I -S -B",
            ),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                result = subprocess.run(
                    command,
                    cwd=PROJECT_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_evidence_shims_fail_closed_before_project_import(self) -> None:
        for shim in (TEST_RUNNER_SHIM, AUDIT_RUNNER_SHIM):
            with self.subTest(shim=shim.name):
                source = shim.read_text(encoding="utf-8")
                self.assertNotIn("sys.path.append", source)
                self.assertNotIn("sys.path.insert", source)
                self.assertNotIn("from scientist_one", source)
                self.assertNotIn("import scientist_one", source)
                result = subprocess.run(
                    [PYTHON, "-S", "-B", str(shim)],
                    cwd=PROJECT_ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("-I -S -B", result.stderr)

    def test_evidence_capability_is_bound_to_the_captured_loader(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import sys
                import unittest
                import scientist_one.security as security
                class ProbeTests(unittest.TestCase):
                    def test_evidence_capability(self):
                        capability = sys._scientist_one_captured_evidence_capability
                        self.assertIs(capability, security.__loader__)
                        self.assertIs(capability, security.__spec__.loader)
                        self.assertIs(capability, sys.meta_path[0])
                        self.assertEqual(
                            sum(item is capability for item in sys.meta_path), 1
                        )
                        self.assertFalse(
                            hasattr(sys, "_scientist_one_isolated_launcher")
                        )
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_captured_test_discovery_resolves_only_captured_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                from .test_support import VALUE

                class ProbeTests(unittest.TestCase):
                    def test_captured_sibling(self):
                        self.assertEqual(VALUE, "captured")
                """,
            )
            (root / "tests" / "test_support.py").write_text(
                'VALUE = "captured"\n', encoding="utf-8"
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            report = json.loads(
                (root / "reports" / "test_results.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(report["successful"])
            self.assertEqual(report["tests_run"], 1)

        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                from .test_not_captured import VALUE
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "uncaptured Scientist-One test module: "
                "tests.test_not_captured",
                result.stderr,
            )

    def test_public_package_support_and_method_import_are_captured(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest

                class ProbeTests(unittest.TestCase):
                    def test_method_time_import(self):
                        from tests import PACKAGE_VALUE
                        from tests.provider_fixtures import SUPPORT_VALUE
                        self.assertEqual((PACKAGE_VALUE, SUPPORT_VALUE), ("package", "support"))
                """,
            )
            (root / "tests" / "__init__.py").write_text(
                'PACKAGE_VALUE = "package"\n', encoding="utf-8"
            )
            (root / "tests" / "provider_fixtures.py").write_text(
                'SUPPORT_VALUE = "support"\n', encoding="utf-8"
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            report = json.loads(
                (root / "reports" / "test_results.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["tests_run"], 1)
            self.assertEqual(
                [
                    entry["path"]
                    for entry in report["test_source_attestation"]["entries"]
                ],
                [
                    "tests/__init__.py",
                    "tests/provider_fixtures.py",
                    "tests/test_probe.py",
                ],
            )
            self.assertEqual(
                report["worker_isolation"]["modules"][0]["loaded_test_modules"],
                [
                    {
                        "module_name": "tests",
                        "sha256": hashlib.sha256(
                            b'PACKAGE_VALUE = "package"\n'
                        ).hexdigest(),
                    },
                    {
                        "module_name": "tests.provider_fixtures",
                        "sha256": hashlib.sha256(
                            b'SUPPORT_VALUE = "support"\n'
                        ).hexdigest(),
                    },
                    {
                        "module_name": "tests.test_probe",
                        "sha256": hashlib.sha256(
                            (root / "tests" / "test_probe.py").read_bytes()
                        ).hexdigest(),
                    },
                ],
            )

    def test_selected_module_is_bound_on_the_captured_package(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest

                class ProbeTests(unittest.TestCase):
                    def test_normal_self_import(self):
                        import sys
                        import tests.test_probe
                        self.assertIs(tests.test_probe, sys.modules[__name__])
                        self.assertIs(tests.test_probe.ProbeTests, type(self))
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            report = json.loads(
                (root / "reports" / "test_results.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(report["successful"])
            self.assertEqual(report["tests_run"], 1)

    def test_captured_test_cannot_forge_its_worker_or_parent_suite_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import __main__
                import unittest

                class ForgedResult:
                    testsRun = 1
                    failures = []
                    errors = []
                    skipped = []
                    expectedFailures = []
                    unexpectedSuccesses = []
                    def wasSuccessful(self):
                        return True

                class ForgedRunner:
                    def __init__(self, *args, **kwargs):
                        pass
                    def run(self, suite):
                        return ForgedResult()

                unittest.TextTestRunner = ForgedRunner
                unittest.TestCase.run = lambda self, result=None: ForgedResult()
                unittest.TestSuite.run = lambda self, result=None: ForgedResult()
                unittest.TestResult.addFailure = lambda self, test, error: None
                __main__._TEST_WORKER_FAILED = 0
                __main__._run_test_module = lambda *args, **kwargs: 0

                class PoisonTests(unittest.TestCase):
                    def test_control_passes(self):
                        self.assertTrue(True)

                    def test_would_fail(self):
                        self.fail("the poisoned module hid its own failure")
                """,
            )

            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr or result.stdout)
            report = json.loads(
                (root / "reports" / "test_results.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(report["successful"])
            self.assertEqual(report["tests_run"], 2)
            self.assertEqual(report["failures"], 1)
            self.assertEqual(
                report["worker_isolation"]["module_count"],
                1,
            )
            self.assertIn("test_would_fail", report["output"])

    def test_preexisting_evidence_capability_is_rejected_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            outer = Path(raw_root)
            root = outer / "project"
            root.mkdir()
            _minimal_project(root, "def main():\n    return 0\n")
            bootstrap = outer / "bootstrap.py"
            bootstrap.write_text(
                "import runpy,sys\n"
                "sys._scientist_one_captured_evidence_capability=object()\n"
                "runpy.run_path(sys.argv[1],run_name='__main__')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-S",
                    "-B",
                    str(bootstrap),
                    str(root / "scripts" / LAUNCHER.name),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("evidence capability existed before capture", result.stderr)

    def test_missing_isolation_is_rejected_before_project_import_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copyfile(LAUNCHER, scripts / LAUNCHER.name)
            (scripts / "hashlib.py").write_text(
                "from pathlib import Path\nPath('early-shadow-ran').write_text('bad')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [PYTHON, "-S", "-B", str(scripts / LAUNCHER.name)],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("-I -S -B", result.stderr)
            self.assertFalse((root / "early-shadow-ran").exists())

    def test_direct_unisolated_module_entry_is_refused(self) -> None:
        result = subprocess.run(
            [PYTHON, "-S", "-B", "-m", "scientist_one", "--help"],
            cwd=PROJECT_ROOT / "src",
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("UnsafeStartupError", result.stdout)
        self.assertIn("refusing unisolated startup", result.stdout)

    def test_legacy_module_entry_does_not_import_poisoned_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            package = _runtime_project(root)
            orchestrator = package / "orchestrator.py"
            benign = orchestrator.read_bytes()
            orchestrator.write_text(
                "from pathlib import Path\n"
                "Path('legacy-project-pyc-ran').write_text('bad', encoding='utf-8')\n",
                encoding="utf-8",
            )
            _compile_pyc_with_launcher_python(
                orchestrator,
                py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            orchestrator.write_bytes(benign)
            (root / "src" / "json.py").write_text(
                "from pathlib import Path\n"
                "Path('legacy-json-shadow-ran').write_text('bad', encoding='utf-8')\n",
                encoding="utf-8",
            )

            control = subprocess.run(
                [
                    PYTHON,
                    "-S",
                    "-B",
                    "-c",
                    "import scientist_one.orchestrator",
                ],
                cwd=root / "src",
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            project_marker = root / "src" / "legacy-project-pyc-ran"
            self.assertTrue(project_marker.is_file())
            project_marker.unlink()

            result = subprocess.run(
                [PYTHON, "-S", "-B", "-m", "scientist_one", "--help"],
                cwd=root / "src",
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr or result.stdout)
            self.assertIn("UnsafeStartupError", result.stdout)
            self.assertFalse(project_marker.exists())
            self.assertFalse((root / "src" / "legacy-json-shadow-ran").exists())

    def test_legacy_console_import_stops_before_project_or_stdlib_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            package = _runtime_project(root)
            (package / "orchestrator.py").write_text(
                "from pathlib import Path\n"
                "Path('console-project-import-ran').write_text('bad', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (root / "src" / "json.py").write_text(
                "from pathlib import Path\n"
                "Path('console-json-shadow-ran').write_text('bad', encoding='utf-8')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [PYTHON, "-S", "-B", "-c", "import scientist_one.cli"],
                cwd=root / "src",
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("UnsafeStartupError", result.stderr)
            self.assertFalse((root / "src" / "console-project-import-ran").exists())
            self.assertFalse((root / "src" / "console-json-shadow-ran").exists())

    def test_test_import_capability_does_not_authorize_cli_main(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _runtime_project(root)
            result = subprocess.run(
                [
                    PYTHON,
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import sys;"
                        "sys._scientist_one_test_runner=True;"
                        "from scientist_one.cli import main;"
                        "raise SystemExit(main(['preflight']))"
                    ),
                ],
                cwd=root / "src",
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr or result.stdout)
            self.assertIn("UnsafeStartupError", result.stdout)

    def test_positive_isolated_help(self) -> None:
        result = _run_launcher(PROJECT_ROOT, "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Offline, custody-aware Scientist-One", result.stdout)
        self.assertIn("preflight", result.stdout)

    def test_attestation_and_marker_exist_only_at_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            _minimal_project(
                root,
                """
                import sys
                if hasattr(sys, "_scientist_one_isolated_launcher"):
                    raise RuntimeError("marker was set during module import")
                if hasattr(sys, "_scientist_one_captured_source_attestation"):
                    raise RuntimeError("attestation was exposed during module import")
                if hasattr(sys, "_scientist_one_captured_evidence_capability"):
                    raise RuntimeError("evidence capability was set during production import")
                def main():
                    if sys._scientist_one_isolated_launcher is not True:
                        return 81
                    if hasattr(sys, "_scientist_one_captured_import_capability"):
                        return 86
                    if hasattr(sys, "_scientist_one_captured_evidence_capability"):
                        return 87
                    version, entries = sys._scientist_one_captured_source_attestation
                    paths = tuple(entry[0] for entry in entries)
                    if version != "SCIENTIST_ONE_CAPTURED_SOURCE_V1":
                        return 82
                    if paths != tuple(sorted(paths)):
                        return 83
                    if "scripts/scientist_one_cli.py" not in paths:
                        return 84
                    if "src/scientist_one/cli.py" not in paths:
                        return 85
                    return 0
                """,
            )
            result = _run_launcher(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_positive_isolated_preflight_in_clean_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _runtime_project(root)

            result = _run_launcher(root, "preflight", timeout=30)
            self.assertIn(result.returncode, (0, 1), result.stderr or result.stdout)
            payload = json.loads(result.stdout)
            self.assertIn(payload["status"], ("PASS", "PAUSE"))
            self.assertTrue(payload["offline"])

    def test_positive_isolated_start_binds_captured_source_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _runtime_project(root)
            result = _run_launcher(root, "start", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "PASS")
            inventories = tuple(
                (root / "runs" / payload["run_id"] / "artifacts" / "calibrate").glob(
                    "frozen_source_inventory-*.json"
                )
            )
            self.assertEqual(len(inventories), 1)
            inventory = json.loads(inventories[0].read_text(encoding="utf-8"))
            entries = {entry["path"]: entry for entry in inventory["entries"]}
            launcher_bytes = (root / "scripts" / LAUNCHER.name).read_bytes()
            self.assertEqual(
                entries["scripts/scientist_one_cli.py"],
                {
                    "path": "scripts/scientist_one_cli.py",
                    "sha256": hashlib.sha256(launcher_bytes).hexdigest(),
                    "size": len(launcher_bytes),
                },
            )

    def test_guarded_research_os_completion_is_bound_and_tamper_detected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _vnext_runtime_project(root)
            run_id = "isolated-guarded-vnext"

            launched = _run_launcher(
                root,
                "research-os-fixture",
                "--run-id",
                run_id,
                # The selected Anaconda runtime completed this guarded
                # authority replay in about 560 seconds uncontended. Keep a
                # finite 15-minute ceiling to distinguish bounded work from a
                # hang while allowing ordinary host variance.
                timeout=900,
            )
            self.assertEqual(
                launched.returncode,
                0,
                launched.stderr or launched.stdout,
            )
            launched_payload = json.loads(launched.stdout)
            self.assertEqual(launched_payload["status"], "PASS")

            run_dir = root / "runs" / run_id
            operation = json.loads(
                (run_dir / "fixture-operation.json").read_bytes()
            )
            self.assertEqual(
                operation["schema_version"],
                "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2",
            )
            self.assertEqual(operation["status"], "COMPLETE")
            self.assertEqual(operation["launch_mode"], "GUARDED_PRODUCTION")
            guarded_path = run_dir / "guarded-launch.json"
            guarded_bytes = guarded_path.read_bytes()
            self.assertEqual(
                hashlib.sha256(guarded_bytes).hexdigest(),
                operation["guarded_launch_receipt_sha256"],
            )
            guarded = json.loads(guarded_bytes)
            self.assertEqual(
                set(guarded),
                {
                    "canonical_project_root",
                    "captured_source_inventory",
                    "command_context",
                    "created_at",
                    "launch_mode",
                    "root_identity",
                    "run_id",
                    "schema_version",
                    "scientific_authority",
                },
            )
            self.assertEqual(
                guarded["schema_version"], "SCIENTIST_ONE_GUARDED_LAUNCH_V1"
            )
            self.assertEqual(
                guarded["canonical_project_root"],
                str(root.resolve(strict=True)),
            )
            self.assertEqual(
                guarded["command_context"],
                [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    "scripts/scientist_one_cli.py",
                    "research-os-fixture",
                    "--run-id",
                    run_id,
                ],
            )
            self.assertFalse(guarded["scientific_authority"])
            inventory_paths = {
                item["path"]
                for item in guarded["captured_source_inventory"]["entries"]
            }
            self.assertIn("scripts/scientist_one_cli.py", inventory_paths)
            self.assertIn("src/scientist_one/orchestrator.py", inventory_paths)
            self.assertIn("src/scientist_one/research_os.py", inventory_paths)

            verified = _run_launcher(root, "verify", run_id, timeout=90)
            self.assertEqual(
                verified.returncode,
                0,
                verified.stderr or verified.stdout,
            )
            verification = json.loads(verified.stdout)
            self.assertEqual(verification["status"], "PASS", verification)
            self.assertTrue(verification["completion_authorities_valid"])
            self.assertTrue(verification["production_completion_valid"])
            self.assertEqual(
                verification["launch_provenance"]["mode"],
                "GUARDED_PRODUCTION",
            )
            self.assertTrue(
                verification["launch_provenance"][
                    "guarded_production_launch_valid"
                ]
            )
            self.assertFalse(verification["scientific_evidence_established"])

            guarded["command_context"][-1] = "substituted-run"
            guarded_path.chmod(0o600)
            guarded_path.write_bytes(
                json.dumps(guarded, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
            tampered = _run_launcher(root, "verify", run_id, timeout=90)
            self.assertEqual(tampered.returncode, 1, tampered.stderr)
            tampered_verification = json.loads(tampered.stdout)
            self.assertEqual(tampered_verification["status"], "FAIL")
            self.assertFalse(
                tampered_verification["completion_authorities_valid"]
            )
            self.assertFalse(
                tampered_verification["production_completion_valid"]
            )
            self.assertTrue(
                any(
                    "guarded launch receipt hash differs" in issue
                    for issue in tampered_verification["issues"]
                )
            )
            self.assertFalse(
                tampered_verification["scientific_evidence_established"]
            )

    def test_sitecustomize_and_project_top_level_shadow_are_never_activated(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            package, _ = _minimal_project(
                root,
                """
                import json
                from pathlib import Path
                def main():
                    root = Path(__file__).parents[2]
                    if (root / "sitecustomize-ran").exists():
                        raise RuntimeError("sitecustomize executed")
                    if Path(json.__file__).is_relative_to(root):
                        raise RuntimeError("project json shadow loaded")
                    return 0
                """,
            )
            source = package.parent
            (source / "sitecustomize.py").write_text(
                "from pathlib import Path\nPath('sitecustomize-ran').write_text('bad')\n",
                encoding="utf-8",
            )
            (source / "json.py").write_text(
                "raise RuntimeError('project json shadow loaded')\n", encoding="utf-8"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(source)
            result = _run_launcher(root, environment=environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected top-level entry", result.stderr)
            self.assertFalse((root / "sitecustomize-ran").exists())

    def test_unchecked_and_timestamp_pyc_cannot_execute(self) -> None:
        modes = (
            py_compile.PycInvalidationMode.UNCHECKED_HASH,
            py_compile.PycInvalidationMode.TIMESTAMP,
        )
        for mode in modes:
            with self.subTest(mode=mode.name), tempfile.TemporaryDirectory() as raw_root:
                root = Path(raw_root)
                malicious = textwrap.dedent(
                    """
                    from pathlib import Path
                    Path("poisoned-pyc-ran").write_text("bad", encoding="utf-8")
                    def main():
                        return 77
                    """
                )
                benign = _pad_source(
                    "def main():\n    return 0\n", len(malicious.encode("utf-8"))
                )
                _, cli = _minimal_project(root, malicious)
                fixed_ns = 1_700_000_000_000_000_000
                os.utime(cli, ns=(fixed_ns, fixed_ns))
                _compile_pyc_with_launcher_python(cli, mode)
                cli.write_text(benign, encoding="utf-8")
                os.utime(cli, ns=(fixed_ns, fixed_ns))

                # Prove the prepared cache is executable through the normal
                # filesystem importer, then remove only its harmless marker.
                control = subprocess.run(
                    [
                        PYTHON,
                        "-S",
                        "-B",
                        "-c",
                        "import sys;sys.path.insert(0,'src');import scientist_one.cli",
                    ],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(control.returncode, 0, control.stderr)
                poison_marker = root / "poisoned-pyc-ran"
                self.assertTrue(poison_marker.is_file())
                poison_marker.unlink()

                result = _run_launcher(root)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(poison_marker.exists())

    def test_evidence_test_runner_ignores_unchecked_and_timestamp_test_pyc(self) -> None:
        modes = (
            py_compile.PycInvalidationMode.UNCHECKED_HASH,
            py_compile.PycInvalidationMode.TIMESTAMP,
        )
        for mode in modes:
            with self.subTest(mode=mode.name), tempfile.TemporaryDirectory() as raw_root:
                root = Path(raw_root) / "ScientistOne"
                malicious = textwrap.dedent(
                    """
                    from pathlib import Path
                    Path("evidence-test-pyc-ran").write_text("bad", encoding="utf-8")
                    import unittest
                    class ProbeTests(unittest.TestCase):
                        def test_probe(self):
                            self.assertTrue(True)
                    """
                )
                benign = _pad_source(
                    textwrap.dedent(
                        """
                        import unittest
                        class ProbeTests(unittest.TestCase):
                            def test_probe(self):
                                self.assertTrue(True)
                        """
                    ),
                    len(malicious.encode("utf-8")),
                )
                _, test_path = _single_test_project(root, malicious)
                fixed_ns = 1_700_000_000_000_000_000
                os.utime(test_path, ns=(fixed_ns, fixed_ns))
                _compile_pyc_with_launcher_python(test_path, mode)
                test_path.write_text(benign, encoding="utf-8")
                os.utime(test_path, ns=(fixed_ns, fixed_ns))

                control = subprocess.run(
                    [
                        PYTHON,
                        "-S",
                        "-B",
                        "-c",
                        "import sys;sys.path.insert(0,'tests');import test_probe",
                    ],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(control.returncode, 0, control.stderr)
                poison_marker = root / "evidence-test-pyc-ran"
                self.assertTrue(poison_marker.is_file())
                poison_marker.unlink()

                result = subprocess.run(
                    [
                        PYTHON,
                        "-I",
                        "-S",
                        "-B",
                        str(root / "scripts" / TEST_RUNNER_SHIM.name),
                    ],
                    cwd=root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                self.assertFalse(poison_marker.exists())
                report = json.loads(
                    (root / "reports" / "test_results.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertTrue(report["successful"])
                self.assertEqual(report["tests_run"], 1)
                self.assertEqual(
                    report["command"],
                    "python3 -I -S -B scripts/scientist_one_cli.py test-suite",
                )
                project_paths = {
                    entry["path"]
                    for entry in report["project_source_attestation"]["entries"]
                }
                self.assertIn("scripts/scientist_one_cli.py", project_paths)
                self.assertIn("src/scientist_one/cli.py", project_paths)
                self.assertEqual(
                    [
                        entry["path"]
                        for entry in report["test_source_attestation"]["entries"]
                    ],
                    ["tests/__init__.py", "tests/test_probe.py"],
                )

    def test_evidence_test_runner_rejects_test_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                from pathlib import Path
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        tests = Path(__file__).parent
                        held = tests.parent / "tests-captured"
                        tests.rename(held)
                        tests.mkdir()
                        tests.joinpath("test_probe.py").write_text(
                            "", encoding="utf-8"
                        )
                        self.assertTrue(True)
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "tests directory identity changed after capture", result.stderr
            )
            self.assertFalse((root / "reports" / "test_results.json").exists())

    def test_evidence_test_report_is_not_published_after_final_attestation_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                from pathlib import Path
                import scientist_one.security as security
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        source = Path(security.__file__).parent / "cli.py"
                        replacement = source.parents[2] / "replacement-cli.py"
                        replacement.write_bytes(source.read_bytes())
                        replacement.replace(source)
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "source identity changed after capture: cli.py", result.stderr
            )
            self.assertFalse((root / "reports" / "test_results.json").exists())

    def test_evidence_report_rejects_captured_file_mutate_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                from pathlib import Path
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        launcher = (
                            Path(__file__).parents[1]
                            / "scripts"
                            / "scientist_one_cli.py"
                        )
                        original = launcher.read_bytes()
                        launcher.write_bytes(original + b"\\n# temporary mutation\\n")
                        launcher.write_bytes(original)
                        self.assertEqual(launcher.read_bytes(), original)
                """,
            )
            result = _run_launcher(root, "test-suite", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "launcher identity changed after capture", result.stderr
            )
            self.assertFalse((root / "reports" / "test_results.json").exists())

    def test_evidence_audit_runner_rejects_test_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            package, test_path = _single_test_project(
                root,
                """
                import unittest
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        self.assertTrue(True)
                """,
            )
            audit_source = package / "audit.py"
            benign = audit_source.read_text(encoding="utf-8")
            future = "from __future__ import annotations\n"
            self.assertIn(future, benign)
            audit_source.write_text(
                benign.replace(
                    future,
                    future
                    + "import os as _evidence_os\n"
                    + "from pathlib import Path as _EvidencePath\n"
                    + "_evidence_tests = _EvidencePath(__file__).parents[2] / 'tests'\n"
                    + "_evidence_held = _evidence_tests.parent / 'tests-captured'\n"
                    + "_evidence_tests.rename(_evidence_held)\n"
                    + "_evidence_tests.mkdir()\n"
                    + "_evidence_tests.joinpath('test_probe.py').write_bytes("
                    + "_evidence_held.joinpath('test_probe.py').read_bytes())\n",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(test_path.is_file())

            result = _run_launcher(root, "audit-project", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "tests directory identity changed after capture", result.stderr
            )
            self.assertFalse((root / "reports" / "final_audit.json").exists())

    def test_evidence_audit_runner_rejects_source_replacement_before_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            package, _ = _single_test_project(
                root,
                """
                import unittest
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        self.assertTrue(True)
                """,
            )
            audit_source = package / "audit.py"
            benign = audit_source.read_text(encoding="utf-8")
            replacement = root / "replacement-audit.py"
            replacement.write_text(benign, encoding="utf-8")
            future = "from __future__ import annotations\n"
            self.assertIn(future, benign)
            audit_source.write_text(
                benign.replace(
                    future,
                    future
                    + "import os as _evidence_os\n"
                    + "from pathlib import Path as _EvidencePath\n"
                    + "_evidence_source = _EvidencePath(__file__)\n"
                    + "_evidence_os.replace("
                    + "_evidence_source.parents[2] / 'replacement-audit.py', "
                    + "_evidence_source)\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-S",
                    "-B",
                    str(root / "scripts" / AUDIT_RUNNER_SHIM.name),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "source identity changed after capture: audit.py", result.stderr
            )
            self.assertFalse((root / "reports" / "final_audit.json").exists())

    def test_evidence_audit_runner_preserves_clean_audit_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            _single_test_project(
                root,
                """
                import unittest
                class ProbeTests(unittest.TestCase):
                    def test_probe(self):
                        self.assertTrue(True)
                """,
            )
            result = _run_launcher(root, "audit-project", timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertIn("passed=true", result.stdout)
            report = json.loads(
                (root / "reports" / "final_audit.json").read_text(encoding="utf-8")
            )
            self.assertTrue(report["passed"])

    def test_source_file_swap_during_import_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            _minimal_project(
                root,
                """
                import os
                from pathlib import Path
                source = Path(__file__)
                replacement = source.parents[2] / "replacement-cli.py"
                replacement.write_text("def main(): return 0\\n", encoding="utf-8")
                os.replace(replacement, source)
                def main():
                    return 0
                """,
            )
            result = _run_launcher(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source identity changed after capture: cli.py", result.stderr)

    def test_launcher_replacement_between_initial_verification_and_capture_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            outer = Path(raw_root)
            root = outer / "project"
            root.mkdir()
            _minimal_project(root, "def main():\n    return 0\n")
            launcher = root / "scripts" / LAUNCHER.name
            replacement = outer / "replacement-launcher.py"
            replacement.write_bytes(launcher.read_bytes() + b"\n# replacement\n")
            bootstrap = outer / "bootstrap.py"
            bootstrap.write_text(
                textwrap.dedent(
                    """
                    import os
                    from pathlib import Path
                    import runpy
                    import sys

                    original_open = os.open
                    root = Path(sys.argv[2]).resolve()
                    launcher = Path(sys.argv[1]).resolve()
                    replacement = Path(sys.argv[3]).resolve()
                    replaced = False

                    def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
                        global replaced
                        if (
                            not replaced
                            and dir_fd is None
                            and Path(path) == root
                            and flags & getattr(os, "O_DIRECTORY", 0)
                        ):
                            os.replace(replacement, launcher)
                            replaced = True
                        return original_open(path, flags, mode, dir_fd=dir_fd)

                    os.open = guarded_open
                    runpy.run_path(str(launcher), run_name="__main__")
                    """
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-S",
                    "-B",
                    str(bootstrap),
                    str(launcher),
                    str(root),
                    str(replacement),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("launcher changed after initial verification", result.stderr)

    def test_source_file_swap_during_dispatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            _minimal_project(
                root,
                """
                import os
                from pathlib import Path
                def main():
                    source = Path(__file__)
                    replacement = source.parents[2] / "replacement-cli.py"
                    replacement.write_text("def main(): return 0\\n", encoding="utf-8")
                    os.replace(replacement, source)
                    return 0
                """,
            )
            result = _run_launcher(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source identity changed after capture: cli.py", result.stderr)

    def test_captured_digest_cannot_be_replaced_by_live_digest_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            malicious = textwrap.dedent(
                """
                import hashlib
                import os
                from pathlib import Path
                import sys
                CAPTURED = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                def main():
                    source = Path(__file__)
                    replacement = source.parents[2] / "benign-cli.py"
                    replacement.write_text("def main(): return 0\\n", encoding="utf-8")
                    os.replace(replacement, source)
                    version, entries = sys._scientist_one_captured_source_attestation
                    claimed = {entry[0]: entry[1] for entry in entries}
                    if version != "SCIENTIST_ONE_CAPTURED_SOURCE_V1":
                        return 91
                    if claimed["src/scientist_one/cli.py"] != CAPTURED:
                        Path("provenance-rebound").write_text("bad", encoding="utf-8")
                        return 92
                    return 0
                """
            )
            _minimal_project(root, malicious)
            result = _run_launcher(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source identity changed after capture: cli.py", result.stderr)
            self.assertFalse((root / "provenance-rebound").exists())

    def test_real_start_rejects_source_replacement_before_inventory_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root) / "ScientistOne"
            package = _runtime_project(root)
            cli = package / "cli.py"
            benign = cli.read_text(encoding="utf-8")
            signature = "def main(argv: Sequence[str] | None = None) -> int:\n"
            self.assertIn(signature, benign)
            injected = (
                signature
                + "    (Path.cwd() / 'benign-cli.py').replace(Path(__file__))\n"
            )
            malicious = benign.replace(signature, injected, 1)
            (root / "benign-cli.py").write_text(benign, encoding="utf-8")
            cli.write_text(malicious, encoding="utf-8")

            result = _run_launcher(root, "start", timeout=30)
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "ERROR")
            self.assertIn("captured source", payload["message"])
            self.assertFalse(
                any(
                    path.name.startswith("frozen_source_inventory-")
                    for path in (root / "runs").rglob("*.json")
                )
            )

    def test_source_directory_swap_during_import_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            _minimal_project(
                root,
                """
                import os
                from pathlib import Path
                package = Path(__file__).parent
                moved = package.parents[1] / "scientist_one-captured"
                os.rename(package, moved)
                package.mkdir()
                package.joinpath("__init__.py").write_text("", encoding="utf-8")
                package.joinpath("cli.py").write_text("def main(): return 0\\n", encoding="utf-8")
                def main():
                    return 0
                """,
            )
            result = _run_launcher(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("package directory identity changed after capture", result.stderr)

    def test_loaded_module_foreign_loader_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            _minimal_project(
                root,
                """
                __loader__ = object()
                def main():
                    return 0
                """,
            )
            result = _run_launcher(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("loaded-module attestation failed: scientist_one.cli", result.stderr)

    def test_preinstalled_foreign_finder_cannot_load_scientist_one(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            outer = Path(raw_root)
            root = outer / "project"
            root.mkdir()
            _minimal_project(root, "def main():\n    return 0\n")
            bootstrap = outer / "bootstrap.py"
            bootstrap.write_text(
                textwrap.dedent(
                    """
                    import importlib.abc
                    import importlib.machinery
                    from pathlib import Path
                    import runpy
                    import sys

                    class ForeignLoader(importlib.abc.Loader):
                        def create_module(self, spec):
                            return None
                        def exec_module(self, module):
                            Path("foreign-loader-ran").write_text("bad", encoding="utf-8")
                            module.main = lambda: 91

                    class ForeignFinder(importlib.abc.MetaPathFinder):
                        def find_spec(self, fullname, path=None, target=None):
                            if fullname == "scientist_one" or fullname.startswith("scientist_one."):
                                return importlib.machinery.ModuleSpec(fullname, ForeignLoader())
                            return None

                    sys.meta_path.insert(0, ForeignFinder())
                    runpy.run_path(sys.argv[1], run_name="__main__")
                    """
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-S",
                    "-B",
                    str(bootstrap),
                    str(root / "scripts" / LAUNCHER.name),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "foreign-loader-ran").exists())

    def test_nonexistent_project_import_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            outer = Path(raw_root)
            root = outer / "project"
            root.mkdir()
            _minimal_project(root, "def main():\n    return 0\n")
            bootstrap = outer / "bootstrap.py"
            bootstrap.write_text(
                "import sys\n"
                "sys.path.insert(0, sys.argv[2])\n"
                "script = sys.argv[1]\n"
                "namespace = {'__name__': '__main__', '__file__': script}\n"
                "with open(script, 'rb') as handle:\n"
                "    code = compile(handle.read(), script, 'exec')\n"
                "exec(code, namespace)\n",
                encoding="utf-8",
            )
            future_path = root / "future-imports"
            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-S",
                    "-B",
                    str(bootstrap),
                    str(root / "scripts" / LAUNCHER.name),
                    str(future_path),
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("project path was active before verification", result.stderr)
            self.assertFalse(future_path.exists())


if __name__ == "__main__":
    unittest.main()
