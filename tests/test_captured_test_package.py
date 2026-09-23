"""Captured-package regression controls using disposable child projects."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tests import test_isolated_launchers as fixtures


class CapturedPackageTests(unittest.TestCase):
    def test_missing_package_marker_refuses_before_test_execution(self):
        root = self.project('''
            raise AssertionError("test must not be imported")
        ''')
        (root / "tests/__init__.py").unlink()
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("test package must contain __init__.py", completed.stderr)
        self.assertNotIn("test must not be imported", completed.stderr)

    def test_preexisting_public_package_or_child_refuses_discovery(self):
        root = self.project('''
            raise AssertionError("test must not be imported")
        ''')
        observed = fixtures._isolated_launcher_probe('''
            from pathlib import Path
            import types
            root = Path(sys.argv[2]).resolve(strict=True)
            launcher, source, identity = namespace["_canonical_regular_file"](
                root / "scripts/scientist_one_cli.py")
            tree = namespace["_CapturedTree"](root, launcher, source, identity, capture_tests=True)
            refused = {}
            for name in ("tests", "tests.foreign"):
                sys.modules[name] = types.ModuleType(name)
                try:
                    namespace["_load_captured_test_suite"](tree)
                except SystemExit as error:
                    refused[name] = str(error)
                finally:
                    sys.modules.pop(name, None)
            print(json.dumps(refused))
        ''', str(root))
        self.assertEqual(set(observed), {"tests", "tests.foreign"})
        for refusal in observed.values():
            self.assertIn("captured test namespace already existed", refusal)

    def test_audit_dispatch_captures_package_without_executing_it(self):
        root = self.project('''
            raise AssertionError("tests must not execute in audit parent")
        ''')
        (root / "tests/__init__.py").write_text(
            'raise AssertionError("package must not execute in audit parent")\n')
        # This is a disposable stub exercising dispatcher wiring, NOT an audit.
        (root / "src/scientist_one/audit.py").write_text(
            'import sys\n'
            'class StubAudit:\n'
            '    passed = True\n'
            '    snapshot_digest = "stub-not-a-real-audit"\n'
            '    file_count = 0\n'
            '    total_bytes = 0\n'
            '    findings = ()\n'
            '    lockfiles = ()\n'
            '    def as_json(self): return "{}"\n'
            'def audit_project(root):\n'
            '    assert not any(n == "tests" or n.startswith("tests.") for n in sys.modules)\n'
            '    return StubAudit()\n'
            'def require_current_audit(*args, **kwargs):\n'
            '    assert not any(n == "tests" or n.startswith("tests.") for n in sys.modules)\n')
        completed = fixtures._run_launcher(root, "audit-project", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("snapshot_digest=stub-not-a-real-audit", completed.stdout)
        self.assertEqual((root / "reports/final_audit.json").read_text(), "{}")

    def test_selected_module_is_bound_on_the_real_parent_package(self):
        root = self.project('''
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_normal_self_import(self):
                    import sys
                    import tests.test_probe
                    self.assertIs(tests.test_probe, sys.modules[__name__])
                    self.assertIs(tests.test_probe.ProbeTests, type(self))
        ''')
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        report = json.loads((root / "reports/test_results.json").read_text())
        self.assertEqual(completed.returncode, 0,
                         completed.stderr or report.get("output") or completed.stdout)
        self.assertTrue(report["successful"])
        self.assertEqual(report["tests_run"], 1)

    def test_support_module_cannot_be_selected_as_direct_worker(self):
        root = self.project('''
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_value(self): pass
        ''')
        (root / "tests/provider_fixtures.py").write_text('VALUE = "support"\n')
        (root / "tests/pmc_wire_fixtures.py").write_text(
            'VALUE = "pmc-wire-support"\n'
        )
        for module in (
            "tests",
            "tests.provider_fixtures",
            "tests.pmc_wire_fixtures",
        ):
            with self.subTest(module=module):
                completed = fixtures._run_launcher(root, "__captured-test-module__", module)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("selected a non-runnable module", completed.stderr)
                self.assertFalse((root / "reports/test_results.json").exists())

    def test_reexported_support_testclass_is_not_silently_filtered(self):
        root = self.project('''
            import unittest
            from tests.provider_fixtures import ForeignTests
            class ProbeTests(unittest.TestCase):
                def test_value(self): pass
        ''')
        (root / "tests/provider_fixtures.py").write_text(
            'import unittest\nclass ForeignTests(unittest.TestCase):\n'
            '    def test_foreign(self): pass\n')
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("captured unittest discovery differs from its static inventory", completed.stderr)
        self.assertFalse((root / "reports/test_results.json").exists())

    def test_late_finder_removal_refuses_final_report(self):
        root = self.project('''
            import sys
            import tests
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_remove_finder(self):
                    sys.meta_path.remove(tests.__loader__)
        ''')
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("captured-test loader was replaced", completed.stderr)
        self.assertFalse((root / "reports/test_results.json").exists())

    def test_unknown_support_file_is_not_captured(self):
        root = self.project('''
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_value(self): pass
        ''')
        (root / "tests/unapproved_support.py").write_text('VALUE = "unknown"\n')
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected Scientist-One test entry: unapproved_support.py", completed.stderr)
        self.assertFalse((root / "reports/test_results.json").exists())

    def project(self, source):
        temporary = tempfile.TemporaryDirectory(prefix="captured-package-root-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "ScientistOne"
        fixtures._single_test_project(root, source)
        self.assertEqual((root / "scripts/scientist_one_cli.py").read_bytes(),
                         fixtures.LAUNCHER.read_bytes())
        return root

    def test_support_testcase_is_attested_but_never_selected_or_counted(self):
        root = self.project('''
            import unittest
            from tests import provider_fixtures
            class ProbeTests(unittest.TestCase):
                def test_value(self):
                    self.assertEqual(provider_fixtures.VALUE, "captured")
        ''')
        support = root / "tests/provider_fixtures.py"
        support.write_text(
            'import unittest\nVALUE = "captured"\n'
            'class NotSelected(unittest.TestCase):\n'
            '    def test_not_a_worker(self):\n'
            '        raise AssertionError("support class selected")\n', encoding="utf-8")
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        report = json.loads((root / "reports/test_results.json").read_text())
        self.assertEqual(report["tests_run"], 1)
        self.assertEqual(report["worker_isolation"]["module_count"], 1)
        worker = report["worker_isolation"]["modules"][0]
        self.assertEqual(worker["test_ids"], ["tests.test_probe.ProbeTests.test_value"])
        loaded = {row["module_name"]: row["sha256"] for row in worker["loaded_test_modules"]}
        self.assertEqual(set(loaded), {"tests", "tests.test_probe", "tests.provider_fixtures"})
        self.assertEqual(loaded["tests.provider_fixtures"], hashlib.sha256(support.read_bytes()).hexdigest())
        self.assertEqual({row["path"] for row in report["test_source_attestation"]["entries"]},
                         {"tests/__init__.py", "tests/test_probe.py", "tests/provider_fixtures.py"})

    def test_unused_captured_support_drift_prevents_report_publication(self):
        root = self.project('''
            from pathlib import Path
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_change_unused_support(self):
                    sibling = Path(__file__).with_name("provider_fixtures.py")
                    sibling.write_text("VALUE = 2\\n", encoding="utf-8")
        ''')
        (root / "tests/provider_fixtures.py").write_text("VALUE = 1\n", encoding="utf-8")
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("test source identity changed after capture: provider_fixtures.py", completed.stderr)
        self.assertFalse((root / "reports/test_results.json").exists())

    def test_module_teardown_first_import_uses_still_active_captured_finder(self):
        root = self.project('''
            import sys
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_before_late_import(self):
                    self.assertNotIn("tests.provider_fixtures", sys.modules)
            def tearDownModule():
                from tests import provider_fixtures
                package = sys.modules["tests"]
                assert provider_fixtures.VALUE == "late-captured"
                assert provider_fixtures.__loader__ is package.__loader__
                assert sys.meta_path[1] is package.__loader__
                assert package.__path__ == []
                assert provider_fixtures.__cached__ is None
        ''')
        (root / "tests/provider_fixtures.py").write_text('VALUE = "late-captured"\n', encoding="utf-8")
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        report = json.loads((root / "reports/test_results.json").read_text())
        self.assertEqual(report["tests_run"], 1)
        worker = report["worker_isolation"]["modules"][0]
        self.assertEqual({row["module_name"] for row in worker["loaded_test_modules"]},
                         {"tests", "tests.test_probe", "tests.provider_fixtures"})

    def test_captured_package_initializer_drift_prevents_report_publication(self):
        root = self.project('''
            from pathlib import Path
            import tests
            import unittest
            class ProbeTests(unittest.TestCase):
                def test_change_initializer_after_capture(self):
                    marker = Path(tests.__file__)
                    marker.write_text(marker.read_text() + "# changed\\n", encoding="utf-8")
        ''')
        completed = fixtures._run_launcher(root, "test-suite", timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("test source identity changed after capture: __init__.py", completed.stderr)
        self.assertFalse((root / "reports/test_results.json").exists())
