"""Three captured regressions reusing exact existing non-evidentiary cases.

Only these three original cases execute. Nested cases are not additional test
counts. Import the helper module without re-exporting its TestCase classes.
"""

import unittest

from tests import test_gates_paper as fixtures


class _ObservedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.started_ids = []
        self.stopped_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.stopped_ids.append(test.id())
        super().stopTest(test)


def tearDownModule():
    fixtures.tearDownModule()


class PaperSemanticFailureEdgesTests(unittest.TestCase):
    def _run_original(self, method_name):
        case = fixtures.PaperPipelineTests(methodName=method_name)
        expected_id = "tests.test_gates_paper.PaperPipelineTests." + method_name
        self.assertEqual(case.id(), expected_id)

        # Original tearDown is called by case.run on successful setup. If setup
        # fails after allocating its temporary root, outer cleanup still runs.
        # unittest records cleanup errors separately rather than hiding a case
        # assertion or setup failure. TemporaryDirectory cleanup is idempotent.
        def cleanup_partial_setup():
            temporary = getattr(case, "temporary", None)
            if temporary is not None:
                temporary.cleanup()

        self.addCleanup(cleanup_partial_setup)
        result = _ObservedResult()
        case.run(result)
        self.assertEqual(result.started_ids, [expected_id])
        self.assertEqual(result.stopped_ids, [expected_id])
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.failures, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.expectedFailures, [])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertTrue(result.wasSuccessful())

    def test_explicit_claim_strength_cannot_override_registered_evidence(self):
        self._run_original(
            "test_self_asserted_eligibility_or_strength_cannot_override_registry"
        )

    def test_paper_metric_value_unit_and_direction_mismatch_refuses(self):
        self._run_original("test_wrong_metric_value_unit_and_direction_fail_closed")

    def test_paper_method_code_and_asset_parent_mismatch_refuses(self):
        self._run_original("test_method_code_and_asset_parent_mismatch_fail_closed")
