"""Actual native storage input controls; no execution or custody authority."""

import unittest

import scientist_one.orchestrator as orchestration
from tests import test_shared_resource_authority as fixtures


class NativeStageRegressions(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SharedResourceAuthorityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_caller_prefix_override_cannot_poison_native_history(self):
        class MisleadingStage(str):
            def startswith(self, *args, **kwargs):
                return True

        before = self.fixture.filesystem_snapshot()
        with self.assertRaises(orchestration.OrchestrationError):
            orchestration._persist_resource_authority_for(
                self.fixture.root, fixtures.RUN_ID,
                MisleadingStage("not-a-resource-stage"), self.fixture.state(0),
            )
        self.assertEqual(self.fixture.filesystem_snapshot(), before)
        self.assertEqual(self.fixture.history(), ())

    def test_caller_equality_override_cannot_claim_another_head(self):
        class AliasingStage(str):
            def __eq__(self, other):
                return True

            __hash__ = str.__hash__

        self.fixture.publish("resource_runtime_initial", 0)
        before = self.fixture.filesystem_snapshot(), self.fixture.history()
        with self.assertRaises(orchestration.OrchestrationError):
            orchestration._persist_resource_authority_for(
                self.fixture.root, fixtures.RUN_ID,
                AliasingStage("resource_runtime_other"), self.fixture.state(0),
            )
        self.assertEqual(
            (self.fixture.filesystem_snapshot(), self.fixture.history()), before
        )
