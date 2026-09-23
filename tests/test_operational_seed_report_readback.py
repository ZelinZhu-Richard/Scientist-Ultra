"""Actual-owner current readback races; no fabricated positive authority."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from scientist_one import seed_reporting as owner
from scientist_one.roles import Role
from tests import test_operational_seed_reporting as fixtures


class OperationalReportReadbackTests(unittest.TestCase):
    def fixture(self):
        case = fixtures.OperationalSeedReportingTests()
        self.addCleanup(case.doCleanups)
        fixture = case.fixture()
        result = case.execute(fixture)
        return case, fixture, result

    def check_recovery_race(self, *, ledger_drift: bool, execute: bool = False):
        case, fixture, result = self.fixture()
        runtime, registry, ledger, _contract, _specs, _receipts, _paths = fixture
        real = owner._read_chain
        after_drift = []

        def interleave(*args, **kwargs):
            chain = real(*args, **kwargs)
            if ledger_drift:
                head = ledger.events()[-1]
                ledger.append_event(
                    run_id="operational-owner", actor_role=Role.EXPERIMENT_RUNNER,
                    state_before=head.requested_state_after,
                    requested_state_after=head.requested_state_after,
                    artifact_hashes=(), code_version=head.code_version,
                    configuration_hash=head.configuration_hash,
                    reason="Concurrent unrelated append during completed report readback.",
                    event_type="CHECKPOINT",
                )
            else:
                registry.put_bytes(
                    b"unrelated bytes arrived during completed owner replay",
                    logical_type="inert_readback_race", origin="inert snapshot race control",
                    creator_role=Role.IMPLEMENTER, validation_result="PENDING", frozen=False,
                )
            after_drift.append((registry.verify_all(), ledger.assert_valid()))
            return chain

        with patch.object(owner, "_read_chain", side_effect=interleave):
            with self.assertRaises(owner.OperationalSeedReportingError):
                if execute:
                    case.execute(fixture)
                else:
                    owner.recover_operational_best_of_n(
                        registry, ledger, expected_run_id="operational-owner",
                        initial_admission_artifact_sha256=result.admission_records[0].sha256,
                        backend=runtime.backend(),
                    )
        self.assertEqual(len(after_drift), 1)
        self.assertEqual((registry.verify_all(), ledger.assert_valid()), after_drift[0])

    def test_completed_recovery_rechecks_registry_population_before_return(self):
        self.check_recovery_race(ledger_drift=False)

    def test_completed_recovery_rechecks_ledger_prefix_before_return(self):
        self.check_recovery_race(ledger_drift=True)

    def test_completed_execute_rechecks_recovered_source_population(self):
        self.check_recovery_race(ledger_drift=False, execute=True)


if __name__ == "__main__":
    unittest.main()
