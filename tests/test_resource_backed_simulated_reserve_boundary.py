"""Resource bookkeeping never grants scientific design or result authority."""

import unittest

from scientist_one.evaluation_contract_amendment import (
    EvaluationContractAmendmentError,
    _require_evaluation_contract_family_before_design,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import record_scientific_design_freeze
from tests import test_resource_backed_simulated_reserve as reserve_fixtures
from tests import test_simulated_reserve_scientific_boundary as boundary_fixtures
from tests.test_resource_prepared_cases import prepared_resource_case


class ResourceBackedReserveScientificBoundaryTests(unittest.TestCase):
    def scientific_fixture(self):
        helper = boundary_fixtures.SimulatedReserveScientificBoundaryTests()
        self.addCleanup(helper.doCleanups)
        return helper, helper.fixture()

    def assert_design_refused_unchanged(self, helper, case):
        before = helper.snapshot(case)
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError, "simulated reservation"
        ):
            record_scientific_design_freeze(
                case.registry, case.ledger, **helper.arguments(case)
            )
        self.assertEqual(helper.snapshot(case), before)

    @prepared_resource_case
    def test_real_resource_backed_reserve_cannot_authorize_scientific_family(self):
        fixture = reserve_fixtures.ResourceBackedSimulatedReserveTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        publication = fixture.publish()
        before, external = fixture.snapshot(), fixture.case.files()
        self.assertEqual(publication.record.schema_version, "sim-reserve/v2")
        with self.assertRaisesRegex(
            EvaluationContractAmendmentError, "simulated reservation"
        ):
            _require_evaluation_contract_family_before_design(
                fixture.registry,
                fixture.ledger,
                expected_run_id=fixture.case.run,
                contract_artifact_sha256=publication.contract_record.sha256,
                input_artifact_sha256s=(fixture.case.source.sha256,) * 4,
                design_event_index=before[1].event_count,
            )
        self.assertEqual(fixture.snapshot(), before)
        self.assertEqual(fixture.case.files(), external)

    def test_renamed_v2_record_markers_block_actual_scientific_design(self):
        for schema, payload in (
            ("sim-reserve/v2", b"inert unowned allocation metadata"),
            ("1.0", b'{"renamed":{"schema_version":"sim-reserve/v2"}}'),
            ("1.0", b'{"renamed":{"schema_version":["sim-reserve/v2"]}}'),
            ("1.0", b'{"schema_version":"sim-reserve/v2",'),
        ):
            with self.subTest(schema=schema, payload=payload):
                helper, case = self.scientific_fixture()
                case.registry.put_bytes(
                    payload,
                    logical_type="inert_unowned_v2_control",
                    schema_version=schema,
                    origin="Renamed unresolved bookkeeping marker, not evidence",
                    creator_role=Role.ORCHESTRATOR,
                    validation_result="PENDING",
                    frozen=False,
                )
                self.assert_design_refused_unchanged(helper, case)

    def test_renamed_v2_event_markers_block_actual_scientific_design(self):
        for metadata in (
            {"renamed": {"schema_version": "sim-reserve-event/v2"}},
            {"renamed": {"schema_version": ["sim-reserve-event/v2"]}},
            {"renamed": {"schema_version": {"sim-reserve/v2": None}}},
        ):
            with self.subTest(metadata=metadata):
                helper, case = self.scientific_fixture()
                head = case.ledger.events()[-1]
                case.ledger.append_event(
                    run_id=case.ledger_run_id,
                    actor_role=Role.ORCHESTRATOR,
                    state_before=head.requested_state_after,
                    requested_state_after=head.requested_state_after,
                    artifact_hashes=(),
                    code_version=head.code_version,
                    configuration_hash=head.configuration_hash,
                    event_type="CHECKPOINT",
                    metadata=metadata,
                    reason="Unowned resource-backed marker, not scientific work.",
                )
                self.assert_design_refused_unchanged(helper, case)


if __name__ == "__main__":
    unittest.main()
