"""No simulated membership evidence may become a scientific design admission."""

import unittest

from scientist_one.evaluation_contract_amendment import (
    EvaluationContractAmendmentError,
    _require_evaluation_contract_family_before_design,
)
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    record_scientific_design_freeze,
    register_evaluation_contract_freeze_gate_receipt,
    require_evaluation_contract_freeze_gate_receipt,
)
from scientist_one.simulated_reserve import register_simulated_reserve_population
from tests import test_scientific_execution_authority as fixtures
from tests import test_simulated_reserve as reserves


class SimulatedReserveScientificBoundaryTests(unittest.TestCase):
    def fixture(self):
        case = fixtures.ScientificExecutionAuthorityTests()
        case.setUp()
        self.addCleanup(case.tearDown)
        return case

    def arguments(self, case):
        return dict(
            run_id=case.ledger_run_id, contract=case.values["contract"],
            contract_artifact_sha256=case.values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(
                record.sha256 for record in case.values["plan_records"]
            ),
            frozen_run_spec_artifact_sha256=case.spec_record.sha256,
        )

    def snapshot(self, case):
        return case.registry.verify_all(raise_on_error=True), case.ledger.assert_valid()

    def test_real_population_is_not_a_scientific_reserve(self):
        case = self.fixture()
        register_simulated_reserve_population(case.registry)
        before = self.snapshot(case)
        with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                    "simulated reservation"):
            record_scientific_design_freeze(case.registry, case.ledger,
                                            **self.arguments(case))
        self.assertEqual(self.snapshot(case), before)

    def test_actual_first_reservation_cannot_be_used_by_scientific_family_admission(self):
        case = reserves.SimulatedReserveTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        publication = case.publish()
        before = self.snapshot(case)
        with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                    "simulated reservation"):
            _require_evaluation_contract_family_before_design(
                case.registry, case.ledger, expected_run_id=reserves.RUN,
                contract_artifact_sha256=publication.contract_record.sha256,
                input_artifact_sha256s=(case.evidence.sha256,) * 4,
                design_event_index=before[1].event_count,
            )
        self.assertEqual(self.snapshot(case), before)

    def test_record_only_schema_alias_blocks_design_without_any_write(self):
        case = self.fixture()
        case.registry.put_bytes(
            b"inert unfinished simulated reservation, not evidence",
            logical_type="inert_boundary_control", schema_version="sim-reserve/v1",
            origin="adversarial boundary control", creator_role=Role.ORCHESTRATOR,
            validation_result="PENDING", frozen=False,
        )
        before = self.snapshot(case)
        with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                    "simulated reservation"):
            record_scientific_design_freeze(case.registry, case.ledger,
                                            **self.arguments(case))
        self.assertEqual(self.snapshot(case), before)

    def test_nested_null_reserved_event_blocks_design_without_any_write(self):
        case = self.fixture()
        head = case.ledger.events()[-1]
        case.ledger.append_event(
            run_id=case.ledger_run_id, actor_role=Role.ORCHESTRATOR,
            state_before=head.requested_state_after,
            requested_state_after=head.requested_state_after,
            artifact_hashes=(), code_version=head.code_version,
            configuration_hash=head.configuration_hash, event_type="CHECKPOINT",
            reason="Inert unresolved simulated-use marker; no execution claim.",
            metadata={"renamed": {"simulated_confirmatory_reserve": None}},
        )
        before = self.snapshot(case)
        with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                    "simulated reservation"):
            record_scientific_design_freeze(case.registry, case.ledger,
                                            **self.arguments(case))
        self.assertEqual(self.snapshot(case), before)

    def test_sealed_historical_freeze_does_not_gain_later_simulated_population(self):
        case = self.fixture()
        receipt = register_evaluation_contract_freeze_gate_receipt(
            case.registry, case.ledger, receipt_id="before-simulated-population",
            **self.arguments(case),
        )
        register_simulated_reserve_population(case.registry)
        before = self.snapshot(case)
        historical = require_evaluation_contract_freeze_gate_receipt(
            case.registry, case.ledger, receipt_artifact_sha256=receipt.sha256,
            expected_run_id=case.ledger_run_id,
            expected_contract_id=case.values["contract"].contract_id,
        )
        self.assertFalse(historical.result_validity_authorized)
        with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                    "simulated reservation"):
            record_scientific_design_freeze(case.registry, case.ledger,
                                            **self.arguments(case))
        self.assertEqual(self.snapshot(case), before)

    def test_unrelated_large_artifact_preserves_existing_scientific_design(self):
        case = self.fixture()
        case.registry.put_bytes(
            b"x" * (3 * 1024 * 1024), logical_type="unrelated_large_control",
            origin="No simulated markers in unrelated inert text",
            creator_role=Role.ORCHESTRATOR, mime_type="text/plain",
        )
        before = self.snapshot(case)
        event = record_scientific_design_freeze(
            case.registry, case.ledger, **self.arguments(case),
        )
        after = self.snapshot(case)
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1].events, (*before[1].events, event))

    def test_malformed_reserved_field_containers_and_json_cannot_authorize_design(self):
        for metadata, payload in (
            ({"schema_version": ["sim-reserve/v1"]}, None),
            ({"schema_version": {"sim-reserve-event/v1": None}}, None),
            ({"profile": ["PINNED_CAL_TRUE_NULL_TWO_WINDOWS_V1"]}, None),
            (None, b'{"simulated_confirmatory_reserve":'),
        ):
            with self.subTest(metadata=metadata, payload=payload):
                case = self.fixture()
                if metadata is not None:
                    head = case.ledger.events()[-1]
                    case.ledger.append_event(
                        run_id=case.ledger_run_id, actor_role=Role.ORCHESTRATOR,
                        state_before=head.requested_state_after,
                        requested_state_after=head.requested_state_after,
                        artifact_hashes=(), code_version=head.code_version,
                        configuration_hash=head.configuration_hash,
                        event_type="CHECKPOINT", metadata=metadata,
                        reason="Malformed reserved fields are not ordinary prose.",
                    )
                else:
                    case.registry.put_bytes(
                        payload, logical_type="renamed_incomplete_profile",
                        origin="Truncated reserved-key control, not evidence",
                        creator_role=Role.ORCHESTRATOR, mime_type="text/plain",
                    )
                before = self.snapshot(case)
                with self.assertRaisesRegex(EvaluationContractAmendmentError,
                                            "simulated reservation"):
                    record_scientific_design_freeze(
                        case.registry, case.ledger, **self.arguments(case),
                    )
                self.assertEqual(self.snapshot(case), before)


if __name__ == "__main__":
    unittest.main()
