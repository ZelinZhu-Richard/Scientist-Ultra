"""Conservative visibility routing, never evidence or execution authority.

Malformed/inert records here only exercise refusal classifiers. Real operational
publication and its exact source history are tested by the reporting owner.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tests.test_compute_prepared_fixture import prepared_compute_tests

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.dataset_statistical_use import _is_late_scientific_event
from scientist_one.ledger import LedgerEvent
from scientist_one.models import MacroState
from scientist_one.research_state import _scientific_result_visibility_event
from scientist_one.roles import Role
from scientist_one.gpu_validation_requirement import GpuValidationRequirementStatus
from scientist_one.experiments import ExperimentError, require_scientific_execution_preparation
from scientist_one.holdout import ConfirmatoryEvaluatorSpec
from scientist_one.recovery import ConfirmatoryRerunError
from scientist_one.compute_terminal import (
    ComputeTerminalAssessmentResolutionStatus,
    resolve_compute_terminal_assessment,
)
from scientist_one.evaluation_contract_amendment import EvaluationContractAmendmentError
from scientist_one.scientific_design import (
    record_scientific_design_freeze,
    register_evaluation_contract_freeze_gate_receipt,
    require_evaluation_contract_freeze_gate_receipt,
)
from tests import test_evaluation_contract_amendment as amendment_fixtures
from tests import test_gpu_validation_requirement as gpu_fixtures
from tests import test_scientific_execution_authority as execution_fixtures
from tests import test_runtime as runtime_fixtures
from tests import test_compute_terminal as compute_fixtures


def operational_alias_records():
    """Independent incomplete selectors, not fabricated valid owner records."""
    defaults = dict(
        logical_type="inert_alias_control", origin="inert no-progress refusal control",
        creator_role=Role.EXPERIMENT_RUNNER, creation_command=("test", "inert-alias"),
        schema_version="1.0", mime_type="application/octet-stream",
        validation_result="PENDING", frozen=False,
    )
    return tuple(
        (label, payload, {**defaults, **override})
        for label, payload, override in (
            ("admission-family", b"inert", {"logical_type": "operational_seed_admission"}),
            ("terminal-family", b"inert", {"logical_type": "local_terminal_observation"}),
            ("report-family", b"inert", {"logical_type": "operational_best_of_n_report"}),
            ("schema-only", b"inert", {"schema_version": "op-seed-admission/v1"}),
            ("origin-only", b"inert", {"origin": "source-owned operational BEST_OF_N"}),
            ("command-only", b"inert", {"creation_command": ("scientist-one", "operational-best-of-n")}),
            ("payload-only", b'{"schema_version":"op-seed-admission/v1"}', {}),
        )
    )


class OperationalSeedVisibilityRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="operational-visibility-")
        self.addCleanup(temporary.cleanup)
        self.registry = ArtifactRegistry(Path(temporary.name))

    def event(self, *, metadata=None, artifacts=(), event_type="CHECKPOINT"):
        return LedgerEvent.create(
            run_id="visibility-routing-fixture",
            actor_role=Role.EXPERIMENT_RUNNER,
            state_before=MacroState.GROUND,
            requested_state_after=MacroState.GROUND,
            artifact_hashes=artifacts,
            code_version="non-evidentiary-classifier-test",
            configuration_hash="c" * 64,
            reason="Inert possible-exposure routing control, not execution.",
            prior_event_hash=None,
            event_id="visibility-event",
            timestamp="2026-09-07T00:00:00Z",
            event_type=event_type,
            supersedes_event_id="earlier-event" if event_type == "CORRECTION" else None,
            metadata={} if metadata is None else metadata,
        )

    def assert_visible(self, event, expected):
        self.assertIs(
            _scientific_result_visibility_event(self.registry, event), expected
        )
        self.assertIs(_is_late_scientific_event(self.registry, event), expected)

    def test_reserved_admission_key_presence_is_possible_exposure(self) -> None:
        for value in (None, False, 0, "", {}, [], {"state": "NOT_INVOKED"}):
            with self.subTest(value=value):
                self.assert_visible(
                    self.event(metadata={"operational_seed_admission": value}), True
                )

    def test_reserved_report_key_presence_is_possible_exposure(self) -> None:
        for value in (None, False, 0, "", {}, [], {"selected": None}):
            with self.subTest(value=value):
                self.assert_visible(
                    self.event(metadata={"operational_best_of_n_report": value}),
                    True,
                )

    def test_operational_record_families_route_without_authority_parsing(self) -> None:
        for family in (
            "operational_seed_admission",
            "local_terminal_observation",
            "operational_best_of_n_report",
        ):
            with self.subTest(family=family):
                record = self.registry.put_bytes(
                    f"inert malformed {family}\n".encode(),
                    logical_type=family,
                    origin="non-authorizing visibility classifier control",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=("scientist-one", "visibility-control"),
                    parent_artifacts=(),
                    schema_version="1.0",
                    mime_type="text/plain",
                    validation_result="PENDING",
                    frozen=False,
                )
                self.assert_visible(self.event(artifacts=(record.sha256,)), True)

    def test_non_checkpoint_reserved_marker_does_not_hide_exposure(self) -> None:
        self.assert_visible(
            self.event(
                metadata={"operational_seed_admission": None},
                event_type="CORRECTION",
            ),
            True,
        )

    def test_no_reserved_evidence_is_not_made_visible(self) -> None:
        for metadata in (
            {},
            {"note": "operational_seed_admission"},
            {"other": {"operational_best_of_n_report": {}}},
            {"operational_seed_admission_typo": {}},
        ):
            with self.subTest(metadata=metadata):
                self.assert_visible(self.event(metadata=metadata), False)

    def test_existing_result_and_statistical_design_routes_are_preserved(self) -> None:
        self.assert_visible(
            self.event(metadata={"promotion": "EXPERIMENT_OUTPUTS_REGISTERED"}),
            True,
        )
        design = self.event(metadata={"scientific_timeline": {"kind": "DESIGN_FROZEN"}})
        self.assertFalse(_scientific_result_visibility_event(self.registry, design))
        self.assertTrue(_is_late_scientific_event(self.registry, design))


class OperationalSeedGpuProgressTests(unittest.TestCase):
    def fixture(self):
        fixture = gpu_fixtures.GpuValidationRequirementTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        inputs = fixture.prepare()
        self.assertIs(
            fixture.resolve(inputs).status,
            GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED,
        )
        return fixture, inputs

    def test_inert_operational_families_cannot_be_ignored_as_no_progress(self) -> None:
        for family in (
            "operational_seed_admission",
            "local_terminal_observation",
            "operational_best_of_n_report",
        ):
            with self.subTest(family=family):
                fixture, inputs = self.fixture()
                fixture.inert_progress(logical_type=family)
                before = (fixture.registry.verify_all(), fixture.ledger.assert_valid())
                fixture.assert_unavailable(fixture.resolve(inputs))
                self.assertEqual(
                    (fixture.registry.verify_all(), fixture.ledger.assert_valid()),
                    before,
                )

    def test_operational_admission_descending_from_selected_work_is_progress(self) -> None:
        fixture, inputs = self.fixture()
        fixture.inert_progress(
            (inputs["local_record"].sha256,),
            logical_type="operational_seed_admission",
        )
        fixture.assert_unavailable(
            fixture.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED
        )

    def test_reserved_null_events_prevent_no_progress_conclusion(self) -> None:
        for key in ("operational_seed_admission", "operational_best_of_n_report"):
            with self.subTest(key=key):
                fixture, inputs = self.fixture()
                fixture.event({key: None})
                fixture.assert_unavailable(fixture.resolve(inputs))

    def test_exact_execution_hint_is_not_erased_by_later_correction(self) -> None:
        fixture, inputs = self.fixture()
        event = fixture.event({"operational_best_of_n_report": {
            "execution_run_id": inputs["local"].run_id,
        }})
        fixture.event(
            {"explanation": "Inert correction cannot prove absence of work."},
            event_type="CORRECTION",
            supersedes=event.event_id,
        )
        fixture.assert_unavailable(
            fixture.resolve(inputs), GpuValidationRequirementStatus.WORK_ALREADY_STARTED
        )

    def test_operational_record_aliases_cannot_establish_absence_of_work(self) -> None:
        for label, payload, metadata in operational_alias_records():
            with self.subTest(label=label):
                fixture, inputs = self.fixture()
                fixture.registry.put_bytes(payload, **metadata)
                before = fixture.registry.verify_all(), fixture.ledger.assert_valid()
                fixture.assert_unavailable(
                    fixture.resolve(inputs), GpuValidationRequirementStatus.BLOCKED_LOCAL,
                )
                self.assertEqual((fixture.registry.verify_all(), fixture.ledger.assert_valid()), before)

    def test_schema_only_renamed_event_cannot_establish_absence_of_work(self) -> None:
        fixture, inputs = self.fixture()
        fixture.event({"renamed": {"schema_version": "op-seed-admission/v1"}})
        before = fixture.registry.verify_all(), fixture.ledger.assert_valid()
        fixture.assert_unavailable(fixture.resolve(inputs), GpuValidationRequirementStatus.BLOCKED_LOCAL)
        self.assertEqual((fixture.registry.verify_all(), fixture.ledger.assert_valid()), before)


@prepared_compute_tests
class OperationalSeedWallProgressTests(unittest.TestCase):
    def fixture(self, *, freeze_elapsed_seconds: float = 0.0,
                assert_authorized: bool = True):
        fixture = compute_fixtures.ComputeTerminalAuthorityTests()
        fixture.configure_scheduled_wall_clock()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        try:
            fixture.advance_scheduled_wall_clock(freeze_elapsed_seconds)
            spec, _spec_record, freeze_record = fixture._freeze_mandatory_work()
            fixture.advance_scheduled_wall_clock(
                fixture.scheduled_wall_budget_seconds + 0.001
            )
            observation = fixture._observe_exhaustion()
            arguments = dict(
                assessment_id="operational-exposure-wall-control",
                expected_ledger_run_id=fixture.run_id,
                expected_execution_run_id=spec.run_id,
                evaluation_contract_freeze_receipt_artifact_sha256=freeze_record.sha256,
                frozen_configuration_inventory_artifact_sha256=(
                    observation.frozen_configuration_inventory_artifact_sha256
                ),
                wall_budget_observation_artifact_sha256=observation.observation_artifact_sha256,
            )
            if assert_authorized:
                resolution = resolve_compute_terminal_assessment(
                    fixture.registry,
                    fixture.ledger,
                    **arguments,
                )
                self.assertIs(
                    resolution.status,
                    ComputeTerminalAssessmentResolutionStatus.AUTHORIZED,
                    f"{resolution.status}/{resolution.reason_code}",
                )
            return fixture, arguments
        except BaseException:
            fixture.tearDown()
            raise

    def assert_blocked_unchanged(self, fixture, arguments):
        before = fixture.registry.verify_all(), fixture.ledger.assert_valid()
        resolution = resolve_compute_terminal_assessment(
            fixture.registry,
            fixture.ledger,
            **arguments,
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
            f"{resolution.status}/{resolution.reason_code}",
        )
        self.assertEqual(
            resolution.reason_code,
            "OPERATIONAL_RESERVATION_OR_POSSIBLE_PROGRESS",
        )
        self.assertEqual((fixture.registry.verify_all(), fixture.ledger.assert_valid()), before)

    def test_all_operational_record_aliases_block_no_progress_terminal(self) -> None:
        for label, payload, metadata in operational_alias_records():
            with self.subTest(label=label):
                fixture, arguments = self.fixture()
                try:
                    fixture.registry.put_bytes(payload, **metadata)
                    self.assert_blocked_unchanged(fixture, arguments)
                finally:
                    fixture.tearDown()

    def test_design_freeze_deadline_boundary_is_strict_and_deterministic(self) -> None:
        for freeze_elapsed_seconds, expected_status, expected_reason in (
            (
                4.999,
                ComputeTerminalAssessmentResolutionStatus.AUTHORIZED,
                "WALL_BUDGET_EXHAUSTED_WITH_REQUIRED_WORK_INCOMPLETE",
            ),
            (
                5.0,
                ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
                "LOCAL_SOURCE_CLOSURE_MISMATCH",
            ),
            (
                5.001,
                ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
                "LOCAL_SOURCE_CLOSURE_MISMATCH",
            ),
        ):
            with self.subTest(freeze_elapsed_seconds=freeze_elapsed_seconds):
                fixture, arguments = self.fixture(
                    freeze_elapsed_seconds=freeze_elapsed_seconds,
                    assert_authorized=False,
                )
                try:
                    before = (
                        fixture.registry.verify_all(),
                        fixture.ledger.assert_valid(),
                    )
                    resolution = resolve_compute_terminal_assessment(
                        fixture.registry,
                        fixture.ledger,
                        **arguments,
                    )
                    self.assertIs(
                        resolution.status,
                        expected_status,
                        f"{resolution.status}/{resolution.reason_code}",
                    )
                    self.assertEqual(resolution.reason_code, expected_reason)
                    self.assertEqual(
                        (
                            fixture.registry.verify_all(),
                            fixture.ledger.assert_valid(),
                        ),
                        before,
                    )
                finally:
                    fixture.tearDown()

    def test_nested_null_and_schema_only_events_block_no_progress_terminal(self) -> None:
        for metadata in (
            {"renamed": {"operational_seed_admission": None}},
            {"renamed": {"schema_version": "op-seed-admission/v1"}},
        ):
            with self.subTest(metadata=metadata):
                fixture, arguments = self.fixture()
                try:
                    head = fixture.ledger.events()[-1]
                    fixture.ledger.append_event(
                        run_id=fixture.run_id, actor_role=Role.EXPERIMENT_RUNNER,
                        state_before=head.requested_state_after,
                        requested_state_after=head.requested_state_after,
                        artifact_hashes=(), code_version=head.code_version,
                        configuration_hash=head.configuration_hash,
                        reason="Inert unresolved progress marker, not actual execution.",
                        event_type="CHECKPOINT", metadata=metadata,
                    )
                    self.assert_blocked_unchanged(fixture, arguments)
                finally:
                    fixture.tearDown()


class OperationalScientificAdmissionTests(unittest.TestCase):
    def fixture(self):
        fixture = execution_fixtures.ScientificExecutionAuthorityTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        return fixture

    def reserve(self, registry):
        return registry.put_bytes(
            b"inert unfinished reservation; no execution claim",
            logical_type="operational_seed_admission", origin="inert refusal control",
            creator_role=Role.EXPERIMENT_RUNNER,
            creation_command=("test", "possible-exposure"), schema_version="1.0",
            validation_result="PENDING", frozen=False,
        )

    def snapshot(self, fixture):
        return fixture.registry.verify_all(), fixture.ledger.assert_valid()

    def test_existing_spec_cannot_prepare_after_record_only_reservation(self) -> None:
        fixture = self.fixture()
        self.reserve(fixture.registry)
        before = self.snapshot(fixture)
        with self.assertRaisesRegex(ExperimentError, "operational reservation"):
            fixture._prepare()
        self.assertEqual(self.snapshot(fixture), before)

    def test_preparation_retry_is_current_use_but_historical_readback_is_preserved(self) -> None:
        fixture = self.fixture()
        record = fixture._prepare()
        arguments = dict(
            preparation_artifact_sha256=record.sha256,
            expected_ledger_run_id=fixture.ledger_run_id,
            expected_execution_run_id=fixture.spec.run_id,
        )
        previous = require_scientific_execution_preparation(
            fixture.registry, fixture.ledger, **arguments,
        )
        self.reserve(fixture.registry)
        before = self.snapshot(fixture)
        with self.assertRaisesRegex(ExperimentError, "operational reservation"):
            fixture._prepare()
        self.assertEqual(
            require_scientific_execution_preparation(
                fixture.registry, fixture.ledger, **arguments,
            ),
            previous,
        )
        self.assertEqual(self.snapshot(fixture), before)

    def test_current_amendment_refuses_unlogged_operational_reservation(self) -> None:
        fixture = amendment_fixtures.EvaluationContractAmendmentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.reserve(fixture.registry)
        before = self.snapshot(fixture)
        with self.assertRaisesRegex(EvaluationContractAmendmentError, "operational reservation"):
            fixture.publish()
        self.assertEqual(self.snapshot(fixture), before)

    def test_historical_freeze_replays_but_new_design_refuses_same_current_population(self) -> None:
        fixture = self.fixture()
        values = fixture.values
        arguments = dict(
            run_id=fixture.ledger_run_id, contract=values["contract"],
            contract_artifact_sha256=values["contract_record"].sha256,
            experiment_plan_artifact_sha256s=tuple(r.sha256 for r in values["plan_records"]),
            frozen_run_spec_artifact_sha256=fixture.spec_record.sha256,
        )
        record = register_evaluation_contract_freeze_gate_receipt(
            fixture.registry, fixture.ledger, receipt_id="prospective-freeze", **arguments,
        )
        self.reserve(fixture.registry)
        before = self.snapshot(fixture)
        receipt = require_evaluation_contract_freeze_gate_receipt(
            fixture.registry, fixture.ledger, receipt_artifact_sha256=record.sha256,
            expected_run_id=fixture.ledger_run_id,
            expected_contract_id=values["contract"].contract_id,
        )
        self.assertFalse(receipt.result_validity_authorized)
        with self.assertRaisesRegex(EvaluationContractAmendmentError, "operational reservation"):
            record_scientific_design_freeze(fixture.registry, fixture.ledger, **arguments)
        self.assertEqual(self.snapshot(fixture), before)


class OperationalLegacyCustodyTests(unittest.TestCase):
    def test_record_only_reservation_blocks_actual_simulated_release_on_legacy_paths(self) -> None:
        fixture = runtime_fixtures.RecoveryTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        bundle = fixture.reveal_authority_bundle()
        registry = bundle["registry"]
        provider = bundle["provider"]
        registry.put_bytes(
            b"inert unresolved operational reservation",
            logical_type="operational_seed_admission", origin="inert no-release control",
            creator_role=Role.EXPERIMENT_RUNNER,
            validation_result="PENDING", frozen=False,
        )
        before = (
            registry.verify_all(), fixture.manager.validate_ledger(fixture.ledger_path),
            provider.verify_journal(), provider.status,
        )
        with self.assertRaisesRegex(ConfirmatoryRerunError, "operational reservation"):
            fixture.manager.run_non_evidentiary_simulated_fixture(
                ledger_path=fixture.ledger_path, study_version=bundle["study"],
                fresh_custody_evidence=bundle["evidence"], reveal_authority=bundle["authority"],
                artifact_registry=registry, custody_provider=provider,
                validity_snapshot=bundle["snapshot"], start_event=bundle["start_event"],
                evaluator_spec=ConfirmatoryEvaluatorSpec(), requester=Role.EXPERIMENT_RUNNER.value,
                reason="Synthetic adverse no-release control, not scientific confirmation.",
                requested_at="2026-01-01T00:01:00Z",
            )
        self.assertEqual(
            (registry.verify_all(), fixture.manager.validate_ledger(fixture.ledger_path),
             provider.verify_journal(), provider.status),
            before,
        )
        self.assertFalse(provider.status.revealed)


if __name__ == "__main__":
    unittest.main()
