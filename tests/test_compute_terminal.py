from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import scientist_one.artifacts as artifacts_module
import scientist_one.ledger as ledger_module
import scientist_one.orchestrator as orchestrator_module
import scientist_one.scientific_design as scientific_design_module

try:
    from tests.test_scientific_design import make_contract
except ImportError:  # pragma: no cover - direct unittest discovery
    from test_scientific_design import make_contract  # type: ignore[no-redef]

from scientist_one.artifacts import ArtifactRegistry
from scientist_one import compute_terminal as compute_terminal_module
from scientist_one.compute_terminal import (
    WALL_BUDGET_EXHAUSTED_STATUS,
    ComputeTerminalAssessmentResolutionStatus,
    ComputeTerminalError,
    register_compute_terminal_assessment,
    require_compute_terminal_assessment,
    resolve_compute_terminal_assessment,
)
from scientist_one.experiments import EvidenceClass, ExperimentPhase, FrozenRunSpec
from scientist_one.ledger import EventLedger, LedgerEvent
from scientist_one.models import TerminalState
from scientist_one.orchestrator import (
    OrchestrationError,
    RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE,
    ScientistOneOrchestrator,
    _require_exact_resource_checkpoint_closure,
    _resource_authority_descriptors_for,
    _validate_monotonic_resource_states,
    require_resource_runtime_wall_budget_observation,
)
from scientist_one.resources import MemoryObservation, ResourceConfig, ResourceController
from scientist_one.research_state import ResearchStateRepository
from scientist_one.roles import Role
from scientist_one.scientific_design import (
    ExperimentPlan,
    ExperimentStage,
    record_scientific_design_freeze,
    register_evaluation_contract_freeze_gate_receipt,
    register_frozen_evaluation_contract,
    register_frozen_experiment_plan,
    register_frozen_run_spec,
)
from scientist_one.security import canonical_json_bytes
from scientist_one.terminal_outcomes import (
    LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
    ResearchTerminalOutcome,
    ResearchTerminalRecord,
    TerminalAuthorityScope,
    TerminalOutcomeDerivation,
    TerminalPhase,
    TerminalSourceKind,
    derive_from_registered_compute_terminal_assessment,
    load_terminal_outcome,
    materialize_terminal_outcome,
)
from tests.test_compute_prepared_fixture import (
    prepared_compute_tests,
    prepared_fixture_root,
    prepared_prospective_compute_profile,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _ScheduledWallClock:
    """Test-only clock with explicit epoch and monotonic scheduling."""

    def __init__(self, *, maximum_wall_clock_seconds: float) -> None:
        self.maximum_wall_clock_seconds = maximum_wall_clock_seconds
        # Keep the synthetic epoch close to the host clock while making its
        # microsecond representation deterministic for exact boundary tests.
        self.wall_epoch_seconds = float(int(time.time()))
        self.monotonic_epoch_seconds = 1000.0
        self.elapsed_seconds = 0.0

    def monotonic(self) -> float:
        return self.monotonic_epoch_seconds + self.elapsed_seconds

    def wall(self) -> float:
        return self.wall_epoch_seconds + self.elapsed_seconds

    def utc_now(self) -> str:
        return (
            datetime.fromtimestamp(self.wall(), timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def advance_to(self, elapsed_seconds: float) -> None:
        if elapsed_seconds < self.elapsed_seconds:
            raise AssertionError("scheduled fixture clock moved backwards")
        self.elapsed_seconds = elapsed_seconds


@prepared_compute_tests
class ComputeTerminalAuthorityTests(unittest.TestCase):
    def configure_scheduled_wall_clock(
        self,
        *,
        maximum_wall_clock_seconds: float = 5.0,
    ) -> None:
        """Opt in only for callers that need deterministic wall scheduling."""

        if hasattr(self, "_scheduled_wall_clock"):
            raise AssertionError("scheduled fixture clock was configured twice")
        self._scheduled_wall_clock = _ScheduledWallClock(
            maximum_wall_clock_seconds=maximum_wall_clock_seconds,
        )

    def setUp(self) -> None:
        self._temporary = None
        self._scheduled_clock_patchers = []
        self._teardown_complete = False
        try:
            self._setUp_transactional()
        except BaseException:
            self.tearDown()
            raise

    def _setUp_transactional(self) -> None:
        prospective_profile = prepared_prospective_compute_profile()
        if prospective_profile is not None:
            self._real_wall_budget_seconds = prospective_profile[1]
        scheduled_clock = getattr(self, "_scheduled_wall_clock", None)
        prepared_root = prepared_fixture_root(self)
        if prepared_root is None:
            self._temporary = tempfile.TemporaryDirectory(
                dir=PROJECT_ROOT / ".scientist-one-build" / "tmp"
            )
            self.root = Path(self._temporary.name)
            shutil.copytree(
                PROJECT_ROOT / "src" / "scientist_one",
                self.root / "src" / "scientist_one",
            )
            (self.root / "scripts").mkdir()
            shutil.copy2(
                PROJECT_ROOT / "scripts" / "scientist_one_cli.py",
                self.root / "scripts" / "scientist_one_cli.py",
            )
            shutil.copytree(PROJECT_ROOT / "configs", self.root / "configs")
            config_path = self.root / "configs" / "resource_limits.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            scheduled_clock = getattr(self, "_scheduled_wall_clock", None)
            config["maximum_wall_clock_seconds"] = (
                scheduled_clock.maximum_wall_clock_seconds
                if scheduled_clock is not None
                else getattr(self, "_real_wall_budget_seconds", 1)
            )
            config_path.write_text(json.dumps(config), encoding="utf-8")
        else:
            self.root = prepared_root
            config_path = self.root / "configs" / "resource_limits.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            expected_budget = (
                scheduled_clock.maximum_wall_clock_seconds
                if scheduled_clock is not None else getattr(self, "_real_wall_budget_seconds", 1)
            )
            if config["maximum_wall_clock_seconds"] != expected_budget:
                raise AssertionError("prepared compute configuration differs from fixture")
        if scheduled_clock is not None:
            original_resource_controller_init = ResourceController.__init__

            def init_with_scheduled_clock(
                controller,
                resource_config,
                project_root,
                *args,
                **kwargs,
            ):
                kwargs.setdefault("clock", scheduled_clock.monotonic)
                kwargs.setdefault("wall_clock", scheduled_clock.wall)
                return original_resource_controller_init(
                    controller,
                    resource_config,
                    project_root,
                    *args,
                    **kwargs,
                )

            self._scheduled_clock_patchers.extend(
                (
                    patch.object(
                        ResourceController,
                        "__init__",
                        init_with_scheduled_clock,
                    ),
                    patch.object(
                        orchestrator_module,
                        "_utc_now",
                        scheduled_clock.utc_now,
                    ),
                    patch.object(
                        ledger_module,
                        "utc_now",
                        scheduled_clock.utc_now,
                    ),
                    patch.object(
                        artifacts_module,
                        "utc_now",
                        scheduled_clock.utc_now,
                    ),
                    patch.object(
                        scientific_design_module,
                        "utc_now",
                        scheduled_clock.utc_now,
                    ),
                )
            )
            for patcher in self._scheduled_clock_patchers:
                patcher.start()
        if prepared_root is None:
            # This copy belongs only to the explicit cleanup/clock failure test.
            # The constructor still uses captured cwd. The existing injected
            # start failure must occur before any successful start or evidence;
            # the temporary copy is never the source of execution authority.
            self.orchestrator = ScientistOneOrchestrator(PROJECT_ROOT)
            self.orchestrator.start()
            raise AssertionError("cleanup subfixture unexpectedly completed start")
        else:
            self.orchestrator = ScientistOneOrchestrator(self.root)
            self.run_id = str(self.orchestrator.start()["run_id"])
        self.registry = ArtifactRegistry(
            self.root, Path("runs") / self.run_id / "registry"
        )
        self.ledger = EventLedger(
            self.root, Path("runs") / self.run_id / "events.jsonl"
        )

    def tearDown(self) -> None:
        if getattr(self, "_teardown_complete", False):
            return
        self._teardown_complete = True
        patchers = tuple(reversed(getattr(self, "_scheduled_clock_patchers", ())))
        self._scheduled_clock_patchers = []
        try:
            for patcher in patchers:
                patcher.stop()
        finally:
            temporary = getattr(self, "_temporary", None)
            self._temporary = None
            if temporary is not None:
                temporary.cleanup()

    def advance_scheduled_wall_clock(self, elapsed_seconds: float) -> None:
        scheduled_clock = getattr(self, "_scheduled_wall_clock", None)
        if scheduled_clock is None:
            raise AssertionError("fixture did not opt into a scheduled wall clock")
        scheduled_clock.advance_to(elapsed_seconds)

    @property
    def scheduled_wall_budget_seconds(self) -> float:
        scheduled_clock = getattr(self, "_scheduled_wall_clock", None)
        if scheduled_clock is None:
            raise AssertionError("fixture did not opt into a scheduled wall clock")
        return scheduled_clock.maximum_wall_clock_seconds

    def _artifact(
        self,
        payload: bytes,
        logical_type: str,
        role: Role,
    ):
        return self.registry.put_bytes(
            payload,
            logical_type=logical_type,
            origin="compute terminal focused source fixture",
            creator_role=role,
            creation_command=("scientist-one", "test-compute-terminal-source"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )

    def _freeze_mandatory_work(self):
        evidence = self._artifact(
            b'{"compute-terminal-contract-evidence":"v1"}\n',
            "compute_terminal_contract_evidence",
            Role.EVIDENCE_CURATOR,
        )
        contract = make_contract()
        contract_record = register_frozen_evaluation_contract(
            self.registry,
            contract=contract,
            parent_artifact_sha256s=(evidence.sha256,),
        )
        code = self._artifact(
            b"print('never started compute terminal workload')\n",
            "experiment_code",
            Role.IMPLEMENTER,
        )
        data = self._artifact(
            b'{"compute-terminal-data":"v1"}\n',
            "experiment_dataset",
            Role.EVIDENCE_CURATOR,
        )
        configuration = self._artifact(
            b'{"compute-terminal-experiment-config":"v1"}\n',
            "experiment_configuration",
            Role.PROTOCOL_DESIGNER,
        )
        evaluator = self._artifact(
            b'{"compute-terminal-evaluator":"v1"}\n',
            "evaluator_implementation",
            Role.PROTOCOL_DESIGNER,
        )
        plans = tuple(
            ExperimentPlan(
                experiment_id="experiment-primary",
                hypothesis_id="hypothesis-primary",
                stage=ExperimentStage.EXPLORATORY,
                contract_sha256=contract.sha256,
                dataset_split_id="development-v1",
                seed=seed,
                evaluator_id="evaluator-v1",
                uses_protected_resource=False,
                results_seen_before_plan=False,
            )
            for seed in contract.seed_reporting.seeds
        )
        plan_records = tuple(
            register_frozen_experiment_plan(
                self.registry,
                contract=contract,
                contract_artifact_sha256=contract_record.sha256,
                plan=plan,
            )
            for plan in plans
        )
        spec = FrozenRunSpec(
            run_id="compute-terminal-never-started-execution",
            experiment_id="experiment-primary",
            hypothesis_id="hypothesis-primary",
            phase=ExperimentPhase.EXPLORATORY,
            argv=("/usr/bin/python3", "fixture.py"),
            working_directory=".",
            code_sha256=code.sha256,
            data_sha256=data.sha256,
            configuration_sha256=configuration.sha256,
            evaluator_sha256=evaluator.sha256,
            seeds=contract.seed_reporting.seeds,
            required_ablations=("ablation-core",),
            evidence_class=EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            metadata={"evaluation_split": "development-v1"},
        )
        spec_record = register_frozen_run_spec(
            self.registry,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in plan_records
            ),
            spec=spec,
        )
        record_scientific_design_freeze(
            self.registry,
            self.ledger,
            run_id=self.run_id,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in plan_records
            ),
            frozen_run_spec_artifact_sha256=spec_record.sha256,
        )
        freeze_record = register_evaluation_contract_freeze_gate_receipt(
            self.registry,
            self.ledger,
            receipt_id="compute-terminal-freeze-receipt",
            run_id=self.run_id,
            contract=contract,
            contract_artifact_sha256=contract_record.sha256,
            experiment_plan_artifact_sha256s=tuple(
                item.sha256 for item in plan_records
            ),
            frozen_run_spec_artifact_sha256=spec_record.sha256,
        )
        if prepared_prospective_compute_profile() is not None:
            # Retain only the selectors returned to the unchanged original body.
            # No diagnostic reads or clock sampling precede its freeze event.
            self._closure_diagnostic_selectors = (spec.run_id, freeze_record.sha256)
        return spec, spec_record, freeze_record

    def _emit_closure_diagnostic(self, returned_observation):
        """Report actual readback predicates, never authorize or replace a source."""
        prospective_profile = prepared_prospective_compute_profile()
        if prospective_profile is None:
            return
        case_id, expected_budget = prospective_profile
        expected_execution_run_id, freeze_sha256 = self._closure_diagnostic_selectors
        expected_ledger_run_id = self.run_id
        frozen_configuration_inventory_artifact_sha256 = (
            returned_observation.frozen_configuration_inventory_artifact_sha256
        )
        prefix = "SCIENTIST_ONE_COMPUTE_CLOSURE_DIAGNOSTIC_V1="
        print(prefix + json.dumps({
            "case_id": case_id, "phase": "READBACK_STARTED",
            "freeze_receipt_sha256": freeze_sha256,
            "observation_sha256": returned_observation.observation_artifact_sha256,
        }, sort_keys=True), flush=True)
        # These are the same existing source readers used by the compute owner.
        # Exceptions propagate normally; no diagnostic failure is swallowed.
        freeze_candidate = (
            compute_terminal_module.EvaluationContractFreezeGateReceipt.from_dict(
                json.loads(self.registry.get_bytes(freeze_sha256))
            )
        )
        freeze = compute_terminal_module.require_evaluation_contract_freeze_gate_receipt(
            self.registry, self.ledger,
            receipt_artifact_sha256=freeze_sha256,
            expected_run_id=expected_ledger_run_id,
            expected_contract_id=freeze_candidate.object_id,
        )
        contract = compute_terminal_module.require_frozen_evaluation_contract(
            self.registry, contract_artifact_sha256=freeze.contract_artifact_sha256,
        )
        spec = compute_terminal_module.require_scientific_execution_run_spec(
            self.registry,
            frozen_run_spec_artifact_sha256=freeze.frozen_run_spec_artifact_sha256,
        )
        observation = require_resource_runtime_wall_budget_observation(
            self.registry, self.ledger,
            observation_artifact_sha256=returned_observation.observation_artifact_sha256,
            expected_run_id=expected_ledger_run_id,
        )
        inventory_record = self.registry.get_metadata(
            frozen_configuration_inventory_artifact_sha256
        )
        events = self.ledger.events()
        if freeze.design_freeze_event_index >= len(events):
            print(prefix + json.dumps({
                "case_id": case_id, "phase": "READBACK_LIMITATION",
                "reason": "DESIGN_FREEZE_EVENT_IS_OUTSIDE_THE_LEDGER",
                "freeze_event_index": freeze.design_freeze_event_index,
                "ledger_event_count": len(events),
            }, sort_keys=True), flush=True)
            self.fail("prospective compute freeze event is outside the ledger")
        freeze_event = events[freeze.design_freeze_event_index]
        freeze_epoch_seconds = compute_terminal_module._utc_epoch_seconds(
            freeze_event.timestamp, "design freeze",
        )
        wall_deadline_epoch_seconds = (
            observation.runtime_state.wall_started_at_epoch_seconds
            + observation.resource_config.maximum_wall_clock_seconds
        )
        # In order, these are the twelve disjuncts of _derive_sources' existing
        # LOCAL_SOURCE_CLOSURE_MISMATCH gate. True means that clause rejects.
        rejecting_predicates = {
            "freeze_run_id_differs": freeze.run_id != expected_ledger_run_id,
            "execution_run_id_differs": spec.run_id != expected_execution_run_id,
            "evidence_class_ineligible": spec.evidence_class is not EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE,
            "seeds_differ": spec.seeds != contract.seed_reporting.seeds,
            "plans_empty": freeze.experiment_plan_artifact_sha256s == (),
            "inventory_sha_differs": observation.frozen_configuration_inventory_artifact_sha256 != frozen_configuration_inventory_artifact_sha256,
            "inventory_record_hash_differs": inventory_record.record_hash != observation.frozen_configuration_inventory_record_hash,
            "freeze_event_id_differs": freeze_event.event_id != freeze.design_freeze_event_id,
            "freeze_event_hash_differs": freeze_event.event_hash != freeze.design_freeze_event_hash,
            "freeze_not_before_observation": freeze.design_freeze_event_index >= observation.ledger_event_index,
            "freeze_not_before_deadline": freeze_epoch_seconds >= wall_deadline_epoch_seconds,
            "observation_not_exhausted": observation.runtime_state.wall_elapsed_seconds < observation.resource_config.maximum_wall_clock_seconds,
        }
        print(prefix + json.dumps({
            "case_id": case_id, "phase": "READBACK_COMPLETE",
            "expected_ledger_run_id": expected_ledger_run_id,
            "freeze_run_id": freeze.run_id,
            "expected_execution_run_id": expected_execution_run_id,
            "execution_run_id": spec.run_id,
            "evidence_class": spec.evidence_class.value,
            "required_evidence_class": EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE.value,
            "spec_seeds": spec.seeds, "contract_seeds": contract.seed_reporting.seeds,
            "plan_artifact_sha256s": freeze.experiment_plan_artifact_sha256s,
            "freeze_receipt_sha256": freeze_sha256,
            "contract_artifact_sha256": freeze.contract_artifact_sha256,
            "spec_artifact_sha256": freeze.frozen_run_spec_artifact_sha256,
            "selected_inventory_sha256": frozen_configuration_inventory_artifact_sha256,
            "observation_inventory_sha256": observation.frozen_configuration_inventory_artifact_sha256,
            "inventory_record_hash": inventory_record.record_hash,
            "observation_inventory_record_hash": observation.frozen_configuration_inventory_record_hash,
            "freeze_event_index": freeze.design_freeze_event_index,
            "freeze_event_id": freeze_event.event_id,
            "receipt_freeze_event_id": freeze.design_freeze_event_id,
            "freeze_event_hash": freeze_event.event_hash,
            "receipt_freeze_event_hash": freeze.design_freeze_event_hash,
            "freeze_timestamp": freeze_event.timestamp,
            "freeze_epoch_seconds": freeze_epoch_seconds,
            "observation_sha256": observation.observation_artifact_sha256,
            "observation_record_hash": observation.observation_record_hash,
            "observation_event_index": observation.ledger_event_index,
            "observation_event_id": observation.ledger_event_id,
            "observation_event_hash": observation.ledger_event_hash,
            "ledger_event_count": len(events),
            "ledger_head_hash": events[-1].event_hash,
            "wall_started_at_epoch_seconds": observation.runtime_state.wall_started_at_epoch_seconds,
            "wall_observed_at_epoch_seconds": observation.runtime_state.wall_observed_at_epoch_seconds,
            "maximum_wall_clock_seconds": observation.resource_config.maximum_wall_clock_seconds,
            "wall_elapsed_seconds": observation.runtime_state.wall_elapsed_seconds,
            "wall_deadline_epoch_seconds": wall_deadline_epoch_seconds,
            "rejecting_predicates": rejecting_predicates,
            "local_source_closure_mismatch": any(rejecting_predicates.values()),
        }, sort_keys=True), flush=True)
        self.assertEqual(observation.resource_config.maximum_wall_clock_seconds, expected_budget)
        self.assertLess(freeze.design_freeze_event_index, observation.ledger_event_index)
        self.assertLess(
            freeze_epoch_seconds, wall_deadline_epoch_seconds,
            "The real prospective compute fixture expired before design freeze.",
        )
        self.assertGreaterEqual(
            observation.runtime_state.wall_elapsed_seconds,
            observation.resource_config.maximum_wall_clock_seconds,
        )
        self.assertFalse(any(rejecting_predicates.values()), rejecting_predicates)

    def _observe_exhaustion(self):
        deadline = time.monotonic() + getattr(self, "_real_wall_budget_seconds", 1) + 1.0
        while True:
            try:
                observation = self.orchestrator.observe_run_wall_budget(self.run_id)
            except OrchestrationError as exc:
                if "not exhausted" not in str(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
                continue
            self._emit_closure_diagnostic(observation)
            return observation

    def test_scheduled_setup_failure_restores_clock_patches_for_default_fixture(self):
        timestamp_bindings = (
            (orchestrator_module, "_utc_now"),
            (ledger_module, "utc_now"),
            (artifacts_module, "utc_now"),
            (scientific_design_module, "utc_now"),
        )
        original_resource_controller_init = ResourceController.__init__
        original_timestamp_providers = tuple(
            getattr(module, name) for module, name in timestamp_bindings
        )

        failed_fixture = ComputeTerminalAuthorityTests()
        failed_fixture._prepared_failure_copy = True
        failed_fixture.configure_scheduled_wall_clock()
        with patch.object(
            ScientistOneOrchestrator,
            "start",
            side_effect=RuntimeError("injected native setup failure"),
        ), self.assertRaisesRegex(RuntimeError, "injected native setup failure"):
            failed_fixture.setUp()

        failed_root = failed_fixture.root
        self.assertFalse(failed_root.exists())
        self.assertIs(ResourceController.__init__, original_resource_controller_init)
        for (module, name), original in zip(
            timestamp_bindings, original_timestamp_providers
        ):
            with self.subTest(provider=f"{module.__name__}.{name}"):
                self.assertIs(getattr(module, name), original)
        failed_fixture.tearDown()

        default_fixture = ComputeTerminalAuthorityTests()
        try:
            default_fixture.setUp()
            manifest = default_fixture.orchestrator.load_manifest(
                default_fixture.run_id
            )
            controller = default_fixture.orchestrator._resource_controller(manifest)
            self.assertIs(controller._clock, time.monotonic)
            self.assertIs(controller._wall_clock, time.time)
        finally:
            default_fixture.tearDown()
            default_fixture.tearDown()

    def _leave_external_wall_observation_unprojected(self):
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            manifest = self.orchestrator.load_manifest(self.run_id)
            started = manifest["resource_runtime_state"][
                "wall_started_at_epoch_seconds"
            ]
            if time.time() - started >= 1.0:
                break
            time.sleep(0.02)
        original = self.orchestrator._persist_resource_authority

        def persist_then_crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated crash after external authority")

        with patch.object(
            self.orchestrator,
            "_persist_resource_authority",
            side_effect=persist_then_crash,
        ), self.assertRaisesRegex(RuntimeError, "simulated crash"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        return self.orchestrator._resource_authority_records(self.run_id)[-1]

    def _fixed_expired_observation_payload(self):
        deadline = time.monotonic() + 2.0
        while True:
            manifest = self.orchestrator.load_manifest(self.run_id)
            started = manifest["resource_runtime_state"][
                "wall_started_at_epoch_seconds"
            ]
            if time.time() - started >= 1.0:
                break
            if time.monotonic() >= deadline:
                self.fail("test run wall budget did not expire")
            time.sleep(0.02)
        config = self.orchestrator._load_frozen_resource_config(manifest)
        controller = self.orchestrator._resource_controller(manifest)
        runtime_state = controller.observe_wall_time()
        payload = self.orchestrator._wall_budget_observation_payload(
            manifest,
            resource_config=config,
            runtime_state=runtime_state,
        )
        return runtime_state, payload

    def _append_security_stop(self) -> None:
        head = self.ledger.events()[-1]
        event = self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.ADVERSARIAL_REVIEWER,
            state_before=head.state_after,
            requested_state_after=TerminalState.STOP_SECURITY,
            artifact_hashes=(),
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            dataset_identifiers=head.dataset_identifiers,
            random_seeds=head.random_seeds,
            evaluator_outputs=(),
            reason="adverse prior security terminal fixture",
            event_type="SECURITY_STOP",
        )
        manifest = self.orchestrator.load_manifest(self.run_id)
        manifest["current_state"] = TerminalState.STOP_SECURITY.value
        manifest["terminal_state"] = TerminalState.STOP_SECURITY.value
        manifest["event_count"] = len(self.ledger.events())
        manifest["ledger_head_hash"] = event.event_hash
        self.orchestrator._checkpoint(manifest)

    def _append_correction(self, superseded_event_id: str) -> None:
        head = self.ledger.events()[-1]
        event = self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.ORCHESTRATOR,
            state_before=head.state_after,
            requested_state_after=head.state_after,
            artifact_hashes=(),
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            dataset_identifiers=head.dataset_identifiers,
            random_seeds=head.random_seeds,
            evaluator_outputs=(),
            reason="adverse resource-source correction fixture",
            event_type="CORRECTION",
            supersedes_event_id=superseded_event_id,
        )
        manifest = self.orchestrator.load_manifest(self.run_id)
        manifest["event_count"] = len(self.ledger.events())
        manifest["ledger_head_hash"] = event.event_hash
        self.orchestrator._checkpoint(manifest)

    def test_dual_clock_skew_pins_a_non_replenishing_effective_start(self) -> None:
        monotonic_ticks = iter((0.0, 3600.001, 7200.001))
        wall_ticks = iter((1000.0, 4600.0, 8200.001))
        controller = ResourceController(
            ResourceConfig(maximum_wall_clock_seconds=3600),
            self.root,
            run_id="compute-skew-runtime",
            clock=lambda: next(monotonic_ticks),
            wall_clock=lambda: next(wall_ticks),
            artifact_roots=(),
            validity_budget_units=10,
        )
        initial = controller.export_state()
        skewed = controller.observe_wall_time()
        self.assertAlmostEqual(
            initial.wall_started_at_epoch_seconds
            - skewed.wall_started_at_epoch_seconds,
            0.001,
            places=6,
        )
        self.assertEqual(controller.export_state(), skewed)

        caught_up = controller.observe_wall_time()
        self.assertEqual(
            caught_up.wall_started_at_epoch_seconds,
            skewed.wall_started_at_epoch_seconds,
        )
        restored_monotonic = iter((9000.0, 9001.0))
        restored_wall = iter(
            (
                caught_up.wall_observed_at_epoch_seconds,
                caught_up.wall_observed_at_epoch_seconds + 1.0,
            )
        )
        restored = ResourceController.from_runtime_state(
            controller.config,
            self.root,
            caught_up,
            clock=lambda: next(restored_monotonic),
            wall_clock=lambda: next(restored_wall),
            artifact_roots=(),
        )
        resumed = restored.observe_wall_time()
        self.assertAlmostEqual(
            resumed.wall_started_at_epoch_seconds,
            caught_up.wall_started_at_epoch_seconds,
            places=6,
        )
        self.assertGreaterEqual(
            resumed.wall_elapsed_seconds,
            caught_up.wall_elapsed_seconds,
        )

        records = tuple(
            {"logical_type": "resource_runtime_test", "state": state.to_dict()}
            for state in (initial, skewed, caught_up, resumed)
        )
        self.assertEqual(
            _validate_monotonic_resource_states(records),
            (initial, skewed, caught_up, resumed),
        )
        forward = replace(
            resumed,
            wall_started_at_epoch_seconds=(
                resumed.wall_started_at_epoch_seconds + 0.01
            ),
            wall_observed_at_epoch_seconds=(
                resumed.wall_observed_at_epoch_seconds + 1.0
            ),
            wall_elapsed_seconds=resumed.wall_elapsed_seconds + 0.99,
        )
        with self.assertRaisesRegex(OrchestrationError, "not monotonic"):
            _validate_monotonic_resource_states(
                (*records, {"logical_type": "resource_runtime_test", "state": forward.to_dict()})
            )

    def test_wall_observation_is_zero_write_before_expiry_and_freshly_replays(self) -> None:
        records_before = self.registry.list_records()
        events_before = self.ledger.events()
        authority_before = self.orchestrator._resource_authority_records(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "not exhausted"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), records_before)
        self.assertEqual(self.ledger.events(), events_before)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            authority_before,
        )

        observation = self._observe_exhaustion()
        replayed = require_resource_runtime_wall_budget_observation(
            self.registry,
            self.ledger,
            observation_artifact_sha256=observation.observation_artifact_sha256,
            expected_run_id=self.run_id,
        )
        self.assertEqual(replayed, observation)
        self.assertGreaterEqual(
            replayed.runtime_state.wall_elapsed_seconds,
            replayed.resource_config.maximum_wall_clock_seconds,
        )
        repeated = self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(repeated, observation)

        event = self.ledger.events()[observation.ledger_event_index]
        head = self.ledger.events()[-1]
        self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.ORCHESTRATOR,
            state_before=head.state_after,
            requested_state_after=head.state_after,
            artifact_hashes=(),
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            reason="supersede the wall observation in an adverse replay fixture",
            event_type="CORRECTION",
            supersedes_event_id=event.event_id,
        )
        with self.assertRaisesRegex(
            OrchestrationError,
            "extra checkpoint|stale|superseded",
        ):
            require_resource_runtime_wall_budget_observation(
                self.registry,
                self.ledger,
                observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
                expected_run_id=self.run_id,
            )

    def test_wall_observation_accepts_exact_optional_pilot_resource_pair(self) -> None:
        manifest = self.orchestrator.load_manifest(self.run_id)
        restore = ResourceController.from_runtime_state

        def restore_with_fixture_memory(*args, **kwargs):
            # This test covers owned resource-pair readback, not live host
            # memory availability. Keep the actual controller, state replay,
            # admission rules and clocks; supply only its existing probe seam.
            self.assertNotIn("memory_probe", kwargs)
            return restore(
                *args,
                memory_probe=lambda: MemoryObservation(
                    8 * 1024**3, 2 * 1024**3, "AVAILABLE", "TEST_FIXTURE_NOT_HOST_MEMORY"
                ),
                **kwargs,
            )

        with patch.object(ResourceController, "from_runtime_state",
                          side_effect=restore_with_fixture_memory) as restore_probe:
            self.orchestrator._run_with_resources(
                manifest,
                experiment_id="compute-terminal-prior-pilot",
                validity_stage="PILOT",
                validity_units=1,
                operation=lambda: None,
            )
        self.assertGreater(restore_probe.call_count, 0)
        observation = self._observe_exhaustion()
        self.assertEqual(
            require_resource_runtime_wall_budget_observation(
                self.registry,
                self.ledger,
                observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
                expected_run_id=self.run_id,
            ),
            observation,
        )

    def test_resource_closure_rejects_shaped_noncanonical_artifact_metadata(self) -> None:
        manifest = self.orchestrator.load_manifest(self.run_id)
        state = replace(
            ResourceController(
                ResourceConfig.from_mapping(
                    json.loads(
                        (self.root / "configs" / "resource_limits.json").read_text(
                            encoding="utf-8"
                        )
                    )
                ),
                self.root,
                run_id=self.run_id,
                validity_budget_units=10,
            ).export_state(),
            wall_started_at_epoch_seconds=(
                manifest["resource_runtime_state"][
                    "wall_started_at_epoch_seconds"
                ]
                - 1.0
            ),
            wall_observed_at_epoch_seconds=(
                manifest["resource_runtime_state"][
                    "wall_observed_at_epoch_seconds"
                ]
            ),
            wall_elapsed_seconds=1.0,
        )
        state_value = state.to_dict()
        stored = self.registry.put_bytes(
            canonical_json_bytes(state_value) + b"\n",
            logical_type="resource_runtime_initial",
            origin="adverse shaped resource source",
            creator_role=Role.ORCHESTRATOR,
            creation_command=(
                "python3",
                "-I",
                "-S",
                "-B",
                "scripts/scientist_one_cli.py",
                "internal",
            ),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        external = {
            "schema_version": "1.0",
            "kind": "RESOURCE_RUNTIME_AUTHORITY",
            "run_id": self.run_id,
            "sequence": 0,
            "logical_type": "resource_runtime_initial",
            "state_sha256": stored.sha256,
            "state": state_value,
            "prior_authority_sha256": None,
        }
        descriptor = _resource_authority_descriptors_for((external,))[0]
        initial = self.ledger.events()[0]
        event = LedgerEvent.create(
            run_id=self.run_id,
            event_id="event-0001",
            timestamp=initial.timestamp,
            actor_role=Role.ORCHESTRATOR,
            state_before=initial.state_before,
            requested_state_after=initial.requested_state_after,
            artifact_hashes=(stored.sha256,),
            code_version=initial.code_version,
            configuration_hash=initial.configuration_hash,
            dataset_identifiers=initial.dataset_identifiers,
            random_seeds=initial.random_seeds,
            evaluator_outputs=(),
            reason="run initialized inside the offline project boundary",
            prior_event_hash=None,
            event_type="CHECKPOINT",
            metadata={
                "schema_version": "1.0",
                "initialization": True,
                "evaluator_keys": [],
                "artifact_types": ["resource_runtime_initial"],
                "artifact_record_hashes": [str(stored.record_hash)],
                "artifact_descriptors": [
                    {
                        "logical_type": "resource_runtime_initial",
                        "sha256": stored.sha256,
                        "registry_record_hash": str(stored.record_hash),
                        "parent_artifacts": [],
                        "parent_record_hashes": [],
                    }
                ],
                "resource_authority_checkpoint": descriptor,
            },
        )
        with self.assertRaisesRegex(OrchestrationError, "provenance is not built-in"):
            _require_exact_resource_checkpoint_closure(
                self.registry,
                (external,),
                (event,),
            )

    def test_wall_observation_recovers_after_external_first_crash(self) -> None:
        committed = self._leave_external_wall_observation_unprojected()
        observed_at = committed["state"]["runtime_state"][
            "wall_observed_at_epoch_seconds"
        ]
        time.sleep(0.05)
        recovered = self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(
            recovered.runtime_state.wall_observed_at_epoch_seconds,
            observed_at,
        )

    def test_wall_observation_recovery_rejects_mixed_manifest_projection(self) -> None:
        self._leave_external_wall_observation_unprojected()
        manifest = self.orchestrator.load_manifest(self.run_id)
        manifest["resource_runtime_artifact"] = (
            RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        )
        self.orchestrator._save_manifest(manifest)
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "resource head is conflicting"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_recovery_rejects_future_manifest_projection(self) -> None:
        self._leave_external_wall_observation_unprojected()
        manifest = self.orchestrator.load_manifest(self.run_id)
        prior_state = manifest["resource_runtime_state"]
        manifest["resource_runtime_state"] = {
            **prior_state,
            "wall_observed_at_epoch_seconds": (
                prior_state["wall_observed_at_epoch_seconds"] + 10.0
            ),
            "wall_elapsed_seconds": prior_state["wall_elapsed_seconds"] + 10.0,
        }
        self.orchestrator._save_manifest(manifest)
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "resource head is conflicting"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_rejects_live_config_drift_without_writes(self) -> None:
        config_path = self.root / "configs" / "resource_limits.json"
        changed = json.loads(config_path.read_text(encoding="utf-8"))
        changed["cpu_worker_limit"] = int(changed["cpu_worker_limit"]) + 1
        config_path.write_text(json.dumps(changed), encoding="utf-8")
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        with self.assertRaisesRegex(OrchestrationError, "frozen inventory"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )

    def test_wall_observation_preflights_conflicting_registry_metadata(self) -> None:
        runtime_state, payload = self._fixed_expired_observation_payload()
        parents = (
            payload["prior_resource_runtime_artifact_sha256"],
            payload["frozen_configuration_inventory_artifact_sha256"],
        )
        self.registry.put_bytes(
            canonical_json_bytes(payload) + b"\n",
            logical_type=(
                RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
            ),
            origin="adverse same-bytes metadata collision fixture",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "observe-run-wall-budget"),
            parent_artifacts=parents,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with (
            patch.object(
                ResourceController,
                "observe_wall_time",
                return_value=runtime_state,
            ),
            self.assertRaisesRegex(OrchestrationError, "conflicting metadata"),
        ):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_preflights_conflicting_manifest_slot(self) -> None:
        self._fixed_expired_observation_payload()
        manifest = self.orchestrator.load_manifest(self.run_id)
        manifest["artifacts"][
            RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        ] = dict(manifest["artifacts"]["frozen_configuration_inventory"])
        self.orchestrator._save_manifest(manifest)
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "already occupied"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_preflights_manifest_provenance_drift(self) -> None:
        self._fixed_expired_observation_payload()
        manifest = self.orchestrator.load_manifest(self.run_id)
        manifest["code_fingerprint"] = "0" * 64
        self.orchestrator._save_manifest(manifest)
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "provenance"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_preflights_substituted_inventory_selector(self) -> None:
        manifest = self.orchestrator.load_manifest(self.run_id)
        original = manifest["artifacts"]["frozen_configuration_inventory"]
        inventory = json.loads(
            self.registry.get_bytes(original["sha256"]).decode("utf-8")
        )
        inventory["entries"].append(
            {
                "path": "configs/adverse-uncommitted-selector.json",
                "sha256": "0" * 64,
                "size": 0,
            }
        )
        inventory["aggregate_sha256"] = "1" * 64
        substituted = self.registry.put_json(
            inventory,
            logical_type="frozen_configuration_inventory",
            origin="adverse uncommitted inventory selector fixture",
            creator_role=Role.ORCHESTRATOR,
            creation_command=("scientist-one", "test-substituted-inventory"),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        manifest["artifacts"].pop("frozen_configuration_inventory")
        self.orchestrator._bind_registered_control_artifact(
            manifest,
            "frozen_configuration_inventory",
            substituted,
        )
        self.orchestrator._save_manifest(manifest)
        self._fixed_expired_observation_payload()
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "inventory binding"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_wall_observation_rejects_corrected_prior_resource_checkpoint(self) -> None:
        self._fixed_expired_observation_payload()
        self._append_correction(self.ledger.events()[0].event_id)
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "superseded"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_prior_resource_correction_revokes_persisted_observation(self) -> None:
        observation = self._observe_exhaustion()
        self._append_correction(self.ledger.events()[0].event_id)
        with self.assertRaisesRegex(OrchestrationError, "superseded"):
            require_resource_runtime_wall_budget_observation(
                self.registry,
                self.ledger,
                observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
                expected_run_id=self.run_id,
            )

    def test_wall_observation_cannot_follow_an_existing_terminal_cause(self) -> None:
        self._fixed_expired_observation_payload()
        self._append_security_stop()
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        before_manifest = self.orchestrator.load_manifest(self.run_id)
        with self.assertRaisesRegex(OrchestrationError, "terminal run state"):
            self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )
        self.assertEqual(
            self.orchestrator.load_manifest(self.run_id), before_manifest
        )

    def test_later_terminal_preserves_observation_but_blocks_compute_owner(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        self._append_security_stop()
        self.assertEqual(
            require_resource_runtime_wall_budget_observation(
                self.registry,
                self.ledger,
                observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
                expected_run_id=self.run_id,
            ),
            observation,
        )
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-after-another-terminal",
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=(
                freeze_record.sha256
            ),
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                observation.observation_artifact_sha256
            ),
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
        )

    def test_freeze_after_wall_observation_cannot_authorize_assessment(self) -> None:
        observation = self._observe_exhaustion()
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        arguments = {
            "assessment_id": "compute-reverse-causal-order",
            "expected_ledger_run_id": self.run_id,
            "expected_execution_run_id": spec.run_id,
            "evaluation_contract_freeze_receipt_artifact_sha256": (
                freeze_record.sha256
            ),
            "frozen_configuration_inventory_artifact_sha256": (
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            "wall_budget_observation_artifact_sha256": (
                observation.observation_artifact_sha256
            ),
        }
        records_before = self.registry.list_records()
        events_before = self.ledger.events()
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            **arguments,
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
        )
        with self.assertRaisesRegex(ComputeTerminalError, "not authorized"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                **arguments,
            )
        self.assertEqual(self.registry.list_records(), records_before)
        self.assertEqual(self.ledger.events(), events_before)

    def test_design_frozen_after_wall_deadline_cannot_authorize_assessment(self) -> None:
        self._fixed_expired_observation_payload()
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        arguments = {
            "assessment_id": "compute-design-frozen-after-deadline",
            "expected_ledger_run_id": self.run_id,
            "expected_execution_run_id": spec.run_id,
            "evaluation_contract_freeze_receipt_artifact_sha256": (
                freeze_record.sha256
            ),
            "frozen_configuration_inventory_artifact_sha256": (
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            "wall_budget_observation_artifact_sha256": (
                observation.observation_artifact_sha256
            ),
        }
        records_before = self.registry.list_records()
        events_before = self.ledger.events()
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            **arguments,
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
        )
        with self.assertRaisesRegex(ComputeTerminalError, "not authorized"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                **arguments,
            )
        self.assertEqual(self.registry.list_records(), records_before)
        self.assertEqual(self.ledger.events(), events_before)

    def test_assessment_event_before_wall_observation_is_rejected_without_write(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        assessment_id = "compute-early-assessment-event"
        head = self.ledger.events()[-1]
        self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.CLAIM_VERIFIER,
            state_before=head.state_after,
            requested_state_after=head.state_after,
            artifact_hashes=(),
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            reason="adverse early compute assessment event fixture",
            event_type="CHECKPOINT",
            metadata={
                "compute_terminal_assessment_authority": {
                    "assessment_id": assessment_id,
                    "scientific_binding_sha256": spec.scientific_binding_sha256,
                }
            },
        )
        observation = self._observe_exhaustion()
        records_before = self.registry.list_records()
        events_before = self.ledger.events()
        with self.assertRaisesRegex(ComputeTerminalError, "competing|must follow"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                assessment_id=assessment_id,
                expected_ledger_run_id=self.run_id,
                expected_execution_run_id=spec.run_id,
                evaluation_contract_freeze_receipt_artifact_sha256=(
                    freeze_record.sha256
                ),
                frozen_configuration_inventory_artifact_sha256=(
                    observation.frozen_configuration_inventory_artifact_sha256
                ),
                wall_budget_observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
            )
        self.assertEqual(self.registry.list_records(), records_before)
        self.assertEqual(self.ledger.events(), events_before)

    def test_owner_backed_compute_assessment_materializes_only_operational_scope(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-terminal-wall-exhausted",
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=freeze_record.sha256,
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                observation.observation_artifact_sha256
            ),
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.AUTHORIZED,
        )
        source = register_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-terminal-wall-exhausted",
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=freeze_record.sha256,
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                observation.observation_artifact_sha256
            ),
        )
        assessment = require_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_artifact_sha256=source.sha256,
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
        )
        self.assertEqual(assessment.factual_status, WALL_BUDGET_EXHAUSTED_STATUS)

        head = self.ledger.events()[-1]
        repository = ResearchStateRepository(
            self.registry,
            self.ledger,
            run_id=self.run_id,
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            state=head.state_after,
            creation_command=("scientist-one", "test-compute-terminal"),
        )
        derivation = derive_from_registered_compute_terminal_assessment(
            repository,
            source.sha256,
            expected_assessment_id=assessment.assessment_id,
        )
        self.assertIs(derivation.outcome, ResearchTerminalOutcome.INSUFFICIENT_COMPUTE)
        self.assertIs(
            derivation.authority_scope, TerminalAuthorityScope.OPERATIONAL_BLOCKER
        )
        record = ResearchTerminalRecord(
            record_id="terminal-compute-wall-budget-exhausted",
            run_id=self.run_id,
            phase=TerminalPhase.COMPUTE,
            outcome=ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
            reason="The exact precommitted run wall budget expired before work started.",
            evidence_artifact_hashes=(
                derivation.source_binding.required_evidence_artifact_hashes
            ),
            derivation=derivation,
            producer=Role.SCIENTIFIC_REVIEWER,
            authority_scope=TerminalAuthorityScope.OPERATIONAL_BLOCKER,
            source_object_id=assessment.assessment_id,
            source_claim_ids=(),
            created_at=source.created_at,
        )
        materialized = materialize_terminal_outcome(record, repository)
        self.assertEqual(
            load_terminal_outcome(
                self.registry,
                materialized.terminal_artifact.sha256,
                repository=repository,
            ),
            record,
        )

    def test_progress_and_legacy_map_cannot_upgrade_to_compute_authority(self) -> None:
        spec, spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        self.registry.put_json(
            {"preparation": "present but deliberately not an authority fixture"},
            logical_type="scientific_execution_preparation",
            origin="compute terminal adverse progress fixture",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "test-compute-progress"),
            parent_artifacts=(spec_record.sha256,),
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-progress-present",
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=freeze_record.sha256,
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                observation.observation_artifact_sha256
            ),
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.NONTERMINAL,
        )
        with self.assertRaises(ComputeTerminalError):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                assessment_id="compute-progress-present",
                expected_ledger_run_id=self.run_id,
                expected_execution_run_id=spec.run_id,
                evaluation_contract_freeze_receipt_artifact_sha256=(
                    freeze_record.sha256
                ),
                frozen_configuration_inventory_artifact_sha256=(
                    observation.frozen_configuration_inventory_artifact_sha256
                ),
                wall_budget_observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
            )
        with self.assertRaisesRegex(Exception, "does not map"):
            TerminalOutcomeDerivation(
                source_kind=TerminalSourceKind.COMPUTE_STATUS,
                source_statuses=(WALL_BUDGET_EXHAUSTED_STATUS,),
                phase=TerminalPhase.COMPUTE,
                outcome=ResearchTerminalOutcome.INSUFFICIENT_COMPUTE,
                mapping_id=LEGACY_TERMINAL_OUTCOME_MAPPING_ID,
            )

    def test_event_first_assessment_crash_recovers_only_exact_identity(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        arguments = {
            "expected_ledger_run_id": self.run_id,
            "expected_execution_run_id": spec.run_id,
            "evaluation_contract_freeze_receipt_artifact_sha256": (
                freeze_record.sha256
            ),
            "frozen_configuration_inventory_artifact_sha256": (
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            "wall_budget_observation_artifact_sha256": (
                observation.observation_artifact_sha256
            ),
        }
        with patch.object(
            self.registry,
            "_put_bytes_locked",
            side_effect=RuntimeError("simulated event-first crash"),
        ), self.assertRaisesRegex(RuntimeError, "event-first crash"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                assessment_id="compute-exact-recovery",
                **arguments,
            )
        event_count = len(self.ledger.events())
        record_count = len(self.registry.list_records())
        with self.assertRaisesRegex(ComputeTerminalError, "competing"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                assessment_id="compute-alias-recovery",
                **arguments,
            )
        self.assertEqual(len(self.ledger.events()), event_count)
        self.assertEqual(len(self.registry.list_records()), record_count)
        recovered = register_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-exact-recovery",
            **arguments,
        )
        repeated = register_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-exact-recovery",
            **arguments,
        )
        self.assertEqual(repeated, recovered)
        self.assertEqual(len(self.ledger.events()), event_count)

    def test_assessment_recovery_preflights_same_bytes_metadata_collision(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        arguments = {
            "assessment_id": "compute-assessment-metadata-collision",
            "expected_ledger_run_id": self.run_id,
            "expected_execution_run_id": spec.run_id,
            "evaluation_contract_freeze_receipt_artifact_sha256": (
                freeze_record.sha256
            ),
            "frozen_configuration_inventory_artifact_sha256": (
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            "wall_budget_observation_artifact_sha256": (
                observation.observation_artifact_sha256
            ),
        }
        with patch.object(
            self.registry,
            "_put_bytes_locked",
            side_effect=RuntimeError("simulated event-first crash"),
        ), self.assertRaisesRegex(RuntimeError, "event-first crash"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                **arguments,
            )

        with compute_terminal_module._project_resource_execution_lock(self.root):
            status, _reason, sources = compute_terminal_module._derive_sources(
                self.registry,
                self.ledger,
                expected_ledger_run_id=self.run_id,
                expected_execution_run_id=spec.run_id,
                evaluation_contract_freeze_receipt_artifact_sha256=(
                    freeze_record.sha256
                ),
                frozen_configuration_inventory_artifact_sha256=(
                    observation.frozen_configuration_inventory_artifact_sha256
                ),
                wall_budget_observation_artifact_sha256=(
                    observation.observation_artifact_sha256
                ),
            )
        self.assertIs(
            status,
            ComputeTerminalAssessmentResolutionStatus.AUTHORIZED,
        )
        self.assertIsNotNone(sources)
        assert sources is not None
        matches = compute_terminal_module._matching_assessment_events(
            self.ledger.events(),
            assessment_id=arguments["assessment_id"],
            scientific_binding_sha256=spec.scientific_binding_sha256,
        )
        self.assertEqual(len(matches), 1)
        event_index, event, _binding = matches[0]
        assessment = compute_terminal_module._assessment_from_event(
            arguments["assessment_id"],
            sources,
            event,
            event_index,
        )
        self.registry.put_bytes(
            canonical_json_bytes(assessment.to_dict()) + b"\n",
            logical_type="compute_terminal_assessment",
            origin="adverse same-bytes assessment metadata collision",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "compute-terminal-assess"),
            parent_artifacts=assessment.source_artifact_sha256s,
            schema_version="1.0",
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
        )
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        before_authority = self.orchestrator._resource_authority_records(
            self.run_id
        )
        with self.assertRaisesRegex(ComputeTerminalError, "registry slot is competing"):
            register_compute_terminal_assessment(
                self.registry,
                self.ledger,
                **arguments,
            )
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)
        self.assertEqual(
            self.orchestrator._resource_authority_records(self.run_id),
            before_authority,
        )

    def test_any_external_consumption_key_blocks_without_writes(self) -> None:
        spec, _spec_record, freeze_record = self._freeze_mandatory_work()
        observation = self._observe_exhaustion()
        head = self.ledger.events()[-1]
        self.ledger.record(
            run_id=self.run_id,
            actor_role=Role.ORCHESTRATOR,
            state_before=head.state_after,
            requested_state_after=head.state_after,
            artifact_hashes=(),
            code_version=head.code_version,
            configuration_hash=head.configuration_hash,
            reason="record an adverse external-consumption marker fixture",
            event_type="CHECKPOINT",
            metadata={"compute_escalation_submission_consumption": "malformed"},
        )
        before_records = self.registry.list_records()
        before_events = self.ledger.events()
        resolution = resolve_compute_terminal_assessment(
            self.registry,
            self.ledger,
            assessment_id="compute-consumption-present",
            expected_ledger_run_id=self.run_id,
            expected_execution_run_id=spec.run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=freeze_record.sha256,
            frozen_configuration_inventory_artifact_sha256=(
                observation.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                observation.observation_artifact_sha256
            ),
        )
        self.assertIs(
            resolution.status,
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.registry.list_records(), before_records)
        self.assertEqual(self.ledger.events(), before_events)


if __name__ == "__main__":
    unittest.main()
