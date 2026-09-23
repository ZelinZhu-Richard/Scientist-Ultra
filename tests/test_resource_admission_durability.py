"""Durable ordinary admission refusals; public synthetic fixtures only.

No test claims an observed OS crash, protected-data validity or scientific
authority. The crash-counter case explicitly seeds the existing counter API.
All source/configuration/fixture bytes are copied before the normal launcher
captures them; no attestation, admission or guard is bypassed.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from scientist_one.artifacts import ArtifactRegistry
from scientist_one.errors import UnsafeSerializationError
from scientist_one.ledger import EventLedger
from scientist_one.recovery import RecoveryManager
from scientist_one.orchestrator import (
    RESOURCE_RUNTIME_ADMISSION_REFUSAL,
    RESOURCE_RUNTIME_PILOT_FAILURE,
    OrchestrationError,
    ScientistOneOrchestrator,
    _ResourceAdmissionBlocked,
    _canonical_bytes,
    _require_exact_resource_checkpoint_closure,
)
from scientist_one.resources import (
    MemoryObservation,
    PressureObservation,
    ResourceConfig,
    ResourceController,
    ResourceLimitError,
    ResourceLease,
    ResourceRuntimeState,
    _ResourceAdmissionRefusal,
    _replay_resource_admission,
)
from tests.test_resource_admission_fixture import (
    _HISTORICAL_DRIFT_CASES,
    prepared_admission_tests,
    prepared_root,
    replay_child,
)

_SLOT = RESOURCE_RUNTIME_ADMISSION_REFUSAL
_FAILURE = RESOURCE_RUNTIME_PILOT_FAILURE
_REPLAY_INPUT = "reports/admission-replay-fixture.json"


def state_bytes(root):
    """Observe complete file/path identities; reading itself is not evidence."""
    return {
        p.relative_to(root).as_posix(): (
            p.read_bytes(), p.stat().st_dev, p.stat().st_ino,
            p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns,
        )
        for p in root.rglob("*") if p.is_file()
    }


def forbid_observation(stack):
    for name in ("__init__", "snapshot", "evaluate", "record_progress", "acquire"):
        guarded = stack.enter_context(mock.patch.object(
            ResourceController, name,
            side_effect=AssertionError("sticky replay observed/admitted new resources"),
        ))
        stack.callback(guarded.assert_not_called)
    guarded = stack.enter_context(mock.patch(
        "scientist_one.resources.os.cpu_count",
        side_effect=AssertionError("sticky replay sampled CPU"),
    ))
    stack.callback(guarded.assert_not_called)
    guarded = stack.enter_context(mock.patch(
        "scientist_one.orchestrator._utc_now",
        side_effect=AssertionError("sticky replay sampled publication time"),
    ))
    stack.callback(guarded.assert_not_called)


def forbid_negative_mutation(stack):
    """Even recover(repair_truncated_tail=False) may quarantine: forbid it."""
    for name in ("recover", "quarantine_incomplete", "_quarantine_move",
                 "repair_truncated_ledger", "create_checkpoint"):
        guarded = stack.enter_context(mock.patch.object(
            RecoveryManager, name, side_effect=AssertionError("negative path invoked recovery/repair/quarantine"),
        ))
        stack.callback(guarded.assert_not_called)
    for name in ("_recovery_report", "_resource_controller", "_transition_terminal", "_handler_candidate",
                 "_artifact", "_artifact_from_file", "_append_event", "_checkpoint", "_save_manifest",
                 "_persist_resource_authority", "_commit_pilot_failure", "_commit_admission_refusal"):
        guarded = stack.enter_context(mock.patch.object(
            ScientistOneOrchestrator, name, side_effect=AssertionError("negative path invoked work/publication"),
        ))
        stack.callback(guarded.assert_not_called)


def forbid_historical_live_reads(stack):
    for name in ("_source_inventory", "_configuration_inventory"):
        guarded = stack.enter_context(mock.patch(
            "scientist_one.orchestrator." + name,
            side_effect=AssertionError("historical negative readback sampled live inventory"),
        ))
        stack.callback(guarded.assert_not_called)
    guarded = stack.enter_context(mock.patch.object(
        ScientistOneOrchestrator, "_load_frozen_resource_config",
        side_effect=AssertionError("historical negative readback reloaded live policy"),
    ))
    stack.callback(guarded.assert_not_called)


def fresh_replay(case):
    """Called only by the physically pre-created second-process wrapper."""
    root = Path.cwd().resolve()
    value = json.loads((root / _REPLAY_INPUT).read_text(encoding="utf-8"))
    case.assertEqual(set(value), {"run_id", "status"})
    selection = json.loads((root / ".prepared-admission-case.json").read_bytes())
    if selection["test_id"].endswith(".test_pending_pilot_fresh_process_evaluator_continuation"):
        return fresh_evaluator_continuation(case, root, value)
    before = state_bytes(root)
    with ExitStack() as stack:
        forbid_observation(stack)
        forbid_negative_mutation(stack)
        orchestrator = ScientistOneOrchestrator(root)
        selection = json.loads((root / ".prepared-admission-case.json").read_bytes())
        case.assertEqual(set(selection), {"test_id"})
        if selection["test_id"] in _HISTORICAL_DRIFT_CASES:
            manifest = orchestrator.load_manifest(value["run_id"])
            case.assertFalse(orchestrator._validate_live_inventories(manifest))
            events = EventLedger(root, Path("runs") / value["run_id"] / "events.jsonl").assert_valid().events
            case.assertEqual(manifest["code_fingerprint"], events[0].code_version)
            case.assertEqual(manifest["configuration_sha256"], events[0].configuration_hash)
            case.assertEqual(manifest["fixture_identifiers"], list(events[0].dataset_identifiers))
            case.assertEqual(manifest["random_seeds"], list(events[0].random_seeds))
            for name, identity in (("frozen_source_inventory", manifest["code_fingerprint"]),
                                   ("frozen_configuration_inventory", manifest["configuration_sha256"])):
                case.assertEqual(orchestrator._json_artifact_payload(manifest, name)["aggregate_sha256"], identity)
            case.assertEqual(value["status"]["authority_channel"], "EXISTING_RESOURCE_ROLLBACK_TERMINAL")
            case.assertEqual(value["status"]["status"], "STOP_SECURITY")
            case.assertFalse(value["status"]["resumable"])
            case.assertIsNone(value["status"]["safe_resume_command"])
        if value["status"].get("authority_channel") == "EXISTING_RESOURCE_ROLLBACK_TERMINAL":
            forbid_historical_live_reads(stack)
        for operation in (orchestrator.status, orchestrator.advance_once, orchestrator.resume):
            case.assertEqual(operation(value["run_id"]), value["status"])
        operation = mock.Mock(side_effect=AssertionError("fresh negative replay admitted work"))
        with case.assertRaises(OrchestrationError):
            orchestrator._run_with_resources(
                orchestrator.load_manifest(value["run_id"]), experiment_id=value["run_id"] + ":pilot",
                validity_stage="PILOT", validity_units=2, operation=operation,
            )
        operation.assert_not_called()
    case.assertEqual(state_bytes(root), before)


def fresh_evaluator_continuation(case, root, value):
    """One fixed original case's real evaluator continuation in a fresh capture."""
    orchestrator = ScientistOneOrchestrator(root)
    manifest = orchestrator.load_manifest(value["run_id"])
    before = state_bytes(root)
    with ExitStack() as stack:
        forbid_observation(stack)
        forbid_negative_mutation(stack)
        case.assertEqual(orchestrator.status(value["run_id"]), value["status"])
    case.assertEqual(state_bytes(root), before)
    original_init = ResourceController.__init__
    runtime = manifest["resource_runtime_state"]

    def init(controller, config, project_root, **kwargs):
        kwargs.update(clock=lambda: 1000.0 + runtime["wall_elapsed_seconds"],
                      wall_clock=lambda: runtime["wall_observed_at_epoch_seconds"],
                      memory_probe=lambda: MemoryObservation(10, 1, "AVAILABLE", "synthetic-test"),
                      pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "synthetic-test"),
                      disk_usage_probe=lambda _path: SimpleNamespace(total=10**12, used=10**9, free=10**12-10**9))
        original_init(controller, config, project_root, **kwargs)

    with mock.patch.object(ResourceController, "__init__", init), ExitStack() as stack:
        for owner, name in ((ResourceController, "acquire"), (ResourceController, "record_progress"),
                            (ScientistOneOrchestrator, "_handler_candidate"),
                            (ScientistOneOrchestrator, "_run_with_resources"),
                            (ScientistOneOrchestrator, "_artifact")):
            guarded = stack.enter_context(mock.patch.object(
                owner, name, side_effect=AssertionError("fresh evaluator replay repeated PILOT")))
            stack.callback(guarded.assert_not_called)
        result = orchestrator.advance_once(value["run_id"])
    case.assertEqual(result["current_state"], "CONFIRM")
    after = orchestrator.load_manifest(value["run_id"])
    case.assertEqual(after["artifacts"], manifest["artifacts"])
    case.assertEqual(after["resource_runtime_state"], runtime)
    case.assertEqual(after["event_count"], manifest["event_count"] + 1)
    case.assertEqual(set(after["evaluator_decisions"]) - set(manifest["evaluator_decisions"]),
                     {"E0:CANDIDATE", "E2:CANDIDATE", "E3:CANDIDATE"})
    case.assertNotIn(_FAILURE, after["artifacts"])


@prepared_admission_tests
class ResourceAdmissionDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.root = prepared_root(self)
        if self._testMethodName == "test_real_controller_fractional_and_divergent_clock_replay":
            # Pure real-controller observation/replay cases need no research
            # trajectory or manufactured initialized run context.
            return
        self.elapsed = 0.0
        self.memory_used = 1
        seed_crashes = self._testMethodName == "test_seeded_counter_fixture_replays_actual_crash_decision"
        original_init = ResourceController.__init__

        def init(controller, config, project_root, **kwargs):
            kwargs.update(
                clock=lambda: 1000.0 + self.elapsed,
                wall_clock=lambda: 1000000.0 + self.elapsed,
                memory_probe=lambda: MemoryObservation(10, self.memory_used, "AVAILABLE", "synthetic-test"),
                pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "synthetic-test"),
                disk_usage_probe=lambda _path: SimpleNamespace(total=10**12, used=10**9, free=10**12-10**9),
            )
            original_init(controller, config, project_root, **kwargs)
            if seed_crashes and kwargs.get("restored_state") is None and controller.run_id.startswith("run-"):
                for _ in range(config.worker_crash_limit):
                    controller.register_worker_crash("synthetic-counter-fixture")

        patcher = mock.patch.object(ResourceController, "__init__", init)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.orchestrator = ScientistOneOrchestrator(self.root)
        brief_cases = {
            "test_pilot_supplied_text_in_synthetic_mode_is_preserved",
            "test_pilot_default_brief_gate_remains_blocked_external",
            "test_pending_pilot_supplied_brief_preserves_text_owner",
        }
        if self._testMethodName in brief_cases:
            brief = Path("reports/supplied-known-answer-brief.txt")
            (self.root / brief).write_text("Synthetic known-answer compatibility fixture only. No external evidence.\n", encoding="utf-8")
            mode = "synthetic_demo" if self._testMethodName != "test_pilot_default_brief_gate_remains_blocked_external" else None
            started = self.orchestrator.start(brief=brief, mode=mode)
        else:
            started = self.orchestrator.start()
        self.assertEqual(started["status"], "PASS")
        self.run_id = started["run_id"]
        if (self._testMethodName == "test_pilot_default_brief_gate_remains_blocked_external"
                or self._testMethodName.startswith("test_calibrate_completed_pair_")):
            return
        # Actual original handlers, evaluators and state transitions. No
        # manufactured MacroState or fabricated protocol/scientific receipt.
        for source in ("CALIBRATE", "CHARTER", "GROUND", "PROTOCOL", "PREFLIGHT", "IDEATE", "DISCOVER"):
            self.assertEqual(self.manifest()["current_state"], source)
            result = self.orchestrator.advance_once(self.run_id)
            self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.manifest()["current_state"], "CANDIDATE")

        if self._testMethodName in {
            "test_legacy_successful_pilot_remains_unchanged",
            "test_confirmatory_preseal_is_retained_without_charge_or_reveal",
        }:
            # Model one second of actual owned pilot work, only after its
            # final real publication succeeds. The resource owner still
            # observes both clocks and records/persists progress itself.
            # A frozen zero-duration clock makes charge/completion payloads
            # identical despite their necessarily different frozen metadata.
            original_artifact = self.orchestrator._artifact

            def timed_artifact(manifest, logical_type, payload, *, creator, parents=()):
                record = original_artifact(
                    manifest, logical_type, payload, creator=creator, parents=parents,
                )
                if logical_type == "blind_interpretation":
                    self.assertEqual(self.elapsed, 0.0)
                    self.elapsed += 1.0
                return record

            timing = mock.patch.object(self.orchestrator, "_artifact", timed_artifact)
            timing.start()
            self.addCleanup(timing.stop)

    def assert_pilot_inert(self, *, status=None):
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("blocked pilot callback ran"))
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            stack.enter_context(mock.patch.object(self.orchestrator, "_recovery_report",
                                                  side_effect=AssertionError("negative path called recovery")))
            stack.enter_context(mock.patch.object(self.orchestrator, "_transition_terminal",
                                                  side_effect=AssertionError("negative path published terminal")))
            for action in (self.orchestrator.status, self.orchestrator.advance_once, self.orchestrator.resume):
                if status is None:
                    with self.assertRaises(OrchestrationError) as captured:
                        action(self.run_id)
                    self.assertNotIsInstance(captured.exception, AssertionError)
                else:
                    self.assertEqual(action(self.run_id), status)
                self.assertEqual(state_bytes(self.root), before)
            with self.assertRaises(OrchestrationError):
                self.call_pilot(operation)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        self.assertNotIn("terminal_report", self.manifest()["artifacts"])

    def owned_pilot_failure(self, prefix, *, before_projection=False, error=None, mutate=None):
        error = error if error is not None else RuntimeError("PRIVATE_TEST_ERROR_NOT_FOR_EVIDENCE")
        original_artifact = self.orchestrator._artifact
        original_put = ArtifactRegistry.put_bytes
        outputs = ("pilot_report", "midrun_review", "blind_interpretation")

        def artifact(manifest, name, *args, **kwargs):
            if not before_projection and prefix < 3 and name == outputs[prefix]:
                if mutate is not None:
                    mutate(manifest)
                raise error
            value = original_artifact(manifest, name, *args, **kwargs)
            if prefix == 3 and name == outputs[-1]:
                raise error
            return value

        def put(registry, data, **kwargs):
            value = original_put(registry, data, **kwargs)
            if before_projection and kwargs.get("logical_type") == outputs[prefix - 1]:
                raise error
            return value

        with mock.patch.object(self.orchestrator, "_artifact", artifact), mock.patch.object(ArtifactRegistry, "put_bytes", put):
            try:
                self.orchestrator.advance_once(self.run_id)
            except BaseException as caught:
                return error, caught
        self.fail("owned pilot failure was not propagated")

    def assert_pilot_failure(self, prefix, *, before_projection=False, resource_error=False):
        before = self.manifest()
        error = ResourceLimitError("PRIVATE_TEST_ERROR_NOT_FOR_EVIDENCE") if resource_error else None
        with mock.patch.object(ResourceController, "record_progress", side_effect=AssertionError("failed body recorded progress")):
            original, caught = self.owned_pilot_failure(prefix, before_projection=before_projection, error=error)
        if resource_error:
            self.assertIs(type(caught), OrchestrationError)
            self.assertIs(caught.__cause__, original)
        else:
            self.assertIs(caught, original)
        manifest = self.manifest()
        payload = self.orchestrator._json_artifact_payload(manifest, _FAILURE)
        charge = self.orchestrator._json_artifact_payload(manifest, "resource_runtime_pilot_charge")
        self.assertEqual(payload["runtime_state"], charge)
        self.assertEqual(manifest["resource_runtime_state"], charge)
        self.assertEqual(charge["exploratory_used"], 2)
        for key in ("confirmatory_used", "worker_crashes", "progress_elapsed_seconds", "checkpoint_elapsed_seconds"):
            self.assertEqual(charge[key], before["resource_runtime_state"][key])
        self.assertEqual(payload["reason"], "OWNED_STAGE_CALL_RAISED")
        self.assertIs(payload["scientific_evidence"], False)
        self.assertIs(payload["retry_allowed"], False)
        self.assertEqual(payload["prefix_disposition"], "INCOMPLETE_STAGE_OUTPUT")
        self.assertEqual([p["logical_type"] for p in payload["incomplete_output_prefix"]],
                         ["pilot_report", "midrun_review", "blind_interpretation"][:prefix])
        self.assertEqual(manifest["event_count"], before["event_count"] + 2)
        self.assertEqual(manifest["current_state"], "CANDIDATE")
        self.assertEqual(manifest["evaluator_decisions"], before["evaluator_decisions"])
        self.assertEqual(manifest["typed_transition_receipts"], before["typed_transition_receipts"])
        self.assertNotIn("resource_runtime_pilot_completion", manifest["artifacts"])
        self.assertNotIn(_SLOT, manifest["artifacts"])
        events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events
        self.assertEqual(tuple(events[-1].metadata["artifact_types"]), (*["pilot_report", "midrun_review", "blind_interpretation"][:prefix], _FAILURE))
        self.assertEqual(events[-1].evaluator_outputs, ())
        checkpoint = json.loads((self.root / "runs" / self.run_id / "checkpoint.json").read_text())
        self.assertIs(checkpoint["resumable"], False)
        self.assertEqual(checkpoint["resource_runtime_artifact"], _FAILURE)
        for path, value in state_bytes(self.root).items():
            if path.startswith(("runs/", ".scientist-one-build/resource-authority/")):
                self.assertNotIn(b"PRIVATE_TEST_ERROR_NOT_FOR_EVIDENCE", value[0])
        status = self.orchestrator.status(self.run_id)
        self.assertEqual(status["status"], "RESOURCE_OPERATION_BLOCKED")
        self.assert_pilot_inert(status=status)
        return payload, status

    def pilot_publication_cut(self, phase, boundary):
        target = _FAILURE if phase == "failure" else f"resource_runtime_pilot_{phase}"
        interruption = RuntimeError("PUBLICATION_CUT_NOT_EVIDENCE")
        with ExitStack() as stack:
            if boundary == "external":
                original = self.orchestrator._persist_resource_authority
                def publish(manifest, name, payload):
                    if name == target:
                        raise interruption
                    return original(manifest, name, payload)
                stack.enter_context(mock.patch.object(self.orchestrator, "_persist_resource_authority", publish))
            elif boundary == "registry":
                original = self.orchestrator._artifact
                def artifact(manifest, name, *args, **kwargs):
                    if name == target:
                        raise interruption
                    return original(manifest, name, *args, **kwargs)
                stack.enter_context(mock.patch.object(self.orchestrator, "_artifact", artifact))
            elif boundary == "ledger":
                if phase == "failure":
                    original = EventLedger.append
                    def append(ledger, event):
                        if _FAILURE in event.metadata.get("artifact_types", ()):
                            raise interruption
                        return original(ledger, event)
                    stack.enter_context(mock.patch.object(EventLedger, "append", append))
                else:
                    original = self.orchestrator._append_event
                    def event(manifest, before, after, reason, names, keys, **kwargs):
                        if target in names:
                            raise interruption
                        return original(manifest, before, after, reason, names, keys, **kwargs)
                    stack.enter_context(mock.patch.object(self.orchestrator, "_append_event", event))
            elif boundary in {"checkpoint", "manifest"}:
                owner = "_checkpoint" if boundary == "checkpoint" else "_save_manifest"
                original = getattr(self.orchestrator, owner)
                def save(manifest):
                    if manifest.get("resource_runtime_artifact") == target:
                        raise interruption
                    return original(manifest)
                stack.enter_context(mock.patch.object(self.orchestrator, owner, save))
            else:
                self.fail("unknown publication cut")
            if phase == "failure":
                body, caught = self.owned_pilot_failure(1)
                self.assertIs(caught, interruption)
                self.assertIs(caught.__cause__, body)
            else:
                with self.assertRaises(RuntimeError) as caught:
                    self.orchestrator.advance_once(self.run_id)
                self.assertIs(caught.exception, interruption)
        if phase == "charge" and boundary == "external":
            self.assertEqual(self.orchestrator.status(self.run_id)["status"], "PASS")
            self.assertNotIn("resource_runtime_pilot_charge", self.manifest()["artifacts"])
        elif phase in {"failure", "completion"} and boundary == "external":
            status = self.orchestrator.status(self.run_id)
            self.assertEqual(status["status"], "RESOURCE_OPERATION_UNRESOLVED")
            self.assert_pilot_inert(status=status)
        else:
            self.assert_pilot_inert()
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])

    def timed_real_pilot(self):
        original = self.orchestrator._artifact
        def artifact(manifest, name, *args, **kwargs):
            value = original(manifest, name, *args, **kwargs)
            if name == "blind_interpretation":
                self.elapsed += 1.0
            return value
        patcher = mock.patch.object(self.orchestrator, "_artifact", artifact)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_pilot_failure_zero_complete_outputs(self):
        self.assert_pilot_failure(0)

    def test_pilot_failure_one_complete_output(self):
        self.assert_pilot_failure(1)

    def test_pilot_failure_two_complete_outputs(self):
        self.assert_pilot_failure(2)

    def test_pilot_failure_registry_before_first_projection(self):
        self.assert_pilot_failure(1, before_projection=True)

    def test_pilot_failure_registry_before_second_projection(self):
        self.assert_pilot_failure(2, before_projection=True)

    def test_pilot_failure_resource_limit_error_is_body_owned(self):
        self.assert_pilot_failure(0, resource_error=True)

    def test_pilot_failure_publication_external_cut(self):
        self.pilot_publication_cut("failure", "external")

    def test_pilot_failure_publication_registry_cut(self):
        self.pilot_publication_cut("failure", "registry")

    def test_pilot_failure_publication_ledger_cut(self):
        self.pilot_publication_cut("failure", "ledger")

    def test_pilot_failure_publication_checkpoint_cut(self):
        self.pilot_publication_cut("failure", "checkpoint")

    def test_pilot_failure_publication_manifest_cut(self):
        self.pilot_publication_cut("failure", "manifest")

    def test_pilot_charge_publication_external_cut(self):
        self.pilot_publication_cut("charge", "external")

    def test_pilot_charge_publication_registry_cut(self):
        self.pilot_publication_cut("charge", "registry")

    def test_pilot_charge_publication_ledger_cut(self):
        self.pilot_publication_cut("charge", "ledger")

    def test_pilot_charge_publication_manifest_cut(self):
        self.pilot_publication_cut("charge", "manifest")

    def test_pilot_completion_publication_external_cut(self):
        self.timed_real_pilot()
        self.pilot_publication_cut("completion", "external")

    def test_pilot_completion_publication_registry_cut(self):
        self.timed_real_pilot()
        self.pilot_publication_cut("completion", "registry")

    def test_pilot_completion_publication_ledger_cut(self):
        self.timed_real_pilot()
        self.pilot_publication_cut("completion", "ledger")

    def test_pilot_completion_publication_manifest_cut(self):
        self.timed_real_pilot()
        self.pilot_publication_cut("completion", "manifest")

    def assert_no_positive_pilot_failure(self):
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertNotIn(_FAILURE, [a["logical_type"] for a in authorities])
        self.assertNotIn("resource_runtime_pilot_completion", self.manifest()["artifacts"])
        before = state_bytes(self.root)
        try:
            status = self.orchestrator.status(self.run_id)
        except OrchestrationError as error:
            self.assertNotIsInstance(error, AssertionError)
            status = None
        if status is not None:
            self.assertEqual(status["status"], "RESOURCE_OPERATION_UNRESOLVED")
        self.assertEqual(state_bytes(self.root), before)
        self.assert_pilot_inert(status=status)

    def partial_pilot_publication(self, kind, prefix=0):
        target = ("pilot_report", "midrun_review", "blind_interpretation")[prefix]
        injected = RuntimeError("partial-owned-output")
        original_put = ArtifactRegistry.put_bytes
        original_publish = ArtifactRegistry._publish_immutable

        def put(registry, data, **kwargs):
            if kind == "mirror" and kwargs.get("logical_type") == target:
                raise injected
            record = original_put(registry, data, **kwargs)
            if kind == "metadata" and kwargs.get("logical_type") == target:
                (self.root / record.metadata_path).write_bytes(b"{truncated-metadata")
                raise injected
            return record

        def publish(registry, guard, relative, data):
            if kind == "object" and "/metadata/" in relative.as_posix():
                value = json.loads(data)
                if value.get("logical_type") == target:
                    raise injected
            return original_publish(registry, guard, relative, data)

        with mock.patch.object(ArtifactRegistry, "put_bytes", put), mock.patch.object(ArtifactRegistry, "_publish_immutable", publish):
            with self.assertRaises(Exception) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIsNot(caught.exception, injected)
        self.assertIs(caught.exception.__cause__, injected)
        self.assert_no_positive_pilot_failure()

    def unsupported_pilot_mutation(self, kind):
        original_artifact = self.orchestrator._artifact
        def mutate(manifest):
            directory = self.root / "runs" / self.run_id / "artifacts/candidate"
            if kind in {"file", "directory"}:
                directory.mkdir(exist_ok=True)
                if kind == "file":
                    (directory / "unknown-output.txt").write_text("unbound")
                else:
                    (directory / "unknown-empty-directory").mkdir()
            elif kind == "identity":
                path = self.root / manifest["artifacts"]["workflow_benchmark"]["path"]
                path.write_bytes(path.read_bytes())
            elif kind == "registry":
                original_artifact(manifest, "unknown_output", {"not_authority": True}, creator="orchestrator")
            elif kind == "projection":
                manifest["novelty"] = "SUBSTITUTED_MUTABLE_PROJECTION"
            elif kind == "nonprefix":
                name, payload, creator, parents = self.orchestrator._pilot_publications(manifest)[1]
                original_artifact(manifest, name, payload, creator=creator, parents=parents)
            else:
                self.fail("unknown output mutation")
        original, caught = self.owned_pilot_failure(0, mutate=mutate)
        self.assertIsNot(caught, original)
        self.assertIs(caught.__cause__, original)
        self.assert_no_positive_pilot_failure()

    def pilot_after_return_error(self, point):
        self.timed_real_pilot()
        injected = RuntimeError("after-body-return-not-a-witness")
        with ExitStack() as stack:
            if point == "lease":
                original = ResourceLease.__exit__
                def exit_lease(lease, *args):
                    original(lease, *args)
                    raise injected
                stack.enter_context(mock.patch.object(ResourceLease, "__exit__", exit_lease))
            else:
                original = ResourceController.record_progress
                def progress(controller, *args, **kwargs):
                    if point == "progress-after":
                        original(controller, *args, **kwargs)
                    raise injected
                stack.enter_context(mock.patch.object(ResourceController, "record_progress", progress))
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, injected)
        self.assert_no_positive_pilot_failure()

    def test_pilot_failure_fresh_process_replay(self):
        _, status = self.assert_pilot_failure(2)
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")
        before = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), before)

    def test_pilot_failure_three_complete_outputs(self):
        self.assert_pilot_failure(3)

    def test_pilot_failure_registry_before_third_projection(self):
        self.assert_pilot_failure(3, before_projection=True)

    def test_pilot_failure_three_outputs_fresh_process_replay(self):
        self.third_failure_fresh_replay(before_projection=False)

    def test_pilot_failure_third_before_projection_fresh_process_replay(self):
        self.third_failure_fresh_replay(before_projection=True)

    def third_failure_fresh_replay(self, *, before_projection):
        _, status = self.assert_pilot_failure(3, before_projection=before_projection)
        (self.root / _REPLAY_INPUT).write_text(
            json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8",
        )
        before = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), before)

    def test_pilot_failure_third_output_replay_corruption(self):
        self.assert_pilot_failure(3)
        manifest = self.manifest()
        registry = self.orchestrator._registry(self.run_id)
        binding = manifest["artifacts"]["blind_interpretation"]
        record = registry.get_metadata(binding["sha256"])
        paths = (binding["path"], record.path, record.metadata_path,
                 manifest["artifacts"]["pilot_report"]["path"])
        self.assertEqual(len(paths), len(set(paths)))
        for relative in paths:
            with self.subTest(relative=relative):
                path = self.root / relative
                raw = path.read_bytes()
                try:
                    path.write_bytes(b"{CORRUPTED_THIRD_PREFIX_OR_PREDECESSOR")
                    self.assert_pilot_inert()
                finally:
                    path.write_bytes(raw)

    def third_output_unaccepted(self, kind):
        original_artifact = self.orchestrator._artifact
        interruption = RuntimeError("THIRD_PUBLICATION_NOT_ACCEPTED")
        observed = []

        def artifact(manifest, name, payload, *, creator, parents=()):
            if name != "blind_interpretation":
                return original_artifact(
                    manifest, name, payload, creator=creator, parents=parents,
                )
            self.assertEqual(observed, [])
            if kind == "payload":
                payload = dict(payload, frozen_before_reveal=False)
            elif kind == "role":
                creator = "orchestrator"
            elif kind == "parents":
                parents = (manifest["artifacts"]["workflow_benchmark"]["sha256"],)
            elif kind != "missing_predecessor":
                self.fail("unknown third-output rejection fixture")
            record = original_artifact(
                manifest, name, payload, creator=creator, parents=parents,
            )
            observed.append(record)
            if kind == "missing_predecessor":
                (self.root / manifest["artifacts"]["pilot_report"]["path"]).unlink()
            raise interruption

        with mock.patch.object(self.orchestrator, "_artifact", artifact):
            with self.assertRaises(OrchestrationError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertEqual(len(observed), 1)
        self.assertIsNot(caught.exception, interruption)
        self.assertIs(caught.exception.__cause__, interruption)
        self.assert_no_positive_pilot_failure()

    def test_pilot_third_output_payload_cannot_be_adopted(self):
        self.third_output_unaccepted("payload")

    def test_pilot_third_output_role_cannot_be_adopted(self):
        self.third_output_unaccepted("role")

    def test_pilot_third_output_parents_cannot_be_adopted(self):
        self.third_output_unaccepted("parents")

    def test_pilot_third_output_missing_predecessor_cannot_be_adopted(self):
        self.third_output_unaccepted("missing_predecessor")

    def test_pilot_partial_third_mirror_is_not_adopted(self):
        self.partial_pilot_publication("mirror", 2)

    def test_pilot_partial_third_object_is_not_adopted(self):
        self.partial_pilot_publication("object", 2)

    def test_pilot_partial_third_metadata_is_not_adopted(self):
        self.partial_pilot_publication("metadata", 2)

    def test_pilot_base_capture_error_is_not_body_failure(self):
        error = RuntimeError("capture-before-body")
        with mock.patch.object(self.orchestrator, "_capture_pilot_base", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        self.assert_no_positive_pilot_failure()

    def test_pilot_baseexception_is_not_body_exception_witness(self):
        original, caught = self.owned_pilot_failure(0, error=KeyboardInterrupt("fixture-only interrupt"))
        self.assertIs(caught, original)
        self.assert_no_positive_pilot_failure()

    def test_pilot_generic_callback_has_no_owned_witness(self):
        error = RuntimeError("OWNED_STAGE_CALL_RAISED")
        with self.assertRaises(RuntimeError) as caught:
            self.call_pilot(mock.Mock(side_effect=error))
        self.assertIs(caught.exception, error)
        self.assert_no_positive_pilot_failure()

    def test_pilot_direct_handler_retains_command_protection(self):
        original_artifact = self.orchestrator._artifact
        observed_depth = []
        error = RuntimeError("direct-owned-handler-fixture")
        def artifact(manifest, name, *args, **kwargs):
            if name == "pilot_report":
                observed_depth.append(self.orchestrator._command_guard_depth())
                raise error
            return original_artifact(manifest, name, *args, **kwargs)
        with mock.patch.object(self.orchestrator, "_artifact", artifact):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator._handler_candidate(self.manifest())
        self.assertIs(caught.exception, error)
        self.assertTrue(observed_depth and all(depth > 0 for depth in observed_depth))
        status = self.orchestrator.status(self.run_id)
        self.assertEqual(status["status"], "RESOURCE_OPERATION_BLOCKED")
        self.assert_pilot_inert(status=status)

    def test_pilot_completed_before_evaluator_error_has_no_failure_witness(self):
        self.timed_real_pilot()
        error = RuntimeError("after-complete-before-evaluation")
        with mock.patch.object(self.orchestrator, "_evaluate", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        manifest = self.manifest()
        self.assertNotIn(_FAILURE, manifest["artifacts"])
        self.assertEqual(manifest["resource_runtime_artifact"], "resource_runtime_pilot_completion")
        before = state_bytes(self.root)
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(manifest))
        self.assertEqual(state_bytes(self.root), before)
        # This does not claim evaluator/transition recovery is implemented.

    def test_pilot_completed_then_confirm_admission_refusal_is_valid(self):
        self.timed_real_pilot()
        self.assertEqual(self.orchestrator.advance_once(self.run_id)["current_state"], "CONFIRM")
        status = self.stall()
        self.assertEqual(status["status"], "RESOURCE_ADMISSION_BLOCKED")
        self.assert_pilot_inert(status=status)

    def test_pilot_failure_mutable_terminal_cannot_hide_marker(self):
        self.assert_pilot_failure(0)
        manifest = self.manifest()
        manifest["terminal_state"] = "STOP_SECURITY"
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_pilot_inert()

    def test_pilot_open_charge_cannot_be_cleared_by_completion_name(self):
        with self.assertRaises(RuntimeError):
            self.call_pilot(mock.Mock(side_effect=RuntimeError("ordinary-unowned")))
        manifest = self.manifest()
        manifest["artifacts"]["resource_runtime_pilot_completion"] = dict(manifest["artifacts"]["resource_runtime_pilot_charge"])
        manifest["resource_runtime_artifact"] = "resource_runtime_pilot_completion"
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_pilot_inert()

    def test_pilot_open_charge_conflicting_refusal_marker_is_inert(self):
        with self.assertRaises(RuntimeError):
            self.call_pilot(mock.Mock(side_effect=RuntimeError("ordinary-unowned")))
        manifest = self.manifest()
        manifest["artifacts"][_SLOT] = dict(manifest["artifacts"]["resource_runtime_pilot_charge"])
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_pilot_inert()

    def test_pilot_partial_mirror_prefix_0(self):
        self.partial_pilot_publication("mirror", 0)

    def test_pilot_partial_mirror_prefix_1(self):
        self.partial_pilot_publication("mirror", 1)

    def test_pilot_partial_object_prefix_0(self):
        self.partial_pilot_publication("object", 0)

    def test_pilot_partial_metadata_prefix_0(self):
        self.partial_pilot_publication("metadata", 0)

    def test_pilot_unsupported_file_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("file")

    def test_pilot_unsupported_directory_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("directory")

    def test_pilot_unsupported_identity_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("identity")

    def test_pilot_unsupported_registry_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("registry")

    def test_pilot_unsupported_projection_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("projection")

    def test_pilot_unsupported_nonprefix_cannot_be_adopted(self):
        self.unsupported_pilot_mutation("nonprefix")

    def test_pilot_after_return_lease_is_not_witnessed(self):
        self.pilot_after_return_error("lease")

    def test_pilot_after_return_progress_before_is_not_witnessed(self):
        self.pilot_after_return_error("progress-before")

    def test_pilot_after_return_progress_after_is_not_witnessed(self):
        self.pilot_after_return_error("progress-after")

    def test_pilot_failure_corrupt_external_retains_registry_marker(self):
        self.pilot_publication_cut("failure", "ledger")
        paths = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))
        self.assertEqual(json.loads(paths[-1].read_text())["logical_type"], _FAILURE)
        paths[-1].write_bytes(b"{truncated-earlier-channel")
        self.assert_pilot_inert()

    def test_pilot_failure_corrupt_external_and_registry_retains_ledger_marker(self):
        self.pilot_publication_cut("failure", "checkpoint")
        records = self.orchestrator._registry(self.run_id).verify_all(raise_on_error=True).records
        record = next(r for r in records if r.logical_type == _FAILURE)
        paths = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))
        paths[-1].write_bytes(b"{truncated-earlier-channel")
        (self.root / record.path).write_bytes(b"truncated-refusal-object")
        self.assert_pilot_inert()

    def pilot_context_substitution(self, field, value, *, replay=False):
        if replay:
            self.assert_pilot_failure(1)
            manifest = self.manifest()
            manifest[field] = value
            (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        else:
            original = self.orchestrator._capture_pilot_base
            def capture(manifest):
                manifest[field] = value
                (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
                return original(manifest)
            with mock.patch.object(self.orchestrator, "_capture_pilot_base", capture):
                with self.assertRaises(OrchestrationError):
                    self.orchestrator.advance_once(self.run_id)
            self.assertNotIn(_FAILURE, self.manifest()["artifacts"])
        self.assert_pilot_inert()

    def test_pilot_charged_base_rejects_fixture_identifier_substitution(self):
        self.pilot_context_substitution("fixture_identifiers", ["substituted"])

    def test_pilot_charged_base_rejects_seed_substitution(self):
        self.pilot_context_substitution("random_seeds", [999])

    def test_pilot_charged_base_rejects_code_substitution(self):
        self.pilot_context_substitution("code_fingerprint", "0" * 64)

    def test_pilot_charged_base_rejects_config_substitution(self):
        self.pilot_context_substitution("configuration_sha256", "0" * 64)

    def test_pilot_failure_replay_rejects_fixture_identifier_substitution(self):
        self.pilot_context_substitution("fixture_identifiers", ["substituted"], replay=True)

    def test_pilot_failure_replay_rejects_seed_substitution(self):
        self.pilot_context_substitution("random_seeds", [999], replay=True)

    def test_pilot_failure_replay_rejects_payload_bytes(self):
        self.assert_pilot_failure(1)
        binding = self.manifest()["artifacts"][_FAILURE]
        path = self.root / binding["path"]
        payload = json.loads(path.read_text())
        payload["reason"] = "FORGED_LOOKALIKE"
        path.write_bytes(_canonical_bytes(payload))
        self.assert_pilot_inert()

    def test_pilot_failure_replay_rejects_later_ledger_work(self):
        self.assert_pilot_failure(0)
        manifest = self.manifest()
        self.orchestrator._append_event(manifest, "CANDIDATE", "CANDIDATE", "adverse later work", (), (), event_type="CHECKPOINT")
        self.assert_pilot_inert()

    def test_pilot_failure_replay_rejects_duplicate_checkpoint(self):
        self.assert_pilot_failure(0)
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        last = sorted(directory.glob("*.json"))[-1]
        (directory / "duplicate-fixture.json").write_bytes(last.read_bytes())
        self.assert_pilot_inert()

    def test_pilot_success_confirm_and_terminal_compatibility(self):
        self.successful_pilot_compatibility()

    def test_pilot_ordinary_resume_compatibility(self):
        self.successful_pilot_compatibility(use_resume=True)

    def successful_pilot_compatibility(self, *, use_resume=False):
        self.timed_real_pilot()
        original_run = self.orchestrator._run_with_resources
        def timed_confirm(manifest, **kwargs):
            if kwargs.get("validity_stage") == "CONFIRMATORY":
                original_operation = kwargs["charged_operation"]
                def operation(charged):
                    value = original_operation(charged)
                    self.elapsed += 1.0
                    return value
                kwargs["charged_operation"] = operation
            return original_run(manifest, **kwargs)
        with mock.patch.object(self.orchestrator, "_run_with_resources", timed_confirm):
            if use_resume:
                result = self.orchestrator.resume(self.run_id)
            else:
                for _ in range(20):
                    result = self.orchestrator.advance_once(self.run_id)
                    self.assertEqual(result["status"], "PASS")
                    if result["terminal_state"] is not None:
                        break
                else:
                    self.fail("ordinary synthetic trajectory did not terminate")
        self.assertEqual(result["terminal_state"], "READY_FOR_HUMAN_REVIEW")
        manifest = self.manifest()
        self.assertNotIn(_FAILURE, manifest["artifacts"])
        self.assertNotIn(_SLOT, manifest["artifacts"])
        self.assertEqual(manifest["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(manifest["resource_runtime_state"]["confirmatory_used"], 4)
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(manifest))
        self.assertEqual(self.orchestrator.status(self.run_id)["status"], "PASS")

    def test_pilot_completed_wall_observation_keeps_existing_authority(self):
        self.timed_real_pilot()
        self.assertEqual(self.orchestrator.advance_once(self.run_id)["current_state"], "CONFIRM")
        prior = self.manifest()["resource_runtime_state"]
        self.elapsed = 1001.0
        observation = self.orchestrator.observe_run_wall_budget(self.run_id)
        self.assertGreaterEqual(observation.runtime_state.wall_elapsed_seconds, 1000.0)
        self.assertEqual(observation.runtime_state.exploratory_used, 2)
        self.assertEqual(observation.runtime_state.confirmatory_used, 0)
        self.assertEqual(observation.runtime_state.progress_elapsed_seconds, prior["progress_elapsed_seconds"])
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(self.manifest()))

    def pilot_metadata_substitution(self, field):
        original_put = ArtifactRegistry.put_bytes
        def put(registry, data, **kwargs):
            if kwargs.get("logical_type") == "pilot_report":
                if field == "parent_artifacts":
                    kwargs[field] = (self.manifest()["artifacts"]["frozen_configuration_inventory"]["sha256"],)
                elif field == "creation_command":
                    kwargs[field] = ("python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", "resume", self.run_id)
                elif field == "created_at":
                    kwargs[field] = "2000-01-01T00:00:00Z"
                elif field == "payload":
                    changed = json.loads(data)
                    changed["passed"] = False
                    data = _canonical_bytes(changed)
                else:
                    self.fail("unknown metadata mutation")
            return original_put(registry, data, **kwargs)
        with mock.patch.object(ArtifactRegistry, "put_bytes", put):
            original, caught = self.owned_pilot_failure(1, before_projection=True)
        self.assertIsNot(caught, original)
        self.assertIs(caught.__cause__, original)
        self.assert_no_positive_pilot_failure()

    def test_pilot_prefix_rejects_wrong_parents(self):
        self.pilot_metadata_substitution("parent_artifacts")

    def test_pilot_prefix_rejects_wrong_command(self):
        self.pilot_metadata_substitution("creation_command")

    def test_pilot_prefix_rejects_wrong_timestamp(self):
        self.pilot_metadata_substitution("created_at")

    def test_pilot_prefix_rejects_changed_payload(self):
        self.pilot_metadata_substitution("payload")

    def test_pilot_charge_corrupt_external_retains_registry_marker(self):
        self.pilot_publication_cut("charge", "ledger")
        path = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))[-1]
        self.assertEqual(json.loads(path.read_text())["logical_type"], "resource_runtime_pilot_charge")
        path.write_bytes(b"{truncated-charge-channel")
        self.assert_pilot_inert()

    def test_pilot_completion_corrupt_external_retains_registry_marker(self):
        self.timed_real_pilot()
        self.pilot_publication_cut("completion", "ledger")
        path = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))[-1]
        self.assertEqual(json.loads(path.read_text())["logical_type"], "resource_runtime_pilot_completion")
        path.write_bytes(b"{truncated-completion-channel")
        self.assert_pilot_inert()

    def test_pilot_failure_replay_rejects_refunded_counter(self):
        self.assert_pilot_failure(0)
        manifest = self.manifest()
        manifest["resource_runtime_state"]["exploratory_used"] = 0
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_pilot_inert()

    def test_pilot_replaced_body_exception_has_no_owned_witness(self):
        replacement = RuntimeError("lease-replaced-owned-error")
        original_exit = ResourceLease.__exit__
        def exit_lease(lease, *args):
            original_exit(lease, *args)
            raise replacement
        with mock.patch.object(ResourceLease, "__exit__", exit_lease):
            original, caught = self.owned_pilot_failure(0)
        self.assertIs(caught, replacement)
        self.assertIsNot(caught, original)
        self.assert_no_positive_pilot_failure()

    def test_pilot_admission_before_purported_charge_is_conflicting(self):
        self.stall()
        manifest = self.manifest()
        # Deliberately invalid mutable lookalike, not a real charged authority.
        manifest["artifacts"]["resource_runtime_pilot_charge"] = dict(manifest["artifacts"][_SLOT])
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_pilot_inert()

    def test_pilot_failure_blocks_future_candidate_handler(self):
        _, status = self.assert_pilot_failure(0)
        future = mock.Mock(side_effect=AssertionError("future handler ran after failure"))
        with mock.patch.dict(self.orchestrator._HANDLERS, {"CANDIDATE": future}):
            self.assert_pilot_inert(status=status)
        future.assert_not_called()

    def test_pilot_unresolved_charge_fresh_process_replay(self):
        with self.assertRaises(RuntimeError):
            self.call_pilot(mock.Mock(side_effect=RuntimeError("unowned-callable-fixture")))
        status = self.orchestrator.status(self.run_id)
        self.assertEqual(status["status"], "RESOURCE_OPERATION_UNRESOLVED")
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")
        before = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), before)

    def test_pilot_supplied_text_in_synthetic_mode_is_preserved(self):
        before = self.manifest()["artifacts"]["research_brief"]
        self.assertEqual(self.manifest()["mode"], "synthetic_demo")
        self.assertEqual(before["mime_type"], "text/markdown")
        self.assertTrue(before["path"].endswith(".txt"))
        self.assertEqual(before["origin"], "generated from machine-readable verified artifacts")
        _, status = self.assert_pilot_failure(1)
        self.assertEqual(self.manifest()["artifacts"]["research_brief"], before)
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")
        snapshot = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), snapshot)

    def test_pilot_default_brief_gate_remains_blocked_external(self):
        self.assertEqual(self.manifest()["mode"], "brief")
        self.assertEqual(self.orchestrator.advance_once(self.run_id)["current_state"], "CHARTER")
        result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["terminal_state"], "BLOCKED_EXTERNAL")
        self.assertNotIn("resource_runtime_pilot_charge", self.manifest()["artifacts"])
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])

    def historical_pilot_stop(self, *, report_mutation=None):
        """Generate old history with real unchanged owners, not authored receipts."""
        error = RuntimeError("actual external charge before local publication")
        original = self.orchestrator._artifact
        def artifact(manifest, name, *args, **kwargs):
            if name == "resource_runtime_pilot_charge":
                raise error
            return original(manifest, name, *args, **kwargs)
        with mock.patch.object(self.orchestrator, "_artifact", artifact):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertEqual([a["logical_type"] for a in authorities],
                         ["resource_runtime_initial", "resource_runtime_pilot_charge"])
        self.assertNotIn("resource_runtime_pilot_charge", self.manifest()["artifacts"])
        self.assertNotIn("pilot_report", self.manifest()["artifacts"])
        # ONLY the new router is suppressed, ONLY for old-history construction.
        # Static comparison proves the old dispatch/controller remainder,
        # actual charge and terminal publisher are otherwise unchanged.
        original_put = ArtifactRegistry.put_bytes
        def put(registry, data, **kwargs):
            if kwargs.get("logical_type") == "terminal_report" and report_mutation == "created_at":
                kwargs["created_at"] = "2000-01-01T00:00:00Z"
            return original_put(registry, data, **kwargs)
        def terminal_artifact(manifest, name, payload, *, creator, parents=()):
            if name == "terminal_report":
                if report_mutation == "parent_order":
                    parents = tuple(reversed(parents))
                elif report_mutation == "payload":
                    payload = dict(payload, honest_negative_or_inconclusive=True)
                elif report_mutation == "command":
                    with mock.patch.object(self.orchestrator, "command_context", ("counterfeit-command",)):
                        return original(manifest, name, payload, creator=creator, parents=parents)
            return original(manifest, name, payload, creator=creator, parents=parents)
        with mock.patch.object(self.orchestrator, "_pilot_operation_disposition", return_value=None), mock.patch.object(ArtifactRegistry, "put_bytes", put), mock.patch.object(self.orchestrator, "_artifact", terminal_artifact):
            result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["terminal_state"], "STOP_SECURITY")
        manifest = self.manifest()
        self.assertEqual(manifest["resource_runtime_artifact"], "resource_runtime_initial")
        self.assertEqual(manifest["resource_runtime_state"], authorities[0]["state"])
        registry = self.orchestrator._registry(self.run_id)
        population = registry.verify_all(raise_on_error=True)
        self.assertNotIn("resource_runtime_pilot_charge", [r.logical_type for r in population.records])
        events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").validate()
        self.assertTrue(events.valid)
        final = events.events[-1]
        self.assertEqual(final.event_type, "SECURITY_STOP")
        self.assertEqual(final.state_before.value, "CANDIDATE")
        self.assertEqual(final.requested_state_after.value, "STOP_SECURITY")
        self.assertEqual(tuple(final.metadata["resource_authority_chain"]),
                         tuple(self.orchestrator._resource_authority_descriptors(authorities)))
        self.assertFalse(any("resource_runtime_pilot_charge" in e.metadata["artifact_types"] for e in events.events))
        self.assertIn("terminal_report", manifest["artifacts"])
        self.assertFalse(json.loads((self.root / "runs" / self.run_id / "checkpoint.json").read_bytes())["resumable"])
        return manifest

    def assert_historical_inert(self, *, expected=None, malformed_external_checkpoint=False):
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("historical stop admitted callback"))
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            forbid_historical_live_reads(stack)
            for action in (self.orchestrator.status, self.orchestrator.advance_once, self.orchestrator.resume):
                if malformed_external_checkpoint and action in (
                    self.orchestrator.status, self.orchestrator.advance_once,
                ):
                    with self.assertRaisesRegex(
                        UnsafeSerializationError, "^malformed JSON payload$",
                    ) as caught:
                        action(self.run_id)
                    self.assertIs(type(caught.exception), UnsafeSerializationError)
                elif expected is None:
                    with self.assertRaises(OrchestrationError):
                        action(self.run_id)
                else:
                    self.assertEqual(action(self.run_id), expected)
                self.assertEqual(state_bytes(self.root), before)
            if malformed_external_checkpoint:
                with self.assertRaisesRegex(
                    UnsafeSerializationError, "^malformed JSON payload$",
                ) as caught:
                    self.call_pilot(operation)
                self.assertIs(type(caught.exception), UnsafeSerializationError)
            else:
                with self.assertRaises(OrchestrationError):
                    self.call_pilot(operation)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)

    def test_pilot_historical_source_stop_is_preserved(self):
        self.historical_pilot_stop()
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            status = self.orchestrator.status(self.run_id)
        self.assertEqual(status["status"], "STOP_SECURITY")
        self.assertTrue(status["persisted"])
        self.assertFalse(status["resumable"])
        self.assertIsNone(status["safe_resume_command"])
        self.assert_historical_inert(expected=status)

    def test_pilot_historical_source_stop_fresh_process(self):
        self.historical_pilot_stop()
        status = self.orchestrator.status(self.run_id)
        self.assert_historical_inert(expected=status)
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")
        before = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), before)

    def historical_drift_construction(self):
        # No source/config mutation or second process here. The owning parent
        # must first validate this entire child's report and unchanged inputs.
        self.historical_pilot_stop()
        status = self.orchestrator.status(self.run_id)
        self.assert_historical_inert(expected=status)
        self.assertTrue(self.orchestrator._validate_live_inventories(self.manifest()))
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")

    def test_pilot_historical_live_source_drift_after_capture(self):
        self.historical_drift_construction()

    def test_pilot_historical_live_config_drift_after_capture(self):
        self.historical_drift_construction()

    def historical_manifest_mutants(self, changes):
        original = self.historical_pilot_stop()
        for field, value in changes:
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field] = value
                self.orchestrator._save_manifest(changed)
                self.assert_historical_inert()
        self.orchestrator._save_manifest(original)

    def test_pilot_historical_initialized_context_mutants(self):
        self.historical_manifest_mutants((
            ("fixture_identifiers", ["substituted"]), ("random_seeds", [999]),
            ("code_fingerprint", "0" * 64), ("configuration_sha256", "0" * 64),
        ))

    def test_pilot_historical_terminal_projection_mutants(self):
        self.historical_manifest_mutants((
            ("event_count", 1), ("ledger_head_hash", "0" * 64), ("terminal_state", None),
            ("outcome", "IN_PROGRESS"), ("typed_transition_receipts", []),
            ("completed_transitions", []), ("evaluator_decisions", {}),
            ("resource_runtime_artifact", "resource_runtime_pilot_charge"),
        ))

    def test_pilot_historical_report_projection_and_absence(self):
        original = self.historical_pilot_stop()
        binding = original["artifacts"]["terminal_report"]
        path = self.root / binding["path"]
        raw = path.read_bytes()
        path.unlink()
        self.assert_historical_inert()
        path.write_bytes(raw)
        for field, value in (("parent_artifacts", []), ("creator_role", "scientific_reviewer"),
                             ("creation_command", ["not-the-owner"]), ("registry_record_hash", "0" * 64)):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed["artifacts"]["terminal_report"][field] = value
                self.orchestrator._save_manifest(changed)
                self.assert_historical_inert()
        self.orchestrator._save_manifest(original)

    def test_pilot_historical_report_parent_order_semantic_mutant(self):
        self.historical_pilot_stop(report_mutation="parent_order")
        self.assert_historical_inert()

    def test_pilot_historical_report_command_semantic_mutant(self):
        self.historical_pilot_stop(report_mutation="command")
        self.assert_historical_inert()

    def test_pilot_historical_report_timestamp_semantic_mutant(self):
        self.historical_pilot_stop(report_mutation="created_at")
        self.assert_historical_inert()

    def test_pilot_historical_report_payload_semantic_mutant(self):
        self.historical_pilot_stop(report_mutation="payload")
        self.assert_historical_inert()

    @staticmethod
    def rehash_mapping(value, field):
        # Test mutants recompute superficial hashes, not source execution receipts.
        from scientist_one.security import canonical_json_bytes
        value[field] = hashlib.sha256(canonical_json_bytes({k: v for k, v in value.items() if k != field})).hexdigest()

    def historical_rehashed_final_mutant(self, mutate):
        original = self.historical_pilot_stop()
        ledger_path = self.root / "runs" / self.run_id / "events.jsonl"
        rows = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        final = rows[-1]
        old_event_id, old_head = final["event_id"], final["event_hash"]
        mutate(final)
        self.rehash_mapping(final, "event_hash")
        ledger_path.write_bytes(b"".join(_canonical_bytes(row).replace(b"\n", b"") + b"\n" for row in rows))
        changed = copy.deepcopy(original)
        changed["ledger_head_hash"] = final["event_hash"]
        self.orchestrator._save_manifest(changed)
        local = self.root / "runs" / self.run_id / "checkpoint.json"
        value = json.loads(local.read_bytes())
        value["ledger_head_hash"] = final["event_hash"]
        local.write_bytes(_canonical_bytes(value))
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        old_path = directory / (old_event_id + "-" + old_head[:12] + ".json")
        value = json.loads(old_path.read_bytes())
        value["ledger_head_hash"] = final["event_hash"]
        value["checkpoint_id"] = old_event_id + "-" + final["event_hash"][:12]
        self.rehash_mapping(value, "checkpoint_hash")
        old_path.unlink()
        (directory / (value["checkpoint_id"] + ".json")).write_bytes(_canonical_bytes(value))
        self.assert_historical_inert()

    def test_pilot_historical_reconciliation_semantic_mutant(self):
        def mutate(final):
            final["metadata"]["resource_authority_chain"][-1]["state_sha256"] = "0" * 64
        self.historical_rehashed_final_mutant(mutate)

    def test_pilot_historical_receipt_semantic_mutant(self):
        def mutate(final):
            final["metadata"]["transition_receipt"] = {}
        self.historical_rehashed_final_mutant(mutate)

    def test_pilot_historical_evaluator_semantic_mutant(self):
        def mutate(final):
            final["evaluator_outputs"] = []
            final["metadata"]["evaluator_keys"] = []
        self.historical_rehashed_final_mutant(mutate)

    def test_pilot_historical_checkpoints_absent_partial_or_substituted(self):
        manifest = self.historical_pilot_stop()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        external = directory / f"event-{manifest['event_count']:04d}-{manifest['ledger_head_hash'][:12]}.json"
        local = self.root / "runs" / self.run_id / "checkpoint.json"
        for path in (local, external):
            raw = path.read_bytes()
            for mode in ("absent", "partial", "pointer", "parents"):
                with self.subTest(path=path.name, mode=mode):
                    if mode == "absent":
                        path.unlink()
                    elif mode == "partial":
                        path.write_bytes(b"{")
                    else:
                        value = json.loads(raw)
                        if mode == "pointer":
                            value["resource_runtime_artifact"] = "resource_runtime_pilot_charge"
                        else:
                            value["artifact_record_hashes"]["terminal_report"] = "0" * 64
                        if "checkpoint_hash" in value:
                            self.rehash_mapping(value, "checkpoint_hash")
                        path.write_bytes(_canonical_bytes(value))
                    self.assert_historical_inert(
                        malformed_external_checkpoint=(path == external and mode == "partial"),
                    )
                    path.write_bytes(raw)

    def test_pilot_historical_duplicate_and_newer_checkpoint(self):
        manifest = self.historical_pilot_stop()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        path = directory / f"event-{manifest['event_count']:04d}-{manifest['ledger_head_hash'][:12]}.json"
        raw = path.read_bytes()
        duplicate = directory / "duplicate.json"
        duplicate.write_bytes(raw)
        self.assert_historical_inert()
        duplicate.unlink()
        value = json.loads(raw)
        value["event_id"] = f"event-{manifest['event_count'] + 1:04d}"
        value["checkpoint_id"] = value["event_id"] + "-" + value["ledger_head_hash"][:12]
        self.rehash_mapping(value, "checkpoint_hash")
        (directory / (value["checkpoint_id"] + ".json")).write_bytes(_canonical_bytes(value))
        # Only resume has the explicit out-of-band checkpoint-refusal channel.
        # It must not authenticate the historical stop, repair, or admit work.
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("historical stop admitted callback"))
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            forbid_historical_live_reads(stack)
            for action in (self.orchestrator.status, self.orchestrator.advance_once):
                with self.assertRaises(OrchestrationError):
                    action(self.run_id)
                self.assertEqual(state_bytes(self.root), before)
            refused = self.orchestrator.resume(self.run_id)
            self.assertEqual(state_bytes(self.root), before)
            recovery = refused["recovery"]
            self.assertEqual(len(recovery["reasons"]), 1)
            self.assertTrue(recovery["reasons"][0].startswith("RECOVERY_VALIDATION_FAILED:"))
            self.assertEqual(recovery, {
                "action": "STOP_SECURITY", "reasons": recovery["reasons"],
                "ledger_valid": True, "ledger_event_count": manifest["event_count"],
                "ledger_head_hash": manifest["ledger_head_hash"],
                "artifacts_valid": True, "artifact_issues": [], "quarantined": [],
                "checkpoint": None, "derived_state": "STOP_SECURITY",
                "confirmatory_touched": False, "confirmatory_completed": False,
                "new_study_protocol_accepted": False, "replay_event_count": 0,
            })
            self.assertEqual(refused, {
                "status": "STOP_SECURITY", "run_id": self.run_id,
                "current_state": "STOP_SECURITY", "terminal_state": "STOP_SECURITY",
                "outcome": "STOP_SECURITY", "mode": manifest.get("mode"),
                "artifact_count": len(manifest["artifacts"]),
                "event_count": manifest["event_count"], "resumable": False,
                "persisted": False,
                "authority_channel": "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL",
                "recovery": recovery,
            })
            self.assertEqual(self.orchestrator.resume(self.run_id), refused)
            self.assertEqual(state_bytes(self.root), before)
            with self.assertRaises(OrchestrationError):
                self.call_pilot(operation)
            self.assertEqual(state_bytes(self.root), before)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)

    def test_pilot_historical_truncated_ledger_never_quarantines(self):
        self.historical_pilot_stop()
        path = self.root / "runs" / self.run_id / "events.jsonl"
        path.write_bytes(path.read_bytes() + b'{"truncated":')
        self.assert_historical_inert()

    def test_pilot_historical_preceding_checkpoint_semantic_mutant(self):
        manifest = self.historical_pilot_stop()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        paths = [p for p in directory.glob("*.json")
                 if json.loads(p.read_bytes())["event_id"] == f"event-{manifest['event_count'] - 1:04d}"]
        self.assertEqual(len(paths), 1)
        value = json.loads(paths[0].read_bytes())
        value["state"] = "CONFIRM"
        self.rehash_mapping(value, "checkpoint_hash")
        paths[0].write_bytes(_canonical_bytes(value))
        self.assert_historical_inert()

    def test_pilot_open_charge_terminal_fields_do_not_create_history(self):
        error = RuntimeError("generic callback is not old terminal authority")
        with self.assertRaises(RuntimeError) as caught:
            self.call_pilot(mock.Mock(side_effect=error))
        self.assertIs(caught.exception, error)
        manifest = self.manifest()
        manifest.update(current_state="STOP_SECURITY", terminal_state="STOP_SECURITY", outcome="STOP_SECURITY")
        manifest["artifacts"]["terminal_report"] = copy.deepcopy(manifest["artifacts"]["resource_runtime_initial"])
        self.orchestrator._save_manifest(manifest)
        self.assert_historical_inert()

    def test_pilot_historical_successor_markers_never_qualify(self):
        original = self.historical_pilot_stop()
        for name in (_FAILURE, _SLOT, "resource_runtime_pilot_completion", "resource_runtime_confirmatory_charge"):
            with self.subTest(name=name):
                changed = copy.deepcopy(original)
                changed["artifacts"][name] = copy.deepcopy(changed["artifacts"]["resource_runtime_initial"])
                self.orchestrator._save_manifest(changed)
                self.assert_historical_inert()
        self.orchestrator._save_manifest(original)

    def completed_projection_mutants(self, mutations):
        self.timed_real_pilot()
        error = RuntimeError("actual completion before evaluator failure")
        with mock.patch.object(self.orchestrator, "_evaluate", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        original = self.manifest()
        self.assertEqual(original["resource_runtime_artifact"], "resource_runtime_pilot_completion")
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(original))
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(original)
                target = changed if section is None else changed[section]
                if section == "artifacts":
                    target = target["resource_runtime_pilot_completion"]
                target[field] = value
                self.orchestrator._save_manifest(changed)
                self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(original))

    def test_pilot_completed_current_runtime_semantic_mutants(self):
        self.completed_projection_mutants((
            ("resource_runtime_state", "exploratory_used", 0),
            ("resource_runtime_state", "confirmatory_used", 1),
            ("resource_runtime_state", "progress_elapsed_seconds", 0),
            (None, "resource_runtime_artifact", "resource_runtime_pilot_charge"),
        ))

    def test_pilot_completed_current_ledger_semantic_mutants(self):
        self.completed_projection_mutants((
            (None, "event_count", 1), (None, "event_count", True),
            (None, "ledger_head_hash", "0" * 64),
            (None, "fixture_identifiers", ["substituted"]), (None, "random_seeds", [999]),
            (None, "typed_transition_receipts", []), (None, "completed_transitions", []),
            (None, "current_state", "CONFIRM"), (None, "terminal_state", "STOP_SECURITY"),
        ))

    def test_pilot_completed_current_resource_binding_mutants(self):
        self.completed_projection_mutants((
            ("artifacts", "registry_record_hash", "0" * 64),
            ("artifacts", "parent_artifacts", []),
            ("artifacts", "creation_command", ["not-the-owner"]),
            ("artifacts", "path", "runs/absent.json"),
            ("artifacts", "size", 0),
        ))

    def test_confirm_started_before_release_refuses_fresh_routing_without_mutation(self):
        """Real completed PILOT, real STARTED, then one ordinary Python exception."""
        from contextlib import ExitStack
        import copy
        import json
        from pathlib import Path
        from unittest import mock

        from scientist_one.holdout import CustodyIndependence, SimulatedHoldoutCustody
        from scientist_one.ledger import EventLedger
        from scientist_one.orchestrator import (
            ScientistOneOrchestrator,
            _custody_journal_path,
        )
        from scientist_one.recovery import RecoveryManager
        from scientist_one.resources import ResourceController
        from scientist_one.roles import Role

        # state_bytes and forbid_observation are the owning test module's existing
        # observers/negative guards, not copied dispatch or provenance machinery.
        self.assertEqual(self.manifest()["current_state"], "CANDIDATE")
        self.assertEqual(self.elapsed, 0.0)
        original_artifact = self.orchestrator._artifact
        timed_publications = []

        def finish_real_pilot(manifest, logical_type, payload, *, creator, parents=()):
            record = original_artifact(
                manifest, logical_type, payload, creator=creator, parents=parents,
            )
            if logical_type == "blind_interpretation":
                self.assertEqual(timed_publications, [])
                timed_publications.append(record["sha256"])
                # Same source-owned synthetic clock convention as the existing
                # successful-PILOT test: only advance after its real final write.
                self.elapsed += 1.0
            return record

        with mock.patch.object(self.orchestrator, "_artifact", finish_real_pilot):
            pilot_status = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(len(timed_publications), 1)
        self.assertEqual(pilot_status["status"], "PASS")
        self.assertEqual(pilot_status["current_state"], "CONFIRM")
        pilot = copy.deepcopy(self.manifest())
        self.assertEqual(pilot["resource_runtime_artifact"], "resource_runtime_pilot_completion")
        self.assertEqual(pilot["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(pilot["resource_runtime_state"]["confirmatory_used"], 0)
        ledger_path = Path("runs") / self.run_id / "events.jsonl"
        pilot_events = EventLedger(self.root, ledger_path).assert_valid().events
        pilot_authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertEqual(tuple(r["logical_type"] for r in pilot_authorities), (
            "resource_runtime_initial", "resource_runtime_pilot_charge",
            "resource_runtime_pilot_completion",
        ))

        original_admit = RecoveryManager._admit_confirmatory_locked
        admitted_calls = []
        interruption = OSError("synthetic interruption after real STARTED before RELEASE")

        def admit_once_then_interrupt(manager, **kwargs):
            self.assertEqual(admitted_calls, [])
            # Call THROUGH the real owner. It validates all real bindings, appends
            # the actual STARTED, and validates readback. No fake return or receipt.
            original_admit(manager, **kwargs)
            admitted_calls.append(kwargs["start_event"])
            raise interruption

        with mock.patch.object(
            RecoveryManager, "_admit_confirmatory_locked", admit_once_then_interrupt,
        ):
            with self.assertRaisesRegex(
                OrchestrationError, "^project resource execution lock failed$",
            ) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(type(caught.exception), OrchestrationError)
        self.assertIs(caught.exception.__cause__, interruption)
        self.assertEqual(len(admitted_calls), 1)

        # Verify the fault really crossed the intended owner boundary BEFORE
        # testing negative routing. No fixture-written manifest/event/custody data.
        retained = state_bytes(self.root)
        try:
            after = self.manifest()
            runtime = after["resource_runtime_state"]
            self.assertEqual(runtime["confirmatory_used"], 4)
            self.assertEqual(runtime["exploratory_used"], 2)
            self.assertEqual(runtime["worker_crashes"], pilot["resource_runtime_state"]["worker_crashes"])
            self.assertEqual(runtime["progress_elapsed_seconds"],
                             pilot["resource_runtime_state"]["progress_elapsed_seconds"])
            self.assertEqual(after["resource_runtime_artifact"], "resource_runtime_confirmatory_charge")
            charge = self.orchestrator._json_artifact_payload(
                after, "resource_runtime_confirmatory_charge",
            )
            self.assertEqual(charge, runtime)
            authorities = self.orchestrator._resource_authority_records(self.run_id)
            self.assertEqual(authorities[:-1], pilot_authorities)
            self.assertEqual(authorities[-1]["logical_type"], "resource_runtime_confirmatory_charge")
            self.assertEqual(authorities[-1]["state"], charge)

            events = EventLedger(self.root, ledger_path).assert_valid().events
            self.assertEqual(events[:len(pilot_events)], pilot_events)
            self.assertEqual(len(events), len(pilot_events) + 3)  # receipt, charge, STARTED
            self.assertEqual(events[-1], admitted_calls[0])
            starts = [e for e in events if e.metadata.get("execution_kind")
                      == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"]
            self.assertEqual(starts, admitted_calls)
            started = starts[0]
            self.assertEqual(started.event_type, "CHECKPOINT")
            self.assertEqual(started.state_before.value, "CONFIRM")
            self.assertEqual(started.requested_state_after.value, "CONFIRM")
            self.assertEqual(started.metadata["evidence_class"], "ARCHITECTURE_CONTROL")
            self.assertEqual(started.metadata["resource_authority_checkpoint"],
                             events[-2].metadata["resource_authority_checkpoint"])
            self.assertIn(after["artifacts"]["resource_runtime_confirmatory_charge"]["sha256"],
                          started.artifact_hashes)
            self.assertFalse(any(e.event_type.startswith("CONFIRMATORY_") for e in events))
            self.assertFalse(any(e.metadata.get("execution_kind")
                                 == "SIMULATED_ARCHITECTURE_CONTROL_COMPLETED" for e in events))
            self.assertFalse(any(e.metadata.get("scientific_evidence") is True for e in events))
            registry = self.orchestrator._registry(self.run_id)
            self.assertTrue(registry.verify_all().valid)
            registry_types = {record.logical_type for record in registry.list_records()}
            for absent in ("resource_runtime_confirmatory_completion", "custody_record",
                           "machine_results", "terminal_report"):
                self.assertNotIn(absent, after["artifacts"])
                self.assertNotIn(absent, registry_types)
            for evaluator in ("E0:CONFIRM", "E2:CONFIRM", "E3:CONFIRM"):
                self.assertNotIn(evaluator, after["evaluator_decisions"])

            # Reopen the EXISTING real synthetic journal through its owner. This
            # observer neither supplies authority nor recreates a missing journal.
            custody = SimulatedHoldoutCustody(
                (Role.EXPERIMENT_RUNNER.value,), journal_root=self.root,
                journal_path=_custody_journal_path(self.run_id),
                require_existing_journal=True,
            )
            with custody.admission_guard() as snapshot:
                self.assertIs(snapshot.status.custody_independence,
                              CustodyIndependence.NON_INDEPENDENT)
                self.assertIs(snapshot.status.sealed, True)
                self.assertIs(snapshot.status.revealed, False)
                self.assertEqual(snapshot.status.authorized_access_count, 0)
                self.assertIsNone(snapshot.status.release_event)
                self.assertIs(snapshot.status.confirmatory_claims_valid, False)
                journal_events = [json.loads(line) for line in snapshot.journal_bytes.splitlines()]
                self.assertEqual([e["event_type"] for e in journal_events], ["SEAL"])
        finally:
            self.assertEqual(state_bytes(self.root), retained,
                             "readback changed retained fault-prefix file identities")

        # V2's actual completed-PILOT projection owner refuses the stale saved
        # ledger head after the real STARTED append. First allow real controller
        # observation under synthetic probes; only then require strict no-observation
        # fresh-object replay. An unexpected result or mutation stops immediately.
        for route, strict_replay in (
            ("status", False), ("status", True),
            ("advance_once", True), ("resume", True),
        ):
            phase = ("strict replay " if strict_replay else "first observation ") + route
            before_route = state_bytes(self.root)
            self.assertEqual(before_route, retained)
            try:
                with ExitStack() as stack:
                    if strict_replay:
                        forbid_observation(stack)
                        forbid_negative_mutation(stack)
                    else:
                        # Do not replace __init__/snapshot/evaluate: this phase must
                        # expose the source-owned exception, not our stricter
                        # replay guard. CPU is a deterministic synthetic observation
                        # too; configured cpu_worker_limit=1 stays effective.
                        stack.enter_context(mock.patch(
                            "scientist_one.resources.os.cpu_count", return_value=2,
                        ))
                        for name in ("acquire", "record_progress"):
                            guarded = stack.enter_context(mock.patch.object(
                                ResourceController, name,
                                side_effect=AssertionError("first status attempted admission/progress"),
                            ))
                            stack.callback(guarded.assert_not_called)
                    blocked_work = mock.Mock(side_effect=AssertionError("started CONFIRM re-entered work"))
                    stack.enter_context(mock.patch.dict(
                        ScientistOneOrchestrator._HANDLERS, {"CONFIRM": blocked_work},
                    ))
                    stack.callback(blocked_work.assert_not_called)
                    for owner, name in (
                        (RecoveryManager, "_admit_confirmatory_locked"),
                        (RecoveryManager, "repair_truncated_ledger"),
                        (SimulatedHoldoutCustody, "seal"),
                        (SimulatedHoldoutCustody, "_run_confirmatory_locked"),
                    ):
                        guarded = stack.enter_context(mock.patch.object(
                            owner, name, side_effect=AssertionError("started CONFIRM attempted work/repair"),
                        ))
                        stack.callback(guarded.assert_not_called)
                    fresh = ScientistOneOrchestrator(self.root)
                    with self.assertRaisesRegex(
                        OrchestrationError,
                        "^completed pilot current ledger projection differs$",
                        msg=phase,
                    ) as refused:
                        getattr(fresh, route)(self.run_id)
                    self.assertIs(type(refused.exception), OrchestrationError, phase)
                    blocked_work.assert_not_called()
            finally:
                self.assertEqual(state_bytes(self.root), before_route,
                                 phase + " changed fault-prefix bytes, paths or file identities")


    def completed_pending(self, *, key="E0:CANDIDATE", after=False):
        self.timed_real_pilot()
        original = self.orchestrator._evaluate
        error = RuntimeError("real completed pilot evaluator cut")

        def evaluate(manifest, name, *args, **kwargs):
            if name == key and not after:
                raise error
            result = original(manifest, name, *args, **kwargs)
            if name == key:
                raise error
            return result

        with mock.patch.object(self.orchestrator, "_evaluate", evaluate):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        manifest = self.manifest()
        self.assertEqual(manifest["current_state"], "CANDIDATE")
        self.assertEqual(manifest["resource_runtime_artifact"], "resource_runtime_pilot_completion")
        self.assertFalse(any(k.endswith(":CANDIDATE") for k in manifest["evaluator_decisions"]))
        self.assertNotIn(_FAILURE, manifest["artifacts"])
        return manifest

    def continue_pending(self):
        before = self.manifest()
        original_evaluate = self.orchestrator._evaluate
        original_recovery = self.orchestrator._recovery_report

        def recovery(manifest):
            self.assertEqual(manifest["current_state"], "CONFIRM")
            return original_recovery(manifest)

        with ExitStack() as stack:
            for owner, name in ((ResourceController, "acquire"), (ResourceController, "record_progress"),
                                (self.orchestrator, "_handler_candidate"),
                                (self.orchestrator, "_run_with_resources"),
                                (self.orchestrator, "_artifact")):
                guarded = stack.enter_context(mock.patch.object(
                    owner, name, side_effect=AssertionError("evaluator continuation repeated PILOT")))
                stack.callback(guarded.assert_not_called)
            stack.enter_context(mock.patch.object(self.orchestrator, "_recovery_report", recovery))
            evaluated = stack.enter_context(mock.patch.object(self.orchestrator, "_evaluate", wraps=original_evaluate))
            transition = stack.enter_context(mock.patch.object(
                self.orchestrator, "_typed_transition", wraps=self.orchestrator._typed_transition))
            result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["current_state"], "CONFIRM")
        self.assertEqual([call.args[1] for call in evaluated.call_args_list],
                         ["E0:CANDIDATE", "E2:CANDIDATE", "E3:CANDIDATE"])
        self.assertEqual(transition.call_count, 1)
        after = self.manifest()
        self.assertEqual(after["artifacts"], before["artifacts"])
        self.assertEqual(after["resource_runtime_state"], before["resource_runtime_state"])
        self.assertEqual(after["event_count"], before["event_count"] + 1)
        self.assertEqual(after["completed_transitions"], before["completed_transitions"] + ["CANDIDATE->CONFIRM"])
        self.assertNotIn(_FAILURE, after["artifacts"])
        return result

    def test_pending_pilot_before_e0_continues_only_actual_evaluators(self):
        self.completed_pending()
        self.continue_pending()

    def test_pending_pilot_before_e2_continues_only_actual_evaluators(self):
        self.completed_pending(key="E2:CANDIDATE")
        self.continue_pending()

    def test_pending_pilot_before_e3_continues_only_actual_evaluators(self):
        self.completed_pending(key="E3:CANDIDATE")
        self.continue_pending()

    def test_pending_pilot_after_in_memory_evaluator_receipt_continues(self):
        self.completed_pending(key="E2:CANDIDATE", after=True)
        self.continue_pending()

    def test_pending_pilot_status_and_direct_admission_are_inert(self):
        manifest = self.completed_pending()
        before = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            status = self.orchestrator.status(self.run_id)
            self.assertEqual(status["status"], "CANDIDATE_EVALUATION_PENDING")
            self.assertEqual(status["continuation_scope"], "EVALUATOR_ONLY")
            self.assertTrue(status["resumable"])
            self.assertFalse(status["persisted"])
            self.assertFalse(status["scientific_evidence"])
            self.assertEqual(status["safe_resume_command"], ["python3", "-I", "-S", "-B",
                             "scripts/scientist_one_cli.py", "resume", self.run_id])
            self.assertEqual(status["event_count"], manifest["event_count"])
            self.assertEqual(status["ledger_head_hash"], manifest["ledger_head_hash"])
            callback = mock.Mock(side_effect=AssertionError("pending PILOT body replayed"))
            with self.assertRaisesRegex(OrchestrationError, "evaluator-only continuation"):
                self.call_pilot(callback)
            callback.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)

    def test_pending_pilot_fresh_process_evaluator_continuation(self):
        self.completed_pending()
        value = {"run_id": self.run_id, "status": self.orchestrator.status(self.run_id)}
        (self.root / _REPLAY_INPUT).write_bytes(_canonical_bytes(value))
        replay_child(self.root, self.id())
        self.assertEqual(self.manifest()["current_state"], "CONFIRM")
        self.assertEqual(self.manifest()["resource_runtime_state"]["exploratory_used"], 2)

    def test_pending_pilot_fresh_command_preserves_historical_record_metadata(self):
        self.completed_pending()
        fresh = ScientistOneOrchestrator(self.root)
        fresh.set_command_context(("python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", "resume", self.run_id))
        self.orchestrator = fresh
        self.elapsed += 0.25
        self.continue_pending()

    def test_pending_pilot_supplied_brief_preserves_text_owner(self):
        manifest = self.completed_pending()
        self.assertEqual(manifest["artifacts"]["research_brief"]["mime_type"], "text/markdown")
        self.continue_pending()
        self.assertEqual(self.manifest()["artifacts"]["research_brief"], manifest["artifacts"]["research_brief"])

    def test_pending_pilot_evaluator_exception_does_not_publish_or_retry(self):
        self.completed_pending()
        before = state_bytes(self.root)
        original = self.orchestrator._evaluate
        error = RuntimeError("second explicit evaluator command interrupted")
        calls = []

        def evaluate(manifest, key, *args, **kwargs):
            result = original(manifest, key, *args, **kwargs)
            calls.append(key)
            if key == "E2:CANDIDATE":
                raise error
            return result

        with mock.patch.object(self.orchestrator, "_evaluate", evaluate):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        self.assertEqual(calls, ["E0:CANDIDATE", "E2:CANDIDATE"])
        self.assertEqual(state_bytes(self.root), before)
        self.continue_pending()

    def test_pending_pilot_evaluator_unrelated_working_mutation_refuses(self):
        self.completed_pending()
        before = state_bytes(self.root)
        original = self.orchestrator._evaluate

        def evaluate(manifest, *args, **kwargs):
            result = original(manifest, *args, **kwargs)
            manifest["synthetic_scenario"] = "injected-unrelated-change"
            return result

        with mock.patch.object(self.orchestrator, "_evaluate", evaluate), mock.patch.object(
                self.orchestrator, "_typed_transition", side_effect=AssertionError("mutated evaluation transitioned")):
            with self.assertRaisesRegex(OrchestrationError, "unrelated working state"):
                self.orchestrator.advance_once(self.run_id)
        self.assertEqual(state_bytes(self.root), before)

    def evaluator_namespace_fault(self, kind, *, during_recognition=False):
        from scientist_one.orchestrator import _custody_journal_path
        import stat

        self.completed_pending()
        paths = {
            "source": Path("src/scientist_one/_pending_evaluator_inert_added_fixture.py"),
            "configuration": Path("configs/pending_evaluator_inert_added_fixture.json"),
            "custody": _custody_journal_path(self.run_id),
        }
        relative = paths[kind]
        path = self.root / relative
        self.assertFalse(path.exists())
        before = state_bytes(self.root)
        original_evaluate = self.orchestrator._evaluate
        original_live = self.orchestrator._pilot_evaluation_live
        original_census = self.orchestrator._pilot_census
        calls, rechecks, created = [], [], []
        raw = b"# inert fixture; never imported or executed\n" if kind == "source" else b'{"inert":true}\n'

        def identity():
            value = path.lstat()
            self.assertTrue(stat.S_ISREG(value.st_mode))
            self.assertEqual(value.st_nlink, 1)
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

        def add_fault():
            self.assertFalse(created)
            self.assertFalse(path.exists())
            with path.open("xb") as stream:
                stream.write(raw)
            created.append(identity())

        def evaluate(manifest, key, *args, **kwargs):
            result = original_evaluate(manifest, key, *args, **kwargs)
            calls.append(key)
            if key == "E0:CANDIDATE":
                add_fault()
            return result

        def live(manifest):
            if created:
                rechecks.append(kind)
                self.assertEqual(identity(), created[0])
                self.assertEqual(path.read_bytes(), raw)
            return original_live(manifest)

        caught_error = None
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(self.orchestrator, "_pilot_evaluation_live", live))
                if during_recognition:
                    # Add only after the first live join, at the closing census.
                    census_calls = []
                    def closing_census(*args, **kwargs):
                        result = original_census(*args, **kwargs)
                        census_calls.append(True)
                        if len(census_calls) == 2:
                            add_fault()
                        return result
                    stack.enter_context(mock.patch.object(self.orchestrator, "_pilot_census", closing_census))
                else:
                    stack.enter_context(mock.patch.object(self.orchestrator, "_evaluate", evaluate))
                for owner, name in ((ResourceController, "acquire"), (ResourceController, "record_progress"),
                                    (RecoveryManager, "recover"), (RecoveryManager, "quarantine_incomplete"),
                                    (self.orchestrator, "_handler_candidate"),
                                    (self.orchestrator, "_run_with_resources"),
                                    (self.orchestrator, "_typed_transition"),
                                    (self.orchestrator, "_artifact"),
                                    (self.orchestrator, "_append_event"),
                                    (self.orchestrator, "_checkpoint"),
                                    (self.orchestrator, "_save_manifest")):
                    guard = stack.enter_context(mock.patch.object(
                        owner, name, side_effect=AssertionError("namespace fault reached work or publication")))
                    stack.callback(guard.assert_not_called)
                with self.assertRaisesRegex(
                        OrchestrationError, "^pending pilot evaluation live inputs or custody changed$") as caught:
                    self.orchestrator.advance_once(self.run_id)
                caught_error = caught.exception
                self.assertIs(type(caught_error), OrchestrationError)
            self.assertEqual(calls, [] if during_recognition else ["E0:CANDIDATE", "E2:CANDIDATE", "E3:CANDIDATE"])
            self.assertTrue(rechecks)
            self.assertEqual(identity(), created[0])
            after = state_bytes(self.root)
            self.assertEqual(set(after) - set(before), {relative.as_posix()})
            self.assertEqual({p: v for p, v in after.items() if p != relative.as_posix()}, before)
            self.assertEqual(path.read_bytes(), raw)
            print("SCIENTIST_ONE_EVALUATOR_NAMESPACE_FAULT_V1=" + json.dumps({
                "test_id": self.id(), "kind": kind, "path": relative.as_posix(),
                "phase": "recognition_close" if during_recognition else "after_evaluators",
                "evaluator_calls": calls, "closing_rechecks": rechecks,
                "refusal_type": type(caught_error).__name__, "refusal": str(caught_error),
                "fault_sha256": hashlib.sha256(raw).hexdigest(),
                "original_file_tuples_unchanged": True,
                "source_endpoint": "captured_inventory_coverage" if kind == "source" else kind,
            }, sort_keys=True), flush=True)
        except BaseException as first_failure:
            print("SCIENTIST_ONE_EVALUATOR_NAMESPACE_FAULT_V1=" + json.dumps({
                "test_id": self.id(), "kind": kind, "phase": "FAIL",
                "error_type": type(first_failure).__name__, "error": str(first_failure),
                "evaluator_calls": calls, "closing_rechecks": rechecks,
            }, sort_keys=True), flush=True)
            raise
        finally:
            # Never rewrite or restore captured originals. Remove only the exact
            # newly created regular file, after the genuine refusal was observed.
            if created:
                self.assertEqual(identity(), created[0])
                path.unlink()
        self.assertEqual(state_bytes(self.root), before)

    def test_pending_pilot_evaluator_creates_custody_journal_refuses(self):
        self.evaluator_namespace_fault("custody")

    def test_pending_pilot_evaluator_source_addition_refuses_at_live_close(self):
        self.evaluator_namespace_fault("source")

    def test_pending_pilot_evaluator_config_addition_refuses_at_live_close(self):
        self.evaluator_namespace_fault("configuration")

    def test_pending_pilot_recognition_closing_config_addition_refuses(self):
        self.evaluator_namespace_fault("configuration", during_recognition=True)

    def test_pending_pilot_saved_evaluator_claims_cannot_authorize(self):
        original = self.completed_pending()
        for keys in (("E0:CANDIDATE",), ("E0:CANDIDATE", "E2:CANDIDATE", "E3:CANDIDATE")):
            with self.subTest(keys=keys):
                changed = copy.deepcopy(original)
                for key in keys:
                    changed["evaluator_decisions"][key] = {"decision": "PASS"}
                self.orchestrator._save_manifest(changed)
                self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)

    def test_pending_pilot_prior_context_and_artifact_mutations_refuse(self):
        original = self.completed_pending()
        for section, key, value in (
                (None, "fixture_identifiers", ["substituted"]),
                (None, "random_seeds", [999]),
                ("evaluator_decisions", "E0:DISCOVER", {"decision": "PASS"}),
                ("artifacts", "workflow_benchmark", original["artifacts"]["frozen_source_inventory"])):
            with self.subTest(section=section, key=key):
                changed = copy.deepcopy(original)
                target = changed if section is None else changed[section]
                target[key] = value
                self.orchestrator._save_manifest(changed)
                self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)

    def test_pending_pilot_extra_registry_record_or_mirror_refuses(self):
        self.completed_pending()
        mirror = self.root / "runs" / self.run_id / "artifacts" / "candidate" / "unexpected.txt"
        mirror.write_bytes(b"unbound")
        self.assert_pilot_inert()
        mirror.unlink()
        from scientist_one.roles import Role
        self.orchestrator._registry(self.run_id).put_bytes(
            b"unbound", logical_type="inert_pending_extra", creator_role=Role.ORCHESTRATOR,
            origin="adverse fixture only", creation_command=("test",), schema_version="1.0",
            mime_type="text/plain", validation_result="FAIL", frozen=False)
        self.assert_pilot_inert()

    def test_evaluator_context_absent_key_is_only_private_inapplicability(self):
        manifest = self.manifest()
        self.assertNotIn("resource_runtime_pilot_completion", manifest["artifacts"])
        before = state_bytes(self.root)
        with mock.patch.object(self.orchestrator, "_resource_authority_records",
                               side_effect=AssertionError("inapplicable lookup read authority")) as read:
            self.assertIsNone(self.orchestrator._pilot_evaluation_context(manifest))
        read.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        # This private None is not permission to bypass the guarded callers.

    def test_evaluator_context_all_guarded_calls_screen_negative_owner_first(self):
        before = state_bytes(self.root)
        original = self.orchestrator._pilot_operation_disposition
        screened = []
        cut = RuntimeError("stop only after real negative owner screening")

        def negative(manifest):
            result = original(manifest)
            self.assertIsNone(result)
            screened.append(manifest["run_id"])
            return result

        def context(manifest):
            self.assertEqual(screened, [self.run_id])
            raise cut

        operation = mock.Mock(side_effect=AssertionError("routing control ran pilot"))
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            stack.enter_context(mock.patch.object(self.orchestrator, "_pilot_operation_disposition", negative))
            stack.enter_context(mock.patch.object(self.orchestrator, "_pilot_evaluation_context", context))
            for route in ("status", "advance_once", "resume", "direct"):
                with self.subTest(route=route):
                    screened.clear()
                    with self.assertRaises(RuntimeError) as caught:
                        if route == "direct":
                            self.call_pilot(operation)
                        else:
                            getattr(self.orchestrator, route)(self.run_id)
                    self.assertIs(caught.exception, cut)
                    self.assertEqual(screened, [self.run_id])
                    self.assertEqual(state_bytes(self.root), before)
        operation.assert_not_called()

    def truncate_unmarked_initial_authority(self):
        paths = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))
        self.assertEqual(len(paths), 1)
        raw = paths[0].read_bytes()
        self.assertEqual(json.loads(raw)["logical_type"], "resource_runtime_initial")
        self.assertNotIn("resource_runtime_pilot_completion", self.manifest()["artifacts"])
        paths[0].write_bytes(raw[:len(raw) // 2])

    def test_unmarked_legacy_corruption_status_resume_keep_recovery_route(self):
        self.truncate_unmarked_initial_authority()
        before = state_bytes(self.root)
        cut = RuntimeError("legacy recovery owner routing spy")
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            for route in ("status", "resume"):
                with self.subTest(route=route), mock.patch.object(
                        self.orchestrator, "_recovery_report", side_effect=cut) as recovery:
                    with self.assertRaises(RuntimeError) as caught:
                        getattr(self.orchestrator, route)(self.run_id)
                    self.assertIs(caught.exception, cut)
                    recovery.assert_called_once()
                    self.assertEqual(state_bytes(self.root), before)

    def test_unmarked_legacy_corruption_direct_keeps_resource_owner(self):
        self.truncate_unmarked_initial_authority()
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("corrupt legacy resources ran work"))
        original = self.orchestrator._resource_controller
        with ExitStack() as stack:
            forbid_observation(stack)
            controller = stack.enter_context(mock.patch.object(self.orchestrator, "_resource_controller", wraps=original))
            with self.assertRaisesRegex(OrchestrationError, "^resource authority record is unsafe$"):
                self.call_pilot(operation)
            controller.assert_called_once()
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)

    def hidden_pending_completion(self, *, corrupt_external=False, corrupt_registry=False):
        manifest = self.completed_pending()
        completion = manifest["artifacts"]["resource_runtime_pilot_completion"]
        registry = self.orchestrator._registry(self.run_id)
        stored = registry.get_metadata(completion["sha256"])
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertEqual(tuple(r["logical_type"] for r in authorities),
                         ("resource_runtime_initial", "resource_runtime_pilot_charge", "resource_runtime_pilot_completion"))
        events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events
        self.assertEqual(tuple(events[-1].metadata["artifact_types"]), ("resource_runtime_pilot_completion",))
        # Hide every manifest PILOT marker, not merely the positive selector.
        manifest["artifacts"].pop("resource_runtime_pilot_charge")
        manifest["artifacts"].pop("resource_runtime_pilot_completion")
        manifest["resource_runtime_artifact"] = "resource_runtime_initial"
        manifest["resource_runtime_state"] = copy.deepcopy(authorities[0]["state"])
        self.orchestrator._save_manifest(manifest)
        if corrupt_external:
            path = sorted((self.root / ".scientist-one-build/resource-authority" / self.run_id).glob("*.json"))[-1]
            self.assertEqual(json.loads(path.read_bytes())["logical_type"], "resource_runtime_pilot_completion")
            path.write_bytes(b"{truncated-completion-channel")
        if corrupt_registry:
            (self.root / stored.path).write_bytes(b"truncated-completion-object")
            self.assertFalse(registry.verify_all(raise_on_error=False).valid)
        self.assertEqual(EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events, events)
        # The complete existing negative owner, never helper applicability,
        # must refuse each guarded route before evaluator lookup or any work.
        with mock.patch.object(self.orchestrator, "_pilot_evaluation_context",
                               side_effect=AssertionError("hidden markers reached evaluator lookup")) as lookup, mock.patch.object(
                self.orchestrator, "_pilot_operation_disposition",
                wraps=self.orchestrator._pilot_operation_disposition) as negative:
            self.assert_pilot_inert()
        lookup.assert_not_called()
        self.assertEqual(negative.call_count, 4)

    def test_pending_pilot_hidden_completion_keeps_external_registry_ledger_markers(self):
        self.hidden_pending_completion()

    def test_pending_pilot_hidden_completion_corrupt_external_retains_registry(self):
        self.hidden_pending_completion(corrupt_external=True)

    def test_pending_pilot_hidden_completion_corrupt_external_registry_retains_ledger(self):
        self.hidden_pending_completion(corrupt_external=True, corrupt_registry=True)

    def test_pending_pilot_null_completion_key_cannot_bypass(self):
        self.completed_pending()
        manifest = self.manifest()
        manifest["artifacts"]["resource_runtime_pilot_completion"] = None
        self.orchestrator._save_manifest(manifest)
        before = state_bytes(self.root)
        cut = RuntimeError("present null completion must still read authority")
        with mock.patch.object(self.orchestrator, "_resource_authority_records", side_effect=cut) as read:
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator._pilot_evaluation_context(manifest)
            self.assertIs(caught.exception, cut)
        read.assert_called_once_with(self.run_id)
        self.assertEqual(state_bytes(self.root), before)
        with mock.patch.object(self.orchestrator, "_pilot_evaluation_context",
                               side_effect=AssertionError("null completion bypassed negative screening")) as lookup, mock.patch.object(
                self.orchestrator, "_pilot_operation_disposition",
                wraps=self.orchestrator._pilot_operation_disposition) as negative:
            self.assert_pilot_inert()
        lookup.assert_not_called()
        self.assertEqual(negative.call_count, 4)

    def test_evaluator_context_runtime_pointer_without_completion_key_refuses(self):
        manifest = self.manifest()
        self.assertNotIn("resource_runtime_pilot_completion", manifest["artifacts"])
        manifest["resource_runtime_artifact"] = "resource_runtime_pilot_completion"
        self.orchestrator._save_manifest(manifest)
        with mock.patch.object(self.orchestrator, "_pilot_evaluation_context",
                               side_effect=AssertionError("runtime pointer bypassed negative screening")) as lookup, mock.patch.object(
                self.orchestrator, "_pilot_operation_disposition",
                wraps=self.orchestrator._pilot_operation_disposition) as negative:
            self.assert_pilot_inert()
        lookup.assert_not_called()
        self.assertEqual(negative.call_count, 4)

    def pending_metadata_mutation(self, field):
        from scientist_one.roles import Role
        original = self.orchestrator._artifact

        def artifact(manifest, name, payload, *, creator, parents=()):
            command, created = self.orchestrator.command_context, manifest["created_at"]
            try:
                if name == "blind_interpretation":
                    if field == "payload":
                        payload = {**payload, "frozen_before_reveal": False}
                    elif field == "creator_role":
                        self.assertNotEqual(creator, Role.ORCHESTRATOR.value)
                        creator = Role.ORCHESTRATOR.value
                    elif field == "parent_artifacts":
                        parents = ()
                    elif field == "creation_command":
                        self.orchestrator.set_command_context(
                            ("python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", "resume", self.run_id))
                    elif field == "created_at":
                        manifest["created_at"] = "2000-01-01T00:00:00Z"
                    else:
                        self.fail("unknown pending output mutation")
                return original(manifest, name, payload, creator=creator, parents=parents)
            finally:
                self.orchestrator.set_command_context(command)
                manifest["created_at"] = created

        with mock.patch.object(self.orchestrator, "_artifact", artifact):
            self.completed_pending()
        if field == "creator_role":
            manifest = self.manifest()
            registry = self.orchestrator._registry(self.run_id)
            registry.verify_all(raise_on_error=True)
            output = manifest["artifacts"]["blind_interpretation"]
            stored = registry.get_metadata(output["sha256"])
            self.assertIs(stored.creator_role, Role.ORCHESTRATOR)
            self.assertEqual(output["creator_role"], Role.ORCHESTRATOR.value)
            self.assertEqual(output["registry_record_hash"], stored.record_hash)
            self.assertEqual((self.root / output["path"]).read_bytes(), registry.get_bytes(stored.sha256))
            authorities = self.orchestrator._resource_authority_records(self.run_id)
            self.assertEqual(tuple(r["logical_type"] for r in authorities),
                             ("resource_runtime_initial", "resource_runtime_pilot_charge", "resource_runtime_pilot_completion"))
            completion = manifest["artifacts"]["resource_runtime_pilot_completion"]
            self.assertEqual(completion["sha256"], authorities[-1]["state_sha256"])
            self.assertEqual(registry.get_metadata(completion["sha256"]).record_hash,
                             completion["registry_record_hash"])
            events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events
            self.assertEqual(tuple(events[-1].metadata["artifact_types"]), ("resource_runtime_pilot_completion",))
            self.assertEqual(events[-1].state_before.value, "CANDIDATE")
            self.assertEqual(events[-1].requested_state_after.value, "CANDIDATE")
            self.assertEqual(manifest["event_count"], len(events))
            self.assertEqual(manifest["ledger_head_hash"], events[-1].event_hash)
        self.assert_pilot_inert()

    def test_pending_pilot_registry_consistent_wrong_payload_refuses(self):
        self.pending_metadata_mutation("payload")

    def test_pending_pilot_wrong_output_creator_refuses(self):
        self.pending_metadata_mutation("creator_role")

    def test_pending_pilot_wrong_output_parents_refuses(self):
        self.pending_metadata_mutation("parent_artifacts")

    def test_pending_pilot_wrong_output_command_refuses(self):
        self.pending_metadata_mutation("creation_command")

    def test_pending_pilot_wrong_output_timestamp_refuses(self):
        self.pending_metadata_mutation("created_at")

    def test_pending_pilot_missing_output_projection_refuses(self):
        self.completed_pending()
        manifest = self.manifest()
        manifest["artifacts"].pop("blind_interpretation")
        self.orchestrator._save_manifest(manifest)
        self.assert_pilot_inert()

    def test_pending_pilot_earlier_checkpoint_semantic_mutations_refuse(self):
        self.completed_pending()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        paths = sorted(directory.glob("*.json"))
        self.assertGreater(len(paths), 1)
        for path in (paths[0], paths[-1]):
            raw = path.read_bytes()
            value = json.loads(raw)
            value["artifact_hashes"] = {}
            self.rehash_mapping(value, "checkpoint_hash")
            path.write_bytes(_canonical_bytes(value))
            self.assert_pilot_inert()
            path.write_bytes(raw)

    def test_pending_pilot_checkpoint_partial_and_absent_refuse_without_repair(self):
        self.completed_pending()
        path = sorted((self.root / ".scientist-one-build/checkpoints" / self.run_id).glob("*.json"))[-1]
        raw = path.read_bytes()
        path.write_bytes(b"{partial")
        before = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            forbid_negative_mutation(stack)
            for action in (self.orchestrator.status, self.orchestrator.advance_once):
                with self.assertRaises(UnsafeSerializationError):
                    action(self.run_id)
            with self.assertRaises(OrchestrationError):
                self.orchestrator.resume(self.run_id)
            with self.assertRaises(UnsafeSerializationError):
                self.call_pilot(mock.Mock(side_effect=AssertionError("partial checkpoint admitted")))
        self.assertEqual(state_bytes(self.root), before)
        path.unlink()
        self.assert_pilot_inert()
        path.write_bytes(raw)

    def pending_transition_cut(self, boundary):
        self.completed_pending()
        error = RuntimeError("actual evaluator transition cut " + boundary)
        original_append = self.orchestrator._append_event
        original_checkpoint = self.orchestrator._checkpoint
        original_save = self.orchestrator._save_manifest
        original_create = RecoveryManager.create_checkpoint

        def append(*args, **kwargs):
            if boundary == "before_event":
                raise error
            value = original_append(*args, **kwargs)
            if boundary == "after_event":
                raise error
            return value

        def checkpoint(manifest):
            if boundary == "before_local":
                raise error
            return original_checkpoint(manifest)

        def create(manager, *args, **kwargs):
            if boundary == "before_external":
                raise error
            value = original_create(manager, *args, **kwargs)
            if boundary == "after_external":
                raise error
            return value

        def save(manifest):
            if boundary == "before_manifest":
                raise error
            value = original_save(manifest)
            if boundary == "after_manifest":
                raise error
            return value

        with mock.patch.object(self.orchestrator, "_append_event", append), \
                mock.patch.object(self.orchestrator, "_checkpoint", checkpoint), \
                mock.patch.object(RecoveryManager, "create_checkpoint", create), \
                mock.patch.object(self.orchestrator, "_save_manifest", save):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])
        if boundary == "before_event":
            self.assertEqual(self.orchestrator.status(self.run_id)["status"], "CANDIDATE_EVALUATION_PENDING")
            self.continue_pending()
        elif boundary == "after_manifest":
            self.assertEqual(self.manifest()["current_state"], "CONFIRM")
            self.assertIsNone(self.orchestrator._pilot_evaluation_context(self.manifest()))
            self.assertEqual(self.orchestrator.status(self.run_id)["status"], "PASS")
        else:
            self.assert_pilot_inert()

    def test_pending_pilot_transition_before_event_remains_resumable(self):
        self.pending_transition_cut("before_event")

    def test_pending_pilot_transition_after_event_refuses_read_only(self):
        self.pending_transition_cut("after_event")

    def test_pending_pilot_transition_before_local_checkpoint_refuses(self):
        self.pending_transition_cut("before_local")

    def test_pending_pilot_transition_before_external_checkpoint_refuses(self):
        self.pending_transition_cut("before_external")

    def test_pending_pilot_transition_after_external_checkpoint_refuses(self):
        self.pending_transition_cut("after_external")

    def test_pending_pilot_transition_before_manifest_refuses(self):
        self.pending_transition_cut("before_manifest")

    def test_pending_pilot_transition_after_manifest_keeps_actual_confirm(self):
        self.pending_transition_cut("after_manifest")

    def test_pending_pilot_typed_receipt_before_append_cut_remains_resumable(self):
        self.completed_pending()
        original = self.orchestrator._typed_transition
        error = RuntimeError("actual typed receipt constructed before append")
        before = state_bytes(self.root)

        def transition(*args, **kwargs):
            original(*args, **kwargs)
            raise error

        with mock.patch.object(self.orchestrator, "_typed_transition", transition):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.advance_once(self.run_id)
        self.assertIs(caught.exception, error)
        self.assertEqual(state_bytes(self.root), before)
        self.continue_pending()

    def test_pending_pilot_resume_handoff_precedes_generic_recovery(self):
        self.completed_pending()
        original_recovery = self.orchestrator._recovery_report
        stop = RuntimeError("existing CONFIRM workflow deliberately not part of handoff")
        entered = []

        def recovery(manifest):
            self.assertEqual(manifest["current_state"], "CONFIRM")
            entered.append(manifest["current_state"])
            return original_recovery(manifest)

        def resources(manifest, **kwargs):
            self.assertEqual(kwargs["validity_stage"], "CONFIRMATORY")
            raise stop

        with mock.patch.object(self.orchestrator, "_recovery_report", recovery), \
                mock.patch.object(self.orchestrator, "_run_with_resources", resources):
            with self.assertRaises(RuntimeError) as caught:
                self.orchestrator.resume(self.run_id)
        self.assertIs(caught.exception, stop)
        self.assertTrue(entered)
        self.assertEqual(self.manifest()["current_state"], "CONFIRM")
        self.assertEqual(self.manifest()["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(self.manifest()["resource_runtime_state"]["confirmatory_used"], 0)
        self.assertNotIn(_FAILURE, self.manifest()["artifacts"])

    def make_calibrate_pair(self, *, units=1):
        self.assertEqual(self.manifest()["current_state"], "CALIBRATE")

        def operation():
            self.elapsed += 1.0

        self.orchestrator._run_with_resources(
            self.manifest(), experiment_id="owned-operational-calibrate-pair",
            validity_stage="PILOT", validity_units=units, operation=operation)
        manifest = self.manifest()
        self.assertEqual(manifest["current_state"], "CALIBRATE")
        self.assertEqual(manifest["resource_runtime_state"]["exploratory_used"], units)
        self.assertIsNone(self.orchestrator._pilot_evaluation_context(manifest))
        return manifest

    def test_calibrate_completed_pair_one_unit_wall_readback_is_preserved(self):
        from scientist_one.orchestrator import require_resource_runtime_wall_budget_observation
        self.make_calibrate_pair()
        self.elapsed = 1001.0
        observation = self.orchestrator.observe_run_wall_budget(self.run_id)
        registry = self.orchestrator._registry(self.run_id)
        ledger = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl")
        self.assertEqual(require_resource_runtime_wall_budget_observation(
            registry, ledger, observation_artifact_sha256=observation.observation_artifact_sha256,
            expected_run_id=self.run_id), observation)
        self.assertEqual(observation.runtime_state.exploratory_used, 1)
        self.assertIsNone(self.orchestrator._pilot_evaluation_context(self.manifest()))

    def test_calibrate_completed_pair_counter_and_projection_mutants_refuse(self):
        original = self.make_calibrate_pair()
        for key, value in (("exploratory_used", 2), ("confirmatory_used", 1),
                           ("progress_elapsed_seconds", 0)):
            with self.subTest(key=key):
                manifest = copy.deepcopy(original)
                manifest["resource_runtime_state"][key] = value
                self.orchestrator._save_manifest(manifest)
                self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)

    def test_calibrate_completed_pair_candidate_claims_cannot_select_generic(self):
        original = self.make_calibrate_pair()
        for name in ("pilot_report", "midrun_review", "blind_interpretation", "custody_record"):
            with self.subTest(name=name):
                manifest = copy.deepcopy(original)
                manifest["artifacts"][name] = copy.deepcopy(manifest["artifacts"]["resource_runtime_initial"])
                self.orchestrator._save_manifest(manifest)
                self.assert_pilot_inert()
        for key in ("E0:CANDIDATE", "E2:CONFIRM"):
            manifest = copy.deepcopy(original)
            manifest["evaluator_decisions"][key] = {"decision": "PASS"}
            self.orchestrator._save_manifest(manifest)
            self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)

    def test_calibrate_completed_pair_two_units_is_not_scientific_continuation(self):
        self.make_calibrate_pair(units=2)
        self.assertIsNone(self.orchestrator._pilot_operation_disposition(self.manifest()))
        self.assertIsNone(self.orchestrator._pilot_evaluation_context(self.manifest()))

    def test_pending_pilot_candidate_one_unit_cannot_select_generic(self):
        def operation():
            self.elapsed += 1.0
        self.call_pilot(operation, units=1)
        self.assert_pilot_inert()



    def test_pending_pilot_unknown_saved_same_stage_successor_refuses(self):
        self.completed_pending()
        manifest = self.manifest()
        self.orchestrator._append_event(
            manifest, "CANDIDATE", "CANDIDATE", "adverse unowned pending successor", (), (),
            event_type="CHECKPOINT")
        self.orchestrator._save_manifest(manifest)
        self.assert_pilot_inert()

    def test_pending_pilot_evaluator_registry_write_refuses_before_transition(self):
        from scientist_one.roles import Role
        self.completed_pending()
        original = self.orchestrator._evaluate
        appended = []

        def evaluate(manifest, *args, **kwargs):
            result = original(manifest, *args, **kwargs)
            if not appended:
                appended.append(self.orchestrator._registry(self.run_id).put_bytes(
                    b"adverse-evaluator-output-not-science", logical_type="unexpected_evaluator_output",
                    creator_role=Role.ORCHESTRATOR, origin="adverse fixture",
                    creation_command=("test",), validation_result="FAIL", frozen=False))
            return result

        before = self.manifest()
        with mock.patch.object(self.orchestrator, "_evaluate", evaluate), mock.patch.object(
                self.orchestrator, "_typed_transition", side_effect=AssertionError("changed census transitioned")):
            with self.assertRaisesRegex(OrchestrationError, "changed committed inputs"):
                self.orchestrator.advance_once(self.run_id)
        self.assertEqual(self.manifest(), before)
        self.assertEqual(len(appended), 1)
        self.assert_pilot_inert()

    def test_calibrate_completed_pair_context_and_parent_projection_mutants_refuse(self):
        original = self.make_calibrate_pair()
        for field, value in (("fixture_identifiers", ["substituted"]), ("random_seeds", [999]),
                             ("current_state", "CANDIDATE")):
            manifest = copy.deepcopy(original)
            manifest[field] = value
            self.orchestrator._save_manifest(manifest)
            self.assert_pilot_inert()
        manifest = copy.deepcopy(original)
        manifest["artifacts"]["resource_runtime_pilot_completion"]["parent_artifacts"] = []
        self.orchestrator._save_manifest(manifest)
        self.assert_pilot_inert()
        self.orchestrator._save_manifest(original)

    def test_calibrate_completed_pair_registry_candidate_claim_refuses(self):
        from scientist_one.roles import Role
        self.make_calibrate_pair()
        self.orchestrator._registry(self.run_id).put_bytes(
            b"adverse-unbound-candidate-name", logical_type="pilot_report",
            creator_role=Role.EXPERIMENT_RUNNER, origin="adverse fixture",
            creation_command=("test",), validation_result="FAIL", frozen=False)
        self.assert_pilot_inert()

    def test_calibrate_completed_pair_mixed_actual_charge_completion_states_refuse(self):
        from scientist_one.errors import LedgerError
        original_artifact = self.orchestrator._artifact
        ledger = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl")
        before_events = ledger.assert_valid().events
        completions = []

        def artifact(manifest, name, *args, **kwargs):
            if name == "resource_runtime_pilot_completion":
                # Only an adverse test mutates the in-memory source state.
                # The real ledger must reject this mixed-state completion edge;
                # earlier completion artifact/external publication remains real.
                manifest["current_state"] = "CANDIDATE"
            record = original_artifact(manifest, name, *args, **kwargs)
            if name == "resource_runtime_pilot_completion":
                completions.append(record)
            return record

        with mock.patch.object(self.orchestrator, "_artifact", artifact):
            with self.assertRaisesRegex(LedgerError, "^event state does not match current ledger head$") as caught:
                self.orchestrator._run_with_resources(
                    self.manifest(), experiment_id="adverse-mixed-source-state",
                    validity_stage="PILOT", validity_units=1,
                    operation=lambda: setattr(self, "elapsed", 1.0))
        self.assertIs(type(caught.exception), LedgerError)
        after_events = ledger.assert_valid().events
        self.assertEqual(after_events[:-1], before_events)
        self.assertEqual(tuple(after_events[-1].metadata["artifact_types"]), ("resource_runtime_pilot_charge",))
        self.assertEqual(after_events[-1].state_before.value, "CALIBRATE")
        self.assertEqual(after_events[-1].requested_state_after.value, "CALIBRATE")
        self.assertEqual(len(completions), 1)
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertEqual(tuple(r["logical_type"] for r in authorities),
                         ("resource_runtime_initial", "resource_runtime_pilot_charge", "resource_runtime_pilot_completion"))
        completion = completions[0]
        self.assertEqual(completion["sha256"], authorities[-1]["state_sha256"])
        registry = self.orchestrator._registry(self.run_id)
        stored = registry.get_metadata(completion["sha256"])
        self.assertEqual(stored.record_hash, completion["registry_record_hash"])
        self.assertEqual((self.root / completion["path"]).read_bytes(), registry.get_bytes(stored.sha256))
        saved = self.manifest()
        self.assertEqual(saved["resource_runtime_artifact"], "resource_runtime_pilot_charge")
        self.assertNotIn("resource_runtime_pilot_completion", saved["artifacts"])
        self.assertEqual(saved["event_count"], len(after_events))
        self.assertEqual(saved["ledger_head_hash"], after_events[-1].event_hash)
        self.assert_pilot_inert()



    def pending_completion_event_mutation(self, mutation):
        original = self.orchestrator._append_event

        def append(manifest, source, destination, reason, artifacts, evaluators, **kwargs):
            if artifacts == ("resource_runtime_pilot_completion",):
                if mutation == "reason":
                    reason = "adverse non-owner completion reason"
                elif mutation == "extra_artifact":
                    artifacts = (*artifacts, "pilot_report")
                else:
                    self.fail("unknown completion mutation")
            return original(manifest, source, destination, reason, artifacts, evaluators, **kwargs)

        with mock.patch.object(self.orchestrator, "_append_event", append):
            self.completed_pending()
        self.assert_pilot_inert()

    def test_pending_pilot_completion_reason_must_match_actual_owner(self):
        self.pending_completion_event_mutation("reason")

    def test_pending_pilot_completion_extra_artifact_cannot_authorize(self):
        self.pending_completion_event_mutation("extra_artifact")

    def test_pending_pilot_duplicate_external_checkpoint_refuses(self):
        self.completed_pending()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        latest = sorted(directory.glob("*.json"))[-1]
        (directory / "duplicate-fixture.json").write_bytes(latest.read_bytes())
        self.assert_pilot_inert()


    def manifest(self):
        return self.orchestrator.load_manifest(self.run_id)

    def payload(self):
        return self.orchestrator._json_artifact_payload(self.manifest(), _SLOT)

    def call_pilot(self, operation, *, units=2):
        return self.orchestrator._run_with_resources(
            self.manifest(), experiment_id=self.run_id + ":pilot",
            validity_stage="PILOT", validity_units=units, operation=operation,
        )

    def stall(self):
        self.elapsed = 11.0
        result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["status"], "RESOURCE_ADMISSION_BLOCKED")
        self.assertFalse(result["resumable"])
        self.assertIsNone(result["safe_resume_command"])
        self.assertIsNone(result["terminal_state"])
        return result

    def assert_retained_refusal(self, before, status):
        after = self.manifest()
        payload = self.payload()
        self.assertEqual(after["current_state"], before["current_state"])
        self.assertIsNone(after["terminal_state"])
        self.assertEqual(after["outcome"], "IN_PROGRESS")
        self.assertEqual(after["event_count"], before["event_count"] + 1)
        self.assertEqual(set(after["artifacts"]) - set(before["artifacts"]), {_SLOT})
        self.assertEqual(payload["authority_scope"], "OPERATIONAL_STICKY_BLOCK")
        self.assertIs(payload["scientific_evidence"], False)
        self.assertEqual(payload["source_event_count"], before["event_count"])
        self.assertEqual(payload["source_ledger_head_hash"], before["ledger_head_hash"])
        prior = before["resource_runtime_state"]
        actual = after["resource_runtime_state"]
        for key in ("worker_crashes", "validity_total_units", "exploratory_used",
                    "confirmatory_used", "progress_elapsed_seconds", "checkpoint_elapsed_seconds"):
            self.assertEqual(actual[key], prior[key])
        self.assertGreaterEqual(actual["wall_elapsed_seconds"], prior["wall_elapsed_seconds"])
        self.assertEqual(payload["observation"]["runtime_state"], actual)
        self.assertEqual(status["operational_blocker"]["reasons"], payload["observation"]["decision"]["reasons"])
        registry = self.orchestrator._registry(self.run_id)
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        ledger = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid()
        self.assertEqual(ledger.events[-1].state_before, ledger.events[-1].requested_state_after)
        self.assertEqual(len([r for r in authorities if r["logical_type"] == _SLOT]), 1)
        with self.assertRaises(OrchestrationError):
            _require_exact_resource_checkpoint_closure(registry, authorities, ledger.events)

    def assert_replay_rejected_without_writes(self):
        before = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            for operation in (self.orchestrator.status, self.orchestrator.advance_once, self.orchestrator.resume):
                with self.assertRaises(OrchestrationError):
                    operation(self.run_id)
        self.assertEqual(state_bytes(self.root), before)

    def test_actual_stall_commits_without_charge_operation_or_progress(self):
        before = self.manifest()
        with mock.patch.object(ResourceController, "record_progress", side_effect=AssertionError("no progress on refusal")):
            status = self.stall()
        self.assert_retained_refusal(before, status)
        self.assertIn("WORK_STALLED", status["operational_blocker"]["reasons"])
        self.assertNotIn("pilot_report", self.manifest()["artifacts"])
        self.assertNotIn("resource_runtime_pilot_charge", self.manifest()["artifacts"])

    def test_seeded_counter_fixture_replays_actual_crash_decision(self):
        before = self.manifest()
        self.assertEqual(before["resource_runtime_state"]["worker_crashes"], {"synthetic-counter-fixture": 3})
        status = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(status["status"], "RESOURCE_ADMISSION_BLOCKED")
        self.assert_retained_refusal(before, status)
        self.assertEqual(status["operational_blocker"]["reasons"], ["REPEATED_WORKER_CRASHES"])
        self.assertEqual(self.payload()["observation"]["decision"]["snapshot"]["worker_crashes"], 3)

    def test_simultaneous_wall_and_stall_preserves_stop_severity(self):
        before = self.manifest()
        status = self.stall()
        self.assert_retained_refusal(before, status)
        self.assertEqual(status["operational_blocker"]["action"], "STOP_BUDGET")
        self.assertEqual(status["operational_blocker"]["reasons"], [
            "WALL_CLOCK_BUDGET_EXHAUSTED", "WORK_STALLED", "CHECKPOINT_INTERVAL_REACHED",
        ])

    def test_exact_replay_is_read_only_and_fresh_process_is_identical(self):
        status = self.stall()
        before = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            for _ in range(2):
                for operation in (self.orchestrator.status, self.orchestrator.advance_once, self.orchestrator.resume):
                    self.assertEqual(operation(self.run_id), status)
        self.assertEqual(state_bytes(self.root), before)
        # This is an output-side test instruction, not source or scientific authority.
        (self.root / _REPLAY_INPUT).write_text(json.dumps({"run_id": self.run_id, "status": status}), encoding="utf-8")
        before = state_bytes(self.root)
        replay_child(self.root, self.id())
        self.assertEqual(state_bytes(self.root), before)

    def test_future_handler_and_direct_admission_cannot_run(self):
        status = self.stall()
        before = state_bytes(self.root)
        handler = mock.Mock(side_effect=AssertionError("blocked handler ran"))
        operation = mock.Mock(side_effect=AssertionError("blocked operation ran"))
        with mock.patch.dict(self.orchestrator._HANDLERS, {"CANDIDATE": handler}):
            self.assertEqual(self.orchestrator.advance_once(self.run_id), status)
            self.assertEqual(self.orchestrator.resume(self.run_id), status)
            with self.assertRaises(_ResourceAdmissionBlocked):
                self.call_pilot(operation)
        handler.assert_not_called()
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)

    def test_wrong_callsite_request_cannot_publish(self):
        self.elapsed = 11.0
        before = state_bytes(self.root)
        operation = mock.Mock()
        with self.assertRaisesRegex(OrchestrationError, "ordinary callsite"):
            self.call_pilot(operation, units=1)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        self.assertNotIn(_SLOT, self.manifest()["artifacts"])

    def test_transient_memory_refusal_remains_nonsticky(self):
        self.memory_used = 8
        before = state_bytes(self.root)
        operation = mock.Mock()
        with self.assertRaisesRegex(OrchestrationError, "MEMORY_HARD_LIMIT_REACHED"):
            self.call_pilot(operation)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        self.assertNotIn(_SLOT, self.manifest()["artifacts"])

    def test_operation_lookalike_cannot_create_admission_authority(self):
        operation = mock.Mock(side_effect=ResourceLimitError("WORK_STALLED; REPEATED_WORKER_CRASHES"))
        with self.assertRaises(OrchestrationError):
            self.call_pilot(operation)
        operation.assert_called_once_with()
        value = self.manifest()
        self.assertNotIn(_SLOT, value["artifacts"])
        self.assertEqual(value["resource_runtime_artifact"], "resource_runtime_pilot_charge")
        self.assertEqual(value["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(value["resource_runtime_state"]["worker_crashes"], {})
        self.assertNotIn("resource_runtime_pilot_completion", value["artifacts"])

    def test_post_charge_exception_does_not_invent_crash_or_completion(self):
        before = self.manifest()["resource_runtime_state"]
        operation = mock.Mock(side_effect=RuntimeError("synthetic ordinary callable failure"))
        with mock.patch.object(ResourceController, "record_progress", side_effect=AssertionError("failure is not progress")):
            with self.assertRaisesRegex(RuntimeError, "synthetic ordinary"):
                self.call_pilot(operation)
        operation.assert_called_once_with()
        value = self.manifest()
        self.assertNotIn(_SLOT, value["artifacts"])
        self.assertEqual(value["resource_runtime_artifact"], "resource_runtime_pilot_charge")
        self.assertEqual(value["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(value["resource_runtime_state"]["worker_crashes"], before["worker_crashes"])
        self.assertEqual(value["resource_runtime_state"]["progress_elapsed_seconds"], before["progress_elapsed_seconds"])
        self.assertNotIn("resource_runtime_pilot_completion", value["artifacts"])
        # Actual post-charge failure collection remains OPEN, not a crash claim.

    def publication_failure(self, boundary):
        self.elapsed = 11.0
        before = self.manifest()
        operation = mock.Mock(side_effect=AssertionError("refused operation ran"))
        if boundary == "registry":
            original = self.orchestrator._artifact

            def artifact(manifest, name, *args, **kwargs):
                if name == _SLOT:
                    raise RuntimeError("injected publication interruption")
                return original(manifest, name, *args, **kwargs)
            patcher = mock.patch.object(self.orchestrator, "_artifact", artifact)
        elif boundary == "ledger":
            original = EventLedger.append

            def append(ledger, event):
                if event.metadata.get("resource_admission_refusal"):
                    raise RuntimeError("injected publication interruption")
                return original(ledger, event)
            patcher = mock.patch.object(EventLedger, "append", append)
        elif boundary == "checkpoint":
            patcher = mock.patch.object(self.orchestrator, "_checkpoint", side_effect=RuntimeError("injected publication interruption"))
        elif boundary == "manifest":
            patcher = mock.patch.object(self.orchestrator, "_save_manifest", side_effect=RuntimeError("injected publication interruption"))
        else:
            raise AssertionError("unknown publication boundary")
        with patcher, self.assertRaisesRegex(RuntimeError, "injected publication interruption"):
            self.call_pilot(operation)
        operation.assert_not_called()
        self.assertEqual(self.manifest(), before)
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        self.assertEqual(authorities[-1]["logical_type"], _SLOT)
        self.assertEqual(authorities[-1]["state"]["observation"]["runtime_state"]["exploratory_used"], 0)
        self.assert_replay_rejected_without_writes()

    def test_partial_registry_publication_is_retained_and_blocked(self):
        self.publication_failure("registry")

    def test_partial_ledger_publication_is_retained_and_blocked(self):
        self.publication_failure("ledger")

    def test_partial_checkpoint_publication_is_retained_and_blocked(self):
        self.publication_failure("checkpoint")

    def test_partial_manifest_publication_is_retained_and_blocked(self):
        self.publication_failure("manifest")

    def test_manifest_parent_substitution_cannot_replay(self):
        self.stall()
        manifest = self.manifest()
        manifest["artifacts"][_SLOT]["parent_artifacts"].reverse()
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.assert_replay_rejected_without_writes()

    def test_later_ledger_work_cannot_replay(self):
        self.stall()
        manifest = self.manifest()
        # Append a real source-owned ordinary event; do not forge a chain.
        self.orchestrator._append_event(
            manifest, "CANDIDATE", "CANDIDATE", "synthetic later-work adverse fixture",
            (), (), event_type="CHECKPOINT",
        )
        self.orchestrator._save_manifest(manifest)
        self.assert_replay_rejected_without_writes()

    def test_duplicate_checkpoint_cannot_replay(self):
        self.stall()
        manifest = self.manifest()
        directory = self.root / ".scientist-one-build/checkpoints" / self.run_id
        checkpoint = directory / f"event-{manifest['event_count']:04d}-{manifest['ledger_head_hash'][:12]}.json"
        (directory / "duplicate-fixture.json").write_bytes(checkpoint.read_bytes())
        self.assert_replay_rejected_without_writes()

    def test_policy_request_counter_and_time_mutations_refuse(self):
        self.stall()
        payload = self.payload()
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        prior = ResourceRuntimeState.from_mapping(authorities[-2]["state"])
        config = ResourceConfig.from_mapping(payload["resource_config"])
        mutations = (
            ("decision", "action", "CONTINUE"),
            ("decision", "reasons", []),
            ("decision", "checkpoint_required", False),
            ("decision", "accept_new_work", True),
            ("decision", "stop_budget", True),
            ("decision", "backoff_seconds", 123),
            ("decision", "effective_disk_reserve_bytes", 1),
            ("request", "validity_units", -1),
            ("runtime_state", "exploratory_used", 1),
            ("runtime_state", "worker_crashes", {"invented": 3}),
            ("runtime_state", "progress_elapsed_seconds", 1),
            ("time_context", "monotonic_observed_at", 1012.0),
        )
        before = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            decision, runtime = _replay_resource_admission(config, prior, payload["observation"])
            self.assertIn("WORK_STALLED", decision.reasons)
            self.assertEqual(runtime.to_dict(), payload["observation"]["runtime_state"])
            for section, field, value in mutations:
                with self.subTest(section=section, field=field):
                    changed = copy.deepcopy(payload["observation"])
                    changed[section][field] = value
                    with self.assertRaises((ValueError, TypeError, KeyError)):
                        _replay_resource_admission(config, prior, changed)
        self.assertEqual(state_bytes(self.root), before)

    def test_legacy_successful_pilot_remains_unchanged(self):
        status = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(status["status"], "PASS")
        self.assertEqual(status["current_state"], "CONFIRM")
        manifest = self.manifest()
        self.assertNotIn(_SLOT, manifest["artifacts"])
        self.assertEqual(manifest["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(manifest["resource_runtime_state"]["confirmatory_used"], 0)
        self.assertEqual(manifest["resource_runtime_artifact"], "resource_runtime_pilot_completion")
        registry = self.orchestrator._registry(self.run_id)
        authorities = self.orchestrator._resource_authority_records(self.run_id)
        events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events
        self.assertEqual(tuple(r["logical_type"] for r in authorities), (
            "resource_runtime_initial", "resource_runtime_pilot_charge", "resource_runtime_pilot_completion",
        ))
        _require_exact_resource_checkpoint_closure(registry, authorities, events)

    def test_confirmatory_preseal_is_retained_without_charge_or_reveal(self):
        result = self.orchestrator.advance_once(self.run_id)
        self.assertEqual(result["current_state"], "CONFIRM")
        before = self.manifest()
        status = self.stall()
        after = self.manifest()
        self.assertEqual(status["current_state"], "CONFIRM")
        self.assertEqual(after["resource_runtime_state"]["exploratory_used"], 2)
        self.assertEqual(after["resource_runtime_state"]["confirmatory_used"], 0)
        self.assertEqual(after["resource_runtime_state"]["progress_elapsed_seconds"],
                         before["resource_runtime_state"]["progress_elapsed_seconds"])
        self.assertTrue({"frozen_confirmatory_split", "fresh_custody_receipt", _SLOT}.issubset(after["artifacts"]))
        self.assertNotIn("resource_runtime_confirmatory_charge", after["artifacts"])
        self.assertNotIn("confirmatory_results", after["artifacts"])
        receipt = self.orchestrator._json_artifact_payload(after, "fresh_custody_receipt")
        self.assertTrue(receipt["status"]["sealed"])
        self.assertFalse(receipt["status"]["revealed"])
        self.assertEqual(receipt["status"]["authorized_access_count"], 0)
        self.assertGreater(self.payload()["source_event_count"], before["event_count"])
        before_replay = state_bytes(self.root)
        with ExitStack() as stack:
            forbid_observation(stack)
            self.assertEqual(self.orchestrator.resume(self.run_id), status)
        self.assertEqual(state_bytes(self.root), before_replay)

    def assert_fresh_prefix_refused_without_writes(self):
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("damaged refusal admitted work"))
        with ExitStack() as stack:
            forbid_observation(stack)
            fresh = ScientistOneOrchestrator(self.root)
            for method in (fresh.status, fresh.advance_once, fresh.resume):
                with self.assertRaises(OrchestrationError):
                    method(self.run_id)
                self.assertEqual(state_bytes(self.root), before)
            with self.assertRaises(OrchestrationError):
                fresh._run_with_resources(
                    fresh.load_manifest(self.run_id), experiment_id=self.run_id + ":pilot",
                    validity_stage="PILOT", validity_units=2, operation=operation,
                )
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        self.assertNotIn("terminal_report", fresh.load_manifest(self.run_id)["artifacts"])

    def corrupt_published_external_refusal(self):
        directory = self.root / ".scientist-one-build/resource-authority" / self.run_id
        path = sorted(directory.glob("*.json"))[-1]
        raw = path.read_bytes()
        self.assertEqual(json.loads(raw)["logical_type"], _SLOT)
        path.write_bytes(raw[:len(raw) // 2])

    def test_corrupt_external_prefix_retains_registry_refusal_without_writes(self):
        self.publication_failure("ledger")
        self.assertNotIn(_SLOT, self.manifest()["artifacts"])
        records = self.orchestrator._registry(self.run_id).verify_all(raise_on_error=True).records
        self.assertEqual(sum(record.logical_type == _SLOT for record in records), 1)
        self.corrupt_published_external_refusal()
        self.assert_fresh_prefix_refused_without_writes()

    def test_surviving_ledger_refusal_survives_unreadable_earlier_channels(self):
        self.publication_failure("checkpoint")
        self.assertNotIn(_SLOT, self.manifest()["artifacts"])
        records = self.orchestrator._registry(self.run_id).verify_all(raise_on_error=True).records
        record = next(record for record in records if record.logical_type == _SLOT)
        self.corrupt_published_external_refusal()
        # A second deliberate output corruption leaves only the existing
        # valid ledger marker readable; it grants no positive authority.
        (self.root / record.path).write_bytes(b"truncated-refusal-fixture")
        events = EventLedger(self.root, Path("runs") / self.run_id / "events.jsonl").assert_valid().events
        self.assertEqual(tuple(events[-1].metadata["artifact_types"]), (_SLOT,))
        self.assert_fresh_prefix_refused_without_writes()

    def test_unmarked_legacy_corruption_keeps_existing_terminal_route(self):
        directory = self.root / ".scientist-one-build/resource-authority" / self.run_id
        paths = sorted(directory.glob("*.json"))
        self.assertEqual(len(paths), 1)
        raw = paths[0].read_bytes()
        self.assertEqual(json.loads(raw)["logical_type"], "resource_runtime_initial")
        paths[0].write_bytes(raw[:len(raw) // 2])
        before = state_bytes(self.root)
        fresh = ScientistOneOrchestrator(self.root)
        self.assertIsNone(fresh._resource_admission_refusal(fresh.load_manifest(self.run_id)))
        # A routing spy stops before legacy terminal publication. It verifies
        # dispatch to the unchanged owner, not a successful repaired history.
        with mock.patch.object(fresh, "_transition_terminal", side_effect=RuntimeError("legacy-owner-routing-spy")) as route:
            with self.assertRaisesRegex(RuntimeError, "legacy-owner-routing-spy"):
                fresh.advance_once(self.run_id)
        route.assert_called_once()
        self.assertEqual(route.call_args.args[0]["pending_terminal"]["destination"], "STOP_SECURITY")
        self.assertEqual(state_bytes(self.root), before)

    def substituted_context_refuses(self, field, value):
        manifest = self.manifest()
        self.assertNotEqual(manifest[field], value)
        manifest[field] = value
        (self.root / "runs" / self.run_id / "manifest.json").write_bytes(_canonical_bytes(manifest))
        self.elapsed = 11.0
        before = state_bytes(self.root)
        operation = mock.Mock(side_effect=AssertionError("substituted run context admitted work"))
        with self.assertRaisesRegex(OrchestrationError, "source projection is stale or substituted"):
            self.call_pilot(operation)
        operation.assert_not_called()
        self.assertEqual(state_bytes(self.root), before)
        current = self.manifest()
        self.assertNotIn(_SLOT, current["artifacts"])
        self.assertEqual(current["resource_runtime_state"]["exploratory_used"], 0)
        self.assertEqual(current["resource_runtime_state"]["confirmatory_used"], 0)
        self.assertEqual(tuple(record["logical_type"] for record in self.orchestrator._resource_authority_records(self.run_id)),
                         ("resource_runtime_initial",))

    def test_substituted_fixture_identifiers_cannot_publish(self):
        self.substituted_context_refuses("fixture_identifiers", ["substituted-fixture-v1"])

    def test_substituted_random_seeds_cannot_publish(self):
        self.substituted_context_refuses("random_seeds", [20260920])

    def test_postcommit_initialized_context_substitution_refuses(self):
        self.stall()
        path = self.root / "runs" / self.run_id / "manifest.json"
        original = path.read_bytes()
        for field, value in (("fixture_identifiers", ["substituted-fixture-v1"]),
                             ("random_seeds", [20260920])):
            with self.subTest(field=field):
                manifest = json.loads(original)
                manifest[field] = value
                path.write_bytes(_canonical_bytes(manifest))
                self.assert_fresh_prefix_refused_without_writes()
                path.write_bytes(original)

    def test_real_controller_fractional_and_divergent_clock_replay(self):
        for label, monotonic_delta, epoch_delta in (
            ("epoch-quantization", 2.0000003, 0.0),
            ("epoch-ahead", 2.0, 3.0),
            ("monotonic-ahead", 5.0, 2.0),
        ):
            with self.subTest(case=label):
                clock = {"monotonic": 10.0, "epoch": 1700000000.0}
                config = ResourceConfig(cpu_worker_limit=1, stall_timeout_seconds=1,
                                        maximum_wall_clock_seconds=100,
                                        checkpoint_interval_seconds=1)
                controller = ResourceController(
                    config, self.root, run_id="clock-fixture-" + label,
                    validity_budget_units=10, artifact_roots=(),
                    clock=lambda: clock["monotonic"], wall_clock=lambda: clock["epoch"],
                    memory_probe=lambda: MemoryObservation(10, 1, "AVAILABLE", "synthetic-clock-fixture"),
                    pressure_probe=lambda: PressureObservation("nominal", "nominal", "AVAILABLE", "synthetic-clock-fixture"),
                    disk_usage_probe=lambda _path: SimpleNamespace(total=10**12, used=10**9, free=10**12-10**9),
                )
                prior = controller.export_state()
                clock["monotonic"] += monotonic_delta
                clock["epoch"] += epoch_delta
                with self.assertRaises(_ResourceAdmissionRefusal) as captured:
                    controller.acquire("clock-fixture-pilot", cpu_workers=1,
                                       validity_stage="PILOT", validity_units=2)
                actual = captured.exception
                observation = json.loads(actual.observation_json)
                with ExitStack() as stack:
                    forbid_observation(stack)
                    decision, runtime = _replay_resource_admission(config, prior, observation)
                self.assertEqual(decision, actual.decision)
                self.assertEqual(runtime.to_dict(), observation["runtime_state"])
                self.assertEqual(runtime.exploratory_used, 0)
                self.assertEqual(runtime.confirmatory_used, 0)
                self.assertEqual(runtime.progress_elapsed_seconds, 0.0)
                self.assertGreaterEqual(runtime.wall_elapsed_seconds, decision.snapshot.wall_elapsed_seconds)
                if label == "epoch-quantization":
                    self.assertGreater(runtime.wall_elapsed_seconds, decision.snapshot.stalled_seconds)
                elif label == "epoch-ahead":
                    self.assertGreater(decision.snapshot.wall_elapsed_seconds, decision.snapshot.stalled_seconds)
                else:
                    self.assertGreater(decision.snapshot.stalled_seconds, epoch_delta)
