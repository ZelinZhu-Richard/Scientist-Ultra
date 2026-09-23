"""Narrow test-only captured fixtures for source-owned admission regressions.

The normal launcher runs each original TestCase with its setup and cleanups.
This helper grants no scientific, custody, execution or release authority.
"""
from functools import wraps
import ast
import hashlib
import importlib
import io
import json
import math
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from scientist_one.resources import ResourceConfig
from scientist_one.security import canonical_json_bytes

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MARKER = ".prepared-admission-fixture"
_SELECTION_MARKER = ".prepared-admission-case.json"
_WRAPPER_MODULE = "tests.test_prepared_admission_case"
_WRAPPER_ID = _WRAPPER_MODULE + ".PreparedAdmissionCaseTests.test_original_case"
_NESTED_PROTOCOL = "SCIENTIST_ONE_PREPARED_ADMISSION_CASE_V1="
_WORKER_PROTOCOL = "SCIENTIST_ONE_CAPTURED_TEST_MODULE_V1="
_CASE_CLASS = "tests.test_resource_admission_durability.ResourceAdmissionDurabilityTests"
_HISTORICAL_DRIFT_CASES = {
    _CASE_CLASS + ".test_pilot_historical_live_source_drift_after_capture": "source",
    _CASE_CLASS + ".test_pilot_historical_live_config_drift_after_capture": "configuration",
}
_CASE_METHODS = frozenset((
    "test_evaluator_context_absent_key_is_only_private_inapplicability",
    "test_evaluator_context_all_guarded_calls_screen_negative_owner_first",
    "test_unmarked_legacy_corruption_status_resume_keep_recovery_route",
    "test_unmarked_legacy_corruption_direct_keeps_resource_owner",
    "test_pending_pilot_hidden_completion_keeps_external_registry_ledger_markers",
    "test_pending_pilot_hidden_completion_corrupt_external_retains_registry",
    "test_pending_pilot_hidden_completion_corrupt_external_registry_retains_ledger",
    "test_pending_pilot_null_completion_key_cannot_bypass",
    "test_evaluator_context_runtime_pointer_without_completion_key_refuses",
    "test_pending_pilot_completion_reason_must_match_actual_owner",
    "test_pending_pilot_completion_extra_artifact_cannot_authorize",
    "test_pending_pilot_duplicate_external_checkpoint_refuses",
    "test_pending_pilot_before_e0_continues_only_actual_evaluators",
    "test_pending_pilot_before_e2_continues_only_actual_evaluators",
    "test_pending_pilot_before_e3_continues_only_actual_evaluators",
    "test_pending_pilot_after_in_memory_evaluator_receipt_continues",
    "test_pending_pilot_status_and_direct_admission_are_inert",
    "test_pending_pilot_fresh_process_evaluator_continuation",
    "test_pending_pilot_fresh_command_preserves_historical_record_metadata",
    "test_pending_pilot_supplied_brief_preserves_text_owner",
    "test_pending_pilot_evaluator_exception_does_not_publish_or_retry",
    "test_pending_pilot_evaluator_unrelated_working_mutation_refuses",
    "test_pending_pilot_evaluator_creates_custody_journal_refuses",
    "test_pending_pilot_evaluator_source_addition_refuses_at_live_close",
    "test_pending_pilot_evaluator_config_addition_refuses_at_live_close",
    "test_pending_pilot_recognition_closing_config_addition_refuses",
    "test_pending_pilot_saved_evaluator_claims_cannot_authorize",
    "test_pending_pilot_prior_context_and_artifact_mutations_refuse",
    "test_pending_pilot_extra_registry_record_or_mirror_refuses",
    "test_pending_pilot_registry_consistent_wrong_payload_refuses",
    "test_pending_pilot_wrong_output_creator_refuses",
    "test_pending_pilot_wrong_output_parents_refuses",
    "test_pending_pilot_wrong_output_command_refuses",
    "test_pending_pilot_wrong_output_timestamp_refuses",
    "test_pending_pilot_missing_output_projection_refuses",
    "test_pending_pilot_earlier_checkpoint_semantic_mutations_refuse",
    "test_pending_pilot_checkpoint_partial_and_absent_refuse_without_repair",
    "test_pending_pilot_transition_before_event_remains_resumable",
    "test_pending_pilot_transition_after_event_refuses_read_only",
    "test_pending_pilot_transition_before_local_checkpoint_refuses",
    "test_pending_pilot_transition_before_external_checkpoint_refuses",
    "test_pending_pilot_transition_after_external_checkpoint_refuses",
    "test_pending_pilot_transition_before_manifest_refuses",
    "test_pending_pilot_transition_after_manifest_keeps_actual_confirm",
    "test_pending_pilot_typed_receipt_before_append_cut_remains_resumable",
    "test_pending_pilot_resume_handoff_precedes_generic_recovery",
    "test_calibrate_completed_pair_one_unit_wall_readback_is_preserved",
    "test_calibrate_completed_pair_counter_and_projection_mutants_refuse",
    "test_calibrate_completed_pair_candidate_claims_cannot_select_generic",
    "test_calibrate_completed_pair_two_units_is_not_scientific_continuation",
    "test_pending_pilot_candidate_one_unit_cannot_select_generic",
    "test_pending_pilot_unknown_saved_same_stage_successor_refuses",
    "test_pending_pilot_evaluator_registry_write_refuses_before_transition",
    "test_calibrate_completed_pair_context_and_parent_projection_mutants_refuse",
    "test_calibrate_completed_pair_registry_candidate_claim_refuses",
    "test_calibrate_completed_pair_mixed_actual_charge_completion_states_refuse",
    "test_confirm_started_before_release_refuses_fresh_routing_without_mutation",
    "test_actual_stall_commits_without_charge_operation_or_progress",
    "test_confirmatory_preseal_is_retained_without_charge_or_reveal",
    "test_corrupt_external_prefix_retains_registry_refusal_without_writes",
    "test_duplicate_checkpoint_cannot_replay",
    "test_exact_replay_is_read_only_and_fresh_process_is_identical",
    "test_future_handler_and_direct_admission_cannot_run",
    "test_later_ledger_work_cannot_replay",
    "test_legacy_successful_pilot_remains_unchanged",
    "test_manifest_parent_substitution_cannot_replay",
    "test_operation_lookalike_cannot_create_admission_authority",
    "test_partial_checkpoint_publication_is_retained_and_blocked",
    "test_partial_ledger_publication_is_retained_and_blocked",
    "test_partial_manifest_publication_is_retained_and_blocked",
    "test_partial_registry_publication_is_retained_and_blocked",
    "test_pilot_admission_before_purported_charge_is_conflicting",
    "test_pilot_after_return_lease_is_not_witnessed",
    "test_pilot_after_return_progress_after_is_not_witnessed",
    "test_pilot_after_return_progress_before_is_not_witnessed",
    "test_pilot_base_capture_error_is_not_body_failure",
    "test_pilot_baseexception_is_not_body_exception_witness",
    "test_pilot_charge_corrupt_external_retains_registry_marker",
    "test_pilot_charge_publication_external_cut",
    "test_pilot_charge_publication_ledger_cut",
    "test_pilot_charge_publication_manifest_cut",
    "test_pilot_charge_publication_registry_cut",
    "test_pilot_charged_base_rejects_code_substitution",
    "test_pilot_charged_base_rejects_config_substitution",
    "test_pilot_charged_base_rejects_fixture_identifier_substitution",
    "test_pilot_charged_base_rejects_seed_substitution",
    "test_pilot_completed_before_evaluator_error_has_no_failure_witness",
    "test_pilot_completed_current_ledger_semantic_mutants",
    "test_pilot_completed_current_resource_binding_mutants",
    "test_pilot_completed_current_runtime_semantic_mutants",
    "test_pilot_completed_then_confirm_admission_refusal_is_valid",
    "test_pilot_completed_wall_observation_keeps_existing_authority",
    "test_pilot_completion_corrupt_external_retains_registry_marker",
    "test_pilot_completion_publication_external_cut",
    "test_pilot_completion_publication_ledger_cut",
    "test_pilot_completion_publication_manifest_cut",
    "test_pilot_completion_publication_registry_cut",
    "test_pilot_default_brief_gate_remains_blocked_external",
    "test_pilot_direct_handler_retains_command_protection",
    "test_pilot_failure_blocks_future_candidate_handler",
    "test_pilot_failure_corrupt_external_and_registry_retains_ledger_marker",
    "test_pilot_failure_corrupt_external_retains_registry_marker",
    "test_pilot_failure_fresh_process_replay",
    "test_pilot_failure_mutable_terminal_cannot_hide_marker",
    "test_pilot_failure_one_complete_output",
    "test_pilot_failure_publication_checkpoint_cut",
    "test_pilot_failure_publication_external_cut",
    "test_pilot_failure_publication_ledger_cut",
    "test_pilot_failure_publication_manifest_cut",
    "test_pilot_failure_publication_registry_cut",
    "test_pilot_failure_registry_before_first_projection",
    "test_pilot_failure_registry_before_second_projection",
    "test_pilot_failure_replay_rejects_duplicate_checkpoint",
    "test_pilot_failure_replay_rejects_fixture_identifier_substitution",
    "test_pilot_failure_replay_rejects_later_ledger_work",
    "test_pilot_failure_replay_rejects_payload_bytes",
    "test_pilot_failure_replay_rejects_refunded_counter",
    "test_pilot_failure_replay_rejects_seed_substitution",
    "test_pilot_failure_resource_limit_error_is_body_owned",
    "test_pilot_failure_two_complete_outputs",
    "test_pilot_failure_zero_complete_outputs",
    "test_pilot_generic_callback_has_no_owned_witness",
    "test_pilot_historical_checkpoints_absent_partial_or_substituted",
    "test_pilot_historical_duplicate_and_newer_checkpoint",
    "test_pilot_historical_evaluator_semantic_mutant",
    "test_pilot_historical_initialized_context_mutants",
    "test_pilot_historical_live_config_drift_after_capture",
    "test_pilot_historical_live_source_drift_after_capture",
    "test_pilot_historical_preceding_checkpoint_semantic_mutant",
    "test_pilot_historical_receipt_semantic_mutant",
    "test_pilot_historical_reconciliation_semantic_mutant",
    "test_pilot_historical_report_command_semantic_mutant",
    "test_pilot_historical_report_parent_order_semantic_mutant",
    "test_pilot_historical_report_payload_semantic_mutant",
    "test_pilot_historical_report_projection_and_absence",
    "test_pilot_historical_report_timestamp_semantic_mutant",
    "test_pilot_historical_source_stop_fresh_process",
    "test_pilot_historical_source_stop_is_preserved",
    "test_pilot_historical_successor_markers_never_qualify",
    "test_pilot_historical_terminal_projection_mutants",
    "test_pilot_historical_truncated_ledger_never_quarantines",
    "test_pilot_open_charge_cannot_be_cleared_by_completion_name",
    "test_pilot_open_charge_conflicting_refusal_marker_is_inert",
    "test_pilot_open_charge_terminal_fields_do_not_create_history",
    "test_pilot_ordinary_resume_compatibility",
    "test_pilot_partial_metadata_prefix_0",
    "test_pilot_partial_mirror_prefix_0",
    "test_pilot_partial_mirror_prefix_1",
    "test_pilot_partial_object_prefix_0",
    "test_pilot_prefix_rejects_changed_payload",
    "test_pilot_prefix_rejects_wrong_command",
    "test_pilot_prefix_rejects_wrong_parents",
    "test_pilot_prefix_rejects_wrong_timestamp",
    "test_pilot_replaced_body_exception_has_no_owned_witness",
    "test_pilot_success_confirm_and_terminal_compatibility",
    "test_pilot_supplied_text_in_synthetic_mode_is_preserved",
    "test_pilot_failure_three_complete_outputs",
    "test_pilot_failure_registry_before_third_projection",
    "test_pilot_failure_three_outputs_fresh_process_replay",
    "test_pilot_failure_third_before_projection_fresh_process_replay",
    "test_pilot_failure_third_output_replay_corruption",
    "test_pilot_third_output_payload_cannot_be_adopted",
    "test_pilot_third_output_role_cannot_be_adopted",
    "test_pilot_third_output_parents_cannot_be_adopted",
    "test_pilot_third_output_missing_predecessor_cannot_be_adopted",
    "test_pilot_partial_third_mirror_is_not_adopted",
    "test_pilot_partial_third_object_is_not_adopted",
    "test_pilot_partial_third_metadata_is_not_adopted",
    "test_pilot_unresolved_charge_fresh_process_replay",
    "test_pilot_unsupported_directory_cannot_be_adopted",
    "test_pilot_unsupported_file_cannot_be_adopted",
    "test_pilot_unsupported_identity_cannot_be_adopted",
    "test_pilot_unsupported_nonprefix_cannot_be_adopted",
    "test_pilot_unsupported_projection_cannot_be_adopted",
    "test_pilot_unsupported_registry_cannot_be_adopted",
    "test_policy_request_counter_and_time_mutations_refuse",
    "test_post_charge_exception_does_not_invent_crash_or_completion",
    "test_postcommit_initialized_context_substitution_refuses",
    "test_real_controller_fractional_and_divergent_clock_replay",
    "test_seeded_counter_fixture_replays_actual_crash_decision",
    "test_simultaneous_wall_and_stall_preserves_stop_severity",
    "test_substituted_fixture_identifiers_cannot_publish",
    "test_substituted_random_seeds_cannot_publish",
    "test_surviving_ledger_refusal_survives_unreadable_earlier_channels",
    "test_transient_memory_refusal_remains_nonsticky",
    "test_unmarked_legacy_corruption_keeps_existing_terminal_route",
    "test_wrong_callsite_request_cannot_publish",
))
_ALLOWED_IDS = frozenset(_CASE_CLASS + "." + name for name in _CASE_METHODS)
_REPLAY_MODULE = "tests.test_prepared_admission_replay"
_REPLAY_ID = _REPLAY_MODULE + ".PreparedAdmissionReplayTests.test_replay"
_BASE_MODULES = {"tests", "tests.test_resource_admission_fixture",
                 "tests.test_resource_admission_durability"}
_ACTIVE = None


def _selection(test_id):
    if test_id not in _ALLOWED_IDS:
        raise AssertionError("unknown prepared admission case")
    return test_id.rsplit(".", 2)


def _modules(test_id):
    _selection(test_id)
    return _BASE_MODULES | {_WRAPPER_MODULE, _REPLAY_MODULE}


def _module_path(name):
    return "tests/__init__.py" if name == "tests" else name.replace(".", "/") + ".py"


def prepared_admission_tests(cls):
    """Keep real TestCase IDs and run each original lifecycle under capture."""
    if (cls.__module__ + "." + cls.__name__ != _CASE_CLASS
            or {name for name in vars(cls) if name.startswith("test_")} != _CASE_METHODS):
        raise AssertionError("prepared admission test inventory changed")
    setup = cls.setUp

    @wraps(setup)
    def dispatched_setup(self):
        if _ACTIVE is not None:
            setup(self)

    def wrap(method):
        @wraps(method)
        def dispatched(self):
            if _ACTIVE is None:
                _run_prepared_child(self.id())
            else:
                if self.id() != _ACTIVE["test_id"]:
                    raise AssertionError("child selected another case")
                method(self)
        return dispatched

    cls.setUp = dispatched_setup
    for name in _CASE_METHODS:
        setattr(cls, name, wrap(getattr(cls, name)))
    return cls


def prepared_root(case):
    if (_ACTIVE is None or case.id() != _ACTIVE["test_id"]
            or _ACTIVE["initializations"] != 0 or Path.cwd().resolve() != _PROJECT_ROOT):
        raise AssertionError("case needs its one captured-root initialization")
    _ACTIVE["initializations"] += 1
    return _ACTIVE["root"]


def _snapshot(root):
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
            path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
            path.stat().st_mode, path.stat().st_nlink,
        )
        for path in root.rglob("*")
        if path.is_file() and (
            path.relative_to(root).parts[0] in {"src", "scripts", "tests", "configs", "fixtures"}
            or path.relative_to(root).as_posix() in {_MARKER, _SELECTION_MARKER, "state/APP_SESSION_BOOTSTRAP.json"}
        )
    }


def _prepare(root, test_id):
    _selection(test_id)
    root.mkdir()
    for directory in ("src/scientist_one", "scripts", "tests", "configs",
                      "fixtures/calibration", "reports"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for source in (_PROJECT_ROOT / "src/scientist_one").glob("*.py"):
        shutil.copyfile(source, root / "src/scientist_one" / source.name)
    shutil.copyfile(_PROJECT_ROOT / "scripts/scientist_one_cli.py",
                    root / "scripts/scientist_one_cli.py")
    for name in _modules(test_id) - {_WRAPPER_MODULE, _REPLAY_MODULE}:
        relative = _module_path(name)
        shutil.copyfile(_PROJECT_ROOT / relative, root / relative)
    for name in ("calibration_cases.json", "synthetic_workflow_tasks.json"):
        relative = "fixtures/calibration/" + name
        shutil.copyfile(_PROJECT_ROOT / relative, root / relative)
    for source in (_PROJECT_ROOT / "configs").glob("*.json"):
        shutil.copyfile(source, root / "configs" / source.name)
    config = ResourceConfig().to_dict()
    config.update(cpu_worker_limit=1, stall_timeout_seconds=10,
                  checkpoint_interval_seconds=5, maximum_wall_clock_seconds=1000,
                  default_device="cpu")
    if test_id.endswith(".test_simultaneous_wall_and_stall_preserves_stop_severity"):
        config.update(stall_timeout_seconds=5, maximum_wall_clock_seconds=10)
    (root / "configs/resource_limits.json").write_bytes(canonical_json_bytes(config) + b"\n")
    (root / _MARKER).write_text("prepared-admission-fixture-20260920\n", encoding="utf-8")
    (root / _SELECTION_MARKER).write_text(
        json.dumps({"test_id": test_id}, sort_keys=True), encoding="utf-8"
    )
    (root / _module_path(_WRAPPER_MODULE)).write_text(
        "import unittest\n"
        "from tests.test_resource_admission_fixture import run_original_case\n\n"
        "class PreparedAdmissionCaseTests(unittest.TestCase):\n"
        "    def test_original_case(self):\n"
        f"        run_original_case({test_id!r})\n", encoding="utf-8",
    )
    (root / _module_path(_REPLAY_MODULE)).write_text(
        "import unittest\n"
        "from tests.test_resource_admission_durability import fresh_replay\n\n"
        "class PreparedAdmissionReplayTests(unittest.TestCase):\n"
        "    def test_replay(self):\n"
        "        fresh_replay(self)\n", encoding="utf-8",
    )
    generated = {_module_path(_REPLAY_MODULE), _MARKER, _SELECTION_MARKER, "configs/resource_limits.json",
                 _module_path(_WRAPPER_MODULE)}
    for relative, identity in _snapshot(root).items():
        path = root / relative
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise AssertionError("prepared input is not a unique regular file")
        if relative not in generated and identity[0] != (_PROJECT_ROOT / relative).read_bytes():
            raise AssertionError("prepared copy differs from original input")
    (root / "state").mkdir(exist_ok=True)
    (root / "state/APP_SESSION_BOOTSTRAP.json").write_text(json.dumps({
        "app_session_bootstrap": "PASS", "canonical_project_root": str(root.resolve()),
        "classification": "NEW_TEST_FIXTURE", "historical_authority": False,
        "scientific_evidence": False, "app_approval_claimed": False,
        "human_e4_authority": False, "provider_authority": False,
        "bootstrap_checks": [{
            "check": "fresh_owned_root_and_exact_prepared_input_identities",
            "result": "PASS",
            "scope": "Measured local preparation only; no app, human, provider or scientific authority.",
            "input_sha256": {p: hashlib.sha256(v[0]).hexdigest() for p, v in sorted(_snapshot(root).items())},
        }],
    }, sort_keys=True), encoding="utf-8")


def _require_success(value, *, test_id, nested):
    counters = {"tests_run", "failures", "errors", "skipped", "expected_failures",
                "unexpected_successes"}
    if (not isinstance(value, dict)
            or any(type(value.get(key)) is not int for key in counters)
            or value["tests_run"] != 1
            or any(value[key] != 0 for key in counters - {"tests_run"})
            or value.get("successful") is not True
            or value.get("test_ids") != [test_id]
            or value.get("failure_details") != [] or value.get("error_details") != []
            or type(value.get("output")) is not str or not value["output"].strip()):
        raise AssertionError(f"prepared child did not pass exact original scope: {value!r}")
    common = counters | {"schema_version", "test_ids", "successful", "failure_details",
                         "error_details", "output"}
    if nested:
        expected = common
        schema = "prepared-admission-case/v1"
    else:
        expected = common | {"module_name", "module_sha256", "elapsed_seconds",
                             "loaded_test_modules", "project_source_attestation",
                             "test_source_attestation"}
        schema = "captured-test-module/v1"
    if set(value) != expected or value["schema_version"] != schema:
        raise AssertionError("prepared child report schema mismatch")


def run_original_case(test_id):
    """Run the original lifecycle, not a duplicated scenario implementation."""
    global _ACTIVE
    module_name, class_name, method = _selection(test_id)
    root = Path.cwd().resolve(strict=True)
    if (_ACTIVE is not None or root != _PROJECT_ROOT or root.name != "ScientistOne"
            or not root.parent.name.startswith("prepared-admission-child-")
            or root.parent.parent != Path(tempfile.gettempdir()).resolve()
            or (root / "runs").exists()
            or (root / ".scientist-one-build/resource-authority").exists()
            or json.loads((root / _SELECTION_MARKER).read_text(encoding="utf-8"))
            != {"test_id": test_id}):
        raise AssertionError("original case requires its fresh prepared child")
    _ACTIVE = {"root": root, "test_id": test_id, "initializations": 0}
    try:
        module = importlib.import_module(module_name)
        case = getattr(module, class_name)(method)
        if case.id() != test_id:
            raise AssertionError("selected original TestCase identity differs")
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(
            unittest.TestSuite((case,))
        )
        report = {
            "schema_version": "prepared-admission-case/v1", "test_ids": [case.id()],
            "tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "successful": result.wasSuccessful(), "output": output.getvalue(),
            "failure_details": [{"test": item.id(), "traceback": detail}
                                for item, detail in result.failures],
            "error_details": [{"test": item.id(), "traceback": detail}
                              for item, detail in result.errors],
        }
        print(_NESTED_PROTOCOL + json.dumps(report, sort_keys=True), flush=True)
        if _ACTIVE["initializations"] != 1:
            raise AssertionError("original case did not prepare exactly one fixture")
        _require_success(report, test_id=test_id, nested=True)
    finally:
        _ACTIVE = None


def _text(value):
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")


def _run_prepared_child(test_id):
    with tempfile.TemporaryDirectory(prefix="prepared-admission-child-") as directory:
        root = Path(directory) / "ScientistOne"
        _prepare(root, test_id)
        if test_id not in _HISTORICAL_DRIFT_CASES:
            captured_child(root, test_id=test_id, module_name=_WRAPPER_MODULE,
                           worker_id=_WRAPPER_ID, nested=True)
            return
        # Two fixed cases only. Every captured_child validates its own exact
        # pre/post inputs, closure and reports before this parent can proceed.
        phase = "construction"
        phases = []
        print("SCIENTIST_ONE_HISTORICAL_DRIFT_PHASE_V1=" + json.dumps({
            "test_id": test_id, "phase": phase, "status": "BEGIN",
            "module_name": _WRAPPER_MODULE,
        }, sort_keys=True), flush=True)
        try:
            phases.append(captured_child(root, test_id=test_id, module_name=_WRAPPER_MODULE,
                                         worker_id=_WRAPPER_ID, nested=True))
            phase = "parent_mutation"
            mutation = _mutate_historical_live_input(root, test_id)
            phase = "replay"
            print("SCIENTIST_ONE_HISTORICAL_DRIFT_PHASE_V1=" + json.dumps({
                "test_id": test_id, "phase": phase, "status": "BEGIN",
                "module_name": _REPLAY_MODULE,
            }, sort_keys=True), flush=True)
            phases.append(replay_child(root, test_id))
            if len(phases) != 2 or any(set(item) != {"original", "worker"} for item in phases):
                raise AssertionError("historical drift requires exactly two complete phases")
            for index, (module, identity, original) in enumerate((
                    (_WRAPPER_MODULE, _WRAPPER_ID, test_id), (_REPLAY_MODULE, _REPLAY_ID, None))):
                phase_report = phases[index]
                worker = phase_report["worker"]
                _require_success(worker, test_id=identity, nested=False)
                if worker["module_name"] != module:
                    raise AssertionError("historical drift phase was swapped or substituted")
                if original is None:
                    if phase_report["original"] is not None:
                        raise AssertionError("replay unexpectedly claims another original case")
                else:
                    _require_success(phase_report["original"], test_id=original, nested=True)
            phase = "complete"
            print("SCIENTIST_ONE_HISTORICAL_DRIFT_PHASE_V1=" + json.dumps({
                "test_id": test_id, "phase": phase, "status": "PASS",
                "mutation": mutation,
                "validated_phases": [{
                    "module_name": item["worker"]["module_name"],
                    "module_sha256": item["worker"]["module_sha256"],
                    "worker_ids": item["worker"]["test_ids"],
                    "original_ids": item["original"]["test_ids"] if item["original"] is not None else [],
                    "project_source_attestation": item["worker"]["project_source_attestation"],
                    "test_source_attestation": item["worker"]["test_source_attestation"],
                } for item in phases],
            }, sort_keys=True), flush=True)
        except BaseException as exc:
            print("SCIENTIST_ONE_HISTORICAL_DRIFT_PHASE_V1=" + json.dumps({
                "test_id": test_id, "phase": phase, "status": "FAIL",
                "error_type": type(exc).__name__, "validated_phase_count": len(phases),
            }, sort_keys=True), flush=True)
            raise


def replay_child(root, test_id):
    return captured_child(root, test_id=test_id, module_name=_REPLAY_MODULE,
                          worker_id=_REPLAY_ID, nested=False)


def _whole_file_snapshot(root):
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
            path.stat().st_size, path.stat().st_mtime_ns, path.stat().st_ctime_ns,
            path.stat().st_mode, path.stat().st_nlink,
        ) for path in root.rglob("*") if path.is_file()
    }


def _mutate_historical_live_input(root, test_id):
    """Parent-only exact delta, after construction exit and before fresh capture."""
    root = root.resolve(strict=True)
    kind = _HISTORICAL_DRIFT_CASES[test_id]
    relative = "src/scientist_one/__init__.py" if kind == "source" else "configs/resource_limits.json"
    path = root / relative
    report = {"schema_version": "historical-drift-mutation/v1", "test_id": test_id,
              "kind": kind, "path": relative, "status": "BEGIN",
              "historical_run_rewritten": False, "bootstrap_rewritten": False}
    before = after = None
    def descriptor(item):
        return {"sha256": hashlib.sha256(item[0]).hexdigest(), "size": len(item[0]),
                "identity": list(item[1:])}
    def inventory_digest(snapshot):
        return hashlib.sha256(canonical_json_bytes(
            {p: descriptor(v) for p, v in sorted(snapshot.items())}
        )).hexdigest()
    try:
        if (root.resolve(strict=True) != root or root.name != "ScientistOne"
                or not root.parent.name.startswith("prepared-admission-child-")
                or root.parent.parent != Path(tempfile.gettempdir()).resolve()
                or root == _PROJECT_ROOT):
            raise AssertionError("historical mutation requires its exact parent-owned temporary root")
        for current in (root, *[root / part for part in Path(relative).parents if part != Path(".")], path):
            if current.is_symlink():
                raise AssertionError("historical mutation path is aliased")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AssertionError("historical mutation target is not a unique regular file")
        before = _whole_file_snapshot(root)
        raw = before[relative][0]
        report.update(before=descriptor(before[relative]), before_snapshot_sha256=inventory_digest(before))
        if kind == "source":
            expected_raw = (_PROJECT_ROOT / relative).read_bytes()
            report["expected_preimage_sha256"] = hashlib.sha256(expected_raw).hexdigest()
            if raw != expected_raw:
                raise AssertionError("historical source preimage differs from the prepared physical copy")
            suffix = b"\n# Test-owned historical negative-readback live identity drift.\n"
            changed = raw + suffix
            if ast.dump(ast.parse(raw)) != ast.dump(ast.parse(changed)):
                raise AssertionError("literal source comment changed Python semantics")
            report["literal_appended_utf8"] = suffix.decode("utf-8")
        else:
            expected = ResourceConfig().to_dict()
            expected.update(cpu_worker_limit=1, stall_timeout_seconds=10,
                            checkpoint_interval_seconds=5, maximum_wall_clock_seconds=1000,
                            default_device="cpu")
            expected_raw = canonical_json_bytes(expected) + b"\n"
            report["expected_preimage_sha256"] = hashlib.sha256(expected_raw).hexdigest()
            if raw != expected_raw:
                raise AssertionError("historical configuration preimage differs from prepared policy")
            changed_value = dict(expected, maximum_wall_clock_seconds=1001)
            ResourceConfig.from_mapping(changed_value)
            changed = canonical_json_bytes(changed_value) + b"\n"
            report["fixed_value_change"] = {"maximum_wall_clock_seconds": [1000, 1001]}
        report.update(before=descriptor(before[relative]),
                      expected_after_sha256=hashlib.sha256(changed).hexdigest(),
                      expected_after_size=len(changed), before_snapshot_sha256=inventory_digest(before))
        print("SCIENTIST_ONE_HISTORICAL_DRIFT_MUTATION_V1=" + json.dumps(report, sort_keys=True), flush=True)
        # In-place write to the one pre-existing unique owned file. No rename,
        # unlink, directory creation, run rewrite, or bootstrap reattestation.
        path.write_bytes(changed)
        after = _whole_file_snapshot(root)
        changed_paths = {p for p in set(before) | set(after) if before.get(p) != after.get(p)}
        report.update(after=descriptor(after[relative]), after_snapshot_sha256=inventory_digest(after),
                      changed_paths=sorted(changed_paths), file_count_before=len(before), file_count_after=len(after))
        if (set(before) != set(after) or changed_paths != {relative}
                or after[relative][0] != changed
                or before[relative][1:3] != after[relative][1:3]
                or before[relative][6:] != after[relative][6:]):
            raise AssertionError("historical mutation exceeded its exact content/identity delta")
        report["status"] = "PASS"
        return report
    except BaseException as exc:
        report["status"] = "FAIL"
        report["error_type"] = type(exc).__name__
        if before is not None and after is None:
            try:
                after = _whole_file_snapshot(root)
                report["after_snapshot_sha256"] = inventory_digest(after)
                report["changed_paths"] = sorted(p for p in set(before) | set(after)
                                                 if before.get(p) != after.get(p))
                if relative in after:
                    report["after"] = descriptor(after[relative])
            except Exception as observation_error:
                report["after_snapshot_error_type"] = type(observation_error).__name__
        raise
    finally:
        print("SCIENTIST_ONE_HISTORICAL_DRIFT_MUTATION_V1=" + json.dumps(report, sort_keys=True), flush=True)


def captured_child(root, *, test_id, module_name, worker_id, nested):
    before = _snapshot(root)
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "scripts/scientist_one_cli.py",
             "__captured-test-module__", module_name], cwd=root,
            check=False, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        print("SCIENTIST_ONE_PREPARED_ADMISSION_RAW_V1=" + json.dumps({
            "test_id": test_id, "timed_out": True,
            "stdout": _text(exc.stdout), "stderr": _text(exc.stderr),
        }, sort_keys=True), flush=True)
        raise AssertionError("captured admission child timed out") from exc
    # Retain raw nested reports before validation or cleanup, including every
    # child failure. This is test evidence, never scientific authority.
    print("SCIENTIST_ONE_PREPARED_ADMISSION_RAW_V1=" + json.dumps({
        "test_id": test_id, "timed_out": False, "returncode": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr,
    }, sort_keys=True), flush=True)
    after = _snapshot(root)
    if after != before:
        raise AssertionError("child changed controlled input bytes, identities or path set")
    if completed.returncode != 0 or completed.stderr:
        raise AssertionError("captured admission child failed; raw reports retained above")
    lines = completed.stdout.splitlines()
    reports = []
    for protocol in ((_NESTED_PROTOCOL, _WORKER_PROTOCOL) if nested else (_WORKER_PROTOCOL,)):
        matches = [line[len(protocol):] for line in lines if line.startswith(protocol)]
        if len(matches) != 1:
            raise AssertionError(f"child must emit exactly one {protocol}: {completed.stdout}")
        reports.append(json.loads(matches[0]))
    if nested:
        original, worker = reports
        _require_success(original, test_id=test_id, nested=True)
    else:
        worker = reports[0]
    _require_success(worker, test_id=worker_id, nested=False)
    if (worker["module_name"] != module_name
            or worker["module_sha256"] != hashlib.sha256(before[_module_path(module_name)][0]).hexdigest()
            or type(worker["elapsed_seconds"]) not in (int, float)
            or not math.isfinite(worker["elapsed_seconds"])
            or worker["elapsed_seconds"] < 0):
        raise AssertionError("child module or elapsed time differs")
    for key, schema, expected_paths in (
        ("project_source_attestation", "SCIENTIST_ONE_CAPTURED_SOURCE_V1",
         {p for p in before if p.startswith(("src/", "scripts/"))}),
        ("test_source_attestation", "SCIENTIST_ONE_CAPTURED_TESTS_V1",
         {p for p in before if p.startswith("tests/")}),
    ):
        attestation = worker[key]
        if (type(attestation) is not dict or set(attestation) != {"schema_version", "entries"}
                or attestation["schema_version"] != schema
                or type(attestation["entries"]) is not list):
            raise AssertionError("child attestation schema differs")
        entries = attestation["entries"]
        if (any(type(e) is not dict or set(e) != {"path", "sha256", "size"}
                or type(e["size"]) is not int for e in entries)
                or len(entries) != len(expected_paths)
                or {e["path"] for e in entries} != expected_paths):
            raise AssertionError("child attestation closure differs")
        for entry in entries:
            raw = before[entry["path"]][0]
            if entry["sha256"] != hashlib.sha256(raw).hexdigest() or entry["size"] != len(raw):
                raise AssertionError("child attestation content differs")
    loaded = worker["loaded_test_modules"]
    expected_modules = _BASE_MODULES | {module_name}
    if (type(loaded) is not list or len(loaded) != len(expected_modules)
            or any(type(e) is not dict or set(e) != {"module_name", "sha256"} for e in loaded)
            or {e["module_name"] for e in loaded} != expected_modules):
        raise AssertionError("child loaded test closure differs")
    for entry in loaded:
        if entry["sha256"] != hashlib.sha256(before[_module_path(entry["module_name"])][0]).hexdigest():
            raise AssertionError("child loaded test identity differs")
    print("SCIENTIST_ONE_PREPARED_ADMISSION_VALIDATION_V1=" + json.dumps({
        "schema_version": "prepared-admission-validation/v1",
        "test_id": test_id, "controlled_inputs_verified": True,
        "worker_and_original_case_verified": True,
    }, sort_keys=True), flush=True)
    return {"original": original if nested else None, "worker": worker}
